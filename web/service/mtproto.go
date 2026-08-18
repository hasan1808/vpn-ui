package service

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hasan1808/pro-ui/backend"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/json_util"
	"github.com/hasan1808/pro-ui/xray"
)

// MtprotoService manages the MTProto Proxy (Telegram) protocol, backed by the
// bundled `telemt` daemon: one process per inbound, like ocserv and accel-ppp.
//
// MTProto is the ODD ONE OUT among the VPN protocols and the differences are
// load-bearing, so they are spelled out here rather than discovered later:
//
//   - It is a userspace TCP RELAY, not a tunnel. There is no ppp0/tun0, no kernel
//     module, no nftables rule, and CRUCIALLY no per-client tunnel IP. Every other
//     VPN protocol hands each device an IP out of 10.N.0.0/16 and that IP is the
//     session-registry key, the nft counter key, and the Xray routing key. MTProto
//     has none of that, so it deliberately does NOT touch vpnrange.go, does NOT get
//     a protocolBase, and does NOT go through the rbridge/nft accounting path. That
//     path would fail SILENTLY (AddClientAccounting discards every nft error and
//     returns nil), leaving accounts that look online and bill zero forever.
//
//   - Accounting comes from telemt's own per-user counters, scraped off its
//     loopback Prometheus endpoint (telemt_user_octets_from_client / _to_client)
//     and folded straight into client_traffics. No IP is involved.
//
//   - User Limit is enforced BY telemt (user_max_unique_ips counts distinct client
//     source IPs per account), not by the panel's K-consecutive-IPs allocator. So
//     there is no rbridge Adapter here: nothing to poll, nothing to evict. The
//     "strategy" (reject vs accept-evict-oldest) is not configurable: telemt
//     rejects the excess device.
//
//   - Xray routing works via the inbound TAG and the socks USERNAME, not source IPs:
//     the panel injects a loopback socks inbound tagged with inbound.Tag
//     (GetSocksConfig) and points telemt's [[upstreams]] at it, so operator rules
//     match this inbound exactly like every other one. Per-CLIENT rules work too,
//     but by a different carrier: telemt presents the authenticated account as the
//     RFC1929 socks username, which Xray turns into inbound.User.Email for the
//     `user` matcher. That is why mtproto is intentionally absent from
//     BuildVpnEmailToIPMap's allowlist: it needs no email-to-IP translation, having
//     no IP to translate.
//
//   - adtag and Xray routing are MUTUALLY EXCLUSIVE, and this is Telegram's design,
//     not a gap in telemt. adtag requires middle-proxy mode, whose RPC session key
//     is derived from the proxy's own egress IP *and port* (aes_create_keys bakes
//     client_ip/client_port into the KDF; both sides derive it independently). Any
//     TCP-terminating proxy (socks5, VLESS, TUN-via-gvisor) re-originates the
//     connection with a new source port, so the keys disagree and the handshake
//     fails. telemt can recover the true tuple from a SOCKS5 BND reply, but Xray's
//     socks server answers with its OWN listen address (proxy/socks/protocol.go:
//     responseAddress = s.address), which telemt classifies as a bogon. We therefore
//     never set an upstream while adtag is on, and pin me_socks_kdf_policy=strict so
//     the failure is loud rather than a silently untagged proxy.
type MtprotoService struct {
	inboundService InboundService
}

// mtprotoSettings is the MTProto slice of an inbound's Settings JSON.
//
// The INBOUND owns the proxy's policy: which connection modes it accepts, the FakeTLS
// domain it emulates, and the per-account device cap. These used to be per-client
// fields, which the data model allowed but telemt never honoured:
//
//   - [censorship].tls_domain models ONE domain's real certificate for the whole
//     process, so the old firstTlsDomain() collapsed every account's domain to the
//     first one anyway.
//   - modes were a per-account map on top of a process-wide listener union, so the
//     inbound already had to accept the union of everything any account held.
//
// The credential (secret), the link endpoints (externalProxy) and the ad tag are
// per-account and stay on the client. The ad tag is the awkward one and is called
// out at anyAdtag: telemt really does key it per user, so two accounts on one inbound
// can carry different tags, but the middle-proxy path any tag needs is a PROCESS
// switch, so a tag on ONE account changes the egress of every account beside it.
//
// Data in the PRE-MOVE shape still reaches this struct, and still has to mean the same
// thing when it does. See the compatibility block below (resolveMtprotoPolicy,
// UnmarshalJSON, MirrorInboundSettingsToClients) before changing any of these five.
type mtprotoSettings struct {
	Clients []mtprotoClient `json:"clients"`

	// Connection modes this inbound accepts. The client picks one via its secret's
	// prefix (bare / dd / ee); these say which the proxy will accept, and which links
	// the UI offers. Rendered into [general.modes] (the listener) and repeated into
	// [access.user_modes] for every account, because telemt reads an EMPTY per-account
	// entry as "no restriction", the exact opposite of what an operator asked for.
	ModeClassic bool `json:"modeClassic"` // no prefix: obfuscated2 / abridged
	ModeSecure  bool `json:"modeSecure"`  // "dd" prefix: random padding
	ModeTls     bool `json:"modeTls"`     // "ee" prefix: FakeTLS

	// TlsDomain is the SNI the FakeTLS links front and the certificate telemt models
	// its fake ServerHello on. One per process: the listener still runs
	// unknown_sni_action="accept" (the handshake HMAC, not the SNI, proves secret
	// possession), so a client presenting another name is not refused, it just gets
	// an emulation modelled on this domain.
	TlsDomain string `json:"tlsDomain"`

	// UserLimit is the PER-ACCOUNT device cap, the same shape l2tp/wgc/gre/openconnect
	// use: nil=absent(legacy=>1); 0=no limit; else 1..64. Enforced by telemt counting
	// distinct client source IPs per account, not by the panel's IP allocator.
	UserLimit *int `json:"userLimit"`

	// ExternalProxy is the inbound-wide default set of link endpoints, used for every
	// account that does not name its own. Like the per-account list it is
	// link-generation only: telemt never sees it.
	ExternalProxy []mtprotoExternalProxy `json:"externalProxy"`
}

// mtprotoClient is a MINIMAL client struct holding only what this service reads.
// The UI posts the FULL client object (tgId as a string, comment, reset, …), and
// unmarshaling into a minimal struct silently drops the extras. Using
// []model.Client instead FAILS on the string tgId and would skip the whole inbound,
// leaving the core stuck "stopped", the same trap ocserv and sstp document.
type mtprotoClient struct {
	// Identity is the EMAIL, like WireGuard (C): there is no separate username.
	// It is the [access.users] key, the client_traffics key, and the routing
	// identity, so one string means one account everywhere.
	Email  string `json:"email"`
	Secret string `json:"secret"` // 32 hex chars, the credential
	Enable bool   `json:"enable"`

	// This account's own device cap. nil = inherit the inbound's User Limit, and it can
	// only LOWER it (resolveUserLimitOverride).
	//
	// A DIFFERENT key from the "userLimit" this service already mirrors onto every
	// client: that one is the INBOUND's cap written down for a downgrade, rewritten by
	// MirrorInboundSettingsToClients on every sweep and read back by deriveMtprotoPolicy
	// as the MAX across accounts. Overloading it would make an operator's per-account
	// value both disappear within seconds and raise the inbound's own cap on its way out.
	UserLimitOverride *int `json:"userLimitOverride"`

	// AdtagEnable/Adtag credit sponsored channels to THIS account's tag, from
	// @MTProxybot. Genuinely per-account storage (telemt's [access.user_ad_tags] is a
	// per-user map, so two accounts can carry different tags), but NOT a per-account
	// decision: the middle-proxy path a tag needs is a process switch, so setting one
	// here takes Xray routing away from every account on the inbound. See anyAdtag.
	AdtagEnable bool   `json:"adtagEnable"`
	Adtag       string `json:"adtag"`

	// ExternalProxy holds alternate host:port endpoints rendered into this
	// account's links instead of the panel's own address (a relay/CDN in front).
	// Link-generation only: telemt never sees it.
	ExternalProxy []mtprotoExternalProxy `json:"externalProxy"`
}

// mtprotoExternalProxy is one alternate endpoint for an account's links.
type mtprotoExternalProxy struct {
	Dest   string `json:"dest"`
	Port   int    `json:"port"`
	Remark string `json:"remark"`
}

// modes returns the connection modes this inbound accepts, as telemt's
// [general.modes] and [access.user_modes] spell them. An inbound with none enabled
// can be dialed by nothing, which RestartServices refuses to start rather than
// render a config telemt reads as unrestricted.
func (m *mtprotoSettings) modes() []string {
	var out []string
	if m.ModeClassic {
		out = append(out, "classic")
	}
	if m.ModeSecure {
		out = append(out, "secure")
	}
	if m.ModeTls {
		out = append(out, "tls")
	}
	return out
}

// --- Compatibility with the pre-move settings shape --------------------------------
//
// Before the release that moved them, the three modes, the FakeTLS domain and the
// device cap lived on every CLIENT. Data in that shape keeps arriving long after the
// upgrade, by paths the startup lift does not sit on: a database restored from an old
// backup, `vpn-ui migrate`, an API caller scripted against the old field names, or an
// operator who rolled back to the previous binary, wrote, and rolled forward again.
// Two halves cover it, and both have to exist:
//
//   - READ: resolveMtprotoPolicy resolves the effective policy out of EITHER shape and
//     mtprotoSettings.UnmarshalJSON applies it, so nothing can read a legacy inbound as
//     "no modes at all" merely because the lift has not run on it yet.
//   - WRITE: MirrorInboundSettingsToClients copies the inbound's settled values back
//     down onto every client, so the same blob still means something to the OLD binary.

// MtprotoInboundPolicy is the inbound-level half of an MTProto inbound's settings:
// everything telemt applies process-wide (see mtprotoSettings). Exported because the
// subscription service builds tg:// links off exactly this set and must resolve it the
// same way, legacy shape included, or a subscriber gets links for transports the proxy
// refuses.
type MtprotoInboundPolicy struct {
	ModeClassic bool
	ModeSecure  bool
	ModeTls     bool
	TlsDomain   string
	// UserLimit keeps the RAW reading: nil=absent(=>1 device); 0=no limit; else 1..64.
	// Resolve it through effectiveUserLimit, never by dereferencing.
	UserLimit *int
	// ExternalProxy is the inbound's default link endpoints. An account carrying its
	// own list overrides this one outright rather than adding to it: the two are
	// alternative answers to "where do this account's links point", and merging them
	// would hand a subscriber endpoints the operator meant to replace.
	ExternalProxy []MtprotoEndpoint
}

// MtprotoEndpoint is one alternate host:port a tg:// link can advertise.
type MtprotoEndpoint struct {
	Dest   string `json:"dest"`
	Port   int    `json:"port"`
	Remark string `json:"remark"`
}

// ModeEnabled reports whether this inbound accepts one of telemt's mode names.
func (p MtprotoInboundPolicy) ModeEnabled(mode string) bool {
	switch mode {
	case "classic":
		return p.ModeClassic
	case "secure":
		return p.ModeSecure
	case "tls":
		return p.ModeTls
	}
	return false
}

// mtprotoLegacyClient is the PRE-MOVE per-client shape, alive as a read format only.
//
// adtagEnable/adtag are deliberately not here. The ad tag never moved: it is still a
// live per-client field on mtprotoClient, so there is nothing about it to resolve and
// nothing to mirror.
type mtprotoLegacyClient struct {
	ModeClassic bool   `json:"modeClassic"`
	ModeSecure  bool   `json:"modeSecure"`
	ModeTls     bool   `json:"modeTls"`
	TlsDomain   string `json:"tlsDomain"`
	UserLimit   *int   `json:"userLimit"`
}

// MtprotoInboundPolicyOf resolves an MTProto inbound's policy straight from its stored
// settings JSON, in either shape. The entry point for readers outside this package;
// inside it, parseSettings already returns a resolved mtprotoSettings.
//
// Unparseable settings resolve to the zero policy (no mode accepted), which is what
// every caller already did with a decode error: offer nothing rather than guess.
func MtprotoInboundPolicyOf(settings string) MtprotoInboundPolicy {
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(settings), &root); err != nil || root == nil {
		return MtprotoInboundPolicy{}
	}
	policy, _ := resolveMtprotoPolicy(root)
	return policy
}

// liftMtprotoSettingsBlob rewrites a settings blob in the pre-move shape into the
// current one, with no database involved. The ADD path's entry point, called from
// NormalizeInboundSettings ahead of FillSettingsDefaults.
//
// Order there is the whole reason this exists. An API body in the old shape carries its
// policy on the CLIENTS and names none of the inbound-level keys, so filling defaults
// first would stamp the fresh-inbound values (all three modes on, no device cap) over
// it. The blob would then look already-migrated to every later reader, the startup lift
// would skip it forever, and the caller's narrower set would be gone with nothing left
// to recover it from.
//
// Returns the input untouched when it is not MTProto, is not a JSON object, or is
// already in the current shape.
func liftMtprotoSettingsBlob(protocol model.Protocol, settings string) string {
	if protocol != model.MTPROTO {
		return settings
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(settings), &raw); err != nil || raw == nil {
		return settings
	}
	policy, legacy := resolveMtprotoPolicy(raw)
	if !legacy {
		return settings
	}
	for key, value := range map[string]any{
		"modeClassic": policy.ModeClassic,
		"modeSecure":  policy.ModeSecure,
		"modeTls":     policy.ModeTls,
		"tlsDomain":   policy.TlsDomain,
		"userLimit":   *policy.UserLimit, // deriveMtprotoPolicy never leaves this nil
	} {
		bs, err := json.Marshal(value)
		if err != nil {
			return settings
		}
		raw[key] = bs
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return settings
	}
	return string(out)
}

// resolveMtprotoPolicy answers what a settings blob MEANS, whichever shape it is in,
// and reports whether it had to fall back to the legacy one.
//
// The shape test is key PRESENCE at the settings root, never a value. A blob carrying
// none of modeClassic/modeSecure/modeTls predates the move: protocoldefaults.go seeds
// all three onto every inbound created since, and the lift stamps all three onto every
// one that existed before, so their joint absence is unambiguous. Anything else is read
// straight off the root, an explicit false included: that is an operator turning a mode
// off, not an absence to be guessed at.
//
// The legacy derivation is the MIGRATION'S, exactly, and sharing one function is the
// point: the value a pre-lift read resolves to and the value the lift will eventually
// store are the same one, so nothing an operator can observe changes when the lift
// lands. A fallback to the fresh-inbound defaults instead would have silently widened
// every legacy inbound to all three modes and no device cap for as long as the lift had
// not run, and permanently for any path that writes back what it read (the panel's own
// inbound form does exactly that).
func resolveMtprotoPolicy(root map[string]json.RawMessage) (MtprotoInboundPolicy, bool) {
	_, hasClassic := root["modeClassic"]
	_, hasSecure := root["modeSecure"]
	_, hasTls := root["modeTls"]
	if !hasClassic && !hasSecure && !hasTls {
		var clients []mtprotoLegacyClient
		if blob, ok := root["clients"]; ok {
			// A clients value that is not an array is somebody else's problem
			// (checkClients refuses it on save); derive from nothing and move on.
			_ = json.Unmarshal(blob, &clients)
		}
		return deriveMtprotoPolicy(clients), true
	}

	var policy MtprotoInboundPolicy
	get := func(key string, into any) {
		if bs, ok := root[key]; ok {
			// A value of the wrong type leaves the field at its zero value rather than
			// failing the whole inbound: one bad key must not take the other four down.
			_ = json.Unmarshal(bs, into)
		}
	}
	get("modeClassic", &policy.ModeClassic)
	get("modeSecure", &policy.ModeSecure)
	get("modeTls", &policy.ModeTls)
	get("tlsDomain", &policy.TlsDomain)
	get("userLimit", &policy.UserLimit)
	get("externalProxy", &policy.ExternalProxy)
	return policy, false
}

// deriveMtprotoPolicy seeds the inbound-level policy from a pre-move blob's accounts.
// The one place the seeding rules live; the lift, the read-side fallback and (mirrored
// by hand) the panel's own form all resolve through them.
//
//   - Modes: the UNION over the accounts, which is what the LISTENER already accepted.
//     Some accounts gain a mode they did not individually hold; that granularity is
//     what is being removed, on purpose.
//   - TlsDomain: the first FakeTLS account's domain, which is the one telemt already
//     modelled its fake certificate on for the whole process.
//   - UserLimit: the MAX across accounts, and THIS ONE CHANGES BEHAVIOUR. Two accounts
//     on one inbound really could hold different device caps, each enforced separately
//     in [access.user_max_unique_ips], and afterwards they cannot. Max is chosen
//     because it is the most permissive: nobody is locked out by the upgrade, at worst
//     an account that was capped tighter than its neighbour gains headroom.
func deriveMtprotoPolicy(clients []mtprotoLegacyClient) MtprotoInboundPolicy {
	var policy MtprotoInboundPolicy
	capEff := -1
	for _, c := range clients {
		policy.ModeClassic = policy.ModeClassic || c.ModeClassic
		policy.ModeSecure = policy.ModeSecure || c.ModeSecure
		policy.ModeTls = policy.ModeTls || c.ModeTls
		if policy.TlsDomain == "" && c.ModeTls && strings.TrimSpace(c.TlsDomain) != "" {
			policy.TlsDomain = strings.TrimSpace(c.TlsDomain)
		}
		// Compare on the EFFECTIVE cap, not the raw number: an ABSENT value means one
		// device while an explicit 0 means no limit, which is 16 here (noLimitDevices),
		// so the raw numbers are not on one scale. Storing the raw value of the winner
		// keeps the distinction intact.
		if eff := effectiveUserLimit(c.UserLimit); eff > capEff {
			capEff, policy.UserLimit = eff, c.UserLimit
		}
	}
	if !policy.ModeClassic && !policy.ModeSecure && !policy.ModeTls {
		// No account held a usable mode (or there are no accounts at all), so there is
		// nothing to preserve: fall back to the same all-on default a freshly created
		// inbound gets rather than resolve to a config that grants everything (telemt
		// reads an EMPTY per-account mode entry as "no restriction").
		policy.ModeClassic, policy.ModeSecure, policy.ModeTls = true, true, true
	}
	if policy.UserLimit == nil {
		// Either there were no accounts, or every one of them predates the field. An
		// absent per-client value resolved to 1 device (effectiveUserLimit), so an
		// explicit 1 keeps the cap exactly where it was; only a truly empty inbound gets
		// the fresh-inbound default of 10 devices.
		legacy := 1
		if len(clients) == 0 {
			legacy = 10
		}
		policy.UserLimit = &legacy
	}
	if policy.TlsDomain == "" {
		policy.TlsDomain = "www.google.com"
	}
	return policy
}

// UnmarshalJSON decodes an MTProto inbound's settings in EITHER shape.
//
// The fallback lives on the TYPE rather than in parseSettings so that it cannot be
// bypassed by a decode that reaches this struct some other way. What it prevents is
// specific and silent: a legacy blob decoded plainly comes out with all three modes
// false, and to telemt that is not "no modes" but "no restriction" (our patch reads an
// empty [access.user_modes] entry that way), so the proxy would hand every account
// every transport. startable() catches the rendered case and refuses to run the inbound
// at all, which is the same outage by a louder route.
func (m *mtprotoSettings) UnmarshalJSON(bs []byte) error {
	// A named type with no methods, so this is the ordinary decode and not a recursion.
	type plain mtprotoSettings
	var decoded plain
	if err := json.Unmarshal(bs, &decoded); err != nil {
		return err
	}
	*m = mtprotoSettings(decoded)

	var root map[string]json.RawMessage
	if err := json.Unmarshal(bs, &root); err != nil || root == nil {
		// Not an object (a literal null is the realistic case): the decode above already
		// left the zero value, and there is nothing to resolve against.
		return nil
	}
	policy, legacy := resolveMtprotoPolicy(root)
	if !legacy {
		return nil
	}
	m.ModeClassic, m.ModeSecure, m.ModeTls = policy.ModeClassic, policy.ModeSecure, policy.ModeTls
	m.TlsDomain, m.UserLimit = policy.TlsDomain, policy.UserLimit
	return nil
}

// mtprotoProcName is this inbound's procMgr child name. telemt does not retitle
// its own process, so the prefix reap in migrateFromSystemd needs no -x entry.
func mtprotoProcName(inboundId int) string {
	return fmt.Sprintf("mtproto-server-%d", inboundId)
}

// configDir holds this inbound's config.toml plus telemt's own data dir (quota
// state, TLS-emulation cache).
func (s *MtprotoService) configDir(inboundId int) string {
	return fmt.Sprintf("/etc/vpn-ui-mtproto/server-%d", inboundId)
}

// GetSocksPort is the loopback socks inbound telemt egresses through, following
// the panel-wide "Xray-side port for inbound N is 12300+N" convention (inbound.Id
// is globally unique, so this cannot collide with another protocol's dokodemo).
func (s *MtprotoService) GetSocksPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// mtprotoMetricsPort is telemt's loopback Prometheus endpoint: the accounting
// source (per-user up/down octets).
func mtprotoMetricsPort(inbound *model.Inbound) int {
	return 14300 + inbound.Id
}

// mtprotoSystemAccount is the socks identity telemt falls back to for its own
// account-less connections (startup DC probes). It is deliberately not a valid
// email, so it cannot be shadowed by a real account and never matches an
// operator's per-client routing rule; that traffic takes the default outbound.
const mtprotoSystemAccount = "telemt-system"

// GetMtprotoInbounds returns every mtproto inbound.
func (s *MtprotoService) GetMtprotoInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", model.MTPROTO).Find(&inbounds).Error
	if err != nil {
		return nil, err
	}
	return inbounds, nil
}

func (s *MtprotoService) parseSettings(inbound *model.Inbound) (*mtprotoSettings, error) {
	settings := &mtprotoSettings{}
	if err := json.Unmarshal([]byte(inbound.Settings), settings); err != nil {
		return nil, err
	}
	return settings, nil
}

// usingRouting reports whether this inbound egresses through Xray. adtag forces
// direct egress (see the type comment), so the two are never both on.
func (s *MtprotoService) usingRouting(settings *mtprotoSettings) bool {
	return !s.anyAdtag(settings)
}

// anyAdtag reports whether ANY account on this inbound carries an ad tag.
//
// Any, not each, and that asymmetry is the whole point. The tag is stored per client
// and telemt writes it per user ([access.user_ad_tags]), so the FIELD looks like a
// per-account choice. Its EFFECT is not: the middle-proxy path a tag needs is a
// PROCESS-wide switch (use_middle_proxy), so tagging ONE account puts every account
// on this inbound onto that path, egressing directly with no Xray routing at all.
// The operator who ticks the box for one customer silently forfeits their routing
// rules for every other customer on the same inbound, which is why the client form
// warns at the switch rather than after the save.
//
// That is Telegram's design, not a telemt gap: the middle-proxy session key is
// derived from the proxy's own egress IP and port, which any proxied egress rewrites.
func (s *MtprotoService) anyAdtag(settings *mtprotoSettings) bool {
	for _, c := range settings.Clients {
		if c.AdtagEnable && strings.TrimSpace(c.Adtag) != "" {
			return true
		}
	}
	return false
}

// tlsDomain is the domain used for ServerHello emulation, defaulted rather than left
// blank because telemt models its fake certificate on a REAL one: an empty value
// leaves the emulation with nothing to imitate.
func (s *MtprotoService) tlsDomain(settings *mtprotoSettings) string {
	if d := strings.TrimSpace(settings.TlsDomain); d != "" {
		return d
	}
	return "www.google.com"
}

// GetSocksConfig builds the loopback socks inbound that telemt egresses through.
// It carries inbound.Tag, so an operator's Xray routing rules target this MTProto
// inbound exactly like any other. Returns nil when adtag is on, because
// middle-proxy mode must reach Telegram directly.
//
// This is the mtproto analogue of the other protocols' GetDokodemoConfig: same
// hook in xray.go, different shape (a socks listener rather than TPROXY capture,
// since there is no tunnel to intercept).
//
// It also carries PER-CLIENT identity. Every other VPN protocol gives each device a
// tunnel IP and routes it with a source-IP rule; a relay has no such IP, so the
// account rides the one channel a socks hop has: the RFC1929 username. telemt
// presents the authenticated account there (upstreams.socks_user_from_account),
// Xray copies it to inbound.User.Email, and routing rules matching `user` resolve
// per client: same operator-facing behaviour, different carrier.
//
// The password is the account name, not a secret: this listener is bound to
// 127.0.0.1 and both ends of the credential are generated by this panel, so it is
// an identity assertion between two local processes, not an auth boundary. Anyone
// who could reach the port already has local root.
func (s *MtprotoService) GetSocksConfig(inbound *model.Inbound) *xray.InboundConfig {
	settings, err := s.parseSettings(inbound)
	if err != nil || !s.usingRouting(settings) {
		return nil
	}

	// Xray's socks inbound has no AddUser API (unlike vless/vmess/trojan), so the
	// account list is fixed at config time and a client add needs an Xray reload.
	// mtprotoChanged already flags one unconditionally, so this costs nothing extra:
	// telemt itself still hot-reloads and keeps every live client connection.
	type socksAccount struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	// telemt's own DC-reachability probes carry no account and fall back to the
	// upstream's configured username, so that identity needs an account too or the
	// probes fail the handshake and telemt reports every DC unreachable.
	accounts := []socksAccount{{User: mtprotoSystemAccount, Pass: mtprotoSystemAccount}}
	seen := map[string]bool{mtprotoSystemAccount: true}
	for _, c := range s.activeClients(settings) {
		if seen[c.Email] {
			continue
		}
		seen[c.Email] = true
		accounts = append(accounts, socksAccount{User: c.Email, Pass: c.Email})
	}

	socksSettings, err := json.Marshal(struct {
		Auth     string         `json:"auth"`
		Accounts []socksAccount `json:"accounts"`
		UDP      bool           `json:"udp"`
	}{Auth: "password", Accounts: accounts, UDP: false})
	if err != nil {
		logger.Warning("MTProto: socks settings marshal failed:", err)
		return nil
	}
	sniffing := `{"enabled":true,"destOverride":["tls"]}`

	return &xray.InboundConfig{
		Listen:   json_util.RawMessage(`"127.0.0.1"`),
		Port:     s.GetSocksPort(inbound),
		Protocol: "socks",
		Settings: json_util.RawMessage(socksSettings),
		Tag:      inbound.Tag,
		Sniffing: json_util.RawMessage(sniffing),
	}
}

// telemtBinaryPath resolves the bundled static telemt binary.
func (s *MtprotoService) telemtBinaryPath() string {
	return daemonBin("telemt")
}

// InitMtproto brings the MTProto stack up at panel start.
func (s *MtprotoService) InitMtproto() {
	inbounds, err := s.GetMtprotoInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}
	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("MTProto: config generation failed:", err)
		return
	}
	if err := s.RestartServices(); err != nil {
		logger.Warning("MTProto: failed to start services:", err)
	}
}

// LiftClientSettingsToInbound is the one-shot move of modes, FakeTLS domain and
// device cap from the CLIENTS of a legacy inbound onto the INBOUND itself. The ad tag
// is NOT among them: it stayed per-client, and lifting it would have flattened two
// customers' different tags into one.
//
// It cannot be a MigrateDB step: that runs only for an explicit migrate/import/restore
// and never on a plain upgrade, so an operator who just replaced the binary would come
// back to an inbound with no modes at all, which renders empty [access.user_modes]
// entries and (per our telemt patch) grants every account every mode. This runs on the
// ordinary startup path instead, via GenerateAllConfigs.
//
// An un-migrated inbound is one whose settings object has NONE of the inbound-level
// mode keys (resolveMtprotoPolicy, which is also what every READ resolves through, so
// the two can never disagree about which inbounds still need this). A new inbound always
// has them (protocoldefaults.go seeds all three), and a migrated one keeps them, so the
// check is stable and the pass is a no-op from the second call on. That matters:
// GenerateAllConfigs runs every 10 seconds off the traffic job.
//
// The per-client keys that WERE lifted are deliberately left in place, and
// MirrorInboundSettingsToClients goes further and keeps them CURRENT. Nothing in this
// binary reads them; they are what the previous binary reads. See that function.
// adtagEnable/adtag are in neither set: the tag is still a live per-client field and
// this pass must leave it exactly as it finds it.
//
// The seeding rules (union of modes, first FakeTLS domain, largest device cap, and the
// one behaviour change that last one carries) live in deriveMtprotoPolicy.
func (s *MtprotoService) LiftClientSettingsToInbound() error {
	inbounds, err := s.GetMtprotoInbounds()
	if err != nil {
		return err
	}
	db := database.GetDB()

	for _, inbound := range inbounds {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(inbound.Settings), &raw); err != nil || raw == nil {
			continue
		}
		policy, legacy := resolveMtprotoPolicy(raw)
		if !legacy {
			continue // already inbound-level
		}

		set := func(key string, value any) {
			bs, err := json.Marshal(value)
			if err != nil {
				return
			}
			raw[key] = bs
		}
		set("modeClassic", policy.ModeClassic)
		set("modeSecure", policy.ModeSecure)
		set("modeTls", policy.ModeTls)
		set("tlsDomain", policy.TlsDomain)
		set("userLimit", *policy.UserLimit) // deriveMtprotoPolicy never leaves this nil

		out, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		inbound.Settings = string(out)
		if db != nil {
			if err := db.Model(model.Inbound{}).Where("id = ?", inbound.Id).
				Update("settings", inbound.Settings).Error; err != nil {
				logger.Warning("MTProto: lifting client settings onto inbound", inbound.Id, "failed:", err)
				continue
			}
		}
		logger.Info("MTProto: inbound", inbound.Id,
			"upgraded: connection modes, FakeTLS domain and device limit now belong to the inbound",
			"(device limit taken from the largest any account held)")
	}
	return nil
}

// MirrorInboundSettingsToClients copies the inbound's effective modes, FakeTLS domain
// and device cap back down onto every client entry.
//
// THIS IS A COMPATIBILITY MIRROR, NOT STATE. Nothing in this binary reads these
// per-client keys: mtprotoClient does not even model them, and the inbound's own values
// are the only ones buildServerConfig renders. They exist so one settings blob satisfies
// the PREVIOUS binary too, which read the modes, the domain and the cap only from the
// clients. Do not "clean them up" as dead fields, and do not start reading them.
//
// Without the mirror a rollback is a silent outage for every account created since the
// upgrade. Leaving the lifted keys in place (which the lift does) covers accounts that
// existed BEFORE it, but a client added afterwards carries none of them, and the old
// activeClients drops a client whose mode set is empty: it disappears from
// [access.users] entirely, so it cannot authenticate, and nothing in the log says why.
//
// The values are chosen so the old binary computes the SAME config, not merely a valid
// one:
//
//   - modes: written explicitly, false included, so the old per-account mode map is the
//     inbound's set exactly rather than the union of whatever survived.
//   - tlsDomain: the EFFECTIVE domain (never ""), because an empty per-client domain made
//     the old firstTlsDomain skip the account, and because "absent" and "" would compare
//     unequal below and turn this pass into a write on every tick.
//   - userLimit: the RAW value, so an explicit 0 still means "no limit" over there and
//     resolves through the same effectiveUserLimit; an ABSENT inbound value meant one
//     device, so 1 is written for it.
//
// It cannot make the generated config churn, which matters because this runs every 10
// seconds: buildServerConfig reads none of these keys, so the rendered TOML is
// byte-identical before and after a mirror write and generateServerConfig's
// write-only-on-change comparison never fires. The pass itself is a no-op once the
// entries match, and only writes again after something replaces the client list
// wholesale (an inbound save posts clients the panel's JS builds, which do not carry
// dead fields).
func (s *MtprotoService) MirrorInboundSettingsToClients() error {
	inbounds, err := s.GetMtprotoInbounds()
	if err != nil {
		return err
	}
	db := database.GetDB()

	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(inbound.Settings), &raw); err != nil || raw == nil {
			continue
		}
		list, ok := raw["clients"].([]any)
		if !ok {
			continue
		}
		// float64 for the cap, because that is what the numbers already in `raw` decoded
		// into: comparing an int against them would report a difference on every pass and
		// rewrite the row every 10 seconds.
		want := map[string]any{
			"modeClassic": settings.ModeClassic,
			"modeSecure":  settings.ModeSecure,
			"modeTls":     settings.ModeTls,
			"tlsDomain":   s.tlsDomain(settings),
			"userLimit":   float64(mirroredUserLimit(settings.UserLimit)),
		}

		changed := false
		for _, item := range list {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			for key, value := range want {
				if entry[key] != value {
					entry[key] = value
					changed = true
				}
			}
		}
		if !changed {
			continue
		}
		out, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		inbound.Settings = string(out)
		if db != nil {
			if err := db.Model(model.Inbound{}).Where("id = ?", inbound.Id).
				Update("settings", inbound.Settings).Error; err != nil {
				logger.Warning("MTProto: mirroring inbound settings onto the clients of inbound",
					inbound.Id, "failed:", err)
			}
		}
	}
	return nil
}

// mirroredUserLimit is the per-client device cap the mirror writes: the inbound's raw
// value, or the 1 device an absent one has always meant.
func mirroredUserLimit(p *int) int {
	if p == nil {
		return 1
	}
	return *p
}

// ReconcileSecrets mints a secret for any account that has none and persists it.
//
// The UI mints secrets client-side so the tg:// link can render on add, but an
// account created through the API (or imported) may arrive with the field blank,
// and a blank secret is not a usable credential, it just silently drops the account
// out of the rendered config. Mirrors wgc's ReconcileAllKeys.
func (s *MtprotoService) ReconcileSecrets() error {
	inbounds, err := s.GetMtprotoInbounds()
	if err != nil {
		return err
	}
	db := database.GetDB()
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		changed := false
		for i := range settings.Clients {
			if strings.TrimSpace(settings.Clients[i].Secret) == "" {
				sec, err := s.GenerateSecret()
				if err != nil {
					return err
				}
				settings.Clients[i].Secret = sec
				changed = true
			}
		}
		if !changed {
			continue
		}
		// Merge back into the raw settings so fields this service does not model
		// (comment, tgId, …) survive the round-trip.
		var raw map[string]any
		if err := json.Unmarshal([]byte(inbound.Settings), &raw); err != nil {
			continue
		}
		clientsRaw, ok := raw["clients"].([]any)
		if !ok || len(clientsRaw) != len(settings.Clients) {
			continue
		}
		for i, cr := range clientsRaw {
			cm, ok := cr.(map[string]any)
			if !ok {
				continue
			}
			cm["secret"] = settings.Clients[i].Secret
		}
		out, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		inbound.Settings = string(out)
		if db != nil {
			if err := db.Model(model.Inbound{}).Where("id = ?", inbound.Id).
				Update("settings", inbound.Settings).Error; err != nil {
				logger.Warning("MTProto: persisting minted secret failed:", err)
			}
		}
	}
	return nil
}

// GenerateAllConfigs writes every enabled inbound's config.toml, restarting only those
// whose egress changed (see generateServerConfig).
func (s *MtprotoService) GenerateAllConfigs() error {
	// Before anything reads the settings: an inbound stored before modes/domain/tag/cap
	// moved onto the inbound would otherwise render a config with no modes at all.
	if err := s.LiftClientSettingsToInbound(); err != nil {
		logger.Warning("MTProto: lifting legacy client settings failed:", err)
	}
	// After it, so the mirror copies the values the lift just settled rather than the
	// absent ones it was called to replace. Both are no-ops from the second pass on.
	if err := s.MirrorInboundSettingsToClients(); err != nil {
		logger.Warning("MTProto: mirroring inbound settings onto clients failed:", err)
	}
	if err := s.ReconcileSecrets(); err != nil {
		logger.Warning("MTProto: secret reconcile failed:", err)
	}
	inbounds, err := s.GetMtprotoInbounds()
	if err != nil {
		return err
	}
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		needRestart, err := s.generateServerConfig(inbound)
		if err != nil {
			logger.Warning("MTProto: config for inbound", inbound.Id, "failed:", err)
			continue
		}
		if needRestart {
			logger.Info("MTProto: inbound", inbound.Id,
				"egress changed (ad tag toggled); restarting telemt so it stops using the old upstream")
			s.restartServer(inbound)
		}
	}
	return nil
}

// egressConfig extracts the parts of a rendered config.toml that telemt CANNOT
// hot-reload: use_middle_proxy and the [[upstreams]] block. Both re-bind the egress
// path, so telemt's watcher skips them (with only a warning) and keeps serving over
// whatever it started with.
//
// This matters because those two fields flip together with an ad tag, which is a
// per-CLIENT field: setting one used to take the hot-reload path and leave telemt on a
// stale egress. Both directions broke silently, and neither looked like a failure:
//
//   - tag ON: the panel drops the inbound's Xray socks inbound (tagged traffic must
//     egress directly or the ME key cannot derive), but telemt kept dialing that now
//     deleted socks port and refused every client with "Connection refused".
//   - tag OFF: the panel restores the socks inbound, but telemt kept egressing DIRECT,
//     so the operator's Xray routing silently did not apply to any of it. A blackhole
//     outbound did not block the proxy, which is the dangerous half: it looks like it
//     works, and it is bypassing the rules.
func egressConfig(content string) string {
	var b strings.Builder
	inUpstreams := false
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "use_middle_proxy"):
			b.WriteString(t + "\n")
		case strings.HasPrefix(t, "[[upstreams]]"):
			inUpstreams = true
			b.WriteString(t + "\n")
		case strings.HasPrefix(t, "["):
			// Any other section header closes the upstream block.
			inUpstreams = false
		case inUpstreams && t != "" && !strings.HasPrefix(t, "#"):
			b.WriteString(t + "\n")
		}
	}
	return b.String()
}

// generateServerConfig renders one inbound's config.toml. It reports whether the change
// needs a telemt restart, which is true only when the egress (see egressConfig) moved:
// everything else telemt applies itself, and restarting for those would drop every live
// connection on the inbound (the whole point of the hot-reload path).
func (s *MtprotoService) generateServerConfig(inbound *model.Inbound) (bool, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return false, err
	}
	dir := s.configDir(inbound.Id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	// Fold the operator's override in BEFORE the write-only-on-change check below, so
	// the comparison is against the bytes that will actually land. Comparing the bare
	// render would make every tick look like a change once an override existed, and
	// telemt watches this file with inotify: it would hot-reload every 10 seconds.
	content := applyCoreConfigOverride("mtproto", inbound.Id, "config.toml",
		s.buildServerConfig(inbound, settings))
	path := dir + "/config.toml"

	// Write ONLY on change. telemt watches this file with inotify, and a write is a
	// modify event whether or not the bytes differ, so an unconditional write made it
	// reload every time this ran. That is every 10s, because the traffic job calls
	// KillDisabledSessions -> GenerateAllConfigs on each tick. It also defeated the
	// point of activeClients' stable sort, which exists to make the output
	// byte-identical precisely so the watcher stays quiet.
	old, readErr := os.ReadFile(path)
	if readErr == nil && bytes.Equal(old, []byte(content)) {
		return false, nil
	}
	// No previous config means no running instance to be stale: RestartServices starts
	// it fresh, so this is only ever about an EXISTING telemt holding an old egress.
	needRestart := readErr == nil && egressConfig(string(old)) != egressConfig(content)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return false, err
	}
	return needRestart, nil
}

// restartServer (re)starts a single inbound's telemt. procMgr.Start supersedes any
// running instance, so this restarts one inbound without touching the others.
func (s *MtprotoService) restartServer(inbound *model.Inbound) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return
	}
	if !s.startable(settings) {
		return
	}
	dir := s.configDir(inbound.Id)
	name := mtprotoProcName(inbound.Id)
	args := []string{"--data-path", dir, dir + "/config.toml"}
	if err := procMgr.Start(name, s.telemtBinaryPath(), args, nil, dir); err != nil {
		logger.Warning("MTProto: restart of", name, "failed:", err)
	}
}

// tomlEscape quotes a value for a TOML basic string.
func tomlEscape(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return v
}

// buildServerConfig renders one inbound's telemt config.toml.
//
// Client changes land in the [access.*] tables plus [general.modes], all of which
// telemt hot-reloads, so adding or editing an account never drops the other
// accounts' live connections. The rest of [general], and [server]/[[upstreams]],
// are restart-only.
//
// [general.modes] MUST stay hot (it is hot only because of our patch): flipping a
// mode is an inbound edit, and were it restart-only, turning one ON while accounts
// are connected would write a config saying the mode is enabled while the listener
// kept refusing it until the next restart, making the toggle look broken rather
// than deferred.
func (s *MtprotoService) buildServerConfig(inbound *model.Inbound, settings *mtprotoSettings) string {
	var b strings.Builder

	b.WriteString("# Auto-generated by pro-ui (MTProto Proxy). Do not edit.\n")
	b.WriteString("# Regenerated on every inbound/client change; edits are lost.\n\n")

	adtag := s.anyAdtag(settings)

	b.WriteString("[general]\n")
	// Middle-proxy mode carries the ad tag and pins egress to a direct path. It is a
	// PROCESS switch, so it is on as soon as ONE account holds a tag: there is no way
	// to tag that account and keep routing the rest.
	b.WriteString(fmt.Sprintf("use_middle_proxy = %t\n", adtag))
	// Fail loudly rather than silently serving an untagged proxy if a middle-proxy
	// handshake is ever attempted over a SOCKS route whose BND tuple is unusable.
	b.WriteString("me_socks_kdf_policy = \"strict\"\n")
	b.WriteString("log_level = \"normal\"\n")
	// telemt colorizes its log by default. procMgr captures it through a pipe and the
	// panel renders it as plain text, so the ANSI escapes survive as literal "[2m"/
	// "[0m" garbage around every line in Core Settings -> Logs.
	b.WriteString("disable_colors = true\n\n")

	// The listener's modes, which decide which handshakes reach the auth step at all.
	// [access.user_modes] below repeats the same set per account: the listener alone
	// is not enough, because our telemt patch reads a MISSING per-account entry as
	// "no restriction", so an account would keep whatever mode the listener allows.
	b.WriteString("[general.modes]\n")
	b.WriteString(fmt.Sprintf("classic = %t\n", settings.ModeClassic))
	b.WriteString(fmt.Sprintf("secure = %t\n", settings.ModeSecure))
	b.WriteString(fmt.Sprintf("tls = %t\n\n", settings.ModeTls))

	b.WriteString("[server]\n")
	b.WriteString(fmt.Sprintf("port = %d\n", inbound.Port))
	b.WriteString(fmt.Sprintf("metrics_listen = \"127.0.0.1:%d\"\n", mtprotoMetricsPort(inbound)))
	b.WriteString("metrics_whitelist = [\"127.0.0.1/32\"]\n\n")

	// The panel is the source of truth for accounts, so telemt's own control API
	// is left off: nothing would call it, and an open mutating endpoint is surface
	// we do not need.
	b.WriteString("[server.api]\n")
	b.WriteString("enabled = false\n\n")

	b.WriteString("[censorship]\n")
	// A client may present any SNI, so the listener must not insist on this one:
	// accept an unknown SNI and let the handshake HMAC (which is what actually
	// proves secret possession) decide. Without this, only clients dialing with the
	// domain below could connect.
	b.WriteString(fmt.Sprintf("tls_domain = %q\n", tomlEscape(s.tlsDomain(settings))))
	b.WriteString("unknown_sni_action = \"accept\"\n")
	b.WriteString("mask = true\n")
	b.WriteString("tls_emulation = true\n\n")

	if s.usingRouting(settings) {
		b.WriteString("# Egress through the panel's Xray socks inbound (tag: " + inbound.Tag + "),\n")
		b.WriteString("# so operator routing rules apply to this inbound.\n")
		b.WriteString("[[upstreams]]\n")
		b.WriteString("type = \"socks5\"\n")
		b.WriteString(fmt.Sprintf("address = \"127.0.0.1:%d\"\n", s.GetSocksPort(inbound)))
		// Present each account as the socks username so Xray can route per client.
		// Nothing account-specific may appear in this section: [[upstreams]] is
		// restart-only, so listing accounts here would drop every live connection on
		// each client add. The account is carried per CONNECTION instead.
		b.WriteString("socks_user_from_account = true\n")
		// Fallback identity for telemt's own connections that have no account (the
		// startup DC-reachability probes). Not a secret: see GetSocksConfig.
		b.WriteString(fmt.Sprintf("username = %q\n", mtprotoSystemAccount))
		b.WriteString(fmt.Sprintf("password = %q\n\n", mtprotoSystemAccount))
	} else {
		b.WriteString("# adtag is on: middle-proxy mode requires a direct egress whose TCP\n")
		b.WriteString("# 4-tuple reaches Telegram unchanged, so no upstream is configured.\n")
		b.WriteString("[[upstreams]]\n")
		b.WriteString("type = \"direct\"\n\n")
	}

	disabled := s.getDisabledEmails()
	clients := s.activeClients(settings)

	// Identity is the email: there is no separate username (the wg-c model). One
	// string keys the secret, the counters, the routing account and client_traffics.
	b.WriteString("[access.users]\n")
	for _, c := range clients {
		b.WriteString(fmt.Sprintf("%q = %q\n", tomlEscape(c.Email), tomlEscape(c.Secret)))
	}
	b.WriteString("\n")

	// Quota and expiry stay panel-owned (client_traffics + the traffic job flips
	// enable=false), matching every other protocol and keeping one source of truth.
	b.WriteString("[access.user_enabled]\n")
	for _, c := range clients {
		on := c.Enable && !disabled[c.Email]
		b.WriteString(fmt.Sprintf("%q = %t\n", tomlEscape(c.Email), on))
	}
	b.WriteString("\n")

	// The device cap IS delegated: telemt counts distinct client source IPs per
	// account natively, which is the closest a relay gets to a tunnel-IP User Limit.
	// The inbound's value is the PER-ACCOUNT cap (the same reading l2tp/wgc/gre use),
	// so it is written once per account rather than shared between them.
	//
	// Which is also what makes an account's own lower cap free here: the map already
	// has a row per account, so an override changes one number in a file telemt was
	// going to be handed anyway. It can only lower the inbound's
	// (resolveUserLimitOverride) - nothing about a relay forces that, but one rule
	// across the panel is worth more than mtproto being the exception.
	deviceCap := effectiveUserLimit(settings.UserLimit)
	b.WriteString("[access.user_max_unique_ips]\n")
	for _, c := range clients {
		b.WriteString(fmt.Sprintf("%q = %d\n", tomlEscape(c.Email),
			resolveUserLimitOverride(deviceCap, c.UserLimitOverride)))
	}
	b.WriteString("\n")

	// telemt's mode enforcement is a per-USER map (vpn-ui patch, see
	// build/backend/telemt-patches), and it treats a missing entry as "no
	// restriction", so the inbound's set has to be spelled out for every account
	// rather than left to [general.modes] alone.
	modes := strings.Join(settings.modes(), ",")
	b.WriteString("[access.user_modes]\n")
	for _, c := range clients {
		b.WriteString(fmt.Sprintf("%q = %q\n", tomlEscape(c.Email), modes))
	}
	b.WriteString("\n")

	// Ad tags are a per-user map in telemt, so each account gets its OWN tag and an
	// account without one gets no line at all: an empty value is not a valid tag
	// (telemt wants exactly 32 hex chars and refuses anything else), and crediting an
	// untagged customer's traffic to a neighbour's channel is not a sane default.
	//
	// The section is written whenever ANY account is tagged, because that is already
	// when use_middle_proxy went on above. Accounts left out of it still ride the
	// middle-proxy path, they just earn nobody anything.
	if adtag {
		b.WriteString("[access.user_ad_tags]\n")
		for _, c := range clients {
			tag := strings.TrimSpace(c.Adtag)
			if !c.AdtagEnable || tag == "" {
				continue
			}
			b.WriteString(fmt.Sprintf("%q = %q\n", tomlEscape(c.Email), tomlEscape(tag)))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// activeClients returns clients usable as telemt accounts, in a stable order so
// the rendered config is byte-identical when nothing changed (which keeps the
// config watcher from reloading on every regeneration).
func (s *MtprotoService) activeClients(settings *mtprotoSettings) []mtprotoClient {
	out := make([]mtprotoClient, 0, len(settings.Clients))
	for _, c := range settings.Clients {
		if strings.TrimSpace(c.Email) == "" || strings.TrimSpace(c.Secret) == "" {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out
}

// startable reports whether telemt can serve this inbound at all.
//
// Two ways it cannot, and neither is an error worth failing a save over: no account
// carries a secret, or the inbound has every connection mode off. The second one is
// the dangerous one to render: with no modes, every [access.user_modes] entry is
// empty, and our telemt patch reads an empty entry as "no restriction", so the proxy
// would grant EVERY account EVERY mode, the exact opposite of what was asked. The
// inbound form refuses to turn off the last mode, so this only catches a blob that
// arrived some other way (an API caller, an import).
func (s *MtprotoService) startable(settings *mtprotoSettings) bool {
	return len(s.activeClients(settings)) > 0 && len(settings.modes()) > 0
}

// getDisabledEmails returns accounts the panel has switched off (quota hit,
// expired, or disabled in settings).
func (s *MtprotoService) getDisabledEmails() map[string]bool {
	disabled := map[string]bool{}
	db := database.GetDB()
	if db == nil {
		return disabled
	}
	var traffics []*xray.ClientTraffic
	err := db.Model(xray.ClientTraffic{}).Where("enable = ?", false).Find(&traffics).Error
	if err != nil {
		return disabled
	}
	for _, t := range traffics {
		disabled[t.Email] = true
	}
	return disabled
}

// RestartServices reconciles the running telemt children with the enabled inbounds.
func (s *MtprotoService) RestartServices() error {
	migrateFromSystemd()

	inbounds, err := s.GetMtprotoInbounds()
	if err != nil {
		return err
	}

	bin := s.telemtBinaryPath()
	desired := map[string]bool{}

	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			logger.Warning("MTProto: skipping inbound", inbound.Id, err)
			continue
		}
		// telemt refuses to start with no users, and an inbound with no connection mode
		// is not dialable either, so it would just restart-loop. Skip it with a reason
		// instead.
		if !s.startable(settings) {
			logger.Warning("MTProto: inbound", inbound.Id,
				"is not startable (it needs at least one account with a secret and at least one connection mode), not starting")
			continue
		}
		dir := s.configDir(inbound.Id)
		name := mtprotoProcName(inbound.Id)
		desired[name] = true
		// telemt runs in the foreground by default and reads everything from the
		// TOML, so procMgr supervises it directly. --data-path keeps its quota
		// state and TLS-emulation cache inside the inbound's own dir.
		//
		// The config path is POSITIONAL, not a flag: telemt's parser treats any
		// non-dash argument that isn't a subcommand as the config path, and an
		// unrecognized flag only warns instead of exiting, so `--config <path>`
		// would log "Unknown option: --config" and still limp along.
		args := []string{"--data-path", dir, dir + "/config.toml"}
		if err := procMgr.Start(name, bin, args, nil, dir); err != nil {
			logger.Warning("MTProto: failed to start", name, err)
		}
	}

	for _, name := range procMgr.namesWithPrefix("mtproto-server-") {
		if !desired[name] {
			_ = procMgr.Stop(name)
		}
	}
	return nil
}

// EnsureServicesRunning is the start-if-down analogue of ensureCharonRunning: it
// launches telemt for any enabled inbound that has a usable account but no running
// process, and leaves inbounds whose telemt is already up untouched.
//
// A plain client change (add/enable/edit) only hot-reloads a RUNNING telemt via its
// config watcher, so RestartServices is deliberately skipped on the client-only path
// to avoid superseding (killing+relaunching) live connections. But that skip also
// meant nothing launched telemt when a client operation produced an inbound's FIRST
// usable account, leaving the backend down until an unrelated inbound-level toggle.
// This closes that gap without dropping any live session, since procMgr.Start (which
// supersedes) is only reached for inbounds that are not currently running.
func (s *MtprotoService) EnsureServicesRunning() error {
	inbounds, err := s.GetMtprotoInbounds()
	if err != nil {
		return err
	}
	bin := s.telemtBinaryPath()
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			logger.Warning("MTProto: skipping inbound", inbound.Id, err)
			continue
		}
		if !s.startable(settings) {
			continue
		}
		name := mtprotoProcName(inbound.Id)
		if procMgr.IsRunning(name) {
			// Already up: GenerateAllConfigs has hot-reloaded it via the config watcher.
			continue
		}
		dir := s.configDir(inbound.Id)
		args := []string{"--data-path", dir, dir + "/config.toml"}
		if err := procMgr.Start(name, bin, args, nil, dir); err != nil {
			logger.Warning("MTProto: failed to start", name, err)
		}
	}
	return nil
}

// StopServices stops all MTProto child processes.
func (s *MtprotoService) StopServices() error {
	procMgr.StopByPrefix("mtproto-server-")
	return nil
}

// SetupRouting is a no-op: MTProto is a userspace relay with no tunnel, so there
// are no nftables rules or kernel modules to install. Egress reaches Xray through
// the loopback socks inbound (GetSocksConfig) instead. Kept so the service matches
// the shape of its siblings.
func (s *MtprotoService) SetupRouting() error { return nil }

// DisableClients switches accounts off in place.
//
// Rewriting the config is the WHOLE operation: telemt watches its config file with
// inotify (config/hot_reload.rs) and applies [access.*] changes without restarting,
// cancelling the affected accounts' live sessions while leaving every other
// account's connections untouched. So client add/edit/disable never bounces the
// daemon, so the panel's hot-add behaviour comes for free.
func (s *MtprotoService) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}
	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("MTProto: disable-clients regeneration failed:", err)
	}
}

// KillDisabledSessions re-renders [access.user_enabled] from client_traffics. The
// config watcher picks it up and telemt drops the cancelled accounts' sessions.
func (s *MtprotoService) KillDisabledSessions() {
	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("MTProto: kill-disabled regeneration failed:", err)
	}
}

// CollectTraffic scrapes each running inbound's loopback Prometheus endpoint and
// returns per-account usage deltas to fold into client_traffics.
//
// This replaces the nft per-IP counter path that every tunnel protocol uses. That
// path cannot work here (no per-client IP) and, worse, would fail SILENTLY
// (AddClientAccounting discards every nft error and returns nil), leaving accounts
// that look healthy and bill nothing.
func (s *MtprotoService) CollectTraffic() []*xray.ClientTraffic {
	inbounds, err := s.GetMtprotoInbounds()
	if err != nil || len(inbounds) == 0 {
		return nil
	}
	var out []*xray.ClientTraffic
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		// The telemt username IS the email, so the metrics label maps straight to the
		// client_traffics key with nothing to translate.
		emails := map[string]string{}
		for _, c := range settings.Clients {
			if strings.TrimSpace(c.Email) != "" {
				emails[c.Email] = c.Email
			}
		}
		up, down := s.scrapeMetrics(mtprotoMetricsPort(inbound))
		for user, email := range emails {
			u, d := up[user], down[user]
			if u == 0 && d == 0 {
				continue
			}
			key := fmt.Sprintf("%d/%s", inbound.Id, user)
			du, dd := s.delta(key, u, d)
			if du == 0 && dd == 0 {
				continue
			}
			// Stamped with the inbound the bytes were scraped from. The delta key
			// above is already per inbound, so the record was the only place the
			// source was being dropped.
			out = append(out, &xray.ClientTraffic{Email: email, InboundId: inbound.Id, Up: du, Down: dd})
		}
	}
	return out
}

// mtprotoCounters remembers the last scraped absolute counters per account, so
// CollectTraffic can emit deltas. telemt's counters are cumulative and reset when
// the process restarts, so a value that went BACKWARDS means a restart: the new
// value is the delta, not a negative.
var mtprotoCounters = map[string][2]int64{}

func (s *MtprotoService) delta(key string, up, down int64) (int64, int64) {
	prev, seen := mtprotoCounters[key]
	mtprotoCounters[key] = [2]int64{up, down}
	if !seen {
		return up, down
	}
	du, dd := up-prev[0], down-prev[1]
	if du < 0 {
		du = up
	}
	if dd < 0 {
		dd = down
	}
	return du, dd
}

// scrapeMetrics reads telemt's Prometheus text endpoint and pulls the two
// per-user byte counters. from_client is the client's UPLOAD, to_client its
// DOWNLOAD, matching client_traffics.up/down.
func (s *MtprotoService) scrapeMetrics(port int) (map[string]int64, map[string]int64) {
	up := map[string]int64{}
	down := map[string]int64{}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
	if err != nil {
		return up, down
	}
	defer resp.Body.Close()
	// ReadAll, not a single Read: one Read is not guaranteed to fill the buffer, so
	// it would silently truncate the metrics page mid-line and drop whichever
	// accounts happened to sort last, under-billing them forever. Bounded by
	// LimitReader so a wedged endpoint can't balloon the panel's heap.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return up, down
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		name, user, val, ok := parsePromUserMetric(line)
		if !ok {
			continue
		}
		switch name {
		case "telemt_user_octets_from_client":
			up[user] = val
		case "telemt_user_octets_to_client":
			down[user] = val
		}
	}
	return up, down
}

// parsePromUserMetric pulls (metric, user-label, value) out of one Prometheus
// text line of the shape: name{user="alice",...} 12345
func parsePromUserMetric(line string) (string, string, int64, bool) {
	brace := strings.IndexByte(line, '{')
	closing := strings.LastIndexByte(line, '}')
	if brace < 0 || closing < brace {
		return "", "", 0, false
	}
	name := line[:brace]
	labels := line[brace+1 : closing]
	rest := strings.TrimSpace(line[closing+1:])
	val, err := strconv.ParseFloat(rest, 64)
	if err != nil {
		return "", "", 0, false
	}
	user := ""
	for _, part := range strings.Split(labels, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if kv[0] == "user" || kv[0] == "username" {
			user = strings.Trim(kv[1], `"`)
		}
	}
	if user == "" {
		return "", "", 0, false
	}
	return name, user, int64(val), true
}

// GenerateSecret mints a 32-hex-char MTProto secret for a new client.
func (s *MtprotoService) GenerateSecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Available reports whether the telemt binary is BUNDLED for this architecture.
// It answers "can this host ever install MTProto", not "is it installed right
// now": a binary that embeds telemt but has not extracted it yet still reports
// true, so the status card reads "not installed" (installable) instead of the
// misleading "telemt binary not bundled for this architecture".
func (s *MtprotoService) Available() bool {
	return backend.Bundled("telemt")
}
