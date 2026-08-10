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

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
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
// The inbound owns only what a LISTENER must own (its port, via inbound.Port).
// Everything a Telegram user actually experiences (modes, FakeTLS domain, ad tag,
// device limit, external proxy) is per-CLIENT, because telemt keys those off the
// authenticated secret rather than the socket.
type mtprotoSettings struct {
	Clients []mtprotoClient `json:"clients"`
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

	// Connection modes this account may use. The client picks one via its secret's
	// prefix (bare / dd / ee); these say which the proxy will ACCEPT from it, and
	// which links the UI offers. Enforced per-account by telemt via
	// [access.user_modes] (our patch), not merely cosmetic.
	ModeClassic bool `json:"modeClassic"` // no prefix: obfuscated2 / abridged
	ModeSecure  bool `json:"modeSecure"`  // "dd" prefix: random padding
	ModeTls     bool `json:"modeTls"`     // "ee" prefix: FakeTLS

	// TlsDomain is the SNI this account's FakeTLS link fronts. Per-account domains
	// work because the inbound runs unknown_sni_action="accept" and the handshake
	// HMAC (not the SNI) is what proves secret possession.
	TlsDomain string `json:"tlsDomain"`

	// AdtagEnable/Adtag credit sponsored channels to this account. telemt keys ad
	// tags per user, but middle-proxy mode itself is process-wide, so ANY account
	// with a tag puts the whole inbound on the middle-proxy path and forfeits Xray
	// routing for every account on it (see usingRouting).
	AdtagEnable bool   `json:"adtagEnable"`
	Adtag       string `json:"adtag"`

	UserLimit *int `json:"userLimit"` // nil=absent(legacy=>1); 0=no limit; else 1..64

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

// modes returns the connection modes this account may use, as telemt's
// [access.user_modes] spells them. An account with none enabled is unusable, which
// activeClients rejects rather than silently rendering a dead entry.
func (c mtprotoClient) modes() []string {
	var out []string
	if c.ModeClassic {
		out = append(out, "classic")
	}
	if c.ModeSecure {
		out = append(out, "secure")
	}
	if c.ModeTls {
		out = append(out, "tls")
	}
	return out
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
// Ad tags are per-account (telemt's [access.user_ad_tags]), but the middle-proxy
// path they need is a PROCESS-wide switch (use_middle_proxy). So one tagged account
// puts the whole inbound on that path: every account on it then egresses directly
// and none of them can be routed through Xray. That is Telegram's design, not a
// telemt gap: the middle-proxy session key is derived from the proxy's own egress
// IP and port, which any proxied egress rewrites.
func (s *MtprotoService) anyAdtag(settings *mtprotoSettings) bool {
	for _, c := range settings.Clients {
		if c.AdtagEnable && strings.TrimSpace(c.Adtag) != "" {
			return true
		}
	}
	return false
}

// unionModes is the set of modes the LISTENER must accept: the union over all
// accounts. [general.modes] is process-wide, so it cannot express per-account
// policy on its own: it only decides which handshakes reach the auth step at all.
// Per-account enforcement is [access.user_modes] (our telemt patch), which rejects
// an account that used a mode it does not hold even though the listener allowed it.
func (s *MtprotoService) unionModes(settings *mtprotoSettings) (classic, secure, tls bool) {
	for _, c := range s.activeClients(settings) {
		classic = classic || c.ModeClassic
		secure = secure || c.ModeSecure
		tls = tls || c.ModeTls
	}
	return
}

// firstTlsDomain picks the domain used for ServerHello emulation. Accounts may each
// front their own SNI (unknown_sni_action="accept" lets any through, and the HMAC
// is what actually authenticates), but telemt models its fake ServerHello on ONE
// domain's real certificate. We use the first FakeTLS account's domain so the
// emulation matches at least that account exactly.
func (s *MtprotoService) firstTlsDomain(settings *mtprotoSettings) string {
	for _, c := range s.activeClients(settings) {
		if c.ModeTls && strings.TrimSpace(c.TlsDomain) != "" {
			return strings.TrimSpace(c.TlsDomain)
		}
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
	content := s.buildServerConfig(inbound, settings)
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
	if len(s.activeClients(settings)) == 0 {
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
// [general.modes] MUST stay hot (it is hot only because of our patch): it is the
// UNION of every account's modes, so a per-client toggle changes it. Were it
// restart-only, turning a mode ON while another account is connected would write a
// config saying the mode is enabled while the listener kept refusing it until the
// next restart, making the toggle look broken rather than deferred.
func (s *MtprotoService) buildServerConfig(inbound *model.Inbound, settings *mtprotoSettings) string {
	var b strings.Builder

	b.WriteString("# Auto-generated by vpn-ui (MTProto Proxy). Do not edit.\n")
	b.WriteString("# Regenerated on every inbound/client change; edits are lost.\n\n")

	adtag := s.anyAdtag(settings)

	b.WriteString("[general]\n")
	// Middle-proxy mode carries ad tags and pins egress to a direct path. It is a
	// PROCESS switch even though the tags themselves are per-account, so one tagged
	// account turns it on for the whole inbound.
	b.WriteString(fmt.Sprintf("use_middle_proxy = %t\n", adtag))
	// Fail loudly rather than silently serving an untagged proxy if a middle-proxy
	// handshake is ever attempted over a SOCKS route whose BND tuple is unusable.
	b.WriteString("me_socks_kdf_policy = \"strict\"\n")
	b.WriteString("log_level = \"normal\"\n")
	// telemt colorizes its log by default. procMgr captures it through a pipe and the
	// panel renders it as plain text, so the ANSI escapes survive as literal "[2m"/
	// "[0m" garbage around every line in Core Settings -> Logs.
	b.WriteString("disable_colors = true\n\n")

	// The listener accepts the UNION of every account's modes; [access.user_modes]
	// below is what holds each account to its own set. Both are required: the union
	// alone would let any account use any mode, and the per-account map alone would
	// never see the handshake because the listener would have refused it first.
	uc, us, ut := s.unionModes(settings)
	b.WriteString("[general.modes]\n")
	b.WriteString(fmt.Sprintf("classic = %t\n", uc))
	b.WriteString(fmt.Sprintf("secure = %t\n", us))
	b.WriteString(fmt.Sprintf("tls = %t\n\n", ut))

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
	// Each account may front its own SNI, so the listener must not insist on one:
	// accept an unknown SNI and let the handshake HMAC (which is what actually
	// proves secret possession) decide. Without this, only accounts using the
	// domain below could connect.
	b.WriteString(fmt.Sprintf("tls_domain = %q\n", tomlEscape(s.firstTlsDomain(settings))))
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
	b.WriteString("[access.user_max_unique_ips]\n")
	for _, c := range clients {
		b.WriteString(fmt.Sprintf("%q = %d\n", tomlEscape(c.Email), effectiveUserLimit(c.UserLimit)))
	}
	b.WriteString("\n")

	// Per-account mode enforcement (vpn-ui patch, see build/backend/telemt-patches).
	// Without this the union in [general.modes] would let ANY account use ANY mode
	// another account enabled, making the per-client toggles cosmetic.
	b.WriteString("[access.user_modes]\n")
	for _, c := range clients {
		b.WriteString(fmt.Sprintf("%q = %q\n", tomlEscape(c.Email), strings.Join(c.modes(), ",")))
	}
	b.WriteString("\n")

	// Ad tags are genuinely per-account in telemt; only the middle-proxy path they
	// ride is process-wide (handled above).
	if adtag {
		b.WriteString("[access.user_ad_tags]\n")
		for _, c := range clients {
			if c.AdtagEnable && strings.TrimSpace(c.Adtag) != "" {
				b.WriteString(fmt.Sprintf("%q = %q\n", tomlEscape(c.Email), tomlEscape(strings.TrimSpace(c.Adtag))))
			}
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
		// An account with every mode off cannot be dialed by anything. Rendering it
		// would put an empty [access.user_modes] entry in the config, which the patch
		// reads as "no restriction", silently granting it EVERY mode, the exact
		// opposite of what the operator asked for.
		if len(c.modes()) == 0 {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out
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
		// telemt refuses to start with no users, and an account with no mode is not
		// dialable, so an inbound whose accounts are all unusable would just
		// restart-loop. Skip it with a reason instead.
		if len(s.activeClients(settings)) == 0 {
			logger.Warning("MTProto: inbound", inbound.Id,
				"has no usable account (each needs a secret and at least one connection mode), not starting")
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
		if len(s.activeClients(settings)) == 0 {
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
			out = append(out, &xray.ClientTraffic{Email: email, Up: du, Down: dd})
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
