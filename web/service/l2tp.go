package service

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hasan1808/pro-ui/backend"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/json_util"
	"github.com/hasan1808/pro-ui/xray"
)

// L2tpService manages L2TP VPN server configuration including xl2tpd, pppd,
// Libreswan (IPsec), and nftables TPROXY rules for routing traffic through Xray.
type L2tpService struct {
	inboundService InboundService
	nftService     NftService
	radiusService  *RadiusService
	radiusSecret   string
}

// l2tpSettings represents the L2TP-specific settings stored in the inbound's Settings JSON.
type l2tpSettings struct {
	IpsecEnable       bool         `json:"ipsecEnable"`
	IpsecPsk          string       `json:"ipsecPsk"`
	AllowRaw          bool         `json:"allowRaw"`
	ClientToClient    bool         `json:"clientToClient"`
	CrossInbound      bool         `json:"crossInbound"`
	UserLimit         *int         `json:"userLimit"`         // nil=absent(legacy=>1); 0=no limit; else 1..64. Parse-only — enforce via effectiveUserLimit.
	UserLimitStrategy string       `json:"userLimitStrategy"` // at the cap: "accept" (default, evict oldest) or "reject" (deny new device)
	IpRanges          []string     `json:"ipRanges"`
	IpRange           string       `json:"ipRange"` // legacy single-range field (read-only fallback)
	LocalIp           string       `json:"localIp"`
	Dns1              string       `json:"dns1"`
	Dns2              string       `json:"dns2"`
	Mtu               int          `json:"mtu"`
	Clients           []l2tpClient `json:"clients"`
}

type l2tpClient struct {
	ID       string `json:"id"`       // L2TP username
	Password string `json:"password"` // L2TP password
	Email    string `json:"email"`    // tracking identifier
	Enable   bool   `json:"enable"`
}

// SetRadius configures the RADIUS service and shared secret for L2TP authentication.
func (s *L2tpService) SetRadius(rs *RadiusService, secret string) {
	s.radiusService = rs
	s.radiusSecret = secret
}

// getRadiusSecret returns the RADIUS secret, falling back to reading from DB
// when the in-memory field is empty (e.g. in the controller's zero-value instance).
func (s *L2tpService) getRadiusSecret() string {
	if s.radiusSecret != "" {
		return s.radiusSecret
	}
	var settingService SettingService
	secret, _ := settingService.GetRadiusSecret()
	return secret
}

func (s *L2tpService) GetL2tpInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", "l2tp").Find(&inbounds).Error
	return inbounds, err
}

func (s *L2tpService) parseSettings(inbound *model.Inbound) (*l2tpSettings, error) {
	settings := &l2tpSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	if err != nil {
		return nil, fmt.Errorf("failed to parse L2TP settings for inbound %d: %w", inbound.Id, err)
	}
	return settings, nil
}

// effectiveRanges returns the inbound's configured IP ranges, seeding from the
// legacy single ipRange field when the ipRanges list is empty.
func (o *l2tpSettings) effectiveRanges() []string {
	if len(o.IpRanges) > 0 {
		return o.IpRanges
	}
	if o.IpRange != "" {
		return []string{o.IpRange}
	}
	return nil
}

// GetSubnetsForInbound returns every /24 prefix ("10.0.x") the inbound's client
// ranges cover. Falls back to the legacy id-derived /24 when nothing is stored.
func (s *L2tpService) GetSubnetsForInbound(inbound *model.Inbound) []string {
	if settings, err := s.parseSettings(inbound); err == nil {
		if subs := subnetsOf(settings.effectiveRanges()); len(subs) > 0 {
			return subs
		}
	}
	return []string{fmt.Sprintf("10.0.%d", inbound.Id)}
}

// GetSubnetForInbound returns the inbound's first /24 subnet (legacy callers).
func (s *L2tpService) GetSubnetForInbound(inbound *model.Inbound) string {
	return s.GetSubnetsForInbound(inbound)[0]
}

// GetTproxyPort returns a deterministic TPROXY port for the given inbound.
func (s *L2tpService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound config for Xray.
// This config captures TPROXY-redirected PPP traffic and feeds it into Xray's routing.
func (s *L2tpService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
	port := s.GetTproxyPort(inbound)
	settings := `{"network":"tcp,udp","followRedirect":true}`
	streamSettings := `{"sockopt":{"tproxy":"tproxy","mark":255}}`
	sniffing := `{"enabled":true,"destOverride":["http","tls"]}`

	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(`"0.0.0.0"`),
		Port:           port,
		Protocol:       "dokodemo-door",
		Settings:       json_util.RawMessage(settings),
		StreamSettings: json_util.RawMessage(streamSettings),
		Tag:            inbound.Tag,
		Sniffing:       json_util.RawMessage(sniffing),
	}
}

// GenerateAllConfigs regenerates all L2TP-related config files from the database state.
func (s *L2tpService) GenerateAllConfigs() error {
	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		return err
	}

	if len(inbounds) == 0 {
		return nil
	}

	if err := s.GenerateXl2tpdConfig(inbounds); err != nil {
		return err
	}
	// IPsec config: on the bundled path (amd64) L2TP/IPsec runs on the shared charon and
	// its swanctl connection is (re)written by RestartServices. The host libreswan
	// ipsec.conf/secrets are only needed on the non-bundle fallback (and GenerateIPsecConfig
	// deletes the swanctl l2tp.conf, so skipping it here avoids churning that file).
	if !backend.HasStrongswanBundle() {
		if err := s.GenerateIPsecConfig(inbounds); err != nil {
			return err
		}
	}
	// One shared xl2tpd LNS serves every inbound, so the PPP options + radcli
	// config are written ONCE for the whole protocol (not per inbound). Link
	// options (DNS/MTU) come from the first inbound.
	cleanupLegacyPerInboundFiles("options.xl2tpd", "l2tp")
	// Conflicting values are refused at save time, but a panel upgraded with them
	// already on disk still needs the winner named somewhere.
	logSharedWinner("l2tp", "DNS/MTU link options", inbounds[0], len(inbounds))
	if err := s.GeneratePPPOptions(inbounds[0]); err != nil {
		return err
	}
	if radiusSecret := s.getRadiusSecret(); radiusSecret != "" {
		if err := GenerateRadiusClientConfig("l2tp", radiusSecret); err != nil {
			return err
		}
	}

	return nil
}

// GenerateXl2tpdConfig writes /etc/xl2tpd/xl2tpd.conf. xl2tpd is a single daemon
// bound to one UDP port (1701) and serves only ONE effective LNS — two [lns …]
// sections on the same port collide (the panel used to emit one per inbound, all
// named "default", so only the last inbound worked). So ALL L2TP inbounds now share
// a SINGLE [lns default]: every inbound's IP range is listed, and the actual
// per-client IP is pinned by RADIUS (Framed-IP-Address), which resolves the account
// to its own inbound's pool. A single shared PPP options file carries a
// protocol-level nas_identifier (see GeneratePPPOptions).
func (s *L2tpService) GenerateXl2tpdConfig(inbounds []*model.Inbound) error {
	// xl2tpd.conf is the DISTRO's file on a host that already ran xl2tpd, and we
	// replace it wholesale. Recorded (and copied to /etc/vpn-ui/backups/ on the first
	// overwrite) so uninstall gives the operator theirs back instead of leaving our
	// render behind. See ownership.go. It belongs on the WRITE, not in the builder:
	// the builder also feeds the config editor's read-only preview.
	ownPrepareHostFile("/etc/xl2tpd/xl2tpd.conf", "l2tp")
	return s.writeFile("/etc/xl2tpd/xl2tpd.conf",
		applyCoreConfigOverride("l2tp", 0, "xl2tpd.conf", s.buildXl2tpdConfig(inbounds)))
}

// buildXl2tpdConfig renders the body. Split from the write so the config editor can show
// the operator the GENERATED text they are diverging from, which reading the file back
// cannot do: what is on disk already has their override merged into it.
func (s *L2tpService) buildXl2tpdConfig(inbounds []*model.Inbound) string {
	var b strings.Builder
	b.WriteString("[global]\n")
	b.WriteString("port = 1701\n\n")
	b.WriteString("[lns default]\n")

	// The PPP gateway (local ip) is the first inbound's first range .1; per-link /32
	// point-to-point addressing means one gateway serves every client /24.
	localIp := ""
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			logger.Warning("L2TP: skipping inbound", inbound.Id, err)
			continue
		}

		ranges := settings.effectiveRanges()
		if len(ranges) == 0 {
			subnet := s.GetSubnetForInbound(inbound)
			ranges = []string{defaultRange(subnet)}
		}
		// xl2tpd accepts multiple `ip range` lines; each range's client IP is then
		// pinned deterministically by RADIUS (Framed-IP-Address).
		for _, r := range ranges {
			b.WriteString(fmt.Sprintf("ip range = %s\n", r))
		}
		if localIp == "" {
			localIp = settings.LocalIp
			if start, _, ok := parseRange(ranges[0]); ok {
				localIp = fmt.Sprintf("%d.%d.%d.1", start[0], start[1], start[2])
			}
		}
	}
	if localIp == "" {
		localIp = "10.0.2.1"
	}

	b.WriteString(fmt.Sprintf("local ip = %s\n", localIp))
	b.WriteString("require authentication = yes\n")
	b.WriteString("name = l2tp\n")
	b.WriteString("pppoptfile = /etc/ppp/options.xl2tpd\n")
	b.WriteString("length bit = yes\n")
	b.WriteString("flow bit = yes\n\n")

	return b.String()
}

// GeneratePPPOptions writes the single shared PPP options file
// /etc/ppp/options.xl2tpd used by the one xl2tpd LNS for every L2TP inbound. It
// carries a protocol-level name + RADIUS config (nas_identifier "l2tp"); the RADIUS
// server maps each account to its inbound by username. DNS/MTU are taken from the
// representative (first) inbound — all L2TP inbounds share these link options.
func (s *L2tpService) GeneratePPPOptions(inbound *model.Inbound) error {
	body, err := s.buildPPPOptions(inbound)
	if err != nil {
		return err
	}
	// Same as xl2tpd.conf: a host file we overwrite, backed up on first sight.
	ownPrepareHostFile("/etc/ppp/options.xl2tpd", "l2tp")
	return s.writeFile("/etc/ppp/options.xl2tpd",
		applyCoreConfigOverride("l2tp", 0, "options.xl2tpd", body))
}

// buildPPPOptions renders the body; see buildXl2tpdConfig for why it is split out.
func (s *L2tpService) buildPPPOptions(inbound *model.Inbound) (string, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return "", err
	}

	mtu := settings.Mtu
	if mtu == 0 {
		mtu = 1400
	}
	dns1 := settings.Dns1
	if dns1 == "" {
		dns1 = "8.8.8.8"
	}
	dns2 := settings.Dns2
	if dns2 == "" {
		dns2 = "8.8.4.4"
	}

	var b strings.Builder
	b.WriteString("name l2tp\n")
	b.WriteString("refuse-pap\n")
	b.WriteString("refuse-chap\n")
	b.WriteString("require-mschap-v2\n")
	b.WriteString("ipcp-accept-local\n")
	b.WriteString("ipcp-accept-remote\n")
	b.WriteString("noccp\n")
	// Disable IPv6CP so no IPv6 address/route is negotiated on the ppp link.
	// The VPN data path (nftables TPROXY -> Xray) is IPv4-only; without this,
	// a dual-stack client could negotiate IPv6 and leak IPv6 traffic and DNS
	// straight out the host's default route, bypassing Xray entirely.
	b.WriteString("noipv6\n")
	b.WriteString(fmt.Sprintf("ms-dns %s\n", dns1))
	b.WriteString(fmt.Sprintf("ms-dns %s\n", dns2))
	b.WriteString("proxyarp\n")
	b.WriteString("lcp-echo-interval 30\n")
	b.WriteString("lcp-echo-failure 4\n")
	b.WriteString("connect-delay 5000\n")
	b.WriteString(fmt.Sprintf("mtu %d\n", mtu))
	b.WriteString(fmt.Sprintf("mru %d\n", mtu))
	b.WriteString("nodefaultroute\n")
	b.WriteString("plugin radius.so\n")
	b.WriteString("radius-config-file /etc/ppp/radius/l2tp.conf\n")

	return b.String(), nil
}

// getDisabledEmails returns a set of client emails that are disabled in the
// client_traffics table (due to traffic limit or expiry).
func (s *L2tpService) getDisabledEmails() map[string]bool {
	disabled := make(map[string]bool)
	db := database.GetDB()
	var emails []string
	db.Model(&xray.ClientTraffic{}).
		Where("enable = ?", false).
		Pluck("email", &emails)
	for _, e := range emails {
		disabled[e] = true
	}
	return disabled
}

// PER-INBOUND IPsec PRE-SHARED KEYS.
//
// Both IPsec backends below can serve one key per inbound, but only under a condition the
// protocol imposes and no configuration setting can lift.
//
// L2TP/IPsec is IKEv1 Main Mode with a pre-shared key. SKEYID = prf(PSK, Ni|Nr) is
// computed at messages 3/4, and the initiator's ID payload does not arrive until message
// 5 — already encrypted under keys derived from the very key the responder is trying to
// choose. The responder therefore has to pick the key knowing nothing but the IP address
// pair, and the peer is a road warrior whose address is unknown. So the ONLY thing that
// can select between two of our keys is OUR OWN address: the one the packet arrived on.
//
// Hence: distinct, concrete listen addresses, or one shared key. There is no strongSwan
// or libreswan option that changes this. (GRE gets away with per-tunnel keys because its
// connections are `version = 0` and negotiate IKEv2 in practice, where the identity is
// available in time to select the secret.)
//
// WHAT A PER-INBOUND KEY DOES AND DOES NOT SEPARATE. It authenticates the IPsec layer per
// listen address, and that is all. Everything above it is still protocol-wide: one xl2tpd
// with one [global] on port 1701, one /etc/ppp/options.xl2tpd, and a RADIUS lookup that
// resolves an account by username across every enabled l2tp inbound. A client that holds
// inbound B's key but authenticates as an inbound-A account still lands in inbound A's IP
// pool with inbound A's routing. The key is a door, not a partition.

// l2tpIpsecPeer is one L2TP inbound that terminates IKE: its key, and the address it
// answers on ("" when it answers on all of them).
type l2tpIpsecPeer struct {
	inbound *model.Inbound
	psk     string
	listen  string
}

// l2tpIpsecPeers returns the inbounds that want IPsec and have a key to do it with, in
// the order they were given.
//
// requireEnable is not a detail to tidy away: the swanctl generator has always skipped
// disabled inbounds and the libreswan one has always ignored the flag, and both of those
// choices are load-bearing for the panel-wide output they produce today.
func (s *L2tpService) l2tpIpsecPeers(inbounds []*model.Inbound, requireEnable bool) []l2tpIpsecPeer {
	var out []l2tpIpsecPeer
	for _, inbound := range inbounds {
		if requireEnable && !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil || !settings.IpsecEnable || settings.IpsecPsk == "" {
			continue
		}
		out = append(out, l2tpIpsecPeer{
			inbound: inbound,
			psk:     settings.IpsecPsk,
			listen:  strings.TrimSpace(inbound.Listen),
		})
	}
	return out
}

// l2tpPerListenPeers returns the peers when each can own its key, and nil when they
// cannot — which is the default and stays the default.
//
// Every condition here is a reason the addresses could not tell two keys apart:
//
//   - fewer than two peers: there is nothing to tell apart, and emitting the per-inbound
//     shape for a lone inbound would rewrite a file on every existing install for no gain.
//   - a wildcard listen: that inbound answers on every address, including the others'.
//   - a listen that is not an IP literal: a hostname becomes an FQDN identity in IKEv1,
//     which never matches the address-derived identity the key lookup uses.
//   - two peers on the same address: the ambiguity this whole mechanism exists to avoid.
func l2tpPerListenPeers(peers []l2tpIpsecPeer) []l2tpIpsecPeer {
	if len(peers) < 2 {
		return nil
	}
	seen := make(map[string]bool, len(peers))
	for _, peer := range peers {
		if listenIsWildcard(peer.listen) || net.ParseIP(peer.listen) == nil || seen[peer.listen] {
			return nil
		}
		seen[peer.listen] = true
	}
	return peers
}

// GenerateIPsecConfig writes /etc/ipsec.conf and /etc/ipsec.secrets for L2TP/IPsec.
// Uses Libreswan format which provides better compatibility across Windows, iOS, and Linux.
//
// One `conn l2tp-psk` on %defaultroute with a wildcard secret, or one `conn l2tp-psk-<id>`
// per inbound pinned to its own left= address with an address-scoped secret. See the
// per-inbound PSK note above for when the second shape is possible.
func (s *L2tpService) GenerateIPsecConfig(inbounds []*model.Inbound) error {
	// The panel-wide fallback reads every inbound, enabled or not, which is what this
	// generator has always done; the per-inbound shape only ever serves enabled ones.
	all := s.l2tpIpsecPeers(inbounds, false)
	perListen := l2tpPerListenPeers(s.l2tpIpsecPeers(inbounds, true))

	if len(all) == 0 {
		return nil
	}

	// The host libreswan's own two files. ipsec.secrets is the painful one: it holds
	// every PSK the operator configured, and we replace it with a single line, so
	// before this recorded a backup an install silently destroyed their IPsec
	// credentials with no way back. See ownership.go.
	ownPrepareHostFile("/etc/ipsec.conf", "l2tp")
	if err := s.writeFile("/etc/ipsec.conf",
		buildIpsecConf(detectLibreswanFeatures(), ipsecConnsFor(all, perListen))); err != nil {
		return err
	}

	// Write /etc/ipsec.secrets (mode 0600 for PSK confidentiality)
	ownPrepareHostFile("/etc/ipsec.secrets", "l2tp")
	if err := s.writeFileMode("/etc/ipsec.secrets", buildIpsecSecrets(all, perListen), 0600); err != nil {
		return err
	}

	// Clean up old StrongSwan swanctl config if present, per-inbound files included:
	// pluto is serving these connections now, and a leftover charon conn would answer
	// on the same addresses with a key of its own.
	os.Remove("/etc/swanctl/conf.d/l2tp.conf")
	l2tpPruneSwanctlConns(nil)

	return nil
}

// ipsecConn is one `conn` stanza: its name and the local address it terminates on.
type ipsecConn struct {
	name string
	left string
}

// ipsecConnsFor maps the peers onto the connections to write: the panel-wide one on
// %defaultroute, or one per inbound pinned to its own address.
func ipsecConnsFor(all, perListen []l2tpIpsecPeer) []ipsecConn {
	if len(perListen) == 0 {
		return []ipsecConn{{name: ipsecConnName, left: "%defaultroute"}}
	}
	out := make([]ipsecConn, 0, len(perListen))
	for _, peer := range perListen {
		out = append(out, ipsecConn{name: fmt.Sprintf("%s-%d", ipsecConnName, peer.inbound.Id), left: peer.listen})
	}
	return out
}

// buildIpsecSecrets renders /etc/ipsec.secrets.
//
// The panel-wide form is the bare wildcard `: PSK "..."`, which libreswan offers to every
// exchange. The per-inbound form names the pair the key belongs to — our address and any
// peer — which is the finest scoping IKEv1 Main Mode allows, since our address is the only
// thing known when the key is chosen.
func buildIpsecSecrets(all, perListen []l2tpIpsecPeer) string {
	escape := func(psk string) string {
		esc := strings.ReplaceAll(psk, `\`, `\\`)
		return strings.ReplaceAll(esc, `"`, `\"`)
	}
	if len(perListen) == 0 {
		if len(all) == 0 {
			return ""
		}
		return fmt.Sprintf(": PSK \"%s\"\n", escape(all[0].psk))
	}
	var b strings.Builder
	for _, peer := range perListen {
		b.WriteString(fmt.Sprintf("%s %%any : PSK \"%s\"\n", peer.listen, escape(peer.psk)))
	}
	return b.String()
}

// libreswanFeatures is what the INSTALLED libreswan understands. Detected once and passed
// in rather than probed inside the renderer, so the rendered text is a pure function of
// the inbounds plus this struct (and so a test can pin the bytes without a libreswan).
type libreswanFeatures struct {
	ikev1Policy   bool
	keyexchangeV1 bool
	modp1024      bool
	// leftupdown is the absolute updown command for the bundled pluto, "" for a host
	// libreswan that finds `ipsec` on its PATH.
	leftupdown string
}

// detectLibreswanFeatures probes the installed libreswan.
//
// Libreswan's L2TP/IPsec keywords are NOT portable across major versions, and getting
// them wrong is fatal in different ways on different distros — which is why "stuck on
// stopped" only showed up on some of them. Emit version-appropriate keywords (validated
// on 3.32, 4.3, 4.14 and 5.2):
//
//	ikev1-policy: `config setup` keyword added in 4.2. From 5.0 (and Debian/
//	RHEL back-patches) IKEv1 is dropped by default, so 4.2+ REQUIRES
//	ikev1-policy=accept or the L2TP conn fails to load ("global ikev1-policy
//	does not allow IKEv1 connections"). But on <4.2 the keyword is UNKNOWN, and
//	an unknown `config setup` keyword makes pluto reject the WHOLE config — the
//	service then won't start and neither a restart nor a reboot fixes it. So
//	emit it only on 4.2+ (pre-4.2 accepts IKEv1 by default anyway).
//
//	keyexchange: the explicit value `ikev1` only exists in 5.x; 3.x and 4.x
//	reject it ("invalid value"). `keyexchange=ike` + `ikev2=no` selects IKEv1
//	and parses on every version, so it's the portable form for <5.0.
func detectLibreswanFeatures() libreswanFeatures {
	lsMajor, lsMinor, lsOK := libreswanVersion()
	feat := libreswanFeatures{
		ikev1Policy:   lsOK && (lsMajor > 4 || (lsMajor == 4 && lsMinor >= 2)),
		keyexchangeV1: lsOK && lsMajor >= 5,
		modp1024:      ipsecSupportsModp1024(),
	}
	// The bundled pluto can't find `ipsec` on its PATH, so the default
	// `leftupdown=ipsec _updown` fails and the IPsec SA never installs (breaking
	// real L2TP/IPsec, esp. a 2nd concurrent client). Point it at the absolute
	// bundle path. Host libreswan has `ipsec` on PATH, so it keeps the default.
	if usingBundledIpsec() {
		feat.leftupdown = bundledIpsecUpdown()
	}
	return feat
}

// buildIpsecConf renders /etc/ipsec.conf: one `config setup` block and one stanza per
// connection. A single conn on %defaultroute is the panel-wide shape and must stay byte
// for byte what it has always been.
func buildIpsecConf(feat libreswanFeatures, conns []ipsecConn) string {
	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui L2TP service — do not edit\n")
	b.WriteString("config setup\n")
	b.WriteString("    uniqueids=no\n")
	b.WriteString("    logfile=/var/log/pluto.log\n")
	if feat.ikev1Policy {
		b.WriteString("    ikev1-policy=accept\n")
	}
	for _, conn := range conns {
		b.WriteString("\n")
		b.WriteString("conn " + conn.name + "\n")
		b.WriteString("    auto=add\n")
		if feat.leftupdown != "" {
			b.WriteString(fmt.Sprintf("    leftupdown=%q\n", feat.leftupdown))
		}
		b.WriteString("    leftprotoport=17/1701\n")
		b.WriteString("    rightprotoport=17/%any\n")
		b.WriteString("    type=transport\n")
		b.WriteString("    authby=secret\n")
		b.WriteString("    pfs=no\n")
		b.WriteString("    rekey=no\n")
		b.WriteString("    dpddelay=40\n")
		b.WriteString("    dpdtimeout=130\n")
		if feat.keyexchangeV1 {
			b.WriteString("    keyexchange=ikev1\n")
		} else {
			b.WriteString("    keyexchange=ike\n")
			b.WriteString("    ikev2=no\n")
		}
		// IKE (phase 1) proposals — widest client compatibility. modp2048/modp1536
		// and the ECP groups (dh19/dh20) are in every Libreswan; modp1024 (DH2) is
		// only present in an ALL_ALGS=true build. Libreswan rejects the WHOLE
		// connection if the proposal names a group it doesn't support, so modp1024
		// is appended only when the installed Libreswan actually has it — otherwise
		// stock/distro Libreswan (which vpn-ui setup installs) fails to load the conn.
		ike := "aes256-sha2;modp2048,aes128-sha2;modp2048,aes256-sha1;modp2048,aes128-sha1;modp2048,3des-sha1;modp2048," +
			"aes256-sha2;modp1536,aes128-sha2;modp1536,aes256-sha1;modp1536,aes128-sha1;modp1536,3des-sha1;modp1536,3des-md5;modp1536," +
			"aes256-sha2;dh20,aes256-sha2;dh19,aes128-sha2;dh19"
		if feat.modp1024 {
			ike += ",aes256-sha2;modp1024,aes128-sha2;modp1024,aes256-sha1;modp1024,aes128-sha1;modp1024,3des-sha1;modp1024,3des-md5;modp1024"
		}
		b.WriteString("    ike=" + ike + "\n")
		// ESP (Phase 2) proposals: SHA2 + SHA1 + MD5 for widest compatibility
		b.WriteString("    phase2alg=aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1,3des-sha1,aes256-md5,aes128-md5,3des-md5\n")
		b.WriteString("    left=" + conn.left + "\n")
		b.WriteString("    right=%any\n")
	}
	return b.String()
}

// ipsecSupportsModp1024 reports whether the installed Libreswan supports the
// MODP1024 (DH2) group. Distro/stock Libreswan omits it (it's cryptographically
// weak — only a build with ALL_ALGS=true has it), and naming an unsupported
// group in a proposal makes Libreswan reject the whole connection. The selftest
// aborts (and thus reports "not supported") if the NSS DB isn't initialized,
// which safely errs toward dropping modp1024.
func ipsecSupportsModp1024() bool {
	// The bundled libreswan is built USE_DH2=true, so MODP1024 is always present —
	// and asserting it here avoids running pluto --selftest before its NSS db is
	// initialized (which would abort and wrongly report "no MODP1024").
	if usingBundledIpsec() {
		return true
	}
	out, _ := exec.Command("ipsec", "pluto", "--selftest").CombinedOutput()
	return strings.Contains(strings.ToUpper(string(out)), "MODP1024")
}

// SetupAllTproxy sets up kernel modules, ip rules, and nftables rules for TPROXY.
func (s *L2tpService) SetupAllTproxy() error {
	// Enable IP forwarding
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")

	// Load kernel modules
	s.runCmd("modprobe", "l2tp_ppp")
	s.runCmd("modprobe", "ppp_generic")
	s.runCmd("modprobe", "af_key")
	s.runCmd("modprobe", "nf_tproxy_ipv4")

	// Set up the shared ip rule and route table (idempotent, and it collapses the
	// duplicates the old per-protocol guard piled up).
	ensureVpnPolicyRoute(s.runCmd)

	return s.nftService.ApplyNftRules()
}

// writeL2tpSwanctlConn writes the L2TP IKEv1 transport-mode PSK connection(s) into the
// SHARED charon's conf.d (charon also serves IKEv2 and GRE from there), and removes what
// is no longer wanted. Two shapes, chosen by l2tpPerListenPeers:
//
//   - the panel-wide l2tp.conf, one `l2tp-psk` connection with an owner-less secret. The
//     default, and byte for byte what the panel has always written.
//   - one l2tp-<id>.conf per inbound, each pinned to that inbound's own listen address,
//     when every IPsec-serving inbound has a distinct concrete one.
//
// MODP1024 is listed for Win7's DH-group-2-only built-in client.
func (s *L2tpService) writeL2tpSwanctlConn(inbounds []*model.Inbound) error {
	confPath := swanctlConfDir + "/l2tp.conf"

	if peers := l2tpPerListenPeers(s.l2tpIpsecPeers(inbounds, true)); len(peers) > 0 {
		_ = os.MkdirAll(swanctlConfDir, 0755)
		wanted := map[string]bool{}
		for _, peer := range peers {
			file := fmt.Sprintf("l2tp-%d.conf", peer.inbound.Id)
			path := swanctlConfDir + "/" + file
			body := applyCoreConfigOverride("l2tp", peer.inbound.Id, file, s.buildL2tpSwanctlConnFor(peer))
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				return err
			}
			wanted[path] = true
		}
		// The panel-wide connection would be a SECOND responder on the same addresses
		// with an owner-less key, which is exactly the ambiguity these files remove.
		_ = os.Remove(confPath)
		l2tpPruneSwanctlConns(wanted)
		return nil
	}

	// Back to (or still on) the panel-wide connection: drop any per-inbound files a
	// previous distinct-listen configuration left behind, or charon would keep serving
	// their keys alongside this one.
	l2tpPruneSwanctlConns(nil)

	body := s.buildL2tpSwanctlConn(inbounds)
	// An empty body means no enabled inbound wants IPsec. The file is REMOVED rather
	// than emptied, and no override is applied to it: charon includes conf.d/*.conf, so
	// leaving a stub behind would keep a dead connection loaded.
	if body == "" {
		_ = os.Remove(confPath)
		return nil
	}
	_ = os.MkdirAll(swanctlConfDir, 0755)
	return os.WriteFile(confPath,
		[]byte(applyCoreConfigOverride("l2tp", 0, "l2tp.conf", body)), 0600)
}

// l2tpPruneSwanctlConns deletes every per-inbound l2tp connection file that is not in
// wanted, so a deleted inbound (or a switch back to the panel-wide connection) stops
// being served. Mirrors GRE's glob cleanup; `l2tp-*.conf` cannot catch another
// protocol's file, which is why each one is prefixed with its protocol.
func l2tpPruneSwanctlConns(wanted map[string]bool) {
	matches, err := filepath.Glob(swanctlConfDir + "/l2tp-*.conf")
	if err != nil {
		return
	}
	for _, m := range matches {
		if !wanted[m] {
			_ = os.Remove(m)
		}
	}
}

// buildL2tpSwanctlConn renders the panel-wide body, or "" when no enabled inbound needs
// IPsec. See buildXl2tpdConfig for why the render is split from the write.
func (s *L2tpService) buildL2tpSwanctlConn(inbounds []*model.Inbound) string {
	peers := s.l2tpIpsecPeers(inbounds, true)
	if len(peers) == 0 {
		return ""
	}
	// One owner-less secret for everyone. The first enabled inbound's key wins, which is
	// safe precisely because the save-time check refuses to store a second, different one
	// for the same listen address.
	return l2tpSwanctlConn("l2tp-psk", "ike-l2tp", peers[0].psk, "")
}

// buildL2tpSwanctlConnFor renders ONE inbound's body: the same connection pinned to the
// address that inbound answers on, with a secret scoped to it.
func (s *L2tpService) buildL2tpSwanctlConnFor(peer l2tpIpsecPeer) string {
	return l2tpSwanctlConn(
		fmt.Sprintf("l2tp-%d", peer.inbound.Id),
		fmt.Sprintf("ike-l2tp-%d", peer.inbound.Id),
		peer.psk, peer.listen)
}

// l2tpSwanctlConn renders one IKEv1 transport-mode PSK connection.
//
// localAddr == "" is the panel-wide form: no local_addrs (charon answers on every
// address) and an owner-less secret (charon offers the key to every peer). It must stay
// byte for byte what the panel wrote before per-inbound keys existed, because every
// existing install regenerates this file on the next restart.
//
// A localAddr pins the connection to one address and scopes the secret to it. In IKEv1
// Main Mode the identities ARE the IP addresses at the point the key is looked up — the
// ID payload does not arrive until message 5, encrypted under keys already derived from
// the key being looked up — so id_local is the owner that matches, and it is the only
// owner that can distinguish two of these connections. id_any = %any is the other half of
// the pair strongSwan requires: a secret that names owners must match BOTH ends, so
// without it this key would never be selected at all (see greipsec.go, which learned that
// the hard way).
func l2tpSwanctlConn(connName, secretName, psk, localAddr string) string {
	esc := strings.ReplaceAll(psk, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)

	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui L2TP service (IKEv1 transport on shared charon) - do not edit\n")
	b.WriteString("connections {\n")
	b.WriteString(fmt.Sprintf("    %s {\n", connName))
	if localAddr != "" {
		b.WriteString(fmt.Sprintf("        local_addrs = %s\n", localAddr))
	}
	b.WriteString("        version = 1\n")
	b.WriteString("        aggressive = no\n")
	b.WriteString("        mobike = no\n")
	b.WriteString("        rekey_time = 3h\n")
	b.WriteString("        reauth_time = 0s\n")
	b.WriteString("        dpd_delay = 30s\n")
	b.WriteString("        fragmentation = yes\n")
	b.WriteString("        proposals = aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,3des-sha1-modp2048,aes256-sha1-modp1536,3des-sha1-modp1536,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024,default\n")
	b.WriteString("        local {\n            auth = psk\n        }\n")
	b.WriteString("        remote {\n            auth = psk\n        }\n")
	b.WriteString("        children {\n")
	b.WriteString("            l2tp {\n")
	b.WriteString("                mode = transport\n")
	// swanctl traffic-selector syntax (NOT stroke): port must be numeric (no `l2tp`
	// service name) and "any remote port" is an OMITTED port, not `%any` (swanctl rejects
	// `%any` with "invalid value for: remote_ts"). We are the LNS: local = our L2TP port
	// 1701, remote = the client's any UDP port.
	b.WriteString("                local_ts = dynamic[udp/1701]\n")
	b.WriteString("                remote_ts = dynamic[udp]\n")
	b.WriteString("                esp_proposals = aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,3des-sha1,default\n")
	b.WriteString("                rekey_time = 1h\n")
	b.WriteString("                dpd_action = clear\n")
	b.WriteString("            }\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	b.WriteString("secrets {\n")
	b.WriteString(fmt.Sprintf("    %s {\n", secretName))
	if localAddr != "" {
		b.WriteString(fmt.Sprintf("        id_local = %s\n", localAddr))
		b.WriteString("        id_any = %any\n")
	}
	b.WriteString(fmt.Sprintf("        secret = \"%s\"\n", esc))
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}

// RestartServices (re)launches xl2tpd as a panel-managed child process and, when any
// inbound needs it, brings up the IPsec layer: on the bundled-strongSwan path (amd64)
// L2TP/IPsec runs on the SHARED charon (IKEv1 transport, one daemon on 500/4500 with
// IKEv2); otherwise it falls back to host libreswan/pluto.
func (s *L2tpService) RestartServices() error {
	migrateFromSystemd()

	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		return err
	}

	if len(inbounds) == 0 {
		procMgr.Stop("xl2tpd")
		return nil
	}

	// xl2tpd -D runs in the foreground reading /etc/xl2tpd/xl2tpd.conf; the panel
	// supervises it and reaps its pppd children.
	os.MkdirAll("/var/run/xl2tpd", 0755)
	if err := procMgr.Start("xl2tpd", daemonBin("xl2tpd"), []string{"-D"}, pppdEnv(), ""); err != nil {
		logger.Warning("L2TP: failed to start xl2tpd:", err)
	}

	// IPsec layer.
	needIpsec := false
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		if settings, err := s.parseSettings(inbound); err == nil && settings.IpsecEnable {
			needIpsec = true
			break
		}
	}

	if backend.HasStrongswanBundle() {
		// UNIFIED path (amd64): serve L2TP/IPsec (IKEv1 transport PSK) on the SAME bundled
		// charon that serves IKEv2, so one daemon owns UDP 500/4500 and there is no
		// charon-vs-pluto collision. Retire any old bundled pluto that would fight for the
		// ports, (re)write the l2tp swanctl conn (removed when no inbound needs IPsec), and
		// sync charon (which stops it only if neither L2TP nor IKEv2 needs it).
		if needIpsec {
			_ = stopBundledPluto()
		}
		if err := s.writeL2tpSwanctlConn(inbounds); err != nil {
			logger.Warning("L2TP: failed to write l2tp swanctl conn:", err)
		}
		if err := syncCharon(); err != nil {
			logger.Warning("L2TP: failed to sync charon for l2tp/ipsec:", err)
		}
		return nil
	}

	// FALLBACK (no strongSwan bundle, e.g. non-amd64): host libreswan/pluto.
	if needIpsec {
		if err := s.GenerateIPsecConfig(inbounds); err != nil {
			logger.Warning("L2TP: failed to regenerate ipsec.conf:", err)
		}
		if usingBundledIpsec() {
			if err := startBundledPluto(); err != nil {
				logger.Warning("L2TP: failed to start bundled pluto:", err)
			}
		} else {
			// Host libreswan: ensure the NSS db exists and the unit is enabled, then restart.
			_, _ = initIpsecNSS()
			if commandExists("systemctl") {
				_ = exec.Command("systemctl", "enable", "ipsec").Run()
			}
			if out, err := restartIpsecService(); err != nil {
				logger.Warning("L2TP: failed to restart ipsec:", err, strings.TrimSpace(out))
			}
		}
	}

	return nil
}

// StopServices stops the L2TP (xl2tpd) child process.
func (s *L2tpService) StopServices() {
	procMgr.Stop("xl2tpd")
}

// InitL2tp initializes L2TP services on panel startup.
func (s *L2tpService) InitL2tp() {
	inbounds, err := s.GetL2tpInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}

	logger.Info("L2TP: initializing L2TP services for", len(inbounds), "inbound(s)")

	s.nftService.CleanupLegacyIptables()

	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("L2TP: failed to generate configs:", err)
		return
	}
	if err := s.SetupAllTproxy(); err != nil {
		logger.Warning("L2TP: failed to setup TPROXY:", err)
	}
	if err := s.RestartServices(); err != nil {
		logger.Warning("L2TP: failed to restart services:", err)
	}
}

// KillDisabledSessions kills active PPP sessions for clients that are no longer
// allowed to connect (disabled in settings or disabled in client_traffics).
// Uses RADIUS session data to find active sessions.
func (s *L2tpService) KillDisabledSessions() {
	inbounds, err := s.GetL2tpInbounds()
	if err != nil {
		return
	}
	disabledEmails := s.getDisabledEmails()

	// Collect emails of clients that should NOT be active
	disabled := make(map[string]bool)
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if !client.Enable || disabledEmails[client.Email] {
				disabled[client.Email] = true
			}
		}
	}

	if len(disabled) > 0 && s.radiusService != nil {
		s.radiusService.KillSessionsByEmail(disabled)
	}
}

// DisableClients enforces limits for the given client emails by killing their active PPP sessions.
// RADIUS handles auth live from the database, so no config regeneration is needed.
func (s *L2tpService) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}

	emailSet := make(map[string]bool, len(emails))
	for _, e := range emails {
		emailSet[e] = true
	}

	if s.radiusService != nil {
		s.radiusService.KillSessionsByEmail(emailSet)
	}
}

func (s *L2tpService) writeFile(path, content string) error {
	return s.writeFileMode(path, content, 0644)
}

func (s *L2tpService) writeFileMode(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func (s *L2tpService) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("L2TP: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
