package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"go.uber.org/atomic"
)

var (
	p                 *xray.Process
	lock              sync.Mutex
	isNeedXrayRestart atomic.Bool // Indicates that restart was requested for Xray
	// UnixNano of the most recent restart request, and of the one that opened the
	// current burst. Both feed the debounce in IsRestartDueAndSetFalse.
	xrayRestartReqAt   atomic.Int64
	xrayRestartFirstAt atomic.Int64
	isManuallyStopped  atomic.Bool // Indicates that Xray was stopped manually from the panel
	result             string
)

const (
	// How long the restart flag must go untouched before the restart fires. Long enough
	// that adding several clients in a row is one restart, short enough that a single
	// add is usable almost immediately.
	xrayRestartDebounce = 2 * time.Second
	// Ceiling on the debounce, so an unending stream of edits still gets a restart.
	xrayRestartMaxWait = 30 * time.Second
)

// XrayService provides business logic for Xray process management.
// It handles starting, stopping, restarting Xray, and managing its configuration.
type XrayService struct {
	inboundService InboundService
	settingService SettingService
	l2tpService    L2tpService
	pptpService    PptpService
	openvpnService OpenVpnService
	ocservService  OcservService
	sstpService    SstpService
	ikev2Service   Ikev2Service
	wgcService     WgcService
	awgService     AwgService
	greService     GreService
	mtprotoService MtprotoService
	sshService     SshService
	xrayAPI        xray.XrayAPI
}

// IsXrayRunning checks if the Xray process is currently running.
func (s *XrayService) IsXrayRunning() bool {
	return p != nil && p.IsRunning()
}

// GetXrayErr returns the error from the Xray process, if any.
func (s *XrayService) GetXrayErr() error {
	if p == nil {
		return nil
	}

	err := p.GetErr()
	if err == nil {
		return nil
	}

	return err
}

// GetXrayResult returns the result string from the Xray process.
func (s *XrayService) GetXrayResult() string {
	if result != "" {
		return result
	}
	if s.IsXrayRunning() {
		return ""
	}
	if p == nil {
		return ""
	}

	result = p.GetResult()

	return result
}

// GetXrayVersion returns the version of the running Xray process.
func (s *XrayService) GetXrayVersion() string {
	if p == nil {
		return "Unknown"
	}
	return p.GetVersion()
}

// RemoveIndex removes an element at the specified index from a slice.
// Returns a new slice with the element removed.
func RemoveIndex(s []any, index int) []any {
	return append(s[:index], s[index+1:]...)
}

// applySshOutbounds replaces, for every configured SSH tunnel, the outbound
// carrying its tag with a `socks` outbound pointing at that tunnel's live local
// proxy. Xray core has no ssh outbound, so this socks one IS the SSH outbound.
//
// Replace-by-tag rather than append-if-missing, so an entry left in the template
// by the older client-side writer is corrected rather than duplicated (a
// duplicate tag makes Xray refuse the whole config).
//
// A tunnel with no port yet is skipped: it has never successfully bound, so there
// is nothing to point at, and emitting 127.0.0.1:0 would be a dead outbound that
// looks live. Everything else in the template is left exactly as it was.
func (s *XrayService) applySshOutbounds(config *xray.Config) {
	var svc SshOutboundService
	if err := applySshOutboundsWith(config, svc.List()); err != nil {
		logger.Warning("ssh outbound: leaving the template outbounds alone:", err)
	}
}

// applySshOutboundsWith is the pure half of applySshOutbounds, taking the tunnel
// list as an argument so it can be tested without a database.
func applySshOutboundsWith(config *xray.Config, tunnels []SshOutboundConfig) error {
	if len(tunnels) == 0 {
		return nil
	}

	var obs []map[string]any
	if len(config.OutboundConfigs) > 0 {
		if err := json.Unmarshal(config.OutboundConfigs, &obs); err != nil {
			return err
		}
	}

	for _, t := range tunnels {
		if t.Tag == "" || t.SocksPort <= 0 {
			continue
		}
		synth := map[string]any{
			"tag":      t.Tag,
			"protocol": "socks",
			"settings": map[string]any{
				"servers": []any{map[string]any{"address": "127.0.0.1", "port": t.SocksPort}},
			},
		}
		replaced := false
		for i, ob := range obs {
			if tag, _ := ob["tag"].(string); tag == t.Tag {
				obs[i] = synth
				replaced = true
				break
			}
		}
		if !replaced {
			obs = append(obs, synth)
		}
	}

	out, err := json.Marshal(obs)
	if err != nil {
		return err
	}
	config.OutboundConfigs = out
	return nil
}

// GetXrayConfig retrieves and builds the Xray configuration from settings and inbounds.
func (s *XrayService) GetXrayConfig() (*xray.Config, error) {
	templateConfig, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}

	xrayConfig := &xray.Config{}
	err = json.Unmarshal([]byte(templateConfig), xrayConfig)
	if err != nil {
		return nil, err
	}

	if len(xrayConfig.DNSConfig) == 0 || string(xrayConfig.DNSConfig) == "null" || string(xrayConfig.DNSConfig) == "{}" || string(xrayConfig.DNSConfig) == "" {
		defaultDNS, _ := json.Marshal(map[string]any{
			"servers": []any{
				"8.8.8.8",
				"1.1.1.1",
				"8.8.4.4",
			},
		})
		xrayConfig.DNSConfig = defaultDNS
	}

	// The socks outbound fronting each SSH tunnel is synthesized here rather than
	// stored in the template, so the tunnel and the outbound that points at it can
	// never disagree. They used to be written from two different places at two
	// different times - the tunnel server-side on save, the outbound by JS into the
	// in-page template - and every way that could drift, did: creating a tunnel and
	// not pressing Save left a running tunnel no outbound referenced; deleting one
	// and not pressing Save left an outbound aimed at a closed port, which refuses
	// every connection on that tag with no explanation; and a boot-time port
	// conflict left the saved outbound pointing at whatever else took the number.
	// Deriving it from the stored tunnel list on every config build removes the
	// second writer, and with it the whole class.
	s.applySshOutbounds(xrayConfig)

	// The client-side VPN tunnels get the same treatment, for the same reason: the
	// interface a dialled tunnel lands on is decided by the client each time it comes
	// up, so a name copied into the template goes stale the first time a peer hands
	// back a different device. See vpnoutbound.go.
	if err := applyVpnOutboundsWith(xrayConfig, (&VpnOutboundService{}).List()); err != nil {
		logger.Warning("could not synthesize the VPN client outbounds:", err)
	}

	s.inboundService.AddTraffic(nil, nil)

	inbounds, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return nil, err
	}

	// Depletion is decided per ACCOUNT (per email), never per inbound.
	//
	// This map used to be built per inbound from inbound.ClientStats, which is a
	// has-many on InboundId, while client_traffics.Email is UNIQUE panel-wide: one
	// account has exactly ONE row, naming exactly ONE inbound. So on every OTHER
	// inbound serving that same email the lookup missed, `exists` came back false,
	// and a client whose quota was exhausted was rendered into the config as
	// ENABLED. Restarting the core did not repair that, it re-created it.
	//
	// Reading the enable state by email closes it for every inbound at once, and
	// matches what the ten non-Xray protocols already do (RADIUS checks
	// client_traffics with no inbound filter at all).
	enableByEmail, err := s.inboundService.EnableStateByEmail()
	if err != nil {
		return nil, err
	}

	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		// Skip L2TP/PPTP/OpenVPN/OpenConnect/SSTP/IKEv2/WireGuard/MTProto inbounds, they
		// are not native Xray protocols. The tunnel ones route through paired
		// dokodemo-door inbounds injected below; mtproto instead gets a paired socks
		// inbound it egresses THROUGH (GetSocksConfig).
		//
		// Omitting a protocol here is not a no-op: its raw settings would be handed to
		// Xray as a native inbound, Xray would reject the unknown protocol, and the
		// WHOLE core would fail to start, taking every other inbound down with it.
		if inbound.Protocol == "l2tp" || inbound.Protocol == "pptp" || inbound.Protocol == "openvpn" || inbound.Protocol == "openconnect" || inbound.Protocol == "sstp" || inbound.Protocol == "ikev2" || inbound.Protocol == "wg-c" || inbound.Protocol == "awg" || inbound.Protocol == "gre" || inbound.Protocol == "mtproto" || inbound.Protocol == "ssh" {
			continue
		}
		// get settings clients
		settings := map[string]any{}
		json.Unmarshal([]byte(inbound.Settings), &settings)
		clients, ok := settings["clients"].([]any)
		if ok {
			// filter and clean clients
			var final_clients []any
			for _, client := range clients {
				c, ok := client.(map[string]any)
				if !ok {
					continue
				}

				email, _ := c["email"].(string)

				// check users active or not via stats (panel-wide, by account)
				if enable, exists := enableByEmail[accountKey(email)]; exists && !enable {
					logger.Infof("Remove Inbound User %s due to expiration or traffic limit", email)
					continue
				}

				// check manual disabled flag
				if manualEnable, ok := c["enable"].(bool); ok && !manualEnable {
					continue
				}

				// clear client config for additional parameters
				//
				// This is an ALLOWLIST, so a credential field that is not named here
				// never reaches the core: it is dropped between the DB and the
				// generated config, with nothing logged. "username" is naive's
				// Basic-auth username, and without it every naive account would keep
				// authenticating as its email no matter what the panel showed. Only
				// naive clients carry the key (model.Client tags it omitempty), and
				// the core ignores unknown client fields for everything else.
				for key := range c {
					if key != "email" && key != "id" && key != "password" && key != "flow" && key != "method" && key != "auth" && key != "username" {
						delete(c, key)
					}
					if flow, ok := c["flow"].(string); ok && flow == "xtls-rprx-vision-udp443" {
						c["flow"] = "xtls-rprx-vision"
					}
				}
				final_clients = append(final_clients, any(c))
			}

			settings["clients"] = final_clients
			modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return nil, err
			}

			inbound.Settings = string(modifiedSettings)
		}

		if len(inbound.StreamSettings) > 0 {
			// Unmarshal stream JSON
			var stream map[string]any
			json.Unmarshal([]byte(inbound.StreamSettings), &stream)

			// Remove the "settings" field under "tlsSettings" and "realitySettings"
			tlsSettings, ok1 := stream["tlsSettings"].(map[string]any)
			realitySettings, ok2 := stream["realitySettings"].(map[string]any)
			if ok1 || ok2 {
				if ok1 {
					delete(tlsSettings, "settings")
				} else if ok2 {
					delete(realitySettings, "settings")
				}
			}

			delete(stream, "externalProxy")

			newStream, err := json.MarshalIndent(stream, "", "  ")
			if err != nil {
				return nil, err
			}
			inbound.StreamSettings = string(newStream)
		}

		inboundConfig := inbound.GenXrayInboundConfig()

		if len(inbound.Sniffing) == 0 || string(inbound.Sniffing) == "null" || string(inbound.Sniffing) == "" {
			proto := string(inbound.Protocol)
			if proto == "vless" || proto == "vmess" || proto == "trojan" || proto == "shadowsocks" {
				defaultSniffing, _ := json.Marshal(map[string]any{
					"enabled":             true,
					"destOverride":        []string{"http", "tls"},
					"metadataOnly":        false,
					"routeOnly":           false,
					"domainsExcluded":     []string{},
					"domainsIncluded":     []string{},
					"ipsExcluded":         []string{},
					"ipsIncluded":         []string{},
					"reasonOnly":          false,
					"unknownTraffic":      false,
				})
				inboundConfig.Sniffing = json_util.RawMessage(defaultSniffing)
			}
		}

		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *inboundConfig)
	}

	// Inject paired dokodemo-door inbounds for L2TP
	l2tpInbounds, _ := s.l2tpService.GetL2tpInbounds()
	for _, l2tpInbound := range l2tpInbounds {
		if !l2tpInbound.Enable {
			continue
		}
		dokodemoConfig := s.l2tpService.GetDokodemoConfig(l2tpInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for PPTP
	pptpInbounds, _ := s.pptpService.GetPptpInbounds()
	for _, pptpInbound := range pptpInbounds {
		if !pptpInbound.Enable {
			continue
		}
		dokodemoConfig := s.pptpService.GetDokodemoConfig(pptpInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for OpenVPN
	ovpnInbounds, _ := s.openvpnService.GetOpenVpnInbounds()
	for _, ovpnInbound := range ovpnInbounds {
		if !ovpnInbound.Enable {
			continue
		}
		dokodemoConfig := s.openvpnService.GetDokodemoConfig(ovpnInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for OpenConnect
	ocservInbounds, _ := s.ocservService.GetOcservInbounds()
	for _, ocservInbound := range ocservInbounds {
		if !ocservInbound.Enable {
			continue
		}
		dokodemoConfig := s.ocservService.GetDokodemoConfig(ocservInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for SSTP
	sstpInbounds, _ := s.sstpService.GetSstpInbounds()
	for _, sstpInbound := range sstpInbounds {
		if !sstpInbound.Enable {
			continue
		}
		dokodemoConfig := s.sstpService.GetDokodemoConfig(sstpInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for IKEv2 (one per inbound; a single shared
	// charon serves them all, but each inbound's /16 block routes to its own dokodemo).
	ikev2Inbounds, _ := s.ikev2Service.GetIkev2Inbounds()
	for _, ikev2Inbound := range ikev2Inbounds {
		if !ikev2Inbound.Enable {
			continue
		}
		dokodemoConfig := s.ikev2Service.GetDokodemoConfig(ikev2Inbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for WireGuard (C) (one per inbound; the kernel
	// wireguard interface decrypts, each inbound's 10.7 block routes to its own dokodemo).
	wgcInbounds, _ := s.wgcService.GetWgcInbounds()
	for _, wgcInbound := range wgcInbounds {
		if !wgcInbound.Enable {
			continue
		}
		dokodemoConfig := s.wgcService.GetDokodemoConfig(wgcInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for AmneziaWG (one per inbound; the amneziawg
	// kernel interface decrypts, each inbound's 10.8 block routes to its own dokodemo).
	awgInbounds, _ := s.awgService.GetAwgInbounds()
	for _, awgInbound := range awgInbounds {
		if !awgInbound.Enable {
			continue
		}
		dokodemoConfig := s.awgService.GetDokodemoConfig(awgInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for GRE (one per inbound; the kernel strips the
	// GRE header, each inbound's 10.9 block is TPROXY'd to its own dokodemo).
	greInbounds, _ := s.greService.GetGreInbounds()
	for _, greInbound := range greInbounds {
		if !greInbound.Enable {
			continue
		}
		dokodemoConfig := s.greService.GetDokodemoConfig(greInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject the loopback socks inbound each MTProto Proxy inbound egresses through.
	// This is the mtproto analogue of the dokodemo-door blocks above, but a socks
	// listener rather than TPROXY capture: telemt is a userspace relay with no tunnel
	// to intercept, so it dials OUT through Xray instead of having packets pushed in.
	// The inbound carries inbound.Tag, so operator routing rules target it like any
	// other. Returns nil when adtag is on, middle-proxy mode must egress directly,
	// because its RPC key is derived from the proxy's own egress IP AND port.
	mtprotoInbounds, _ := s.mtprotoService.GetMtprotoInbounds()
	for _, mtInbound := range mtprotoInbounds {
		if !mtInbound.Enable {
			continue
		}
		if socksConfig := s.mtprotoService.GetSocksConfig(mtInbound); socksConfig != nil {
			xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *socksConfig)
		}
	}

	// Inject the loopback socks inbound each SSH inbound egresses through. Like the
	// mtproto block above, but with UDP enabled (settings.udp): SSH forwards TCP via
	// direct-tcpip channels and UDP via its in-process udpgw bridge, and the UDP path
	// needs the socks inbound to accept UDP ASSOCIATE so Xray routes+accounts UDP per
	// client too. Per-client identity rides the socks username (the account email).
	sshInbounds, _ := s.sshService.GetSshInbounds()
	for _, sshInbound := range sshInbounds {
		if !sshInbound.Enable {
			continue
		}
		if socksConfig := s.sshService.GetSocksConfig(sshInbound); socksConfig != nil {
			xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *socksConfig)
		}
	}

	// Translate email-based routing rules for L2TP/PPTP clients to source-IP rules.
	// Dokodemo-door doesn't support per-user identification, so we use deterministic
	// IP assignment and match on source IP instead.
	//
	// MTProto is deliberately absent from this translation: it assigns no per-client
	// IP, so a per-CLIENT rule has nothing to match on. Its routing is per-INBOUND,
	// via the socks inbound's tag above.
	s.translateVpnRoutingRules(xrayConfig)

	if len(xrayConfig.RouterConfig) > 0 {
		var routing map[string]any
		if err := json.Unmarshal(xrayConfig.RouterConfig, &routing); err == nil {
			if ds, ok := routing["domainStrategy"].(string); ok && ds == "AsIs" {
				routing["domainStrategy"] = "IPIfNonMatch"
				if data, err := json.Marshal(routing); err == nil {
					xrayConfig.RouterConfig = data
				}
			}
		}
	}

	if len(xrayConfig.OutboundConfigs) > 0 {
		var outbounds []map[string]any
		if err := json.Unmarshal(xrayConfig.OutboundConfigs, &outbounds); err == nil {
			modified := false
			for i, ob := range outbounds {
				if ob["tag"] == "direct" {
					if settings, ok := ob["settings"].(map[string]any); ok {
						if ds, ok := settings["domainStrategy"].(string); ok && ds == "AsIs" {
							settings["domainStrategy"] = "UseIP"
							outbounds[i] = ob
							modified = true
						}
					}
				}
			}
			if modified {
				if data, err := json.Marshal(outbounds); err == nil {
					xrayConfig.OutboundConfigs = data
				}
			}
		}
	}

	return xrayConfig, nil
}

// translateVpnRoutingRules rewrites routing rules so that "user" (email) matches
// for L2TP/PPTP clients are translated to "source" (IP) matches.
//
// Emails absent from the map are left as "user" rules on purpose, and two very
// different protocol families rely on that: Xray-native ones (vless/vmess), which
// match the user natively, and mtproto, whose account arrives as the socks username
// (see MtprotoService.GetSocksConfig). So an operator writes the same
// user:[email] rule for every protocol and this decides the carrier. Do NOT add
// mtproto to BuildVpnEmailToIPMap to "complete" it: a relay has no per-client IP,
// so it would translate the rule into a source match on an IP that never exists
// and the rule would silently stop matching anything.
// buildXrayNativeEmailSet returns the normalized emails that appear on an inbound
// Xray terminates ITSELF, and can therefore match a routing rule's "user" field.
//
// The predicate is the complement of what GetXrayConfig skips: the nine pool VPN
// protocols (isVpnProtocol) plus the two relays, mtproto and ssh, none of which
// hand Xray a user list to match on.
func buildXrayNativeEmailSet() map[string]bool {
	out := map[string]bool{}
	var inbounds []*model.Inbound
	if err := database.GetDB().Model(&model.Inbound{}).
		Select("protocol", "settings", "enable").Find(&inbounds).Error; err != nil {
		logger.Warning("could not read inbounds while building the native-email set:", err)
		return out
	}
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		if isVpnProtocol(inbound.Protocol) || inbound.Protocol == model.MTPROTO || inbound.Protocol == model.SSH {
			continue
		}
		clients, ok := parseSettingsClients(inbound.Settings)
		if !ok {
			continue
		}
		for _, entry := range clients {
			email, _ := entry["email"].(string)
			if key := accountKey(email); key != "" {
				out[key] = true
			}
		}
	}
	return out
}

func (s *XrayService) translateVpnRoutingRules(config *xray.Config) {
	if len(config.RouterConfig) == 0 {
		return
	}

	vpnMap := BuildVpnEmailToIPMap()
	if len(vpnMap) == 0 {
		return
	}

	// Emails Xray authenticates itself, so a rule's "user" match can still fire
	// for them even though they also hold a tunnel address.
	nativeEmails := buildXrayNativeEmailSet()

	var routing map[string]any
	if err := json.Unmarshal(config.RouterConfig, &routing); err != nil {
		return
	}

	rulesRaw, ok := routing["rules"].([]any)
	if !ok || len(rulesRaw) == 0 {
		return
	}

	var newRules []any
	modified := false

	for _, ruleRaw := range rulesRaw {
		rule, ok := ruleRaw.(map[string]any)
		if !ok {
			newRules = append(newRules, ruleRaw)
			continue
		}

		usersRaw, ok := rule["user"].([]any)
		if !ok || len(usersRaw) == 0 {
			newRules = append(newRules, rule)
			continue
		}

		// Separate VPN emails from regular Xray emails.
		//
		// An account can be BOTH: one email on vless and on l2tp is exactly what
		// the accounts layer exists to allow. This used to be an either/or -- the
		// moment an email had any pool-protocol membership it was moved out of the
		// rule's "user" list entirely and replaced by a source-IP match -- so the
		// account's vless traffic stopped matching its own routing rule: the source
		// rule only covers tunnel addresses, and the native user match was gone.
		// Silently, with a valid config and a running core.
		//
		// So an email that Xray also authenticates natively stays in BOTH lists:
		// it gets the source rule for its tunnel addresses AND keeps the user rule
		// for the traffic the core terminates itself.
		var vpnIPs []any
		var regularEmails []any
		for _, u := range usersRaw {
			email, ok := u.(string)
			if !ok {
				regularEmails = append(regularEmails, u)
				continue
			}
			ips, found := vpnMap[email]
			if !found {
				regularEmails = append(regularEmails, u)
				continue
			}
			for _, ip := range ips {
				vpnIPs = append(vpnIPs, ip)
			}
			if nativeEmails[accountKey(email)] {
				regularEmails = append(regularEmails, u)
			}
		}

		if len(vpnIPs) == 0 {
			newRules = append(newRules, rule)
			continue
		}

		modified = true

		// Create source-based rule for VPN clients (copy all fields except "user")
		vpnRule := make(map[string]any)
		for k, v := range rule {
			if k != "user" {
				vpnRule[k] = v
			}
		}
		vpnRule["source"] = vpnIPs
		newRules = append(newRules, vpnRule)

		// Keep original rule with remaining non-VPN emails
		if len(regularEmails) > 0 {
			rule["user"] = regularEmails
			newRules = append(newRules, rule)
		}
	}

	// Backstop: block any VPN tunnel source that isn't a valid account device IP.
	// nftables TPROXYs the WHOLE client /24 into Xray, and with no matching rule a
	// packet falls through to Xray's default (first) outbound — so a device holding an
	// in-/24 but out-of-block IP (an over-limit device, a failed eviction, or a keyless
	// Access-Accept fallback) would otherwise reach the internet, making the User Limit
	// cap cosmetic. We list every legitimate device IP -> the default outbound, then
	// blackhole the rest of the VPN space. Appended last, so operator per-account rules
	// still take precedence for valid IPs; only unrecognized (over-limit / leaked)
	// sources hit the blackhole. Tags are taken from the config's own outbounds so the
	// default egress is preserved and the backstop is skipped when no blackhole exists.
	defaultTag, blockTag := "direct", ""
	var obs []map[string]any
	if json.Unmarshal(config.OutboundConfigs, &obs) == nil {
		for i, ob := range obs {
			t, _ := ob["tag"].(string)
			if i == 0 && t != "" {
				defaultTag = t
			}
			if p, _ := ob["protocol"].(string); p == "blackhole" && t != "" {
				blockTag = t
			}
		}
	}
	var validIPs []any
	seen := make(map[string]bool)
	for _, ips := range vpnMap {
		for _, ip := range ips {
			if ip != "" && !seen[ip] {
				seen[ip] = true
				validIPs = append(validIPs, ip)
			}
		}
	}
	if blockTag != "" && len(validIPs) > 0 {
		newRules = append(newRules,
			map[string]any{"type": "field", "source": validIPs, "outboundTag": defaultTag},
			map[string]any{"type": "field", "source": []any{vpnAddrSpace}, "outboundTag": blockTag},
		)
		modified = true
	}

	if !modified {
		return
	}

	routing["rules"] = newRules
	if data, err := json.Marshal(routing); err == nil {
		config.RouterConfig = data
	}
}

// GetXrayTraffic fetches the current traffic statistics from the running Xray process.
func (s *XrayService) GetXrayTraffic() ([]*xray.Traffic, []*xray.ClientTraffic, error) {
	if !s.IsXrayRunning() {
		err := errors.New("xray is not running")
		logger.Debug("Attempted to fetch Xray traffic, but Xray is not running:", err)
		return nil, nil, err
	}
	apiPort := p.GetAPIPort()
	if err := s.xrayAPI.Init(apiPort); err != nil {
		logger.Debug("Failed to initialize Xray API:", err)
		return nil, nil, err
	}
	defer s.xrayAPI.Close()

	traffic, clientTraffic, err := s.xrayAPI.GetTraffic(true)
	if err != nil {
		logger.Debug("Failed to fetch Xray traffic:", err)
		return nil, nil, err
	}
	return traffic, clientTraffic, nil
}

// RestartXray restarts the Xray process, optionally forcing a restart even if config unchanged.
func (s *XrayService) RestartXray(isForce bool) error {
	lock.Lock()
	defer lock.Unlock()
	logger.Debug("restart Xray, force:", isForce)
	isManuallyStopped.Store(false)

	xrayConfig, err := s.GetXrayConfig()
	if err != nil {
		return err
	}

	// Top up the geo data files the config names before handing it over. Saving a
	// routing rule already fetches them (SaveXraySetting), but a config can arrive
	// by other roads that never passed through that check: a restored backup, an
	// imported 3x-ui database, a bin/ folder wiped between runs. The core
	// treats a geo file it cannot open as a fatal parse error, not a bad rule. The
	// process then never comes up at all, taking every inbound with it.
	//
	// Routing is not the only section the core runs through its geo parsers:
	// per-inbound sniffing (domainsExcluded/ipsExcluded, infra/conf
	// SniffingConfig.Build) and freedom outbounds (ipsBlocked, infra/conf
	// freedom.go) use the very same ParseDomainRules/ParseIPRules. Sniffing is also
	// the reason this sits here rather than only on the save path: the inbound form
	// offers `ext:*` for both fields and stores them per inbound, so the template
	// SaveXraySetting sees never contains them.
	//
	// Inbound settings are deliberately not scanned: they hold the client lists,
	// which are the bulk of a large config and cannot carry a geo reference.
	sections := []([]byte){xrayConfig.RouterConfig, xrayConfig.DNSConfig, xrayConfig.OutboundConfigs}
	for _, in := range xrayConfig.InboundConfigs {
		if len(in.Sniffing) > 0 {
			sections = append(sections, in.Sniffing)
		}
	}
	if refs := ExtGeoRefs(sections...); len(refs) > 0 {
		if _, missing := EnsureGeofilesAuto(refs); len(missing) > 0 {
			// Nothing left to do about it here: starting anyway produces the real
			// error from the core, which names the file and is what the user sees.
			logger.Warning("xray config references geo files that are missing and could not be downloaded:",
				strings.Join(missing, ", "))
		}
	}

	if s.IsXrayRunning() {
		if !isForce && p.GetConfig().Equals(xrayConfig) && !isNeedXrayRestart.Load() {
			logger.Debug("It does not need to restart Xray")
			return nil
		}
		p.Stop()
	}

	p = xray.NewProcess(xrayConfig)
	result = ""
	err = p.Start()
	if err != nil {
		return err
	}

	return nil
}

// StopXray stops the running Xray process.
func (s *XrayService) StopXray() error {
	lock.Lock()
	defer lock.Unlock()
	isManuallyStopped.Store(true)
	logger.Debug("Attempting to stop Xray...")
	if s.IsXrayRunning() {
		return p.Stop()
	}
	return errors.New("xray is not running")
}

// ReapOrphanXray kills a stray Xray left by a previous panel instance that never
// stopped it — most importantly a self-update re-exec: syscall.Exec keeps the SAME
// PID, so the old Xray survives as an orphaned child still holding 127.0.0.1:62790
// (the API/dokodemo port) and every inbound port. The re-exec'd panel starts with
// p == nil, so RestartXray's stop-guard is a no-op and it just spawns a SECOND Xray
// that fails to bind ("address already in use") — the health job then reports the
// error state in a permanent loop. Mirrors procmgr's daemon reap (procmgr.go).
//
// MUST be called at startup BEFORE the first RestartXray, while p is still nil, so it
// can only ever match an orphan — never the Xray we manage.
func (s *XrayService) ReapOrphanXray() {
	if s.IsXrayRunning() {
		return
	}
	// Our working directory. Xray inherits the panel's cwd, so we match orphaned xray
	// processes by cwd == ours: a coexisting upstream x-ui's xray runs from a different
	// dir and is never touched. We deliberately do NOT match /proc/<pid>/exe — the core
	// bundle re-extracts bin/xray on startup (fresh inode), so an orphan's exe reads
	// "…(deleted)" and would no longer compare equal; cwd (and the cmdline) are stable.
	myCwd, err := os.Getwd()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(myCwd); err == nil {
		myCwd = resolved
	}
	self := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		// Only xray processes (the bundled core binary name appears in the cmdline)...
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || !strings.Contains(string(cmdline), "xray-linux-amd64") {
			continue
		}
		// ...that were launched from OUR working directory.
		cwd, err := os.Readlink("/proc/" + e.Name() + "/cwd")
		if err != nil || cwd != myCwd {
			continue
		}
		logger.Warning("reaping orphaned Xray holding its ports before start (e.g. from a self-update re-exec): pid", pid)
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Kill()
		}
	}
}

// SetToNeedRestart marks that Xray needs to be restarted.
func (s *XrayService) SetToNeedRestart() {
	now := time.Now().UnixNano()
	// Remember when this burst of changes started, so a continuous stream of edits can
	// never starve the restart (see IsRestartDueAndSetFalse).
	if isNeedXrayRestart.CompareAndSwap(false, true) {
		xrayRestartFirstAt.Store(now)
	}
	xrayRestartReqAt.Store(now)
}

// IsRestartDueAndSetFalse reports whether a requested restart should happen NOW, and
// clears the flag if so.
//
// Why a debounce rather than a plain flag on a slow tick: the relay protocols (mtproto,
// ssh) egress through a paired Xray socks inbound and authenticate as the account's
// email. Xray's socks inbound has no AddUser API, so that account list is fixed at
// config time and only a restart applies it. That makes the delay here the exact window
// in which a NEWLY ADDED relay client cannot use the proxy at all: it is not a
// background optimization, it is user-visible as "the proxy does not work", which is
// what a 30s tick was doing.
//
// Restarting on every request instead would drop live connections once per edit, so the
// flag is allowed to settle first: a burst of edits (adding several clients in a row)
// still collapses into ONE restart shortly after the last one, and maxWait bounds the
// worst case at the old tick's latency even if edits never stop arriving.
func (s *XrayService) IsRestartDueAndSetFalse() bool {
	if !isNeedXrayRestart.Load() {
		return false
	}
	now := time.Now().UnixNano()
	settled := now-xrayRestartReqAt.Load() >= int64(xrayRestartDebounce)
	waitedTooLong := now-xrayRestartFirstAt.Load() >= int64(xrayRestartMaxWait)
	if !settled && !waitedTooLong {
		return false
	}
	return isNeedXrayRestart.CompareAndSwap(true, false)
}

// IsNeedRestartAndSetFalse checks if restart is needed and resets the flag to false.
func (s *XrayService) IsNeedRestartAndSetFalse() bool {
	return isNeedXrayRestart.CompareAndSwap(true, false)
}

// DidXrayCrash checks if Xray crashed by verifying it's not running and wasn't manually stopped.
func (s *XrayService) DidXrayCrash() bool {
	return !s.IsXrayRunning() && !isManuallyStopped.Load()
}
