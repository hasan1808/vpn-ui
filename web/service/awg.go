package service

import (
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	wgctrl "github.com/Jipok/wgctrl-go"
	"github.com/Jipok/wgctrl-go/wgtypes"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/json_util"
	"github.com/hasan1808/pro-ui/web/service/rbridge"
	"github.com/hasan1808/pro-ui/xray"
	"github.com/vishvananda/netlink"
)

// AwgService manages "AmneziaWG" , obfuscated WireGuard on the in-kernel `amneziawg`
// module, driven natively from Go via the AmneziaWG-aware wgctrl fork (netlink). It is a
// sibling of WgcService ("wg-c"): the account/IP/limit/accounting model is identical
// (gateway model, one keypair per account, rbridge-swept), so this reuses WgcService's
// shared package helpers (nextPow2, allowedIPsKey, wgcEffectiveK, computeVpnClientIP,
// pppSubnetsOrDefault, vpnBlock, vpnAccountBlock, jsonString/jsonBool/setRawString). The
// differences from wg-c are: (1) the `amneziawg` kernel module + link kind (a separate,
// DKMS-built out-of-tree module, base 8 -> 10.8/16); (2) the AWG 1.0 obfuscation params
// (Jc/Jmin/Jmax/S1/S2/H1-H4) rendered into [Interface] and pushed to the device; (3) the
// wgctrl fork instead of upstream wgctrl. Magic headers H1-H4 are minted server-side.
type AwgService struct {
	inboundService InboundService
	nftService     NftService

	mu        sync.Mutex
	firstSeen map[string]time.Time // deviceKey -> first-seen handshake (oldest-first eviction)
	lastObfs  map[string]string    // iface -> last-applied obfuscation signature (force re-apply on edit)
}

const (
	// awgIfacePrefix names the per-inbound kernel interfaces (awg<id>); short so awg<id>
	// stays within the 15-char IFNAMSIZ limit.
	awgIfacePrefix = "awg"
	// amneziawgModule is the out-of-tree AmneziaWG kernel module (built via DKMS, base 8).
	amneziawgModule = "amneziawg"
	// amneziawgLinkKind is the rtnetlink link kind the module registers (ip link add type amneziawg).
	amneziawgLinkKind = "amneziawg"
)

// awgSettings is the AmneziaWG slice of an inbound's Settings JSON. Clones wgcSettings and
// adds the AWG 1.0 obfuscation parameters. All obfuscation params must match between server
// and client EXCEPT Jc/Jmin/Jmax (junk counts may differ per peer). Magic headers H1-H4 are
// stored as strings (the AmneziaWG 2.0 form allows ranges like "5-9"; 1.0 uses single values).
type awgSettings struct {
	ServerPrivKey string `json:"serverPrivKey"`
	ServerPubKey  string `json:"serverPubKey"`
	PskEnable     bool   `json:"pskEnable"`

	Dns1 string `json:"dns1"`
	Dns2 string `json:"dns2"`
	Mtu  int    `json:"mtu"`

	// AWG 1.0 obfuscation parameters (per-inbound, shared by all this inbound's clients).
	Jc   *int   `json:"jc"`
	Jmin *int   `json:"jmin"`
	Jmax *int   `json:"jmax"`
	S1   *int   `json:"s1"`
	S2   *int   `json:"s2"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`

	ClientToClient    bool               `json:"clientToClient"`
	CrossInbound      bool               `json:"crossInbound"`
	UserLimit         *int               `json:"userLimit"`
	UserLimitStrategy string             `json:"userLimitStrategy"`
	IpRanges          []string           `json:"ipRanges"`
	ExternalProxy     []awgExternalProxy `json:"externalProxy"`
	Clients           []awgClient        `json:"clients"`
}

// awgExternalProxy is one alternate Endpoint written into the generated client config + QR.
type awgExternalProxy struct {
	Dest   string `json:"dest"`
	Port   int    `json:"port"`
	Remark string `json:"remark"`
}

// awgDevice is ONE device slot of an account: its own keypair (and optional preshared key)
// and, derived from its index, its own /32 out of the account's block.
//
// Per-device keypairs are REQUIRED, not a nicety. WireGuard/AmneziaWG identifies a peer by
// its public key and tracks a single endpoint per peer, so two devices sharing one keypair
// cannot be online at once: whichever handshakes last steals the tunnel and the other goes
// dark. Handing out one config per account also hands both devices the same Address, so
// they present the same tunnel IP. K device slots => K keypairs => K configs => K distinct
// IPs, which is what makes "User Limit K" actually mean K simultaneous devices.
type awgDevice struct {
	PrivKey string `json:"privKey"`
	PubKey  string `json:"pubKey"`
	Psk     string `json:"psk"`
}

// awgClient is one AmneziaWG account. Identity is Email; each device's public key is its
// credential. Devices holds one entry per device slot (sized to the inbound's User Limit).
// The legacy top-level PrivKey/PubKey/Psk are the pre-per-device shape and are read as
// device 0 when Devices is empty, so an inbound created before this change keeps working.
type awgClient struct {
	Email   string      `json:"email"`
	Enable  bool        `json:"enable"`
	PrivKey string      `json:"privKey"`
	PubKey  string      `json:"pubKey"`
	Psk     string      `json:"psk"`
	Devices []awgDevice `json:"devices"`
	Slot    *int        `json:"slot"` // address-pool slot; nil = fall back to list index
}

// deviceList returns the account's device slots, seeding from the legacy single-keypair
// fields when the per-device array has not been written yet.
func (c *awgClient) deviceList() []awgDevice {
	if len(c.Devices) > 0 {
		return c.Devices
	}
	if strings.TrimSpace(c.PubKey) != "" {
		return []awgDevice{{PrivKey: c.PrivKey, PubKey: c.PubKey, Psk: c.Psk}}
	}
	return nil
}

func (o *awgSettings) effectiveRanges() []string { return o.IpRanges }

func (o *awgSettings) mtu() int {
	if o.Mtu > 0 {
		return o.Mtu
	}
	return wgDefaultMTU
}

// awgObfs is the resolved (defaults applied) AWG 1.0 obfuscation parameter set.
type awgObfs struct {
	Jc, Jmin, Jmax, S1, S2 int
	H1, H2, H3, H4         string
}

// resolveObfs applies recommended defaults for any unset numeric params (magic headers are
// minted by ReconcileKeys, so they are normally present).
func (o *awgSettings) resolveObfs() awgObfs {
	pick := func(p *int, def int) int {
		if p != nil {
			return *p
		}
		return def
	}
	return awgObfs{
		Jc:   pick(o.Jc, 4),
		Jmin: pick(o.Jmin, 8),
		Jmax: pick(o.Jmax, 80),
		S1:   pick(o.S1, 77),
		S2:   pick(o.S2, 90),
		H1:   o.H1, H2: o.H2, H3: o.H3, H4: o.H4,
	}
}

func (b awgObfs) sig() string {
	return fmt.Sprintf("%d|%d|%d|%d|%d|%s|%s|%s|%s", b.Jc, b.Jmin, b.Jmax, b.S1, b.S2, b.H1, b.H2, b.H3, b.H4)
}

// apply writes the obfuscation params into a wgtypes.Config (only when H1-H4 are present).
func (b awgObfs) apply(cfg *wgtypes.Config) {
	jc, jmin, jmax, s1, s2 := b.Jc, b.Jmin, b.Jmax, b.S1, b.S2
	cfg.Jc, cfg.Jmin, cfg.Jmax = &jc, &jmin, &jmax
	cfg.S1, cfg.S2 = &s1, &s2
	if b.H1 != "" {
		h1, h2, h3, h4 := b.H1, b.H2, b.H3, b.H4
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = &h1, &h2, &h3, &h4
	}
}

// awgIfaceName returns the kernel interface name for an inbound.
func awgIfaceName(id int) string { return fmt.Sprintf("%s%d", awgIfacePrefix, id) }

func (s *AwgService) GetAwgInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", "awg").Find(&inbounds).Error
	return inbounds, err
}

func (s *AwgService) parseSettings(inbound *model.Inbound) (*awgSettings, error) {
	settings := &awgSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	return settings, err
}

// awgBlockFor returns an inbound's client block network + prefix in the 10.8 /16.
func awgBlockFor(inbound *model.Inbound, settings *awgSettings) (net.IP, int) {
	return vpnBlock(settings.effectiveRanges(), protocolBase("awg"), inbound.Id)
}

func (s *AwgService) GetSubnetForInbound(inbound *model.Inbound) string {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		settings = &awgSettings{}
	}
	netAddr, prefix := awgBlockFor(inbound, settings)
	return fmt.Sprintf("%s/%d", netAddr.String(), prefix)
}

func (s *AwgService) GetSubnetsForInbound(inbound *model.Inbound) []string {
	return []string{s.GetSubnetForInbound(inbound)}
}

// GetTproxyPort returns the deterministic TPROXY/dokodemo port (shared 12300+id).
func (s *AwgService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound feeding TPROXY traffic into Xray.
func (s *AwgService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
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

// awgAccountBlock mirrors wgcAccountBlock in the 10.8 /16 (gateway model, block sized to K).
// The slot comes from the account (model.Client.Slot), not from its position in clients[]:
// see wgcAccountBlock for why that distinction is load-bearing here.
func (s *AwgService) awgAccountBlock(inbound *model.Inbound, settings *awgSettings, accountSlot int) (string, int) {
	ranges := settings.effectiveRanges()
	k := wgcEffectiveK(settings.UserLimit)
	if k <= 1 {
		if ip := computeVpnClientIP(ranges, inbound.Id, accountSlot, "awg"); ip != nil {
			return ip.String(), 32
		}
		return "", 0
	}
	bs := nextPow2(k)
	subnets := pppSubnetsOrDefault(ranges, "awg", inbound.Id)
	subnet, hostBase, ok := vpnAccountBlock(subnets, accountSlot, bs)
	if !ok {
		return "", 0
	}
	return fmt.Sprintf("%s.%d", subnet, hostBase), 32 - log2i(bs)
}

// awgDeviceIPs returns the account's K per-device tunnel IPs, in slot order. Device d gets
// the d-th address of the account's block, so the block CIDR used for routing/accounting
// still covers every device. K<=1 collapses to the single legacy address.
func (s *AwgService) awgDeviceIPs(inbound *model.Inbound, settings *awgSettings, accountSlot int) []string {
	ranges := settings.effectiveRanges()
	k := wgcEffectiveK(settings.UserLimit)
	if k <= 1 {
		if ip := computeVpnClientIP(ranges, inbound.Id, accountSlot, "awg"); ip != nil {
			return []string{ip.String()}
		}
		return nil
	}
	base, _ := s.awgAccountBlock(inbound, settings, accountSlot)
	if base == "" {
		return nil
	}
	baseIP := net.ParseIP(base).To4()
	if baseIP == nil {
		return nil
	}
	start, ok := ipToU32(baseIP)
	if !ok {
		return nil
	}
	out := make([]string, 0, k)
	for d := 0; d < k; d++ {
		out = append(out, u32ToIP(start+uint32(d)).String())
	}
	return out
}

func (s *AwgService) awgAccountCIDR(inbound *model.Inbound, settings *awgSettings, accountSlot int) string {
	ip, prefix := s.awgAccountBlock(inbound, settings, accountSlot)
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("%s/%d", ip, prefix)
}

func (s *AwgService) disabledEmails() map[string]bool {
	disabled := make(map[string]bool)
	db := database.GetDB()
	if db == nil {
		return disabled
	}
	var emails []string
	db.Model(&xray.ClientTraffic{}).Where("enable = ?", false).Pluck("email", &emails)
	for _, e := range emails {
		disabled[e] = true
	}
	return disabled
}

// InitAwg brings AmneziaWG up on panel startup.
func (s *AwgService) InitAwg() {
	inbounds, err := s.GetAwgInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}
	logger.Info("AmneziaWG: initializing services for", len(inbounds), "inbound(s)")
	s.ReconcileAllKeys()
	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("AmneziaWG: failed to generate configs:", err)
		return
	}
	if err := s.SetupRouting(); err != nil {
		logger.Warning("AmneziaWG: failed to setup routing:", err)
	}
}

// GenerateAllConfigs reconciles every kernel awg<id> interface to DB state, exactly like
// WgcService.GenerateAllConfigs but with the obfuscation parameters applied at the device.
func (s *AwgService) GenerateAllConfigs() error {
	inbounds, err := s.GetAwgInbounds()
	if err != nil {
		return err
	}

	wanted := make(map[string]bool)
	if len(inbounds) > 0 {
		disabled := s.disabledEmails()
		cl, err := wgctrl.New()
		if err != nil {
			return fmt.Errorf("wgctrl: %w", err)
		}
		defer cl.Close()

		for _, inbound := range inbounds {
			if !inbound.Enable {
				continue
			}
			// Claimed before the reconcile is attempted; see WgcService.GenerateAllConfigs
			// for why a failed reconcile must not hand the interface to removeStaleLinks.
			wanted[awgIfaceName(inbound.Id)] = true

			settings, err := s.parseSettings(inbound)
			if err != nil {
				logger.Warning("AmneziaWG: skipping inbound", inbound.Id, err)
				continue
			}
			if strings.TrimSpace(settings.ServerPrivKey) == "" {
				logger.Warning("AmneziaWG: inbound", inbound.Id, "has no server key yet")
				continue
			}
			priv, err := wgtypes.ParseKey(settings.ServerPrivKey)
			if err != nil {
				logger.Warning("AmneziaWG: inbound", inbound.Id, "bad server key:", err)
				continue
			}
			iface := awgIfaceName(inbound.Id)
			blockNet, prefix := awgBlockFor(inbound, settings)
			if err := s.ensureLink(iface, settings.mtu(), blockNet, prefix); err != nil {
				logger.Warning("AmneziaWG: interface setup failed for", iface, err)
				continue
			}
			port := inbound.Port
			desiredPeers := s.buildPeers(inbound, settings, disabled)
			if err := s.reconcilePeers(cl, iface, &priv, port, settings.resolveObfs(), desiredPeers); err != nil {
				logger.Warning("AmneziaWG: configure device failed for", iface, err)
				continue
			}
		}
	}

	s.removeStaleLinks(wanted)
	return nil
}

// buildPeers returns one peer per enabled, non-disabled account (gateway model).
func (s *AwgService) buildPeers(inbound *model.Inbound, settings *awgSettings, disabled map[string]bool) []wgtypes.PeerConfig {
	var peers []wgtypes.PeerConfig
	for i, client := range settings.Clients {
		if client.Email == "" || !client.Enable || disabled[client.Email] {
			continue
		}
		ips := s.awgDeviceIPs(inbound, settings, slotOr(client.Slot, i))
		// One peer PER DEVICE, each cryptokey-routed to its own /32. Pinning the peer to a
		// single address (not the whole block) is what stops one device from sourcing
		// another's IP, and gives every device an identity the data plane can tell apart.
		for d, dev := range client.deviceList() {
			if d >= len(ips) {
				break // more stored keypairs than the current User Limit allows
			}
			if strings.TrimSpace(dev.PubKey) == "" {
				continue
			}
			pub, err := wgtypes.ParseKey(dev.PubKey)
			if err != nil {
				continue
			}
			_, ipNet, err := net.ParseCIDR(ips[d] + "/32")
			if err != nil {
				continue
			}
			pc := wgtypes.PeerConfig{
				PublicKey:         pub,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{*ipNet},
			}
			if settings.PskEnable && strings.TrimSpace(dev.Psk) != "" {
				if psk, err := wgtypes.ParseKey(dev.Psk); err == nil {
					pc.PresharedKey = &psk
				}
			}
			peers = append(peers, pc)
		}
	}
	return peers
}

// reconcilePeers applies the desired peer set + obfuscation to iface INCREMENTALLY (see
// WgcService.reconcilePeers). Obfuscation params + key + port are (re)applied when the device
// is fresh OR any of them changed (tracked via lastObfs), so an obfuscation edit takes effect
// without disturbing unrelated live sessions.
func (s *AwgService) reconcilePeers(cl *wgctrl.Client, iface string, priv *wgtypes.Key, port int, obfs awgObfs, desired []wgtypes.PeerConfig) error {
	dev, derr := cl.Device(iface)
	curAllowed := make(map[string]string)
	if derr == nil && dev != nil {
		for _, p := range dev.Peers {
			curAllowed[p.PublicKey.String()] = allowedIPsKey(p.AllowedIPs)
		}
	}

	desiredKeys := make(map[string]bool, len(desired))
	var ops []wgtypes.PeerConfig
	for _, pc := range desired {
		pk := pc.PublicKey.String()
		desiredKeys[pk] = true
		if cur, ok := curAllowed[pk]; !ok || cur != allowedIPsKey(pc.AllowedIPs) {
			ops = append(ops, pc)
		}
	}
	for pk := range curAllowed {
		if !desiredKeys[pk] {
			if key, err := wgtypes.ParseKey(pk); err == nil {
				ops = append(ops, wgtypes.PeerConfig{PublicKey: key, Remove: true})
			}
		}
	}

	needKey := derr != nil || dev == nil || dev.PublicKey != priv.PublicKey()
	needPort := derr != nil || dev == nil || dev.ListenPort != port
	needObfs := needKey || s.obfsChanged(iface, obfs)
	if !needKey && !needPort && !needObfs && len(ops) == 0 {
		return nil
	}
	cfg := wgtypes.Config{ReplacePeers: false, Peers: ops}
	if needKey {
		cfg.PrivateKey = priv
	}
	if needPort {
		cfg.ListenPort = &port
	}
	if needObfs {
		obfs.apply(&cfg)
	}
	if err := cl.ConfigureDevice(iface, cfg); err != nil {
		return err
	}
	s.rememberObfs(iface, obfs)
	return nil
}

func (s *AwgService) obfsChanged(iface string, obfs awgObfs) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastObfs[iface] != obfs.sig()
}

func (s *AwgService) rememberObfs(iface string, obfs awgObfs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastObfs == nil {
		s.lastObfs = make(map[string]string)
	}
	s.lastObfs[iface] = obfs.sig()
}

// ensureLink makes sure the kernel amneziawg interface exists (created via netlink as a
// generic link of kind "amneziawg"), has the block gateway address, and is up. A missing
// module surfaces as EOPNOTSUPP on link add so the caller can Warn (kernel-only, no fallback).
func (s *AwgService) ensureLink(iface string, mtu int, blockNet net.IP, prefix int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		// See wg-c's ensureLink: claimed before the LinkAdd so ownership is a record
		// rather than an inference from the name.
		ownIfaceCreated(iface, "awg")
		la := netlink.NewLinkAttrs()
		la.Name = iface
		if mtu > 0 {
			la.MTU = mtu
		}
		if addErr := netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: la, LinkType: amneziawgLinkKind}); addErr != nil {
			if isNotSupported(addErr) {
				return fmt.Errorf("amneziawg kernel module unavailable (run Core Settings setup to DKMS-build it): %w", addErr)
			}
			return addErr
		}
		if link, err = netlink.LinkByName(iface); err != nil {
			return err
		}
	} else if ownForbidsDelete(ownIface, iface) {
		return fmt.Errorf("%s already exists and was not created by vpn-ui; not touching it", iface)
	}
	if blockNet != nil {
		v4 := blockNet.To4()
		if v4 != nil {
			gw := net.IPv4(v4[0], v4[1], v4[2], v4[3]+1)
			addr := &netlink.Addr{IPNet: &net.IPNet{IP: gw, Mask: net.CIDRMask(prefix, 32)}}
			_ = netlink.AddrReplace(link, addr)
			// Same stale-address cleanup as wg-c; see dropForeignV4Addrs.
			dropForeignV4Addrs(link, addr)
		}
	}
	return netlink.LinkSetUp(link)
}

// removeStaleLinks deletes every awg<id> interface not present in keep.
//
// Same fix as wg-c's: this matched a bare name prefix with no link-type check, so anything
// at all on the host called "awg<something>" was deleted on the next reconcile tick. See
// awgOwnsLink in ifaceown.go for the ownership test that replaced it.
func (s *AwgService) removeStaleLinks(keep map[string]bool) {
	links, err := netlink.LinkList()
	if err != nil {
		return
	}
	for _, l := range links {
		name := l.Attrs().Name
		if keep[name] || !awgOwnsLink(l) {
			continue
		}
		if err := netlink.LinkDel(l); err == nil {
			ownRemoveEntry(ownIface, name)
		}
	}
}

// SetupRouting shares the fwmark policy route + nftables regeneration with the other VPN
// protocols; best-effort modprobe of the amneziawg module.
func (s *AwgService) SetupRouting() error {
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
	s.runCmd("modprobe", amneziawgModule)

	ensureVpnPolicyRoute(s.runCmd)
	return s.nftService.ApplyNftRules()
}

func (s *AwgService) RestartServices() error { return s.GenerateAllConfigs() }

func (s *AwgService) StopServices() error {
	s.removeStaleLinks(map[string]bool{})
	return nil
}

// AmneziawgAvailable reports whether the out-of-tree amneziawg module is usable.
func (s *AwgService) AmneziawgAvailable() bool {
	return moduleAvailable(amneziawgModule)
}

// AnyInterfaceUp reports whether at least one awg interface exists and is up.
//
// Ownership-checked like the stale-link sweep: a prefix match let an operator's own "awg0"
// make the status row claim the AmneziaWG core was running.
func (s *AwgService) AnyInterfaceUp() bool {
	links, err := netlink.LinkList()
	if err != nil {
		return false
	}
	for _, l := range links {
		if awgOwnsLink(l) && l.Attrs().Flags&net.FlagUp != 0 {
			return true
		}
	}
	return false
}

// amneziawgModuleVersion reads the running amneziawg module version, or "kernel" when unreadable.
func amneziawgModuleVersion() string {
	b, err := os.ReadFile("/sys/module/amneziawg/version")
	if err != nil {
		return "kernel"
	}
	if v := strings.TrimSpace(string(b)); v != "" {
		return v
	}
	return "kernel"
}

// AwgClientConfig is an account's rendered client config (for the panel + QR).
type AwgClientConfig struct {
	DeviceIndex int    `json:"deviceIndex"`
	IP          string `json:"ip"`
	Remark      string `json:"remark"`
	PublicKey   string `json:"publicKey"`
	Config      string `json:"config"`
	// PreSharedKey is this device's own preshared key, empty when PSK is off. See
	// WgcClientConfig, same field for the same reason.
	PreSharedKey string `json:"psk"`
	// Host/Port mirror this config's own Endpoint= — see WgcClientConfig, same reason.
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (o *awgSettings) dnsList() string {
	var parts []string
	if d := strings.TrimSpace(o.Dns1); d != "" {
		parts = append(parts, d)
	}
	if d := strings.TrimSpace(o.Dns2); d != "" {
		parts = append(parts, d)
	}
	if len(parts) == 0 {
		return "1.1.1.1, 1.0.0.1"
	}
	return strings.Join(parts, ", ")
}

// RenderClientConfigs returns the AmneziaWG .conf(s) for the account with the given email.
// Identical to WgcService.RenderClientConfigs plus the AWG 1.0 obfuscation lines in [Interface]
// (which a plain WireGuard client rejects , an AmneziaWG-aware client is required).
func (s *AwgService) RenderClientConfigs(inbound *model.Inbound, email, endpointHost string) ([]AwgClientConfig, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return nil, err
	}
	obfs := settings.resolveObfs()

	type endpointTarget struct {
		host   string
		port   int
		remark string
	}
	var targets []endpointTarget
	for _, ep := range settings.ExternalProxy {
		dest := strings.TrimSpace(ep.Dest)
		if dest == "" {
			continue
		}
		port := ep.Port
		if port <= 0 {
			port = inbound.Port
		}
		targets = append(targets, endpointTarget{host: dest, port: port, remark: strings.TrimSpace(ep.Remark)})
	}
	if len(targets) == 0 {
		host := endpointHost
		if l := strings.TrimSpace(inbound.Listen); l != "" && l != "0.0.0.0" {
			host = l
		}
		targets = append(targets, endpointTarget{host: host, port: inbound.Port})
	}

	var out []AwgClientConfig
	for i, client := range settings.Clients {
		if client.Email != email {
			continue
		}
		ips := s.awgDeviceIPs(inbound, settings, slotOr(client.Slot, i))
		devices := client.deviceList()
		if len(ips) == 0 || len(devices) == 0 {
			break
		}
		// ONE CONFIG PER DEVICE. Each carries its own keypair and its own /32, so importing
		// device 1 on one machine and device 2 on another gives them distinct tunnel IPs and
		// lets both stay connected at once. Handing the same config to two devices cannot
		// work: they would share a keypair, and the server keeps one endpoint per peer.
		for d, dev := range devices {
			if d >= len(ips) || strings.TrimSpace(dev.PrivKey) == "" {
				continue
			}
			cidr := ips[d] + "/32"
			// Per device, not per endpoint: see WgcService.RenderClientConfigs.
			psk := ""
			if settings.PskEnable && strings.TrimSpace(dev.Psk) != "" {
				psk = dev.Psk
			}
			for ti, t := range targets {
				var b strings.Builder
				b.WriteString("[Interface]\n")
				b.WriteString("PrivateKey = " + dev.PrivKey + "\n")
				b.WriteString("Address = " + cidr + "\n")
				b.WriteString("DNS = " + settings.dnsList() + "\n")
				b.WriteString(fmt.Sprintf("MTU = %d\n", settings.mtu()))
				// AWG 1.0 obfuscation (must match the server, except Jc/Jmin/Jmax).
				b.WriteString(fmt.Sprintf("Jc = %d\n", obfs.Jc))
				b.WriteString(fmt.Sprintf("Jmin = %d\n", obfs.Jmin))
				b.WriteString(fmt.Sprintf("Jmax = %d\n", obfs.Jmax))
				b.WriteString(fmt.Sprintf("S1 = %d\n", obfs.S1))
				b.WriteString(fmt.Sprintf("S2 = %d\n", obfs.S2))
				b.WriteString("H1 = " + obfs.H1 + "\n")
				b.WriteString("H2 = " + obfs.H2 + "\n")
				b.WriteString("H3 = " + obfs.H3 + "\n")
				b.WriteString("H4 = " + obfs.H4 + "\n")
				b.WriteString("\n[Peer]\n")
				b.WriteString("PublicKey = " + settings.ServerPubKey + "\n")
				if psk != "" {
					b.WriteString("PresharedKey = " + psk + "\n")
				}
				b.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", t.host, t.port))
				b.WriteString("AllowedIPs = 0.0.0.0/0\n")
				b.WriteString("PersistentKeepalive = 25\n")
				// Label each config with its device slot so it is obvious that device 1 and
				// device 2 are DIFFERENT configs to import on different machines, not copies.
				remark := ""
				if len(devices) > 1 {
					remark = fmt.Sprintf("Device %d", d+1)
				}
				if t.remark != "" {
					if remark != "" {
						remark += " - "
					}
					remark += t.remark
				}
				out = append(out, AwgClientConfig{
					DeviceIndex:  d*len(targets) + ti,
					IP:           cidr,
					Remark:       remark,
					PublicKey:    dev.PubKey,
					Config:       b.String(),
					PreSharedKey: psk,
					Host:         t.host,
					Port:         t.port,
				})
			}
		}
		break
	}
	return out, nil
}

// AwgClientParams is WgcClientParams plus AmneziaWG obfuscation, for the Clash
// `type: wireguard` + `amnezia-wg-option` proxy. The obfuscation values are exported
// (rather than the unexported awgObfs) so the sub package can read them. Keep in
// lock-step with RenderClientConfigs.
type AwgClientParams struct {
	WgcClientParams
	Jc, Jmin, Jmax, S1, S2 int
	H1, H2, H3, H4         string
}

// RenderClientParams mirrors RenderClientConfigs (same targets/devices loop + obfs)
// but returns structured params instead of .conf text.
func (s *AwgService) RenderClientParams(inbound *model.Inbound, email, endpointHost string) ([]AwgClientParams, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return nil, err
	}
	obfs := settings.resolveObfs()
	type endpointTarget struct {
		host   string
		port   int
		remark string
	}
	var targets []endpointTarget
	for _, ep := range settings.ExternalProxy {
		dest := strings.TrimSpace(ep.Dest)
		if dest == "" {
			continue
		}
		port := ep.Port
		if port <= 0 {
			port = inbound.Port
		}
		targets = append(targets, endpointTarget{host: dest, port: port, remark: strings.TrimSpace(ep.Remark)})
	}
	if len(targets) == 0 {
		host := endpointHost
		if l := strings.TrimSpace(inbound.Listen); l != "" && l != "0.0.0.0" {
			host = l
		}
		targets = append(targets, endpointTarget{host: host, port: inbound.Port})
	}
	dns := strings.Split(settings.dnsList(), ", ")
	mtu := settings.mtu()

	var out []AwgClientParams
	for i, client := range settings.Clients {
		if client.Email != email {
			continue
		}
		ips := s.awgDeviceIPs(inbound, settings, slotOr(client.Slot, i))
		devices := client.deviceList()
		if len(ips) == 0 || len(devices) == 0 {
			break
		}
		for d, dev := range devices {
			if d >= len(ips) || strings.TrimSpace(dev.PrivKey) == "" {
				continue
			}
			cidr := ips[d] + "/32"
			psk := ""
			if settings.PskEnable && strings.TrimSpace(dev.Psk) != "" {
				psk = dev.Psk
			}
			for _, t := range targets {
				remark := ""
				if len(devices) > 1 {
					remark = fmt.Sprintf("Device %d", d+1)
				}
				if t.remark != "" {
					if remark != "" {
						remark += " - "
					}
					remark += t.remark
				}
				out = append(out, AwgClientParams{
					WgcClientParams: WgcClientParams{
						Name:         remark,
						PrivateKey:   dev.PrivKey,
						Address:      cidr,
						PublicKey:    settings.ServerPubKey,
						PreSharedKey: psk,
						Host:         t.host,
						Port:         t.port,
						MTU:          mtu,
						DNS:          dns,
						AllowedIPs:   []string{"0.0.0.0/0"},
					},
					Jc: obfs.Jc, Jmin: obfs.Jmin, Jmax: obfs.Jmax, S1: obfs.S1, S2: obfs.S2,
					H1: obfs.H1, H2: obfs.H2, H3: obfs.H3, H4: obfs.H4,
				})
			}
		}
		break
	}
	return out, nil
}

// ReconcileKeys ensures the server keypair, per-client keypairs/PSKs, AND the obfuscation
// params (default junk/padding sizes + minted unique magic headers) exist, operating on raw
// JSON to preserve unknown UI fields. Returns whether inbound.Settings changed.
func (s *AwgService) ReconcileKeys(inbound *model.Inbound) (bool, error) {
	var raw map[string]json.RawMessage
	if len(inbound.Settings) > 0 {
		if err := json.Unmarshal([]byte(inbound.Settings), &raw); err != nil {
			return false, err
		}
	}
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}
	changed := false

	if strings.TrimSpace(jsonString(raw["serverPrivKey"])) == "" {
		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return changed, err
		}
		setRawString(raw, "serverPrivKey", priv.String())
		setRawString(raw, "serverPubKey", priv.PublicKey().String())
		changed = true
	} else if priv, err := wgtypes.ParseKey(jsonString(raw["serverPrivKey"])); err == nil {
		if jsonString(raw["serverPubKey"]) != priv.PublicKey().String() {
			setRawString(raw, "serverPubKey", priv.PublicKey().String())
			changed = true
		}
	}

	if ensureAwgObfuscation(raw) {
		changed = true
	}

	pskEnable := jsonBool(raw["pskEnable"])

	var clients []map[string]json.RawMessage
	if cb, ok := raw["clients"]; ok {
		_ = json.Unmarshal(cb, &clients)
	}
	// One keypair PER DEVICE SLOT, sized to the inbound's User Limit. K devices need K
	// keypairs: two devices sharing one would fight over the single endpoint the server
	// keeps per peer, and would be handed the same tunnel IP.
	k := wgcEffectiveK(userLimitPtrFromRaw(raw))
	for _, c := range clients {
		var devices []map[string]json.RawMessage
		if db, ok := c["devices"]; ok {
			_ = json.Unmarshal(db, &devices)
		}
		// Adopt a pre-per-device account's single keypair as device 0 so existing inbounds
		// keep their working config instead of silently getting a new key.
		if len(devices) == 0 && strings.TrimSpace(jsonString(c["privKey"])) != "" {
			d0 := map[string]json.RawMessage{}
			setRawString(d0, "privKey", jsonString(c["privKey"]))
			setRawString(d0, "pubKey", jsonString(c["pubKey"]))
			setRawString(d0, "psk", jsonString(c["psk"]))
			devices = append(devices, d0)
			changed = true
		}
		// Grow to K, then trim anything beyond it (lowering the User Limit revokes the
		// surplus devices' keys, which is what makes the limit enforceable).
		for len(devices) < k {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return changed, err
			}
			d := map[string]json.RawMessage{}
			setRawString(d, "privKey", key.String())
			setRawString(d, "pubKey", key.PublicKey().String())
			devices = append(devices, d)
			changed = true
		}
		if len(devices) > k {
			devices = devices[:k]
			changed = true
		}
		for _, d := range devices {
			if key, err := wgtypes.ParseKey(jsonString(d["privKey"])); err == nil {
				if jsonString(d["pubKey"]) != key.PublicKey().String() {
					setRawString(d, "pubKey", key.PublicKey().String())
					changed = true
				}
			}
			if pskEnable {
				if strings.TrimSpace(jsonString(d["psk"])) == "" {
					psk, err := wgtypes.GenerateKey()
					if err != nil {
						return changed, err
					}
					setRawString(d, "psk", psk.String())
					changed = true
				}
			} else if jsonString(d["psk"]) != "" {
				setRawString(d, "psk", "")
				changed = true
			}
		}
		db, _ := json.Marshal(devices)
		c["devices"] = db
		// Keep the legacy fields mirroring device 0 so anything still reading them (and the
		// UI's read-only key display) stays correct.
		if len(devices) > 0 {
			setRawString(c, "privKey", jsonString(devices[0]["privKey"]))
			setRawString(c, "pubKey", jsonString(devices[0]["pubKey"]))
			setRawString(c, "psk", jsonString(devices[0]["psk"]))
		}
	}

	if changed {
		if len(clients) > 0 {
			cb, _ := json.Marshal(clients)
			raw["clients"] = cb
		}
		out, err := json.Marshal(raw)
		if err != nil {
			return changed, err
		}
		inbound.Settings = string(out)
	}
	return changed, nil
}

func (s *AwgService) ReconcileAllKeys() bool {
	db := database.GetDB()
	if db == nil {
		return false
	}
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ?", "awg").Find(&inbounds).Error; err != nil {
		return false
	}
	any := false
	for _, ib := range inbounds {
		changed, err := s.ReconcileKeys(ib)
		if err != nil {
			logger.Warningf("AmneziaWG: key reconcile failed for inbound %d: %v", ib.Id, err)
			continue
		}
		if changed {
			if err := db.Model(&model.Inbound{}).Where("id = ?", ib.Id).Update("settings", ib.Settings).Error; err != nil {
				logger.Warningf("AmneziaWG: persist keys failed for inbound %d: %v", ib.Id, err)
			} else {
				any = true
			}
		}
	}
	return any
}

// ---- rbridge.Adapter (identical sweep model to WgcService) ------------------------------
var _ rbridge.Adapter = (*AwgService)(nil)

func (s *AwgService) Protocol() string { return "awg" }

func (s *AwgService) Poll() ([]rbridge.Live, error) {
	inbounds, err := s.GetAwgInbounds()
	if err != nil {
		return nil, err
	}
	if len(inbounds) == 0 {
		return nil, nil
	}
	cl, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer cl.Close()

	now := time.Now()
	seen := make(map[string]bool)
	var live []rbridge.Live

	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		iface := awgIfaceName(inbound.Id)
		dev, err := cl.Device(iface)
		if err != nil {
			continue
		}
		type acctInfo struct {
			email  string
			cidr   string
			enable bool
		}
		// EVERY device key maps back to its account, so all K devices are seen as live
		// tunnels of the one account. They share the account's block CIDR as the billing
		// key, which is what keeps usage/quota aggregated per account rather than per device.
		byPub := make(map[string]acctInfo)
		for i, client := range settings.Clients {
			cidr := s.awgAccountCIDR(inbound, settings, slotOr(client.Slot, i))
			for _, d := range client.deviceList() {
				if strings.TrimSpace(d.PubKey) == "" {
					continue
				}
				byPub[d.PubKey] = acctInfo{
					email:  client.Email,
					cidr:   cidr,
					enable: client.Enable,
				}
			}
		}
		for _, peer := range dev.Peers {
			if peer.LastHandshakeTime.IsZero() || now.Sub(peer.LastHandshakeTime) > wgHandshakeStale {
				continue
			}
			pk := peer.PublicKey.String()
			info, ok := byPub[pk]
			if !ok || info.cidr == "" || info.email == "" {
				continue
			}
			dk := iface + "|" + pk
			seen[dk] = true
			live = append(live, rbridge.Live{
				Protocol:  "awg",
				InboundID: inbound.Id,
				Email:     info.email,
				IP:        info.cidr,
				DeviceKey: dk,
				Disabled:  !info.enable,
				Since:     s.recordFirstSeen(dk, now),
			})
		}
	}
	s.pruneFirstSeen(seen)
	return live, nil
}

func (s *AwgService) Limit(inboundID int) (int, string) {
	inbounds, err := s.GetAwgInbounds()
	if err != nil {
		return 0, ""
	}
	for _, inbound := range inbounds {
		if inbound.Id != inboundID {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			return 0, ""
		}
		return wgcEffectiveK(settings.UserLimit), normUserLimitStrategy(settings.UserLimitStrategy)
	}
	return 0, ""
}

func (s *AwgService) Evict(l rbridge.Live) error {
	iface, pkStr, ok := strings.Cut(l.DeviceKey, "|")
	if !ok {
		return fmt.Errorf("awg: malformed device key %q", l.DeviceKey)
	}
	pk, err := wgtypes.ParseKey(pkStr)
	if err != nil {
		return err
	}
	cl, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer cl.Close()
	return cl.ConfigureDevice(iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: pk, Remove: true}},
	})
}

func (s *AwgService) recordFirstSeen(key string, now time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.firstSeen == nil {
		s.firstSeen = make(map[string]time.Time)
	}
	if t, ok := s.firstSeen[key]; ok {
		return t
	}
	s.firstSeen[key] = now
	return now
}

func (s *AwgService) pruneFirstSeen(seen map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.firstSeen {
		if !seen[k] {
			delete(s.firstSeen, k)
		}
	}
}

func (s *AwgService) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("AmneziaWG: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}

// userLimitPtrFromRaw reads the raw-JSON userLimit as the *int wgcEffectiveK expects, so an
// ABSENT field (legacy => 1 device) stays distinguishable from an explicit 0 (=> the max).
func userLimitPtrFromRaw(raw map[string]json.RawMessage) *int {
	b, ok := raw["userLimit"]
	if !ok {
		return nil
	}
	var k int
	if json.Unmarshal(b, &k) != nil {
		return nil
	}
	return &k
}

// setRawInt stores n as a JSON number under key.
func setRawInt(raw map[string]json.RawMessage, key string, n int) {
	b, _ := json.Marshal(n)
	raw[key] = b
}

// ensureAwgObfuscation defaults the junk/padding sizes and mints four distinct magic headers
// (in [5, 2^31-1]) when any is missing. Returns whether raw changed.
func ensureAwgObfuscation(raw map[string]json.RawMessage) bool {
	changed := false
	defInts := []struct {
		k string
		v int
	}{{"jc", 4}, {"jmin", 8}, {"jmax", 80}, {"s1", 77}, {"s2", 90}}
	for _, d := range defInts {
		if _, ok := raw[d.k]; !ok {
			setRawInt(raw, d.k, d.v)
			changed = true
		}
	}
	need := false
	for _, k := range []string{"h1", "h2", "h3", "h4"} {
		if strings.TrimSpace(jsonString(raw[k])) == "" {
			need = true
		}
	}
	if need {
		vals := uniqueMagic(4)
		for i, k := range []string{"h1", "h2", "h3", "h4"} {
			setRawString(raw, k, vals[i])
		}
		changed = true
	}
	return changed
}

// uniqueMagic returns n distinct random magic-header values (decimal strings) in [5, 2^31-1].
func uniqueMagic(n int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, n)
	for len(out) < n {
		v := randUint31()
		s := fmt.Sprintf("%d", v)
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// randUint31 returns a cryptographically-random integer in [5, 2^31-1].
func randUint31() int64 {
	const lo = 5
	max := big.NewInt(2147483647 - lo)
	n, err := cryptorand.Int(cryptorand.Reader, max)
	if err != nil {
		return lo
	}
	return n.Int64() + lo
}
