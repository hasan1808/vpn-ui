package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/json_util"
	"github.com/hasan1808/pro-ui/web/service/rbridge"
	"github.com/hasan1808/pro-ui/xray"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WgcService manages "WireGuard (C)" — the in-kernel WireGuard data plane driven
// natively from Go via wgctrl-go (netlink), NOT Xray's userspace WireGuard inbound
// (which owns the "wireguard" protocol string; this one is "wg-c").
//
// Unlike the daemon-backed protocols (ocserv/accel-ppp/charon) there is NO child
// process: each wgc inbound is one kernel `wgc<id>` interface created via netlink
// and configured via wgctrl. WireGuard has no username/password and no RADIUS round
// trip — a peer's public key IS its credential — so, like ikev2 psk/eap-tls, wgc
// is a rbridge.Adapter: the sweeper polls live tunnels (peers with a recent handshake),
// bills their per-IP nft traffic through the Sink, and enforces disable/quota by
// removing peers. The panel generates and stores every keypair server-side.
//
// Account model: one inbound hosts many accounts (like l2tp/sstp); each account with
// User Limit K materializes as K device peers (K keypairs, K consecutive tunnel IPs
// from the shared block allocator), one Xray source-route over the block. Because a
// removed peer cannot complete a handshake, disable/quota enforcement is HARD: the
// periodic reconcile (GenerateAllConfigs each traffic tick) keeps the interface's peer
// set equal to exactly the enabled, non-disabled devices, so a disabled account cannot
// reconnect at all — no eventual-eviction window.
type WgcService struct {
	inboundService InboundService
	nftService     NftService

	mu        sync.Mutex
	firstSeen map[string]time.Time // deviceKey -> first-seen handshake (drives oldest-first eviction order)
}

const (
	// wgHandshakeStale is how long after its last handshake a peer is still considered
	// a live device. WireGuard rekeys roughly every 2 minutes under traffic, so a 3
	// minute window avoids flapping a briefly-idle device offline.
	wgHandshakeStale = 180 * time.Second
	// wgDefaultMTU is the WireGuard standard tunnel MTU.
	wgDefaultMTU = 1420
	// wgIfacePrefix names the per-inbound kernel interfaces (wgc<id>). Kept short so
	// wgc<id> stays within the 15-char IFNAMSIZ limit.
	wgIfacePrefix = "wgc"
	// wgKernelModule is the in-kernel WireGuard module (mainline since Linux 5.6).
	wgKernelModule = "wireguard"
)

// wgcSettings is the WireGuard-specific slice of an inbound's Settings JSON. It clones
// the sstp/ocserv block model (auto-managed IP ranges + User Limit) and adds the server
// keypair and an optional preshared-key toggle. Per-device keypairs live on each client.
type wgcSettings struct {
	ServerPrivKey string `json:"serverPrivKey"`
	ServerPubKey  string `json:"serverPubKey"`
	PskEnable     bool   `json:"pskEnable"`

	Dns1 string `json:"dns1"`
	Dns2 string `json:"dns2"`
	Mtu  int    `json:"mtu"`

	ClientToClient    bool               `json:"clientToClient"`
	CrossInbound      bool               `json:"crossInbound"`
	UserLimit         *int               `json:"userLimit"`
	UserLimitStrategy string             `json:"userLimitStrategy"`
	IpRanges          []string           `json:"ipRanges"`
	ExternalProxy     []wgcExternalProxy `json:"externalProxy"`
	Clients           []wgcClient        `json:"clients"`
}

// wgcExternalProxy is one alternate Endpoint (a relay/CDN host:port) written into the
// generated client config + QR instead of the server's own address. Mirrors OpenVPN's
// external-proxy list; WireGuard carries no TLS, so there is no forceTls field. A zero
// Port inherits the inbound's listen port.
type wgcExternalProxy struct {
	Dest   string `json:"dest"`
	Port   int    `json:"port"`
	Remark string `json:"remark"`
}

func (o *wgcSettings) effectiveRanges() []string { return o.IpRanges }

func (o *wgcSettings) mtu() int {
	if o.Mtu > 0 {
		return o.Mtu
	}
	return wgDefaultMTU
}

// wgcClient is one WireGuard account parsed from Settings JSON. Gateway model: ONE
// keypair per account, whose config addresses the account's whole CIDR block (e.g. a /29),
// so a router/gateway behind that one link hands the block out to its LAN. Identity is
// Email (no username/password — the public key is the credential). A dedicated struct
// (like ikev2Client) so the UI's extra string fields don't break json.Unmarshal.
type wgcClient struct {
	Email   string      `json:"email"`
	Enable  bool        `json:"enable"`
	PrivKey string      `json:"privKey"`
	PubKey  string      `json:"pubKey"`
	Psk     string      `json:"psk"`
	Devices []wgcDevice `json:"devices"`
	Slot    *int        `json:"slot"` // address-pool slot; nil = fall back to list index
}

// wgcDevice is ONE device slot of an account: its own keypair (and optional preshared key)
// and, from its index, its own /32 out of the account's block.
//
// WireGuard identifies a peer by its public key and keeps a SINGLE endpoint per peer, so two
// devices sharing one keypair cannot both be online: whichever handshakes last takes the
// tunnel and the other goes dark. The protocol also has no address assignment (the client
// self-assigns from its config's Address line), so one config handed to two devices gives
// both the same tunnel IP. K devices therefore require K keypairs and K configs - the same
// model Mullvad/Windscribe use, where the "device limit" is a cap on registered keys.
type wgcDevice struct {
	PrivKey string `json:"privKey"`
	PubKey  string `json:"pubKey"`
	Psk     string `json:"psk"`
}

// deviceList returns the account's device slots, seeding device 0 from the legacy
// single-keypair fields so accounts created before per-device keys keep their working key.
func (c *wgcClient) deviceList() []wgcDevice {
	if len(c.Devices) > 0 {
		return c.Devices
	}
	if strings.TrimSpace(c.PubKey) != "" {
		return []wgcDevice{{PrivKey: c.PrivKey, PubKey: c.PubKey, Psk: c.Psk}}
	}
	return nil
}

// wgcDeviceIPs returns the account's K per-device tunnel IPs in slot order; device d takes
// the d-th address of the account's block, so the block CIDR still covers every device.
func (s *WgcService) wgcDeviceIPs(inbound *model.Inbound, settings *wgcSettings, accountSlot int) []string {
	ranges := settings.effectiveRanges()
	k := wgcEffectiveK(settings.UserLimit)
	if k <= 1 {
		if ip := computeVpnClientIP(ranges, inbound.Id, accountSlot, "wg-c"); ip != nil {
			return []string{ip.String()}
		}
		return nil
	}
	base, _ := s.wgcAccountBlock(inbound, settings, accountSlot)
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

// wgIfaceName returns the kernel interface name for an inbound.
func wgIfaceName(id int) string { return fmt.Sprintf("%s%d", wgIfacePrefix, id) }

func (s *WgcService) GetWgcInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", "wg-c").Find(&inbounds).Error
	return inbounds, err
}

func (s *WgcService) parseSettings(inbound *model.Inbound) (*wgcSettings, error) {
	settings := &wgcSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	return settings, err
}

// wgcBlockFor returns an inbound's client block network + prefix in the 10.7 /16,
// mirroring ikev2BlockFor. The interface takes the block's .1; clients get /32s within.
func wgcBlockFor(inbound *model.Inbound, settings *wgcSettings) (net.IP, int) {
	return vpnBlock(settings.effectiveRanges(), protocolBase("wg-c"), inbound.Id)
}

// GetSubnetForInbound returns the inbound's client block as a CIDR string.
func (s *WgcService) GetSubnetForInbound(inbound *model.Inbound) string {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		settings = &wgcSettings{}
	}
	netAddr, prefix := wgcBlockFor(inbound, settings)
	return fmt.Sprintf("%s/%d", netAddr.String(), prefix)
}

// GetSubnetsForInbound returns the inbound's client subnet(s) as one contiguous block,
// like OpenConnect/IKEv2. Used by the nftables TPROXY/accounting path.
func (s *WgcService) GetSubnetsForInbound(inbound *model.Inbound) []string {
	return []string{s.GetSubnetForInbound(inbound)}
}

// GetTproxyPort returns the deterministic TPROXY/dokodemo port (shared 12300+id, unique
// per inbound id across all protocols).
func (s *WgcService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound that captures the
// TPROXY-redirected WireGuard traffic and feeds it into Xray — identical to the others.
func (s *WgcService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
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

// nextPow2 returns the smallest power of two >= n (>=1).
func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// wgcAccountBlock returns the CIDR block of the account holding this SLOT, as (first-IP
// string, prefix). The slot is stored on the account (model.Client.Slot), NOT its position in
// clients[]: deriving it from position moved every later account's address when an earlier
// one was deleted, and a WireGuard config carries its address, so those tunnels went silently
// dead. An
// aligned power-of-two block sized to the User Limit K. K<=1 -> a single /32 IP (walks the
// ranges, computeVpnClientIP); K>=2 -> nextPow2(K) addresses as one aligned block (e.g. K
// in 5..8 -> a /29 like 10.7.8.8/29). ONE config addresses this whole block so a gateway
// behind the link routes it to its LAN. Must match BuildVpnEmailToIPMap for routing.
func (s *WgcService) wgcAccountBlock(inbound *model.Inbound, settings *wgcSettings, accountSlot int) (string, int) {
	ranges := settings.effectiveRanges()
	k := wgcEffectiveK(settings.UserLimit)
	if k <= 1 {
		if ip := computeVpnClientIP(ranges, inbound.Id, accountSlot, "wg-c"); ip != nil {
			return ip.String(), 32
		}
		return "", 0
	}
	bs := nextPow2(k)
	subnets := pppSubnetsOrDefault(ranges, "wg-c", inbound.Id)
	subnet, hostBase, ok := vpnAccountBlock(subnets, accountSlot, bs)
	if !ok {
		return "", 0
	}
	return fmt.Sprintf("%s.%d", subnet, hostBase), 32 - log2i(bs)
}

// wgcAccountCIDR returns account i's block as a CIDR string ("10.7.8.8/29"), or "" past
// capacity. Used as the routing / accounting / session key for the account.
func (s *WgcService) wgcAccountCIDR(inbound *model.Inbound, settings *wgcSettings, accountSlot int) string {
	ip, prefix := s.wgcAccountBlock(inbound, settings, accountSlot)
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("%s/%d", ip, prefix)
}

// disabledEmails returns the set of accounts disabled by quota/expiry or in settings
// (client_traffics.enable = false), mirroring the rbridge Sink's DisabledEmails.
func (s *WgcService) disabledEmails() map[string]bool {
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

// InitWgc brings WireGuard up on panel startup.
func (s *WgcService) InitWgc() {
	inbounds, err := s.GetWgcInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}
	logger.Info("WireGuard: initializing services for", len(inbounds), "inbound(s)")
	s.ReconcileAllKeys()
	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("WireGuard: failed to generate configs:", err)
		return
	}
	if err := s.SetupRouting(); err != nil {
		logger.Warning("WireGuard: failed to setup routing:", err)
	}
}

// GenerateAllConfigs reconciles every kernel interface to DB state: each enabled inbound
// gets a wgc<id> interface configured with the server key, listen port, and the peer
// set of exactly its enabled, non-disabled accounts' devices (ReplacePeers, authoritative);
// disabled/deleted inbounds' interfaces are torn down. Runs on client changes AND each
// traffic tick, so disable/quota is enforced hard (a removed peer cannot handshake) with
// no eventual-eviction window. Safe to call repeatedly: re-applying an unchanged peer set
// does not disturb live handshakes.
func (s *WgcService) GenerateAllConfigs() error {
	inbounds, err := s.GetWgcInbounds()
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
			// Claim the interface BEFORE attempting to reconcile it. `wanted` decides
			// what removeStaleLinks tears down, so building it only from SUCCESSFUL
			// reconciles meant a single transient failure below (an unparseable
			// settings blob, a momentary wgctrl error) deleted a live interface and
			// dropped every connected client, turning a retryable hiccup into an
			// outage that only a later save would repair. An interface is stale when
			// its inbound is gone or disabled, which is exactly what this loop skips.
			wanted[wgIfaceName(inbound.Id)] = true

			settings, err := s.parseSettings(inbound)
			if err != nil {
				logger.Warning("WireGuard: skipping inbound", inbound.Id, err)
				continue
			}
			if strings.TrimSpace(settings.ServerPrivKey) == "" {
				logger.Warning("WireGuard: inbound", inbound.Id, "has no server key yet")
				continue
			}
			priv, err := wgtypes.ParseKey(settings.ServerPrivKey)
			if err != nil {
				logger.Warning("WireGuard: inbound", inbound.Id, "bad server key:", err)
				continue
			}
			iface := wgIfaceName(inbound.Id)
			blockNet, prefix := wgcBlockFor(inbound, settings)
			if err := s.ensureLink(iface, settings.mtu(), blockNet, prefix); err != nil {
				logger.Warning("WireGuard: interface setup failed for", iface, err)
				continue
			}
			port := inbound.Port
			desiredPeers := s.buildPeers(inbound, settings, disabled)
			if err := s.reconcilePeers(cl, iface, &priv, port, desiredPeers); err != nil {
				logger.Warning("WireGuard: configure device failed for", iface, err)
				continue
			}
		}
	}

	// Tear down interfaces of disabled/deleted inbounds so no stale peer lingers.
	s.removeStaleLinks(wanted)
	return nil
}

// buildPeers returns the WireGuard peer set for an inbound: ONE peer per enabled,
// non-disabled account (gateway model), keyed by the account's public key with AllowedIPs
// = the account's whole CIDR block (e.g. a /29). A router/gateway behind that one link
// routes the block to its LAN; WireGuard cryptokey-routes the whole block to this peer.
// Disabled/over-quota accounts are omitted entirely — that is the hard enforcement
// (no peer -> no handshake -> no tunnel).
func (s *WgcService) buildPeers(inbound *model.Inbound, settings *wgcSettings, disabled map[string]bool) []wgtypes.PeerConfig {
	var peers []wgtypes.PeerConfig
	for i, client := range settings.Clients {
		if client.Email == "" || !client.Enable || disabled[client.Email] {
			continue
		}
		ips := s.wgcDeviceIPs(inbound, settings, slotOr(client.Slot, i))
		// One peer PER DEVICE, each cryptokey-routed to its own /32 so a device cannot
		// source another's address and every device is separable on the data plane.
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

// reconcilePeers applies the desired peer set to iface INCREMENTALLY: it adds newly
// desired peers, removes peers no longer desired, and re-applies a peer only when its
// AllowedIPs changed. Existing, unchanged peers are deliberately left untouched so their
// live endpoint + crypto session SURVIVE — a full ReplacePeers would remove and re-add
// every peer on each call, wiping every connected client's endpoint until its next
// handshake (stalling return traffic for up to a rekey interval). PrivateKey/ListenPort
// are set only when the device is fresh or they differ (re-setting the same private key
// can reset sessions). A steady state issues NO ConfigureDevice call at all.
func (s *WgcService) reconcilePeers(cl *wgctrl.Client, iface string, priv *wgtypes.Key, port int, desired []wgtypes.PeerConfig) error {
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
		// New peer, or an existing one whose tunnel IP moved -> add/update. Endpoint is
		// left nil (unchanged), so an update never disturbs a live session.
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
	if !needKey && !needPort && len(ops) == 0 {
		return nil // steady state: leave every live session intact
	}
	cfg := wgtypes.Config{ReplacePeers: false, Peers: ops}
	if needKey {
		cfg.PrivateKey = priv
	}
	if needPort {
		cfg.ListenPort = &port
	}
	return cl.ConfigureDevice(iface, cfg)
}

// allowedIPsKey renders a peer's AllowedIPs as a stable, order-independent comparison key.
func allowedIPsKey(ips []net.IPNet) string {
	parts := make([]string, 0, len(ips))
	for _, n := range ips {
		parts = append(parts, n.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// ensureLink makes sure the kernel wireguard interface exists, has the block gateway
// address (block .1 with the block prefix, so the connected route covers every client
// /32), and is up. Creates it via netlink when absent. A missing kernel module surfaces
// as EOPNOTSUPP on link add and is returned so the caller can Warn (kernel-only build).
func (s *WgcService) ensureLink(iface string, mtu int, blockNet net.IP, prefix int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		// Nothing there, so what we are about to create is unambiguously ours: record it
		// before the LinkAdd, so the stale-link sweep has a positive claim to work from
		// rather than inferring ownership from the name alone.
		ownIfaceCreated(iface, "wgc")
		la := netlink.NewLinkAttrs()
		la.Name = iface
		if mtu > 0 {
			la.MTU = mtu
		}
		if addErr := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la}); addErr != nil {
			if isNotSupported(addErr) {
				return fmt.Errorf("wireguard kernel module unavailable (install/modprobe wireguard): %w", addErr)
			}
			return addErr
		}
		if link, err = netlink.LinkByName(iface); err != nil {
			return err
		}
	} else if ownForbidsDelete(ownIface, iface) {
		// A device with our exact generated name that the manifest says predates us. We
		// would otherwise adopt it, rewrite its addresses and eventually delete it.
		return fmt.Errorf("%s already exists and was not created by vpn-ui; not touching it", iface)
	}
	if blockNet != nil {
		v4 := blockNet.To4()
		if v4 != nil {
			gw := net.IPv4(v4[0], v4[1], v4[2], v4[3]+1)
			addr := &netlink.Addr{IPNet: &net.IPNet{IP: gw, Mask: net.CIDRMask(prefix, 32)}}
			_ = netlink.AddrReplace(link, addr)
			dropForeignV4Addrs(link, addr)
		}
	}
	return netlink.LinkSetUp(link)
}

// dropForeignV4Addrs removes every IPv4 address on link except keep. AddrReplace
// only replaces an address with the SAME prefix, so an interface whose block moved
// kept the old gateway address too, and with it a connected route for a block the
// peers no longer use. Blocks are pinned now (see keepOwnedBlock in vpnrange.go), so
// this is mostly cleanup for interfaces that already drifted before the fix.
func dropForeignV4Addrs(link netlink.Link, keep *netlink.Addr) {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return
	}
	for i := range addrs {
		if addrs[i].IPNet == nil || addrs[i].IPNet.String() == keep.IPNet.String() {
			continue
		}
		if err := netlink.AddrDel(link, &addrs[i]); err != nil {
			logger.Debugf("WireGuard: could not remove stale address %s from %s: %v",
				addrs[i].IPNet, link.Attrs().Name, err)
		}
	}
}

// removeStaleLinks deletes every wgc<id> interface not present in keep.
//
// This was the worst of the three stale-link sweeps: a bare name prefix with NO link-type
// check at all, so a bridge, a veth or an operator's own WireGuard interface called
// "wgc-home" was deleted on the next reconcile tick and every tick after it. Ownership is
// now the exact wgIfaceName shape plus the wireguard link kind plus the manifest; see
// wgcOwnsLink in ifaceown.go.
func (s *WgcService) removeStaleLinks(keep map[string]bool) {
	links, err := netlink.LinkList()
	if err != nil {
		return
	}
	for _, l := range links {
		name := l.Attrs().Name
		if keep[name] || !wgcOwnsLink(l) {
			continue
		}
		if err := netlink.LinkDel(l); err == nil {
			ownRemoveEntry(ownIface, name)
		}
	}
}

// isNotSupported reports whether err is the "operation not supported" errno the kernel
// returns for `ip link add type wireguard` when the module is missing.
func isNotSupported(err error) bool {
	if errors.Is(err, syscall.EOPNOTSUPP) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "not supported")
}

// SetupRouting prepares the host so WireGuard client traffic is TPROXY-redirected into
// Xray. Shares the fwmark policy route + nftables regeneration with the other VPN
// protocols; loads the wireguard module (best-effort, autoloads on interface create anyway).
func (s *WgcService) SetupRouting() error {
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
	s.runCmd("modprobe", wgKernelModule)

	ensureVpnPolicyRoute(s.runCmd)
	return s.nftService.ApplyNftRules()
}

// RestartServices re-applies the interface/peer configuration. WireGuard has no daemon,
// so this is just GenerateAllConfigs (kept for parity with the other services' lifecycle).
func (s *WgcService) RestartServices() error { return s.GenerateAllConfigs() }

// StopServices tears down every wgc interface.
func (s *WgcService) StopServices() error {
	s.removeStaleLinks(map[string]bool{})
	return nil
}

// WireguardAvailable reports whether the in-kernel wireguard module is usable.
func (s *WgcService) WireguardAvailable() bool {
	return moduleAvailable(wgKernelModule)
}

// AnyInterfaceUp reports whether at least one wgc interface exists and is up (the
// data plane is live). Used by the Core Settings status row (WireGuard has no daemon).
//
// Ownership-checked like the stale-link sweep: an operator's own "wgc-home" used to make
// the status row claim the wg-c core was running on a host that had never started it.
func (s *WgcService) AnyInterfaceUp() bool {
	links, err := netlink.LinkList()
	if err != nil {
		return false
	}
	for _, l := range links {
		if wgcOwnsLink(l) && l.Attrs().Flags&net.FlagUp != 0 {
			return true
		}
	}
	return false
}

// wireguardModuleVersion reads the running wireguard module's version, or "kernel" when
// it is built-in / unreadable.
func wireguardModuleVersion() string {
	b, err := os.ReadFile("/sys/module/wireguard/version")
	if err != nil {
		return "kernel"
	}
	if v := strings.TrimSpace(string(b)); v != "" {
		return v
	}
	return "kernel"
}

// WgcClientConfig is an account's rendered client config (for the panel + QR). Gateway
// model: normally one config per account, but each configured external-proxy endpoint
// yields its own config (a distinct Endpoint), so there can be several — DeviceIndex
// disambiguates them and Remark labels the endpoint.
type WgcClientConfig struct {
	DeviceIndex int    `json:"deviceIndex"`
	IP          string `json:"ip"`        // the account's block CIDR (Address in the config)
	Remark      string `json:"remark"`    // external-proxy label (empty for the default endpoint)
	PublicKey   string `json:"publicKey"` // the account's public key (identifier)
	Config      string `json:"config"`    // the full wg .conf text
	// PreSharedKey is THIS device's own preshared key, empty when PSK is off, and is the
	// same value the Config text above carries on its PresharedKey= line. It is repeated
	// as a field because a caller that prints the key as its own row (the account export's
	// PSK row) would otherwise have to parse it back out of the .conf, and there is no
	// other source for it: each device of a multi-device account has a DIFFERENT key, so
	// the account's legacy top-level psk is not a stand-in for the device's.
	PreSharedKey string `json:"psk"`
	// Host/Port mirror this config's own Endpoint= (the target this specific config
	// dials, an external-proxy relay or the panel host). Callers that print a separate
	// "Server" summary row (the account export) must read it from here rather than
	// re-deriving the inbound's default address, or that row goes stale the moment an
	// external proxy is set while the attached .conf (which is always correct) does not.
	Host string `json:"host"`
	Port int    `json:"port"`
}

// dnsList joins the inbound's configured DNS servers (defaults to Cloudflare).
func (o *wgcSettings) dnsList() string {
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

// RenderClientConfigs returns the WireGuard .conf(s) for the account with the given email:
// ONE keypair whose Address is the account's whole block CIDR (e.g. 10.7.8.8/29), which a
// router/gateway hands out to its LAN. endpointHost is the address clients dial (the
// panel-access host); the listen port is the inbound port. AllowedIPs is full-tunnel IPv4
// only (no ::/0) to avoid an IPv6 leak, matching the other protocols. When the inbound has
// external-proxy endpoints, one config is emitted per endpoint (each with that Endpoint and
// its remark) instead of a single default config — a WireGuard config holds only one
// Endpoint, so alternate relays become separate configs (unlike OpenVPN's `remote` list).
func (s *WgcService) RenderClientConfigs(inbound *model.Inbound, email, endpointHost string) ([]WgcClientConfig, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return nil, err
	}

	// Endpoint targets: one per configured external proxy (a zero port inherits the
	// inbound's listen port); with none, a single target at the panel-access host.
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
		// Parity with OpenVPN: an explicit non-wildcard Listen address wins over the
		// panel host, so an operator who pins the inbound to a public IP gets it.
		host := endpointHost
		if l := strings.TrimSpace(inbound.Listen); l != "" && l != "0.0.0.0" {
			host = l
		}
		targets = append(targets, endpointTarget{host: host, port: inbound.Port})
	}

	var out []WgcClientConfig
	for i, client := range settings.Clients {
		if client.Email != email {
			continue
		}
		ips := s.wgcDeviceIPs(inbound, settings, slotOr(client.Slot, i))
		devices := client.deviceList()
		if len(ips) == 0 || len(devices) == 0 {
			break
		}
		// ONE CONFIG PER DEVICE, each with its own key and /32. Two devices cannot share one
		// config: they would share a keypair (only one could stay connected) and self-assign
		// the same Address, since WireGuard has no server-side address assignment.
		for d, dev := range devices {
			if d >= len(ips) || strings.TrimSpace(dev.PrivKey) == "" {
				continue
			}
			cidr := ips[d] + "/32"
			// Resolved once per device, not per endpoint: the key belongs to the device, and
			// every endpoint config of that device carries the same one. Same shape (and same
			// gate) as RenderClientParams below, which is what keeps the two in lock-step.
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
				b.WriteString("\n[Peer]\n")
				b.WriteString("PublicKey = " + settings.ServerPubKey + "\n")
				if psk != "" {
					b.WriteString("PresharedKey = " + psk + "\n")
				}
				b.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", t.host, t.port))
				b.WriteString("AllowedIPs = 0.0.0.0/0\n")
				b.WriteString("PersistentKeepalive = 25\n")
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
				out = append(out, WgcClientConfig{
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

// WgcClientParams is the structured form of a rendered WireGuard client config, the
// same data RenderClientConfigs writes as .conf text, for callers that need the fields
// rather than the text (e.g. the Clash subscription's `type: wireguard` proxy). Keep it
// in lock-step with RenderClientConfigs: they share the target/device loop.
type WgcClientParams struct {
	Name         string   // per-device/endpoint label, fed to the subscription remark
	PrivateKey   string   // client device private key
	Address      string   // client address CIDR, e.g. 10.7.8.8/32
	PublicKey    string   // server public key
	PreSharedKey string   // empty when PSK is off
	Host         string   // endpoint host the client dials
	Port         int      // endpoint port
	MTU          int
	DNS          []string
	AllowedIPs   []string
}

// RenderClientParams mirrors RenderClientConfigs (same targets/devices loop) but returns
// structured params instead of .conf text.
func (s *WgcService) RenderClientParams(inbound *model.Inbound, email, endpointHost string) ([]WgcClientParams, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return nil, err
	}
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

	var out []WgcClientParams
	for i, client := range settings.Clients {
		if client.Email != email {
			continue
		}
		ips := s.wgcDeviceIPs(inbound, settings, slotOr(client.Slot, i))
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
				out = append(out, WgcClientParams{
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
				})
			}
		}
		break
	}
	return out, nil
}

// ReconcileKeys ensures an inbound's server keypair and every client's device keypairs
// (sized to the User Limit K) exist, minting any missing keys and preshared keys (or
// clearing PSKs when the mode is off), trimming devices beyond K. It preserves unknown
// UI fields by operating on the raw JSON. Returns whether it changed inbound.Settings.
func (s *WgcService) ReconcileKeys(inbound *model.Inbound) (bool, error) {
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

	// Server keypair.
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

	pskEnable := jsonBool(raw["pskEnable"])

	var clients []map[string]json.RawMessage
	if cb, ok := raw["clients"]; ok {
		_ = json.Unmarshal(cb, &clients)
	}
	// One keypair PER DEVICE SLOT, sized to the User Limit. Device 0 adopts the account's
	// pre-existing key so accounts created before per-device keys keep their working config.
	k := wgcEffectiveK(userLimitPtrFromRaw(raw))
	for _, c := range clients {
		var devices []map[string]json.RawMessage
		if db, ok := c["devices"]; ok {
			_ = json.Unmarshal(db, &devices)
		}
		if len(devices) == 0 && strings.TrimSpace(jsonString(c["privKey"])) != "" {
			d0 := map[string]json.RawMessage{}
			setRawString(d0, "privKey", jsonString(c["privKey"]))
			setRawString(d0, "pubKey", jsonString(c["pubKey"]))
			setRawString(d0, "psk", jsonString(c["psk"]))
			devices = append(devices, d0)
			changed = true
		}
		// Grow to K, then trim past it: lowering the User Limit must revoke the surplus
		// devices' keys or the limit would not be enforceable.
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
		// Keep the legacy fields mirroring device 0 for anything still reading them.
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

// ReconcileAllKeys reconciles + persists keys for every wgc inbound. Returns true if
// any inbound's settings were changed (the caller then reloads the data plane).
func (s *WgcService) ReconcileAllKeys() bool {
	db := database.GetDB()
	if db == nil {
		return false
	}
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ?", "wg-c").Find(&inbounds).Error; err != nil {
		return false
	}
	any := false
	for _, ib := range inbounds {
		changed, err := s.ReconcileKeys(ib)
		if err != nil {
			logger.Warningf("WireGuard: key reconcile failed for inbound %d: %v", ib.Id, err)
			continue
		}
		if changed {
			if err := db.Model(&model.Inbound{}).Where("id = ?", ib.Id).Update("settings", ib.Settings).Error; err != nil {
				logger.Warningf("WireGuard: persist keys failed for inbound %d: %v", ib.Id, err)
			} else {
				any = true
			}
		}
	}
	return any
}

// ---- rbridge.Adapter (WireGuard is sweep-reconciled: no RADIUS, key-based auth) --------
//
// The sweeper polls live tunnels each traffic tick, bills their per-IP nft traffic via the
// Sink, and evicts disabled/over-quota devices. K-limit is structural here (an account has
// exactly K device peers), so TrimToLimit rarely acts; the load-bearing work is accounting
// (ReconcileLocalSessions) and the hard peer-set reconcile in GenerateAllConfigs.
var _ rbridge.Adapter = (*WgcService)(nil)

// Protocol identifies the sessions this adapter reconciles.
func (s *WgcService) Protocol() string { return "wg-c" }

// Poll enumerates live device tunnels — peers with a handshake inside wgHandshakeStale —
// mapping each peer pubkey back to its account/email and deterministic tunnel IP. Since
// WireGuard has no monotonic session id, arrival order is tracked in firstSeen.
func (s *WgcService) Poll() ([]rbridge.Live, error) {
	inbounds, err := s.GetWgcInbounds()
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
		iface := wgIfaceName(inbound.Id)
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
		// tunnels of the one account and bill against the account's block CIDR (usage and
		// quota stay per-account, not per-device).
		byPub := make(map[string]acctInfo)
		for i, client := range settings.Clients {
			cidr := s.wgcAccountCIDR(inbound, settings, slotOr(client.Slot, i))
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
				Protocol:  "wg-c",
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

// Limit returns the inbound's User Limit K and normalized strategy. Unknown inbound -> no limit.
func (s *WgcService) Limit(inboundID int) (int, string) {
	inbounds, err := s.GetWgcInbounds()
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

// Evict removes one device peer from its interface (best-effort). A removed peer cannot
// handshake, so this both drops the live tunnel and blocks reconnect until re-added.
func (s *WgcService) Evict(l rbridge.Live) error {
	iface, pkStr, ok := strings.Cut(l.DeviceKey, "|")
	if !ok {
		return fmt.Errorf("wgc: malformed device key %q", l.DeviceKey)
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

func (s *WgcService) recordFirstSeen(key string, now time.Time) time.Time {
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

func (s *WgcService) pruneFirstSeen(seen map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.firstSeen {
		if !seen[k] {
			delete(s.firstSeen, k)
		}
	}
}

func (s *WgcService) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("WireGuard: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}

// jsonString decodes a JSON string value, returning "" on any error.
func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// jsonBool decodes a JSON bool value, returning false on any error.
func jsonBool(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var b bool
	if json.Unmarshal(raw, &b) != nil {
		return false
	}
	return b
}

// setRawString stores s as a JSON string value under key.
func setRawString(raw map[string]json.RawMessage, key, s string) {
	b, _ := json.Marshal(s)
	raw[key] = b
}
