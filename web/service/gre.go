package service

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/json_util"
	"github.com/hasan1808/pro-ui/web/service/rbridge"
	"github.com/hasan1808/pro-ui/xray"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// GreService manages GRE (Generic Routing Encapsulation, IP protocol 47) tunnels driven
// natively from Go via netlink. Like wg-c and awg it is DAEMON-LESS: the data plane is the
// in-tree `ip_gre` kernel module plus netdevs this service reconciles, so it never touches
// procmgr and needs nothing bundled.
//
// GRE's customer is a ROUTER, not a phone: nearly every router ships GRE, including old and
// cheap ones. That framing decides the design. One account is one customer site, and the
// customer NATs their whole LAN behind the tunnel, so from the panel's side an account is a
// small set of addresses, which is exactly what accounting/routing/limits already key on.
//
// Two things make GRE unlike every other protocol here, and both are handled explicitly:
//
//  1. NO CREDENTIALS AND NO HANDSHAKE. There is nothing to authenticate, so there is no
//     RADIUS round-trip (the wg-c/awg precedent). Accounts are plumbed from DB state every
//     tick and billed through the static email->IP machinery; a disabled account has no data
//     path by the time anything polls it. See GenerateAllConfigs.
//  2. NO ENCRYPTION. Every byte is cleartext. So the panel offers GRE-over-IPsec (ESP
//     transport mode) on the already-shared charon, gated exactly like L2TP's
//     ipsecEnable/allowRaw pair, plus optional FOU (UDP encapsulation) for Linux/OpenWrt
//     peers stuck behind a NAT that protocol 47 cannot traverse.
//
// PEER DEMULTIPLEXING is the load-bearing choice. Two shapes coexist, verified against the
// kernel:
//
//   - A peer with a KNOWN public IP gets its own point-to-point netdev
//     (`local <server> remote <peer>`). No packet-path code, no learning.
//   - A peer with a DYNAMIC public IP is served by a shared unkeyed catch-all netdev
//     (`local <server>` with no remote), demultiplexed on the inner address the panel
//     assigned it, with the reverse path learned by greLearner.
//
// The kernel prefers an exact (local, remote) match over the wildcard, so the two never
// fight: a static peer is always taken by its own device even though the catch-all would
// also accept it. That is what makes the hybrid safe. Keys (RFC 2890) are deliberately NOT
// used for the base design, because RouterOS plain GRE exposes no key field and MikroTik is
// the dominant router in this market.
type GreService struct {
	inboundService InboundService
	nftService     NftService

	mu        sync.Mutex
	firstSeen map[string]time.Time // deviceKey -> first-seen, for oldest-first eviction
	learner   *greLearner
}

const (
	// greP2pPrefix / greCatPrefix name the kernel netdevs. Both start with "gre" so one
	// prefix scan reclaims every device this service owns. Names must stay inside the
	// 15-char IFNAMSIZ limit; see greP2pName/greCatName.
	greP2pPrefix = "gre"
	greCatPrefix = "grecat"

	// greModule is the in-tree GRE module. It is ALREADY required and provisioned for PPTP,
	// so the cross-distro kernel-module pipeline needs nothing new for the base protocol.
	greModule = "ip_gre"
	// greFouModule backs the optional UDP encapsulation. Creating an encap device before it
	// is loaded fails with EINVAL, so it is modprobe'd in SetupRouting before any LinkAdd.
	greFouModule = "fou"

	// greDefaultTTL matches the `ip` CLI's usual tunnel TTL.
	greDefaultTTL = 64
	// greDefaultFouPort is the default UDP port for FOU-encapsulated GRE.
	greDefaultFouPort = 15547
)

// FOU APPLIES TO PEERS WITH A KNOWN ADDRESS ONLY, and that is a deliberate boundary rather
// than an oversight, for two independent reasons:
//
//  1. FOU-encapsulated GRE arrives as UDP, so the kernel decapsulates it before anything
//     with protocol 47 is visible. greLearner reads a raw IPPROTO_GRE socket and therefore
//     cannot observe a FOU peer at all, leaving nothing to learn a dynamic peer's address
//     from.
//  2. The kernel's tunnel uniqueness tuple is (local, remote, ikey, okey) and does NOT
//     include the encap port, so an unkeyed FOU catch-all would collide (EEXIST) with the
//     raw catch-all already bound to the same local address.
//
// A dynamic peer is therefore always served over raw GRE, which the shared catch-all
// already accepts, so enabling FOU never takes anything away. The two audiences also do not
// overlap much in practice: FOU exists for Linux/OpenWrt peers behind a NAT, while the
// dynamic-address path exists for consumer routers that speak plain GRE only.

// greSettings is the GRE slice of an inbound's Settings JSON.
//
// The ipsecEnable/allowRaw pair mirrors l2tpSettings exactly, and yields the same three
// meaningful states: raw only, IPsec only, or both accepted. FouEnable is INDEPENDENT of
// IPsec rather than bundled with it: FOU is a Linux/OpenWrt encapsulation that MikroTik,
// Cisco and Keenetic do not implement, so tying it to the encrypted mode would lock the
// main audience out of encryption.
type greSettings struct {
	IpsecEnable bool   `json:"ipsecEnable"`
	IpsecPsk    string `json:"ipsecPsk"`
	AllowRaw    bool   `json:"allowRaw"`
	FouEnable   bool   `json:"fouEnable"`
	FouPort     int    `json:"fouPort"`

	Mtu int `json:"mtu"`
	Ttl int `json:"ttl"`

	ClientToClient    bool        `json:"clientToClient"`
	CrossInbound      bool        `json:"crossInbound"`
	UserLimit         *int        `json:"userLimit"`         // nil=absent(legacy=>1); 0=max; else 1..64
	UserLimitStrategy string      `json:"userLimitStrategy"` // parsed for parity; GRE enforces K structurally
	IpRanges          []string    `json:"ipRanges"`
	Clients           []greClient `json:"clients"`
}

// grePeer is ONE peer slot of an account: one customer router.
//
// PeerIp is the router's own public address, i.e. the `remote` of our tunnel and the "Peer
// IP Address" field the router's UI asks for. Leaving it EMPTY is a first-class choice, not
// a broken record: that peer is then served by the shared catch-all and its reverse path is
// learned from arriving traffic, which is what lets a customer on a dynamic IP use this at
// all.
type grePeer struct {
	PeerIp string `json:"peerIp"`
	Remark string `json:"remark"`
}

// greClient is one GRE account. Identity is Email; there is no credential, because GRE
// carries none. Peers holds one entry per peer slot, sized to the inbound's User Limit.
type greClient struct {
	Email  string    `json:"email"`
	Enable bool      `json:"enable"`
	Peers  []grePeer `json:"peers"`
	Slot   *int      `json:"slot"` // address-pool slot; nil = fall back to list index
}

// peerList returns the account's peer slots. A brand-new account has none, which is valid:
// it owns its addresses but has no data path until the operator fills in a peer (or the
// customer's first packet is learned against a dynamic slot).
func (c *greClient) peerList() []grePeer { return c.Peers }

func (o *greSettings) effectiveRanges() []string { return o.IpRanges }

// mtu returns 0 when unset, meaning "let the kernel pick". That is deliberate: the right
// default differs per encapsulation (1476 raw, 1464 under FOU) and the kernel already knows
// which, so hardcoding one number here would be wrong for the other.
func (o *greSettings) mtu() int {
	if o.Mtu > 0 {
		return o.Mtu
	}
	return 0
}

// Kernel defaults for a GRE netdev, i.e. what `mtu()==0` will actually produce.
const (
	greKernelMtuRaw = 1476 // 1500 - 20 (outer IP) - 4 (GRE)
	greKernelMtuFou = 1464 // ...minus 8 more for the UDP header
	// ESP transport mode with AES-GCM costs another ~48 bytes (SPI, sequence, IV, ICV and
	// padding). Measured on a live peer: with the device left at the raw default of 1476 the
	// largest packet that survived was 1428, so anything above that black-holes.
	greKernelMtuIpsec = 1428
)

// clampMss is the largest TCP payload that fits this tunnel: the value to force onto a SYN
// the CLIENT sends out to the internet, so that remote servers answer with segments the
// tunnel can carry.
//
// This cannot use nftables' `rt mtu` the way the reverse direction does. By the time the
// client's SYN reaches postrouting it is on its way out of the WAN, so the route MTU is the
// WAN's 1500, not the tunnel's. Clamping to that is the same as not clamping at all, which is
// exactly the bug this fixes: only the server->client direction was clamped, so uploads and
// small replies worked while every full-size DOWNLOAD was silently black-holed.
func (o *greSettings) clampMss() int {
	return o.effectiveMtu() - 40 // 20 IP + 20 TCP
}

// effectiveMtu is the inner MTU this inbound's tunnels really get: the operator's value when
// set, otherwise the largest that fits the encapsulation actually in use. IPsec is checked
// FIRST and beats FOU: ESP costs the most, and when both are on the packet carries both
// overheads, so the smallest of the two has to win or the peer black-holes.
func (o *greSettings) effectiveMtu() int {
	if m := o.mtu(); m > 0 {
		return m
	}
	if o.IpsecEnable {
		return greKernelMtuIpsec
	}
	if o.FouEnable {
		return greKernelMtuFou
	}
	return greKernelMtuRaw
}

func (o *greSettings) ttl() uint8 {
	if o.Ttl > 0 && o.Ttl < 256 {
		return uint8(o.Ttl)
	}
	return greDefaultTTL
}

func (o *greSettings) fouPort() int {
	if o.FouPort > 0 && o.FouPort < 65536 {
		return o.FouPort
	}
	return greDefaultFouPort
}

// greP2pName is the netdev for one account peer slot. Encoding the identity in the name
// keeps reconciliation stateless: the desired set is recomputed from the DB every tick and
// diffed against the kernel by name. Worst realistic case "gre9999_254_63" is 14 chars, but
// the length is enforced rather than assumed, because exceeding IFNAMSIZ fails the LinkAdd.
func greP2pName(inboundID, slot, peerIdx int) string {
	name := fmt.Sprintf("%s%d_%d_%d", greP2pPrefix, inboundID, slot, peerIdx)
	if len(name) <= 15 {
		return name
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return fmt.Sprintf("%s%08x", greP2pPrefix, h.Sum32())
}

// greCatName is the catch-all netdev for one server local address. It is derived from the
// address (not from a counter) so the name is stable across restarts and across inbounds
// being added or removed.
//
// The catch-all MUST bind a concrete local address. `modprobe ip_gre` auto-creates `gre0`,
// which already owns the (any, any) tuple, so a local-less catch-all is rejected EEXIST.
func greCatName(local net.IP) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(local.String()))
	return fmt.Sprintf("%s%04x", greCatPrefix, uint16(h.Sum32()))
}

func (s *GreService) GetGreInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", "gre").Find(&inbounds).Error
	return inbounds, err
}

func (s *GreService) parseSettings(inbound *model.Inbound) (*greSettings, error) {
	settings := &greSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	return settings, err
}

// greBlockFor returns an inbound's client block network + prefix in the 10.9 /16.
func greBlockFor(inbound *model.Inbound, settings *greSettings) (net.IP, int) {
	return vpnBlock(settings.effectiveRanges(), protocolBase("gre"), inbound.Id)
}

func (s *GreService) GetSubnetForInbound(inbound *model.Inbound) string {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		settings = &greSettings{}
	}
	netAddr, prefix := greBlockFor(inbound, settings)
	return fmt.Sprintf("%s/%d", netAddr.String(), prefix)
}

func (s *GreService) GetSubnetsForInbound(inbound *model.Inbound) []string {
	return []string{s.GetSubnetForInbound(inbound)}
}

// GetTproxyPort returns the deterministic TPROXY/dokodemo port (shared 12300+id; inbound
// ids are globally unique, so this cannot collide with another protocol's).
func (s *GreService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound feeding TPROXY traffic into
// Xray. The kernel strips the GRE header before nftables sees anything, so the inner packet
// is ordinary TCP/UDP from a 10.9.x source and is indistinguishable from ppp0 or wg0
// traffic at the mangle hook. That is why routing rules, speed limit and the outbound
// chooser all work here unchanged.
func (s *GreService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
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

// greAccountBlock mirrors wgcAccountBlock/awgAccountBlock in the 10.9 /16: the account owns
// ONE aligned power-of-two block sized to the inbound's User Limit, so one routing rule and
// one accounting key cover every peer of the account. The slot comes from the account
// (model.Client.Slot), not from its position in clients[].
func (s *GreService) greAccountBlock(inbound *model.Inbound, settings *greSettings, accountSlot int) (string, int) {
	ranges := settings.effectiveRanges()
	k := wgcEffectiveK(settings.UserLimit)
	if k <= 1 {
		if ip := computeVpnClientIP(ranges, inbound.Id, accountSlot, "gre"); ip != nil {
			return ip.String(), 32
		}
		return "", 0
	}
	bs := nextPow2(k)
	subnets := pppSubnetsOrDefault(ranges, "gre", inbound.Id)
	subnet, hostBase, ok := vpnAccountBlock(subnets, accountSlot, bs)
	if !ok {
		return "", 0
	}
	return fmt.Sprintf("%s.%d", subnet, hostBase), 32 - log2i(bs)
}

// grePeerIPs returns the account's K inner tunnel addresses, in slot order. Peer d gets the
// d-th address of the account's block.
//
// This is what makes "User Limit K" mean K peer routers with no runtime enforcement to
// build: only K addresses exist, so the cap holds by construction. GRE offers no session
// and no auth event to evict on, so a structural limit is the only honest one.
func (s *GreService) grePeerIPs(inbound *model.Inbound, settings *greSettings, accountSlot int) []string {
	ranges := settings.effectiveRanges()
	k := wgcEffectiveK(settings.UserLimit)
	if k <= 1 {
		if ip := computeVpnClientIP(ranges, inbound.Id, accountSlot, "gre"); ip != nil {
			return []string{ip.String()}
		}
		return nil
	}
	base, _ := s.greAccountBlock(inbound, settings, accountSlot)
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

func (s *GreService) greAccountCIDR(inbound *model.Inbound, settings *greSettings, accountSlot int) string {
	ip, prefix := s.greAccountBlock(inbound, settings, accountSlot)
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("%s/%d", ip, prefix)
}

// GreNftView is what the nftables layer needs to know about one GRE inbound that it cannot
// derive from the address block alone.
//
// Both fields exist because GRE has NO cryptographic gate. Every other tunnel protocol here
// gets two properties for free from its handshake: a disabled account cannot bring a tunnel
// up at all, and a connected peer cannot source another peer's address. GRE gives neither,
// and the shared catch-all netdev accepts traffic from anyone, so withdrawing an account's
// route is not by itself enough to stop it being decapsulated and TPROXY'd. These two rule
// sets close that gap in the packet path.
type GreNftView struct {
	// Allowed maps each GRE netdev to the inner addresses that may legitimately be sourced
	// from it. For a point-to-point device that is exactly one address, which makes
	// anti-spoofing complete; for the catch-all it is the set of assigned dynamic addresses.
	Allowed map[string][]string
	// Blocked holds account CIDRs whose data path must be dropped outright: disabled,
	// expired or over quota.
	Blocked []string
}

// NftView computes the packet-path facts for one inbound, using the same plan the data
// plane builds so the two cannot drift.
func (s *GreService) NftView(inbound *model.Inbound, settings *greSettings) GreNftView {
	view := GreNftView{Allowed: map[string][]string{}}
	local := s.localIPFor(inbound)
	if local == nil {
		return view
	}
	cat := greCatName(local)
	disabled := s.disabledEmails()

	for i, client := range settings.Clients {
		if client.Email == "" {
			continue
		}
		slot := slotOr(client.Slot, i)
		if !client.Enable || disabled[client.Email] {
			if cidr := s.greAccountCIDR(inbound, settings, slot); cidr != "" {
				view.Blocked = append(view.Blocked, cidr)
			}
			continue
		}
		ips := s.grePeerIPs(inbound, settings, slot)
		for d, peer := range client.peerList() {
			if d >= len(ips) {
				break
			}
			if strings.TrimSpace(peer.PeerIp) != "" {
				name := greP2pName(inbound.Id, slot, d)
				view.Allowed[name] = append(view.Allowed[name], ips[d])
				continue
			}
			view.Allowed[cat] = append(view.Allowed[cat], ips[d])
		}
	}
	// The catch-all must appear even with no dynamic peers, so that an unassigned address
	// arriving on it is dropped rather than silently accepted.
	if _, ok := view.Allowed[cat]; !ok {
		view.Allowed[cat] = nil
	}
	return view
}

func (s *GreService) disabledEmails() map[string]bool {
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

// greGateway returns the inner gateway address of a block: the network address + 1, which
// is the address the customer points their tunnel at (their "Peer IP Address" on the inner
// side) and the source of our replies.
func greGateway(blockNet net.IP) net.IP {
	v4 := blockNet.To4()
	if v4 == nil {
		return nil
	}
	return net.IPv4(v4[0], v4[1], v4[2], v4[3]+1)
}

// localIPFor resolves the server address a GRE tunnel terminates on: the inbound's Listen
// when it names a concrete address, else the source address the kernel would use to reach
// the internet. GRE has no ports, so this address (not a port) is the tunnel's identity.
func (s *GreService) localIPFor(inbound *model.Inbound) net.IP {
	if l := strings.TrimSpace(inbound.Listen); l != "" && l != "0.0.0.0" && l != "::" {
		if ip := net.ParseIP(l); ip != nil && ip.To4() != nil {
			return ip.To4()
		}
	}
	return primaryV4Addr()
}

// primaryV4Addr asks the routing table which source address egresses to the internet.
func primaryV4Addr() net.IP {
	routes, err := netlink.RouteGet(net.IPv4(1, 1, 1, 1))
	if err != nil || len(routes) == 0 {
		return nil
	}
	for _, r := range routes {
		if r.Src != nil && r.Src.To4() != nil {
			return r.Src.To4()
		}
	}
	return nil
}

// grePlan is the desired kernel state for one reconcile pass, computed purely from DB state
// so that a tick is idempotent and a disabled account simply falls out of the plan.
type grePlan struct {
	links   map[string]bool            // every netdev we still want (prefix-scanned for staleness)
	cats    map[string]net.IP          // catch-all name -> its local address
	catMtu  map[string]int             // catch-all name -> smallest MTU any inbound on it asked for
	gws     map[string]map[string]bool // netdev -> inner gateway addrs it must hold
	routes  map[string]map[string]bool // netdev -> inner /32s routed out of it
	dynamic map[string]greDynamicPeer  // inner IP -> catch-all binding, for the learner
	fou     map[int]bool               // FOU udp ports to register
	live    []rbridge.Live             // sessions to publish (accounting attribution)
}

// greDynamicPeer is one address the learner is allowed to bind, and where.
type greDynamicPeer struct {
	Iface string
	Email string
}

func newGrePlan() *grePlan {
	return &grePlan{
		links:   map[string]bool{},
		cats:    map[string]net.IP{},
		catMtu:  map[string]int{},
		gws:     map[string]map[string]bool{},
		routes:  map[string]map[string]bool{},
		dynamic: map[string]greDynamicPeer{},
		fou:     map[int]bool{},
	}
}

func (p *grePlan) addGw(iface, addr string) {
	if p.gws[iface] == nil {
		p.gws[iface] = map[string]bool{}
	}
	p.gws[iface][addr] = true
}

func (p *grePlan) addRoute(iface, cidr string) {
	if p.routes[iface] == nil {
		p.routes[iface] = map[string]bool{}
	}
	p.routes[iface][cidr] = true
}

// InitGre brings GRE up on panel startup.
func (s *GreService) InitGre() {
	inbounds, err := s.GetGreInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}
	logger.Info("GRE: initializing services for", len(inbounds), "inbound(s)")
	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("GRE: failed to generate configs:", err)
		return
	}
	if err := s.SetupRouting(); err != nil {
		logger.Warning("GRE: failed to setup routing:", err)
	}
}

// GenerateAllConfigs reconciles every kernel GRE netdev, address, route and learner binding
// to DB state, the same hard-enforcement contract wg-c and awg use.
//
// Because it runs before every traffic sweep, a disabled/expired/over-quota account has NO
// data path by the time anything polls it: its point-to-point device is deleted and its
// route and learned neighbour entry are withdrawn. Verified against the kernel: removing
// the neighbour entry alone kills a catch-all-served account without touching any other.
func (s *GreService) GenerateAllConfigs() error {
	inbounds, err := s.GetGreInbounds()
	if err != nil {
		return err
	}

	plan := newGrePlan()
	if len(inbounds) > 0 {
		disabled := s.disabledEmails()
		for _, inbound := range inbounds {
			if !inbound.Enable {
				continue
			}
			settings, err := s.parseSettings(inbound)
			if err != nil {
				logger.Warning("GRE: skipping inbound", inbound.Id, err)
				continue
			}
			local := s.localIPFor(inbound)
			if local == nil {
				logger.Warning("GRE: inbound", inbound.Id, "has no usable local address")
				continue
			}
			s.planInbound(plan, inbound, settings, local, disabled)
		}
	}

	s.applyPlan(plan)
	s.publishDynamic(plan.dynamic)
	return nil
}

// planInbound adds one inbound's desired state to the plan.
func (s *GreService) planInbound(plan *grePlan, inbound *model.Inbound, settings *greSettings, local net.IP, disabled map[string]bool) {
	cat := greCatName(local)
	plan.cats[cat] = local
	plan.links[cat] = true

	// The inner gateway lives on the catch-all, which always exists, so point-to-point
	// devices can stay ADDRESS-LESS and carry nothing but a route. Verified: an address-less
	// p2p device works fine with the gateway held elsewhere.
	blockNet, _ := greBlockFor(inbound, settings)
	if gw := greGateway(blockNet); gw != nil {
		plan.addGw(cat, gw.String())
	}

	// One catch-all can serve SEVERAL inbounds, so take the SMALLEST MTU any of them asked
	// for: too small only costs efficiency, too large black-holes the constrained peer.
	if m := settings.effectiveMtu(); m > 0 {
		if cur, ok := plan.catMtu[cat]; !ok || m < cur {
			plan.catMtu[cat] = m
		}
	}

	if settings.FouEnable {
		plan.fou[settings.fouPort()] = true
	}
	// A dynamic peer cannot use FOU (see the note by greDefaultFouPort): it stays on the
	// raw catch-all, which is always present, so nothing breaks. Said once per inbound
	// rather than per peer so a large inbound does not flood the log.
	if settings.FouEnable {
		for _, client := range settings.Clients {
			dynamic := false
			for _, p := range client.peerList() {
				if strings.TrimSpace(p.PeerIp) == "" {
					dynamic = true
					break
				}
			}
			if dynamic {
				logger.Debug("GRE: inbound", inbound.Id,
					"has FOU enabled and dynamic peer slots; those peers are served over raw GRE")
				break
			}
		}
	}

	for i, client := range settings.Clients {
		if client.Email == "" || !client.Enable || disabled[client.Email] {
			continue
		}
		slot := slotOr(client.Slot, i)
		ips := s.grePeerIPs(inbound, settings, slot)
		acctCIDR := s.greAccountCIDR(inbound, settings, slot)
		for d, peer := range client.peerList() {
			if d >= len(ips) {
				break // more stored peers than the current User Limit allows
			}
			inner := ips[d]
			if p := strings.TrimSpace(peer.PeerIp); p != "" {
				remote := net.ParseIP(p)
				if remote == nil || remote.To4() == nil {
					logger.Warning("GRE: inbound", inbound.Id, "account", client.Email, "has an unparseable peer IP", p)
					continue
				}
				name := greP2pName(inbound.Id, slot, d)
				plan.links[name] = true
				plan.addRoute(name, inner+"/32")
				if err := s.ensureP2p(name, local, remote.To4(), settings); err != nil {
					logger.Warning("GRE: p2p device setup failed for", name, err)
					continue
				}
				plan.live = append(plan.live, rbridge.Live{
					Protocol: "gre", InboundID: inbound.Id, Email: client.Email,
					IP: acctCIDR, DeviceKey: name, Disabled: false,
					Since: s.recordFirstSeen(name, time.Now()),
				})
				continue
			}
			// Dynamic peer: served by the shared catch-all, reverse path learned.
			plan.addRoute(cat, inner+"/32")
			plan.dynamic[inner] = greDynamicPeer{Iface: cat, Email: client.Email}
			plan.live = append(plan.live, rbridge.Live{
				Protocol: "gre", InboundID: inbound.Id, Email: client.Email,
				IP: acctCIDR, DeviceKey: cat + "|" + inner, Disabled: false,
				Since: s.recordFirstSeen(cat+"|"+inner, time.Now()),
			})
		}
	}
}

// applyPlan creates/updates every planned device, then withdraws whatever is no longer
// wanted. Order matters: adding before removing means a peer that merely moved between two
// devices is never briefly dark.
func (s *GreService) applyPlan(plan *grePlan) {
	for name, local := range plan.cats {
		if err := s.ensureCatchAll(name, local, plan.catMtu[name]); err != nil {
			logger.Warning("GRE: catch-all setup failed for", name, err)
		}
	}
	for port := range plan.fou {
		if err := ensureFouPort(port); err != nil {
			logger.Warning("GRE: FOU port", port, "registration failed:", err)
		}
	}
	if len(plan.fou) > 0 {
		s.disableGroForFou()
	}
	s.reconcileFouPorts(plan.fou)
	for iface, addrs := range plan.gws {
		s.reconcileAddrs(iface, addrs)
	}
	for iface := range plan.links {
		s.reconcileRoutes(iface, plan.routes[iface])
	}
	// A catch-all's neighbour table is the learner's, but entries for addresses that are no
	// longer planned must go, or a disabled account keeps its reverse path.
	for name := range plan.cats {
		s.reconcileNeigh(name, plan.dynamic)
	}
	s.removeStaleLinks(plan.links)
}

// ensureP2p makes sure a point-to-point GRE netdev exists for one peer and is up.
func (s *GreService) ensureP2p(name string, local, remote net.IP, settings *greSettings) error {
	want := &netlink.Gretun{
		Local:    local,
		Remote:   remote,
		Ttl:      settings.ttl(),
		PMtuDisc: 1,
	}
	if settings.FouEnable {
		// Gretun.EncapType is a bare uint16 while netlink.FOU is a TunnelEncapType, so the
		// conversion is required.
		want.EncapType = uint16(netlink.FOU)
		want.EncapDport = uint16(settings.fouPort())
		want.EncapSport = 0 // "auto": the kernel picks, which is what a NATed peer needs
	}
	return s.ensureGretun(name, want, settings.effectiveMtu())
}

// ensureCatchAll makes sure the shared wildcard netdev for one local address exists and is
// up. Remote stays nil, which the kernel renders as `remote any`: one netdev that accepts
// GRE from ANY source address, demultiplexed on the inner address we assigned.
// The MTU matters more here than for a point-to-point device and was previously ignored
// (this passed 0, so an inbound's MTU setting had no effect on any DYNAMIC peer). GRE does not
// negotiate MTU, and path-MTU discovery through a tunnel is unreliable: the learned value sits
// in the route cache and expires, after which the kernel goes back to the device MTU and starts
// black-holing again. A device MTU that fits the customer's real path is the only stable fix,
// and on a constrained link (PPPoE, LTE) the 1476 default is too big. 0 keeps the kernel
// default, which is correct for an ordinary 1500-byte path.
func (s *GreService) ensureCatchAll(name string, local net.IP, mtu int) error {
	return s.ensureGretun(name, &netlink.Gretun{
		Local:    local,
		Ttl:      greDefaultTTL,
		PMtuDisc: 1,
	}, mtu)
}

// ensureGretun is the idempotent create-or-replace for a GRE netdev.
//
// PMtuDisc MUST be set explicitly by every caller. The netlink library sends
// IFLA_GRE_PMTUDISC unconditionally with no nil-guard, so a zero value does not mean
// "default", it means "PMTU discovery DISABLED", the opposite of the `ip` CLI's own default.
// Leaving it zero would silently break path-MTU discovery for every tunnel.
func (s *GreService) ensureGretun(name string, want *netlink.Gretun, mtu int) error {
	la := netlink.NewLinkAttrs()
	la.Name = name
	if mtu > 0 {
		la.MTU = mtu
	}
	want.LinkAttrs = la

	if existing, err := netlink.LinkByName(name); err == nil {
		// A device wearing one of our generated names that the manifest says was here
		// before us is the operator's, however improbable the collision. Refuse rather
		// than recreate it: the recreate path below is a LinkDel.
		if ownForbidsDelete(ownIface, name) {
			return fmt.Errorf("%s already exists and was not created by vpn-ui; not touching it", name)
		}
		// Recreate only when an addressing-relevant attribute actually changed, so an
		// unrelated edit never drops a live tunnel.
		if g, ok := existing.(*netlink.Gretun); ok && greTunEquivalent(g, want) {
			if mtu > 0 && existing.Attrs().MTU != mtu {
				_ = netlink.LinkSetMTU(existing, mtu)
			}
			return netlink.LinkSetUp(existing)
		}
		_ = netlink.LinkDel(existing)
	} else {
		// First sighting of this name: nothing there, so whatever we create next is
		// unambiguously ours. Recorded BEFORE the LinkAdd so a crash between the two
		// leaves an entry that says "ours" for a device that does not exist, which the
		// next sweep simply drops, rather than the reverse.
		ownIfaceCreated(name, "gre")
	}

	if err := netlink.LinkAdd(want); err != nil {
		if isNotSupported(err) {
			return fmt.Errorf("GRE kernel module unavailable (ip_gre): %w", err)
		}
		return err
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

// greTunEquivalent compares the attributes that define a tunnel's identity and data path.
func greTunEquivalent(a, b *netlink.Gretun) bool {
	return greIPEqual(a.Local, b.Local) &&
		greIPEqual(a.Remote, b.Remote) &&
		a.Ttl == b.Ttl &&
		a.IKey == b.IKey && a.OKey == b.OKey &&
		a.EncapType == b.EncapType && a.EncapDport == b.EncapDport
}

// greIPEqual compares two tunnel endpoints treating "absent" and "unspecified" as the same
// thing.
//
// This is load-bearing for the catch-all. We CONSTRUCT it with Remote nil (meaning
// `remote any`), but the kernel reads it back as 0.0.0.0, and net.IP.Equal(nil) is false. A
// plain Equal therefore reported the device as changed on EVERY reconcile tick, so
// ensureGretun deleted and recreated it about every ten seconds -- and recreating the netdev
// wipes its neighbour table, which is exactly where the learner stores every dynamic peer's
// reverse path. The visible effect was a dynamic peer whose tunnel came up, answered one
// ping, and then went dark, intermittently, while static peers (whose Remote round-trips
// correctly and so were never recreated) worked perfectly.
func greIPEqual(a, b net.IP) bool {
	aAny := a == nil || a.IsUnspecified()
	bAny := b == nil || b.IsUnspecified()
	if aAny || bAny {
		return aAny && bAny
	}
	return a.Equal(b)
}

// ensureFouPort registers a FOU receive port for GRE. Idempotent: an existing port comes
// back as EEXIST, which is success.
//
// The EEXIST branch is also the only cheap way to tell OUR listener from one the operator
// registered themselves, so ownership is decided right here: a clean add is ours, an add
// that bounced off an existing registration is not (unless we had already claimed it on an
// earlier run, in which case the first sighting stands). reconcileFouPorts then only
// unregisters what this recorded.
func ensureFouPort(port int) error {
	id := fouPortID(port)
	err := netlink.FouAdd(netlink.Fou{
		Port:     port,
		Protocol: unix.IPPROTO_GRE,
		Family:   unix.AF_INET,
		// EncapType is REQUIRED; omitting it sends FOU_ENCAP_UNSPEC and fails EINVAL.
		EncapType: netlink.FOU_ENCAP_DIRECT,
	})
	if err == nil {
		ownClaim(ownFouPort, id, "gre")
		return nil
	}
	if errIsExist(err) {
		ownNote(ownFouPort, id, "gre", "a FOU listener was already registered on this port")
		return nil
	}
	return err
}

// fouPortID is the manifest key for a FOU receive port.
func fouPortID(port int) string { return fmt.Sprintf("%d/gre", port) }

// reconcileFouPorts unregisters FOU receive ports no inbound asks for any more.
//
// Registration alone is a one-way door: turning FOU off, changing the port, or deleting the
// inbound used to leave the old UDP listener bound until the next reboot. Only ports that carry
// GRE are touched, so a FOU listener another service registered for a different inner protocol
// is left alone.
//
// And only ports WE registered: this used to unregister every GRE-carrying FOU port on the
// host that was not in our plan, which silently killed an operator's own fou listener the
// first time any GRE inbound reconciled. ensureFouPort records who registered what.
func (s *GreService) reconcileFouPorts(want map[int]bool) {
	have, err := netlink.FouList(unix.AF_INET)
	if err != nil {
		return // kernel without FOU support, or nothing registered: nothing to clean
	}
	for _, f := range have {
		if f.Protocol != unix.IPPROTO_GRE || want[f.Port] {
			continue
		}
		state, found := ownStateOf(ownFouPort, fouPortID(f.Port))
		if !found || !state.mayDelete() {
			continue // someone else's listener, or nobody knows whose: leave it bound
		}
		if err := netlink.FouDel(netlink.Fou{
			Port:     f.Port,
			Protocol: unix.IPPROTO_GRE,
			Family:   unix.AF_INET,
		}); err != nil {
			logger.Debug("GRE: could not unregister stale FOU port", f.Port, err)
			continue
		}
		ownRemoveEntry(ownFouPort, fouPortID(f.Port))
		logger.Info("GRE: unregistered stale FOU port", f.Port)
	}
}

// disableGroForFou turns GRO off on the interface that receives the FOU packets.
//
// This is not tuning, it is a correctness fix. Coalesced UDP is not decapsulated back into
// the individual GRE payloads correctly, so nearly every segment is lost while a trickle
// survives: the tunnel comes up, ping and small requests work, and any real transfer dies.
// Measured on a clean 1Gb Hetzner-to-Hetzner path with GRO left on, an offered 20MB upload
// delivered 557KB, and a 10MB download ran at 28 KB/s and never completed. With GRO off the
// same transfers ran at 11-14 MB/s and completed.
//
// There is no narrower knob: rx-gro-list and rx-udp-gro-forwarding are already off by default
// and turning them off explicitly changes nothing, and the GRO happens on the physical NIC
// before the packet reaches the tunnel device, so setting it on the GRE device cannot help.
// Only applied when an inbound actually enables FOU, and never turned back on WHILE THE CORE
// IS INSTALLED: an operator who wants it on has a reason, and re-enabling it mid-flight would
// silently break a working FOU peer.
//
// Uninstalling GRE is a different matter, and this used to be a genuinely one-way change to
// the host's NIC that nothing recorded and nothing put back. The previous setting is now
// captured in the ownership manifest the first time we turn it off, and restoreGro puts it
// back when the core goes.
func (s *GreService) disableGroForFou() {
	iface, err := greWanIface()
	if err != nil {
		logger.Warning("GRE: cannot find the WAN interface to disable GRO for FOU:", err)
		return
	}
	if _, found := ownStateOf(ownEthtool, groSettingID(iface)); !found {
		if prev := ethtoolFeature(iface, "generic-receive-offload"); prev != "" {
			ownClaimPrev(ownEthtool, groSettingID(iface), "gre", prev,
				"GRO turned off so FOU-encapsulated GRE is not coalesced")
		}
	}
	if err := s.runCmd("ethtool", "-K", iface, "gro", "off"); err != nil {
		// Not fatal, and worth saying out loud rather than leaving a peer to discover it as
		// mysterious packet loss.
		logger.Warning("GRE: could not disable GRO on", iface,
			"- FOU peers will see heavy loss until it is off:", err)
	}
}

// groSettingID is the manifest key for one interface's GRO setting.
func groSettingID(iface string) string { return iface + "/gro" }

// ethtoolFeature reads one offload feature's current state ("on"/"off"), or "" when ethtool
// is missing or does not report it. `ethtool -k` prints lines like
// "generic-receive-offload: on [fixed]"; the "[fixed]" suffix means the driver will not let
// it change, which is worth recording verbatim so a restore does not claim to have done
// something it could not.
func ethtoolFeature(iface, feature string) string {
	out, err := exec.Command("ethtool", "-k", iface).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) != feature {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return ""
		}
		return fields[0]
	}
	return ""
}

// restoreGro puts an interface's GRO setting back to what it was before FOU needed it off.
// Called from the GRE core's uninstall.
func restoreGro(iface, prev string) error {
	if prev != "on" && prev != "off" {
		return fmt.Errorf("no usable previous GRO setting (%q)", prev)
	}
	return exec.Command("ethtool", "-K", iface, "gro", prev).Run()
}

// greWanIface returns the interface the default route uses, i.e. the one FOU packets arrive on.
func greWanIface() (string, error) {
	routes, err := netlink.RouteGet(net.IPv4(1, 1, 1, 1))
	if err != nil || len(routes) == 0 {
		return "", fmt.Errorf("no route to the internet: %w", err)
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", err
	}
	return link.Attrs().Name, nil
}

// errIsExist treats "already registered" as success so a steady-state reconcile is silent.
// FouAdd reports an existing port as EADDRINUSE, not EEXIST, which is why both are here: the
// EEXIST-only version logged a spurious warning on every tick once FOU was enabled.
func errIsExist(err error) bool {
	if err == nil {
		return false
	}
	if err == unix.EEXIST || err == unix.EADDRINUSE {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "exists") || strings.Contains(s, "address already in use")
}

// reconcileAddrs makes iface hold exactly the wanted inner gateway addresses.
func (s *GreService) reconcileAddrs(iface string, wanted map[string]bool) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return
	}
	have, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return
	}
	present := map[string]bool{}
	for _, a := range have {
		key := a.IP.String()
		if wanted[key] {
			present[key] = true
			continue
		}
		_ = netlink.AddrDel(link, &a)
	}
	for addr := range wanted {
		if present[addr] {
			continue
		}
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		_ = netlink.AddrReplace(link, &netlink.Addr{
			IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		})
	}
}

// reconcileRoutes makes iface carry exactly the wanted inner /32 routes. A peer's route is
// the switch that turns its data path on: withdrawing it (plus its neighbour entry) is how
// a disabled account is cut off.
func (s *GreService) reconcileRoutes(iface string, wanted map[string]bool) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return
	}
	idx := link.Attrs().Index
	have, err := netlink.RouteList(link, unix.AF_INET)
	if err != nil {
		return
	}
	present := map[string]bool{}
	for _, r := range have {
		if r.Dst == nil {
			continue
		}
		key := r.Dst.String()
		if wanted[key] {
			present[key] = true
			continue
		}
		// Only withdraw host routes we could have installed; never touch the kernel's own
		// prefix routes for an address we added.
		if ones, bits := r.Dst.Mask.Size(); ones == 32 && bits == 32 {
			// Delete the object the KERNEL handed us, not a hand-built one. A
			// `netlink.Route{LinkIndex, Dst}` carries scope UNIVERSE and table 0, which does
			// not match a scope-link route, so the delete failed ESRCH on every tick --
			// silently, because the error was discarded. Withdrawal never happened at all:
			// stale host routes accumulated for every account whose addresses changed or
			// that was deleted while served by the shared catch-all. Verified against the
			// kernel: hand-built delete "no such process", kernel object nil.
			victim := r
			if err := netlink.RouteDel(&victim); err != nil {
				logger.Debugf("GRE: could not withdraw route %s from %s: %v", key, iface, err)
			}
		}
	}
	for cidr := range wanted {
		if present[cidr] {
			continue
		}
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		_ = netlink.RouteReplace(&netlink.Route{
			LinkIndex: idx,
			Dst:       dst,
			Scope:     netlink.SCOPE_LINK,
		})
	}
}

// reconcileNeigh drops learned reverse-path entries for addresses that are no longer
// planned dynamic peers. Adding entries is the learner's job; this only revokes.
func (s *GreService) reconcileNeigh(iface string, dynamic map[string]greDynamicPeer) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return
	}
	entries, err := netlink.NeighList(link.Attrs().Index, unix.AF_INET)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IP == nil {
			continue
		}
		if d, ok := dynamic[e.IP.String()]; ok && d.Iface == iface {
			continue
		}
		n := e
		_ = netlink.NeighDel(&n)
	}
}

// removeStaleLinks deletes every GRE netdev this service owns that is no longer wanted.
// `gre0` is the kernel's own fallback device (auto-created by ip_gre) and is deliberately
// left alone: we never created it, PPTP's module shares it, and deleting it is not ours to
// do.
//
// OWNERSHIP IS A NAME SHAPE, NOT A PREFIX. This used to delete any *netlink.Gretun whose
// name merely began with "gre", which is every hand-made tunnel an operator has: `ip tunnel
// add gre1 mode gre` matched, and since this sweep runs on panel start, on every inbound
// save and on every 10-second traffic tick, installing the GRE core silently destroyed the
// operator's own tunnel and kept destroying it. See greOwnsLink in ifaceown.go for the
// three gates that replaced the prefix.
func (s *GreService) removeStaleLinks(keep map[string]bool) {
	links, err := netlink.LinkList()
	if err != nil {
		return
	}
	for _, l := range links {
		name := l.Attrs().Name
		if keep[name] || !greOwnsLink(l) {
			continue
		}
		if err := netlink.LinkDel(l); err == nil {
			ownRemoveEntry(ownIface, name)
		}
	}
}

// publishDynamic hands the learner the current set of addresses it may bind, and starts it
// on first use. The learner is the ONLY component that writes neighbour entries.
func (s *GreService) publishDynamic(dynamic map[string]greDynamicPeer) {
	s.mu.Lock()
	if s.learner == nil {
		s.learner = newGreLearner()
	}
	l := s.learner
	s.mu.Unlock()
	l.SetPeers(dynamic)
}

// SetupRouting shares the fwmark policy route + nftables regeneration with the other VPN
// protocols. ip_gre is loaded for the netdevs and fou before any encap device is created,
// because a FOU LinkAdd against an unloaded module fails EINVAL rather than degrading.
func (s *GreService) SetupRouting() error {
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
	s.runCmd("modprobe", greModule)
	s.runCmd("modprobe", greFouModule)

	ensureVpnPolicyRoute(s.runCmd)

	// A GRE netdev is NOARP and the catch-all is fed by learned neighbour entries, so
	// strict reverse-path filtering on it would drop perfectly good customer traffic.
	for name := range s.currentIfaces() {
		s.runCmd("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", name))
	}

	if err := s.syncIpsec(); err != nil {
		logger.Warning("GRE: IPsec sync failed:", err)
	}
	return s.nftService.ApplyNftRules()
}

// currentIfaces lists the GRE netdevs this service owns right now.
//
// Same ownership rule as removeStaleLinks, and for the same reason in a quieter form:
// SetupRouting forces rp_filter=0 on everything this returns, so the old prefix scan
// silently relaxed reverse-path filtering on an operator's unrelated gre1.
func (s *GreService) currentIfaces() map[string]bool {
	out := map[string]bool{}
	links, err := netlink.LinkList()
	if err != nil {
		return out
	}
	for _, l := range links {
		if greOwnsLink(l) {
			out[l.Attrs().Name] = true
		}
	}
	return out
}

func (s *GreService) RestartServices() error {
	if err := s.GenerateAllConfigs(); err != nil {
		return err
	}
	return s.SetupRouting()
}

// StopServices tears down every GRE netdev and stops the learner.
func (s *GreService) StopServices() error {
	s.mu.Lock()
	l := s.learner
	s.mu.Unlock()
	if l != nil {
		l.Stop()
	}
	s.removeStaleLinks(map[string]bool{})
	return nil
}

// GreAvailable reports whether the in-kernel GRE data plane is usable.
func (s *GreService) GreAvailable() bool {
	if moduleAvailable(greModule) {
		return true
	}
	// ip_gre is frequently built straight into the kernel rather than as a module, in which
	// case there is no /sys/module entry to find but GRE works fine. The fallback device the
	// module registers is the reliable tell.
	_, err := netlink.LinkByName("gre0")
	return err == nil
}

// FouAvailable reports whether UDP-encapsulated GRE is usable on this host.
func (s *GreService) FouAvailable() bool { return moduleAvailable(greFouModule) }

// AnyInterfaceUp reports whether at least one GRE netdev of ours exists and is up.
//
// Ownership matters here too, in the opposite direction: with a prefix scan the operator's
// own gre1 made the panel report the GRE core as running on a host where it had never
// started a thing.
func (s *GreService) AnyInterfaceUp() bool {
	links, err := netlink.LinkList()
	if err != nil {
		return false
	}
	for _, l := range links {
		if greOwnsLink(l) && l.Attrs().Flags&net.FlagUp != 0 {
			return true
		}
	}
	return false
}

// GrePeerConfig is one peer slot rendered for the panel: everything the customer has to
// type into their router, plus the mode they must use.
type GrePeerConfig struct {
	PeerIndex int    `json:"peerIndex"`
	Remark    string `json:"remark"`
	PeerIp    string `json:"peerIp"`
	Dynamic   bool   `json:"dynamic"`
	ServerIp  string `json:"serverIp"`
	InnerIp   string `json:"innerIp"`
	InnerMask string `json:"innerMask"`
	GatewayIp string `json:"gatewayIp"`
	Mtu       int    `json:"mtu"`
	Mode      string `json:"mode"`
	IpsecPsk  string `json:"ipsecPsk"`
	// IpsecId is the identity the peer must present as the SERVER's id. Required on a
	// shared charon: without it charon cannot tell which pre-shared key to use. See greIkeID.
	IpsecId string `json:"ipsecId"`
	FouPort int    `json:"fouPort"`
	// Config is the whole recipe (values + both platforms) and is what the subscription
	// hands out as a .txt. The panel instead shows the two platform recipes separately,
	// because a customer runs one of them, never both, and a single blob invites pasting
	// RouterOS syntax into a Linux shell.
	Config         string `json:"config"`
	ConfigMikrotik string `json:"configMikrotik"`
	ConfigLinux    string `json:"configLinux"`
}

// RenderPeerConfigs returns the router-side setup for every peer slot of an account.
//
// There is no config FILE to hand out and no QR to scan: GRE's client is a router, and the
// deliverable is the handful of values its web UI asks for. The rendered text is a
// copy-pasteable RouterOS recipe plus the same values in neutral form, because MikroTik is
// the dominant device here and every other platform asks for the same four fields.
func (s *GreService) RenderPeerConfigs(inbound *model.Inbound, email, endpointHost string) ([]GrePeerConfig, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return nil, err
	}
	server := endpointHost
	if ip := s.localIPFor(inbound); ip != nil {
		server = ip.String()
	}
	blockNet, _ := greBlockFor(inbound, settings)
	gw := greGateway(blockNet)
	gwStr := ""
	if gw != nil {
		gwStr = gw.String()
	}

	mode := "raw"
	switch {
	case settings.IpsecEnable && settings.AllowRaw:
		mode = "ipsec-or-raw"
	case settings.IpsecEnable:
		mode = "ipsec"
	}

	var out []GrePeerConfig
	for i, client := range settings.Clients {
		if client.Email != email {
			continue
		}
		slot := slotOr(client.Slot, i)
		ips := s.grePeerIPs(inbound, settings, slot)
		for d, peer := range client.peerList() {
			if d >= len(ips) {
				break
			}
			cfg := GrePeerConfig{
				PeerIndex: d,
				Remark:    strings.TrimSpace(peer.Remark),
				PeerIp:    strings.TrimSpace(peer.PeerIp),
				Dynamic:   strings.TrimSpace(peer.PeerIp) == "",
				ServerIp:  server,
				InnerIp:   ips[d],
				InnerMask: "255.255.255.255",
				GatewayIp: gwStr,
				Mtu:       settings.effectiveMtu(),
				Mode:      mode,
			}
			if settings.IpsecEnable {
				cfg.IpsecPsk = settings.IpsecPsk
				// The peer must present this as the server's identity, or charon cannot
				// tell which pre-shared key to use on a shared daemon.
				cfg.IpsecId = greIkeID(inbound.Id)
			}
			// FOU only for a PINNED peer. A dynamic peer is served by the shared raw
			// catch-all (see the note by greDefaultFouPort), so handing it a FOU port
			// would tell the customer to configure an encapsulation this server will
			// never speak back to them -- a tunnel that comes up and then carries
			// nothing, which is the hardest kind of failure to diagnose.
			if settings.FouEnable && !cfg.Dynamic {
				cfg.FouPort = settings.fouPort()
			}
			multi := len(client.peerList()) > 1
			cfg.Config = renderGreRecipe(cfg, multi, d)
			cfg.ConfigMikrotik = renderGreMikrotik(cfg, multi, d)
			cfg.ConfigLinux = renderGreLinux(cfg, multi, d)
			out = append(out, cfg)
		}
		break
	}
	return out, nil
}

// renderGreRecipe renders the router-side instructions for one peer slot.
func renderGreRecipe(c GrePeerConfig, multi bool, idx int) string {
	var b strings.Builder
	if multi {
		b.WriteString(fmt.Sprintf("# Peer %d\n", idx+1))
	}
	b.WriteString("# GRE tunnel settings for your router\n")
	b.WriteString(fmt.Sprintf("Remote / Peer IP Address : %s\n", c.ServerIp))
	if c.Dynamic {
		b.WriteString("Local / Your public IP   : (any - this peer is not pinned)\n")
	} else {
		b.WriteString(fmt.Sprintf("Local / Your public IP   : %s\n", c.PeerIp))
	}
	b.WriteString(fmt.Sprintf("Local Tunnel Address     : %s\n", c.InnerIp))
	b.WriteString(fmt.Sprintf("Local Tunnel Netmask     : %s\n", c.InnerMask))
	b.WriteString(fmt.Sprintf("Remote Tunnel Address    : %s\n", c.GatewayIp))
	b.WriteString(fmt.Sprintf("Route all traffic        : default via %s\n", c.GatewayIp))
	if c.Mtu > 0 {
		b.WriteString(fmt.Sprintf("MTU                      : %d\n", c.Mtu))
	}
	switch c.Mode {
	case "ipsec":
		b.WriteString("Encryption               : IPsec REQUIRED (bare GRE is dropped)\n")
	case "ipsec-or-raw":
		b.WriteString("Encryption               : IPsec optional (bare GRE also accepted)\n")
	default:
		b.WriteString("Encryption               : none (bare GRE)\n")
	}
	if c.IpsecPsk != "" {
		b.WriteString(fmt.Sprintf("IPsec pre-shared key     : %s\n", c.IpsecPsk))
		b.WriteString(fmt.Sprintf("IPsec remote identity    : %s\n", c.IpsecId))
	}
	if c.FouPort > 0 {
		b.WriteString(fmt.Sprintf("FOU (UDP encap) port     : %d  [Linux/OpenWrt peers only]\n", c.FouPort))
	}

	b.WriteString("\n")
	b.WriteString(greOuterRouteNote(c, "Both recipes below add that host route FIRST."))

	b.WriteString("\n# MikroTik RouterOS\n")
	b.WriteString(greMikrotikCommands(c))
	b.WriteString("\n# Linux (iproute2)\n")
	b.WriteString(greLinuxCommands(c))
	return b.String()
}

// renderGreMikrotik is the RouterOS half on its own: the panel shows one recipe per
// platform, so each has to carry the routing warning and stand alone.
func renderGreMikrotik(c GrePeerConfig, multi bool, idx int) string {
	var b strings.Builder
	if multi {
		b.WriteString(fmt.Sprintf("# Peer %d\n", idx+1))
	}
	b.WriteString(greOuterRouteNote(c, "The commands below add that host route FIRST."))
	b.WriteString("\n")
	b.WriteString(greMikrotikCommands(c))
	return b.String()
}

// renderGreLinux is the iproute2 half on its own. See renderGreMikrotik.
func renderGreLinux(c GrePeerConfig, multi bool, idx int) string {
	var b strings.Builder
	if multi {
		b.WriteString(fmt.Sprintf("# Peer %d\n", idx+1))
	}
	b.WriteString(greOuterRouteNote(c, "The commands below add that host route FIRST."))
	b.WriteString("\n")
	b.WriteString(greLinuxCommands(c))
	return b.String()
}

// greOuterRouteNote is the warning that has to precede every recipe: it prevents the one
// failure the customer cannot debug, where the default route swallows the tunnel's own
// outer packets and takes their internet down with the tunnel.
func greOuterRouteNote(c GrePeerConfig, closing string) string {
	return "# IMPORTANT, read before you route all traffic through this tunnel.\n" +
		"# The tunnel's OWN packets travel to the server over your normal internet\n" +
		"# connection. If you point the default route at the tunnel without first\n" +
		fmt.Sprintf("# pinning a host route to %s via your existing gateway, those\n", c.ServerIp) +
		"# packets try to travel through the tunnel itself. That loop takes the tunnel\n" +
		"# down and, because the default route now points into it, your internet with\n" +
		"# it. " + closing + "\n"
}

// greMikrotikCommands is the bare RouterOS recipe, no heading. The MTU is written out
// explicitly because the two recipes are shown on their own now, away from the settings
// block that used to carry it, and GRE never negotiates it.
func greMikrotikCommands(c GrePeerConfig) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("/interface gre add name=gre-vpnui remote-address=%s", c.ServerIp))
	if !c.Dynamic {
		b.WriteString(fmt.Sprintf(" local-address=%s", c.PeerIp))
	}
	if c.Mtu > 0 {
		b.WriteString(fmt.Sprintf(" mtu=%d", c.Mtu))
	}
	b.WriteString(" clamp-tcp-mss=yes keepalive=10s,10\n")
	b.WriteString(fmt.Sprintf("/ip address add address=%s/32 interface=gre-vpnui\n", c.InnerIp))
	b.WriteString(fmt.Sprintf("# Keep the tunnel's own traffic on the physical link (replace ISP-GATEWAY\n"+
		"# with the gateway from /ip route print, the one you use today for 0.0.0.0/0):\n"+
		"/ip route add dst-address=%s/32 gateway=ISP-GATEWAY comment=\"gre outer, do not tunnel\"\n",
		c.ServerIp))
	b.WriteString(fmt.Sprintf("/ip route add dst-address=0.0.0.0/0 gateway=%s\n", c.GatewayIp))
	if c.IpsecPsk != "" {
		b.WriteString(fmt.Sprintf("/ip ipsec peer add address=%s/32 exchange-mode=ike2\n", c.ServerIp))
		b.WriteString(fmt.Sprintf(
			"/ip ipsec identity add peer=%s secret=\"%s\" remote-id=fqdn:%s\n",
			c.ServerIp, c.IpsecPsk, c.IpsecId))
		b.WriteString(fmt.Sprintf("/ip ipsec policy add src-address=%s/32 dst-address=%s/32 protocol=gre tunnel=no action=encrypt\n",
			firstNonEmpty(c.PeerIp, "YOUR-PUBLIC-IP"), c.ServerIp))
	}
	if c.FouPort > 0 {
		b.WriteString("# NOTE: RouterOS has no FOU support. Use the Linux recipe on a peer\n" +
			"# that needs UDP encapsulation.\n")
	}
	return b.String()
}

// greLinuxCommands is the bare iproute2 recipe, no heading. See greMikrotikCommands on the
// explicit MTU.
func greLinuxCommands(c GrePeerConfig) string {
	var b strings.Builder
	dev := "gre-vpnui"
	if c.FouPort > 0 {
		b.WriteString(fmt.Sprintf("ip fou add port %d ipproto 47\n", c.FouPort))
		b.WriteString(fmt.Sprintf("ip link add %s type gre remote %s ttl 64 encap fou encap-sport auto encap-dport %d\n",
			dev, c.ServerIp, c.FouPort))
		// GRO must be off on the interface that RECEIVES the FOU packets. Measured on a
		// clean 1Gb path: with GRO on, a 10MB download ran at 28 KB/s and never finished;
		// with it off, 11 MB/s. Coalesced UDP is not decapsulated correctly, so almost
		// every segment is lost while a trickle survives -- the tunnel looks up and small
		// requests work. There is no narrower knob: rx-gro-list and
		// rx-udp-gro-forwarding are already off and make no difference.
		b.WriteString("ethtool -K $(ip route show default | awk '{print $5; exit}') gro off" +
			"   # REQUIRED for FOU, coalesced UDP is not decapsulated correctly\n")
	} else {
		b.WriteString(fmt.Sprintf("ip link add %s type gre remote %s ttl 64\n", dev, c.ServerIp))
	}
	b.WriteString(fmt.Sprintf("ip addr add %s/32 dev %s\n", c.InnerIp, dev))
	if c.Mtu > 0 {
		b.WriteString(fmt.Sprintf("ip link set %s mtu %d\n", dev, c.Mtu))
	}
	b.WriteString(fmt.Sprintf("ip link set %s up\n", dev))
	// Computed rather than a placeholder: the client can read its current gateway itself, so
	// this block stays copy-pasteable and cannot be pasted in the wrong order.
	b.WriteString(fmt.Sprintf("GW=$(ip route show default | awk '{print $3; exit}'); " +
		"DEV=$(ip route show default | awk '{print $5; exit}')\n"))
	b.WriteString(fmt.Sprintf("ip route add %s/32 via $GW dev $DEV   # gre outer, do not tunnel\n", c.ServerIp))
	b.WriteString(fmt.Sprintf("ip route replace default dev %s\n", dev))
	return b.String()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ReconcilePeers sizes each account's peer array to the inbound's User Limit, operating on
// raw JSON so unknown UI fields survive. Returns whether inbound.Settings changed.
//
// Unlike the WireGuard family there is no key material to mint: a peer slot holds only the
// customer's public IP, and an empty one is meaningful (a dynamic peer). Growing is
// therefore additive and harmless; shrinking revokes the surplus slots, which is what makes
// lowering the User Limit actually reduce the number of routers that can attach.
func (s *GreService) ReconcilePeers(inbound *model.Inbound) (bool, error) {
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

	// Turning IPsec on without a key would load a charon connection nothing can authenticate
	// against, so mint one here rather than leaving the operator to notice.
	settings := &greSettings{}
	if json.Unmarshal([]byte(inbound.Settings), settings) == nil {
		if settings.IpsecEnable && strings.TrimSpace(settings.IpsecPsk) == "" {
			setRawString(raw, "ipsecPsk", randomPsk())
			changed = true
		}
	}

	var clients []map[string]json.RawMessage
	if cb, ok := raw["clients"]; ok {
		_ = json.Unmarshal(cb, &clients)
	}
	k := wgcEffectiveK(userLimitPtrFromRaw(raw))
	for _, c := range clients {
		var peers []map[string]json.RawMessage
		if pb, ok := c["peers"]; ok {
			_ = json.Unmarshal(pb, &peers)
		}
		for len(peers) < k {
			peers = append(peers, map[string]json.RawMessage{})
			changed = true
		}
		if len(peers) > k {
			peers = peers[:k]
			changed = true
		}
		pb, _ := json.Marshal(peers)
		c["peers"] = pb
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

func (s *GreService) ReconcileAllPeers() bool {
	db := database.GetDB()
	if db == nil {
		return false
	}
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ?", "gre").Find(&inbounds).Error; err != nil {
		return false
	}
	any := false
	for _, ib := range inbounds {
		changed, err := s.ReconcilePeers(ib)
		if err != nil {
			logger.Warningf("GRE: peer reconcile failed for inbound %d: %v", ib.Id, err)
			continue
		}
		if changed {
			if err := db.Model(&model.Inbound{}).Where("id = ?", ib.Id).Update("settings", ib.Settings).Error; err != nil {
				logger.Warningf("GRE: persist peers failed for inbound %d: %v", ib.Id, err)
			} else {
				any = true
			}
		}
	}
	return any
}

// ---- rbridge.Adapter -------------------------------------------------------------------
//
// GRE has no session, no handshake and no auth event, so "live" means "this peer slot is
// plumbed": it has a data path right now because GenerateAllConfigs built one from DB state.
// That is what the session registry needs in order to attribute bytes to an account, and it
// is what makes traffic accounting, quota, the traffic multiplier and per-account speed
// limits work through the existing email-keyed machinery.
//
// The User Limit is enforced STRUCTURALLY (an account owns exactly K addresses, so only K
// peers can ever be plumbed), which means the Sweeper's eviction path should never fire
// here. Evict is implemented anyway, because the Sweeper also uses it to enforce a disable
// that lands mid-tick.
var _ rbridge.Adapter = (*GreService)(nil)

func (s *GreService) Protocol() string { return "gre" }

func (s *GreService) Poll() ([]rbridge.Live, error) {
	inbounds, err := s.GetGreInbounds()
	if err != nil {
		return nil, err
	}
	if len(inbounds) == 0 {
		return nil, nil
	}
	disabled := s.disabledEmails()
	present := s.currentIfaces()

	now := time.Now()
	seen := map[string]bool{}
	var live []rbridge.Live
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		local := s.localIPFor(inbound)
		if local == nil {
			continue
		}
		cat := greCatName(local)
		bound := s.boundInner(cat)
		for i, client := range settings.Clients {
			if client.Email == "" || !client.Enable || disabled[client.Email] {
				continue
			}
			slot := slotOr(client.Slot, i)
			ips := s.grePeerIPs(inbound, settings, slot)
			acctCIDR := s.greAccountCIDR(inbound, settings, slot)
			if acctCIDR == "" {
				continue
			}
			for d, peer := range client.peerList() {
				if d >= len(ips) {
					break
				}
				var dk string
				if strings.TrimSpace(peer.PeerIp) != "" {
					name := greP2pName(inbound.Id, slot, d)
					if !present[name] {
						continue // no device yet, so no data path to bill
					}
					dk = name
				} else {
					if !bound[ips[d]] {
						continue // the customer has never been seen, so nothing is plumbed
					}
					dk = cat + "|" + ips[d]
				}
				seen[dk] = true
				live = append(live, rbridge.Live{
					Protocol:  "gre",
					InboundID: inbound.Id,
					Email:     client.Email,
					IP:        acctCIDR,
					DeviceKey: dk,
					Disabled:  false,
					Since:     s.recordFirstSeen(dk, now),
				})
			}
		}
	}
	s.pruneFirstSeen(seen)
	return live, nil
}

// boundInner returns the inner addresses on iface that currently have a learned reverse
// path, i.e. the dynamic peers that have actually shown up.
func (s *GreService) boundInner(iface string) map[string]bool {
	out := map[string]bool{}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return out
	}
	entries, err := netlink.NeighList(link.Attrs().Index, unix.AF_INET)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IP != nil && greNeighOuter(e) != nil {
			out[e.IP.String()] = true
		}
	}
	return out
}

// greNeighOuter returns the OUTER address a neighbour entry maps an inner address to, or nil
// when the entry carries no usable link address.
//
// BOTH fields have to be read. When the link address is 4 bytes -- which is always, for a GRE
// device, where "lladdr" IS an IPv4 address -- netlink stores it in LLIPAddr (a field it
// documents as "Used in the case of NHRP", precisely this mapping) and leaves HardwareAddr
// EMPTY. Checking only HardwareAddr reported every learned peer as unbound, and that is worse
// than it sounds: Poll() gates dynamic peers on this, so they never entered the session
// registry, never got an nft accounting counter, and their traffic was neither billed nor
// counted against quota. Nothing looked broken, because writing the entry uses a different
// field and the tunnel itself worked perfectly.
func greNeighOuter(n netlink.Neigh) net.IP {
	if ip := n.LLIPAddr; ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
	}
	if len(n.HardwareAddr) == net.IPv4len {
		return net.IP(n.HardwareAddr).To4()
	}
	return nil
}

func (s *GreService) Limit(inboundID int) (int, string) {
	inbounds, err := s.GetGreInbounds()
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

// Evict withdraws one peer's data path. For a point-to-point peer that is the netdev; for a
// catch-all peer it is the learned neighbour entry, which the kernel needs in order to
// reach the customer at all.
func (s *GreService) Evict(l rbridge.Live) error {
	iface, inner, isCat := strings.Cut(l.DeviceKey, "|")
	if !isCat {
		link, err := netlink.LinkByName(l.DeviceKey)
		if err != nil {
			return nil // already gone
		}
		return netlink.LinkDel(link)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(inner)
	if ip == nil {
		return fmt.Errorf("gre: malformed device key %q", l.DeviceKey)
	}
	s.mu.Lock()
	lr := s.learner
	s.mu.Unlock()
	if lr != nil {
		lr.Forget(inner)
	}
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		Family:    unix.AF_INET,
		IP:        ip,
	})
}

func (s *GreService) recordFirstSeen(key string, now time.Time) time.Time {
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

func (s *GreService) pruneFirstSeen(seen map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.firstSeen {
		if !seen[k] {
			delete(s.firstSeen, k)
		}
	}
}

func (s *GreService) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("GRE: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
