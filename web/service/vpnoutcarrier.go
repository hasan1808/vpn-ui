package service

import (
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strings"

	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/json_util"
	"github.com/hasan1808/pro-ui/xray"

	"github.com/goccy/go-json"
	"github.com/vishvananda/netlink"
)

// Carrying a tunnel through an XRAY OUTBOUND, rather than only through another
// tunnel.
//
// vpnoutvia.go carries one tunnel inside another by policy-routing its outer
// transport into the carrier's netdev. That mechanism is not changed here and does
// not need to be: it is L4-agnostic, it asks nothing of the nine client daemons, and
// it is the only thing that works for charon's kernel ESP. What this file adds is the
// answer to one question it could not previously answer -
//
//	given an outbound TAG, which device do I steer into?
//
// because a vless, a vmess, a trojan or a socks outbound has no device at all. It
// answers in three ways, in order of how little they cost:
//
//	the tag is a VPN tunnel            -> its own netdev            (vpnoutvia.go, today)
//	the tag is freedom + an iface pin  -> the pinned device         (it already IS a device)
//	the tag is anything else           -> a CARRIER TUN, below
//
// and refuses the shapes that cannot mean anything (see vpnOutCarrierFor).
//
// # The carrier tun
//
// The bundled core registers `tun` as an INBOUND (infra/conf/xray.go). On Linux it
// opens /dev/net/tun with IFF_TUN|IFF_NO_PI, sets the MTU, brings the link up, and
// assigns NO addresses: proxy/tun/README.md says explicitly that OS-level
// configuration of the interface is the caller's job. That is exactly the division
// this panel already has, because vpnOutBindEgress does precisely that job for every
// tunnel. So a tun inbound tagged and routed to one outbound is a DEVICE whose
// traffic leaves through that outbound, and every existing steer rule works on it
// unchanged.
//
// Measured on this core (26.4.17), 2026-08-12, both directions:
//
//   - A tun inbound plus `{"inboundTag":["carrier-x"],"outboundTag":"x"}`, with an
//     ordinary `ip rule to <dest> lookup <table>` and `default dev <tun>` in that
//     table, carried both UDP and TCP to a real server and back, with the client
//     unaware. The core logged `from udp:10.77.0.1:34564 accepted udp:...:53
//     [carrier-tun -> direct]`.
//   - THE PANEL OWNS THE DEVICE. Creating it first as a persistent tuntap and letting
//     the core attach kept the SAME ifindex, and the device SURVIVED the core exiting
//     (it only goes DOWN). That is what makes this safe to build on: the table id is
//     vpnOutRouteTableBase+ifindex, so an ifindex that moved every time Xray restarted
//     would strand every rule pointing into it.
//
// The device going DOWN when Xray stops is not a gap, it is the fail-closed path
// arriving for free: a down device drops its route out of the table, and the
// `blackhole default metric 1000` that vpnOutEgressRoutes already parks in every
// tunnel table is then what the steer rule finds. Xray down means the carried tunnel
// is BLACKHOLED, not leaked out of the host's WAN.
//
// # What a carrier tun cannot carry
//
// Measured: TCP and UDP only. ICMP is dropped (ping through it: 100% loss, and the
// core's README says "No ICMP support"), and so is every raw IP protocol - GRE (47)
// and ESP (50) among them. A device carrier has no such limit, which is why the two
// are kept as distinct kinds rather than collapsed: the refusals differ, and telling
// an operator "pptp cannot be carried" would be false for the carrier they already
// have working.
//
// vpnOutCarrierRefusal is where that lands, per carried kind, and the drivers that
// can answer only for themselves do so through VpnOutCarriable.

const (
	// vpnOutCarrierDevPrefix starts every carrier tun's device name. The rest is 8 hex
	// of the carrier tag's hash, which keeps the whole name at 12 characters - inside
	// IFNAMSIZ (15) with room to spare - and makes it deterministic, so the device a
	// tag gets today is the device it gets after a reboot.
	//
	// Derived from the tag rather than allocated in sequence on purpose: a sequence
	// renumbers every device after the one an operator deletes, and each renumber
	// moves a device, an address and a routing table for tunnels that were not
	// touched.
	vpnOutCarrierDevPrefix = "xcar"

	// vpnOutCarrierTagPrefix names the synthesized tun inbound for a carrier. It is
	// only ever seen in the Xray config and the core's own log lines.
	vpnOutCarrierTagPrefix = "carrier-"

	// vpnOutCarrierNet is the second octet of the /16 carrier devices are addressed
	// out of: 10.11.<slot>.1/30.
	//
	// INSIDE vpnAddrSpace (10.0.0.0/12) deliberately, so a carrier device inherits the
	// firewalld trust and the routing blackhole backstop that every VPN address
	// already has. nftables.go documents bases 10-15 as spare, and 10.10 is taken by
	// wgxray, so carriers take 11.
	vpnOutCarrierNet = 11

	// vpnOutCarrierSlots is how many carrier devices can exist at once, one per /30 in
	// the /16. Far beyond any real panel; the cap exists so the slot arithmetic has an
	// end rather than wrapping silently onto another carrier's address.
	vpnOutCarrierSlots = 250

	// vpnOutCarrierMTU is the carrier tun's MTU.
	//
	// This is NOT a path MTU. Nothing on the wire has to fit it: the core terminates
	// what enters the device and re-originates it as its own connection through the
	// carrier outbound, so this only bounds how large a single datagram may be when it
	// ENTERS the stack. 1500 takes every tunnel's outer packet whole - a WireGuard
	// datagram is ~1420 with its header - and leaves the kernel to fragment anything
	// larger, which the gvisor stack reassembles.
	vpnOutCarrierMTU = 1500
)

// vpnOutCarrierKind is how a carrier's device was arrived at. It is the difference
// between "this carrier can take anything" and "this carrier can take TCP and UDP",
// so it travels with the carrier rather than being re-derived where it is needed.
type vpnOutCarrierKind int

const (
	// vpnOutCarrierTunnel is another VPN tunnel on this panel. L4-agnostic.
	vpnOutCarrierTunnel vpnOutCarrierKind = iota + 1
	// vpnOutCarrierPinned is a freedom outbound with sockopt.interface set: already a
	// device, so also L4-agnostic. Nothing is synthesized for it.
	vpnOutCarrierPinned
	// vpnOutCarrierBridged is any other outbound, reached through a carrier tun.
	// TCP and UDP only.
	vpnOutCarrierBridged
)

// vpnOutCarrier is one resolved carrier: a tag, and the device to steer into.
type vpnOutCarrier struct {
	Tag   string
	Kind  vpnOutCarrierKind
	Iface string

	// Addr is the carrier tun's own address, "10.11.<slot>.1/30", and is set only for
	// vpnOutCarrierBridged.
	//
	// A device needs one because a socket that has not bound a source of its own gets
	// its source from the route, and a route out of a device with no address cannot
	// supply one. The /30 is per carrier so two of them can never claim one address.
	Addr string
	Slot int

	// Uplink is every address that must NEVER be steered into this carrier: for a
	// bridged carrier, the addresses the carrier outbound itself dials. Steering one
	// of those into the carrier's own tun is the loop the core's README warns about,
	// and vpnoutvia.go's exclusion band is where these end up.
	Uplink []string
}

// Bridged reports whether this carrier needs a synthesized tun and can only take TCP
// and UDP.
func (c vpnOutCarrier) Bridged() bool { return c.Kind == vpnOutCarrierBridged }

// vpnOutCarrierFor resolves one carrier tag against the panel's tunnels and the
// operator's outbound list.
//
// PURE, and takes the outbound list rather than reading it, for the same reason
// applyVpnOutboundsWith's tunnel list is an argument: every refusal below is a
// sentence an operator will read, and they are worth testing without a database.
//
// `obs` is the outbound template as stored, parsed. `sshTags` are the SSH tunnels,
// which are a socks outbound aimed at a loopback port by the time the core sees them
// (applySshOutboundsWith) but may not be in the template at all yet.
func vpnOutCarrierFor(tag string, tunnels []VpnOutboundConfig, sshTags []string,
	obs []map[string]any) (vpnOutCarrier, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return vpnOutCarrier{}, nil
	}

	// A VPN tunnel first, and before the outbound list, because a tunnel HAS a row in
	// that list: applyVpnOutboundsWith writes it as a freedom outbound pinned to the
	// tunnel's device. Reading it as a pinned outbound instead would work by accident
	// today and break the moment a tunnel is down, when the same row is a blackhole.
	if t, ok := findVpnTunnel(tunnels, tag); ok {
		if !t.Enable {
			return vpnOutCarrier{}, fmt.Errorf("the %q tunnel is switched off, so it cannot carry anything", tag)
		}
		if t.Iface == "" {
			return vpnOutCarrier{}, fmt.Errorf("the %q tunnel has no network device, so it never came up", tag)
		}
		return vpnOutCarrier{Tag: tag, Kind: vpnOutCarrierTunnel, Iface: t.Iface}, nil
	}

	// An SSH tunnel is a socks outbound onto a loopback port, so it is bridged like any
	// other proxy. Its uplink is 127.0.0.1, which is never a tunnel's server address,
	// so there is nothing to exclude.
	for _, s := range sshTags {
		if s == tag {
			return vpnOutCarrier{Tag: tag, Kind: vpnOutCarrierBridged,
				Iface: vpnOutCarrierDev(tag)}, nil
		}
	}

	ob := vpnOutFindOutbound(obs, tag)
	if ob == nil {
		// The second half of this sentence is not padding. The outbound list this reads
		// is the SAVED template, and the tunnel modal offers every tag the PAGE holds,
		// so an operator who adds an outbound and names it as a carrier in the same
		// sitting lands here with a tag they can see on screen. Saying only "unknown
		// tag" would read as a bug in the panel.
		return vpnOutCarrier{}, fmt.Errorf("%q is not a tunnel and not a saved outbound on this panel; "+
			"if you have just added it, save the Xray page first so the carrier exists before something rides on it", tag)
	}
	protocol, _ := ob["protocol"].(string)
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "freedom":
		// A freedom outbound with an interface pin IS a device, and the cheapest
		// carrier there is: steer into it and the packets leave exactly where that
		// outbound's own traffic leaves. Nothing is synthesized.
		if pin := vpnOutOutboundPin(ob); pin != "" {
			if vpnOutIfaceGone(pin) {
				return vpnOutCarrier{}, fmt.Errorf("the %q outbound is pinned to device %q, which is not on this host", tag, pin)
			}
			return vpnOutCarrier{Tag: tag, Kind: vpnOutCarrierPinned, Iface: pin}, nil
		}
		// sendThrough names a SOURCE ADDRESS, and an address belongs to a device, so a
		// freedom outbound that has one is also naming an egress and can carry. The
		// device is looked up rather than assumed, because the two ways this can be
		// wrong are both silent: an address that is on no device at all still binds
		// (the kernel only checks that the host owns it) and then leaves from the
		// wrong place, and an address that moved takes the carry with it.
		//
		// What is steered is the DEVICE holding the address, not the address itself.
		// For the ordinary case, a host with one address per device, those are the
		// same answer. On a device carrying several, the carried tunnel leaves through
		// the right device with the kernel's own choice of source rather than the one
		// this outbound would have used for its own traffic, and that is worth knowing
		// before an operator reads too much into it.
		if through, _ := ob["sendThrough"].(string); strings.TrimSpace(through) != "" {
			dev := vpnOutDevWithAddr(through)
			if dev == "" {
				return vpnOutCarrier{}, fmt.Errorf("the %q outbound sends through %s, which is not an address on any "+
					"device of this host, so there is nothing to steer into", tag, strings.TrimSpace(through))
			}
			return vpnOutCarrier{Tag: tag, Kind: vpnOutCarrierPinned, Iface: dev}, nil
		}
		// A freedom outbound with neither is the one shape that cannot carry. It is not
		// a limitation of this panel: `freedom` means "dial it yourself, from here", so
		// there is no second place for the packets to go, and a tunnel whose panel says
		// carried while its packets leave exactly as they always did is the failure
		// this whole scheme exists to prevent.
		//
		// It is also the only carrier that would LOOP. Everything else dials somewhere
		// that is not the carried tunnel's server, so the steer rule does not catch it;
		// a bare freedom dials that server directly, which is precisely the destination
		// being steered, so the core would hand its own packet back to itself. The
		// core's own tun documentation warns about this shape by name.
		return vpnOutCarrier{}, fmt.Errorf("the %q outbound has no interface and no sendThrough, so it dials straight "+
			"out of this host and there is nowhere to carry %s to; give that outbound an Interface Name (or a "+
			"sendThrough address) and it becomes a carrier, or name a tunnel or a proxy outbound instead", tag, tag)
	case "blackhole":
		return vpnOutCarrier{}, fmt.Errorf("the %q outbound discards everything sent to it, so a tunnel carried by "+
			"it could never connect", tag)
	case "dns":
		return vpnOutCarrier{}, fmt.Errorf("the %q outbound only answers DNS, so it cannot carry a tunnel", tag)
	case "":
		return vpnOutCarrier{}, fmt.Errorf("the %q outbound has no protocol, so there is nothing to carry through", tag)
	}

	return vpnOutCarrier{
		Tag:    tag,
		Kind:   vpnOutCarrierBridged,
		Iface:  vpnOutCarrierDev(tag),
		Uplink: vpnOutOutboundUplinks(ob),
	}, nil
}

// vpnOutFindOutbound returns the outbound with this tag, or nil.
func vpnOutFindOutbound(obs []map[string]any, tag string) map[string]any {
	for _, ob := range obs {
		if t, _ := ob["tag"].(string); t == tag {
			return ob
		}
	}
	return nil
}

// vpnOutDevWithAddr names the device that holds this address, or "".
//
// Uses the same address reader the tunnel synthesis does, so a test can pin what this
// host looks like without a kernel, and so the two can never disagree about whether an
// address is really there.
// A var, like vpnOutIfaceGone and vpnOutIfaceAddrs beside it, so a test can say what
// this host looks like: the answer depends on every device on the machine, which no
// unit test can arrange.
var vpnOutDevWithAddr = func(addr string) string {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return ""
	}
	links, err := netlink.LinkList()
	if err != nil {
		logger.Warning("vpn carrier: cannot list devices to find", addr+":", err)
		return ""
	}
	for _, link := range links {
		name := link.Attrs().Name
		have, err := vpnOutIfaceAddrs(name)
		if err != nil {
			continue
		}
		for _, a := range have {
			if a.Equal(ip) {
				return name
			}
		}
	}
	return ""
}

// vpnOutOutboundPin returns an outbound's streamSettings.sockopt.interface, or "".
func vpnOutOutboundPin(ob map[string]any) string {
	stream, _ := ob["streamSettings"].(map[string]any)
	if stream == nil {
		return ""
	}
	sockopt, _ := stream["sockopt"].(map[string]any)
	if sockopt == nil {
		return ""
	}
	pin, _ := sockopt["interface"].(string)
	return strings.TrimSpace(pin)
}

// vpnOutOutboundUplinks returns every remote address an outbound dials.
//
// Needed for one reason: those addresses must never be steered into the carrier this
// outbound feeds, or the core dials its own tun and the traffic goes round forever
// (proxy/tun/README.md warns about exactly this). vpnoutvia.go's exclusion band is
// where they are used.
//
// Every protocol spells its server differently, so all the shapes the core accepts
// are read here rather than guessed per call site. A protocol whose server this does
// not know about yields nothing, which is safe in the direction that matters: the
// exclusion is a belt for a collision that is already unlikely (the carrier's own
// uplink having the same address as the carried tunnel's server), not the thing that
// makes carrying work.
func vpnOutOutboundUplinks(ob map[string]any) []string {
	settings, _ := ob["settings"].(map[string]any)
	if settings == nil {
		return nil
	}
	var out []string
	add := func(v any) {
		if s, _ := v.(string); strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	// vless/vmess
	if vnext, ok := settings["vnext"].([]any); ok {
		for _, e := range vnext {
			if m, ok := e.(map[string]any); ok {
				add(m["address"])
			}
		}
	}
	// trojan/shadowsocks/socks/http
	if servers, ok := settings["servers"].([]any); ok {
		for _, e := range servers {
			if m, ok := e.(map[string]any); ok {
				add(m["address"])
			}
		}
	}
	// wireguard: peers carry "endpoint" as host:port
	if peers, ok := settings["peers"].([]any); ok {
		for _, e := range peers {
			if m, ok := e.(map[string]any); ok {
				if ep, _ := m["endpoint"].(string); ep != "" {
					if host, _, err := net.SplitHostPort(ep); err == nil {
						add(host)
					} else {
						add(ep)
					}
				}
			}
		}
	}
	// anytls/tuic/naive and anything else that names its server flat
	add(settings["address"])
	add(settings["server"])
	return out
}

// vpnOutCarrierDev is the device name for a bridged carrier tag.
func vpnOutCarrierDev(tag string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tag))
	return fmt.Sprintf("%s%08x", vpnOutCarrierDevPrefix, h.Sum32())
}

// vpnOutCarrierSlot is the /30 a bridged carrier addresses itself out of.
//
// Hashed like the device name, then resolved against the OTHER carriers in the same
// plan: two tags hashing into one slot is rare, and when it happens the tag that
// sorts first keeps the slot and the other takes the next free one. Deterministic
// given the set, and stable for every carrier that was not part of the collision -
// which is the property a plain running index does not have.
func vpnOutCarrierSlots0(tags []string) map[string]int {
	sorted := append([]string(nil), tags...)
	sort.Strings(sorted)

	taken := map[int]bool{}
	out := make(map[string]int, len(sorted))
	for _, tag := range sorted {
		h := fnv.New32a()
		_, _ = h.Write([]byte(tag))
		want := int(h.Sum32()%vpnOutCarrierSlots) + 1
		slot := want
		for n := 0; taken[slot]; n++ {
			if n >= vpnOutCarrierSlots {
				logger.Warning("vpn carrier: no address left for", tag,
					"- there are more carriers than the 10."+fmt.Sprint(vpnOutCarrierNet)+" block holds")
				slot = 0
				break
			}
			slot = slot%vpnOutCarrierSlots + 1
		}
		if slot == 0 {
			continue
		}
		taken[slot] = true
		out[tag] = slot
	}
	return out
}

// vpnOutCarrierAddr is the address a slot gives its device.
func vpnOutCarrierAddr(slot int) string {
	return fmt.Sprintf("10.%d.%d.1/30", vpnOutCarrierNet, slot)
}

// vpnOutEnsureCarrierDev creates the carrier's tun device if it is not there, gives
// it its address, and puts it in a routing table of its own.
//
// The device is PERSISTENT and made here rather than left to Xray, which would also
// create it. Measured: the core attaches to an existing tuntap of the same name and
// leaves it behind on exit with its ifindex intact, and that is the whole point -
// the routing table id is derived from the ifindex, so a device that came and went
// with each core restart would take every rule pointing into it out of service.
//
// Idempotent, because it is called on save, at boot, and from the reconciler.
func vpnOutEnsureCarrierDev(c vpnOutCarrier) error {
	if !c.Bridged() || c.Iface == "" {
		return nil
	}
	link, err := netlink.LinkByName(c.Iface)
	if err != nil {
		tuntap := &netlink.Tuntap{
			LinkAttrs: netlink.LinkAttrs{Name: c.Iface, MTU: vpnOutCarrierMTU},
			Mode:      netlink.TUNTAP_MODE_TUN,
			// NO_PI to match what the core asks for when it attaches
			// (proxy/tun/tun_linux.go opens with IFF_TUN|IFF_NO_PI); a device created
			// with the packet-information header would hand it a stream it cannot
			// parse. NonPersist is left false: outliving the core is the requirement.
			Flags: netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI,
		}
		if err := netlink.LinkAdd(tuntap); err != nil {
			return fmt.Errorf("cannot create the carrier device %q for %s: %w", c.Iface, c.Tag, err)
		}
		// Recorded the moment it exists, so uninstall takes it away again and so a
		// device this panel made is told apart from one that merely wears the name.
		ownIfaceCreated(c.Iface, "vpnoutcarrier")
		if link, err = netlink.LinkByName(c.Iface); err != nil {
			return fmt.Errorf("carrier device %q for %s went missing right after it was made: %w", c.Iface, c.Tag, err)
		}
	}

	if c.Addr != "" {
		addr, err := netlink.ParseAddr(c.Addr)
		if err != nil {
			return fmt.Errorf("carrier %s: %q is not an address: %w", c.Tag, c.Addr, err)
		}
		// Replace rather than add: a slot that moved (a collision resolved differently
		// after another carrier was added) would otherwise leave the old address on
		// the device beside the new one.
		if err := netlink.AddrReplace(link, addr); err != nil {
			return fmt.Errorf("cannot address the carrier device %q for %s: %w", c.Iface, c.Tag, err)
		}
	}

	// UP is Xray's job and it does it on attach, but a device that has never had the
	// core attached would otherwise have no table at all until it did, and
	// vpnOutBindEgress needs the link either way. Bringing it up here costs nothing
	// and makes the table exist from the moment the carrier does.
	if err := netlink.LinkSetUp(link); err != nil {
		logger.Warning("vpn carrier: cannot bring", c.Iface, "up:", err)
	}

	// The same table, rule, blackhole and rp_filter treatment every tunnel device
	// gets. This is what makes a carrier tun a carrier at all: vpnoutvia.go's steer
	// rules name a TABLE, and this is where that table comes from.
	return vpnOutBindEgress(c.Iface)
}

// vpnOutSweepCarrierDevs removes carrier devices no plan claims any more.
//
// A carrier device left behind is not inert: it holds an address, a routing table and
// an oif rule, and the next device to take its ifindex would inherit the table. Swept
// by NAME PREFIX rather than from a stored list, so a device whose carrier was
// deleted while the panel was down is still collected at the next boot.
func vpnOutSweepCarrierDevs(keep map[string]bool) {
	links, err := netlink.LinkList()
	if err != nil {
		logger.Warning("vpn carrier: cannot list devices to sweep:", err)
		return
	}
	for _, link := range links {
		name := link.Attrs().Name
		if keep[name] || !vpnOutCarrierOwnsLink(link) {
			continue
		}
		// The rules AND the table, in that order, before the device goes.
		//
		// vpnOutUnbindEgress rather than a bare rule sweep, because a table outlives
		// its device: the kernel drops the device route when the device does, but the
		// blackhole default is not attached to any device and simply stays. Measured
		// here: after deleting a carrier device by hand, `ip route show table 30026`
		// still printed `blackhole default metric 1000`. Left behind, it is inherited
		// by whatever device next takes that ifindex, which would find its own table
		// pre-loaded with a route that drops everything.
		//
		// It also computes the table BEFORE sweeping, which is the ordering that
		// closes the window where a table is empty and something is still steered
		// into it.
		vpnOutUnbindEgress(name)
		if err := netlink.LinkDel(link); err != nil {
			logger.Warning("vpn carrier: cannot remove the stale carrier device", name+":", err)
			continue
		}
		logger.Info("vpn carrier: removed the stale carrier device", name)
	}
}

// applyCarrierBridgesWith writes one tun inbound per bridged carrier into the config,
// plus the routing rule that sends that inbound to the carrier's outbound.
//
// Derived on every config build from the carriers in play, exactly like the tunnel
// outbounds and the SSH facade, and for the same reason: the device name and the tag
// are decided here, so a copy saved into the operator's template would be a second
// writer of the same fact.
//
// The rule is PREPENDED. Routing is first-match, and an operator whose own first rule
// sends everything to a proxy would otherwise swallow the carrier's traffic and send
// a tunnel's outer transport somewhere nobody asked for.
func applyCarrierBridgesWith(config *xray.Config, carriers []vpnOutCarrier) error {
	var bridged []vpnOutCarrier
	for _, c := range carriers {
		if !c.Bridged() || c.Iface == "" || c.Tag == "" {
			continue
		}
		// The device must already EXIST, and this is not a formality. A tun inbound
		// naming a device the core cannot open is not a partial failure: measured, the
		// core refuses to start at all ("failed to create server > operation not
		// permitted" without CAP_NET_ADMIN), which would take every inbound and every
		// other tunnel on the panel down with it because one carrier could not be made.
		//
		// Skipping it instead is fail-closed rather than fail-hard: the steer rules for
		// whatever rides on this carrier still point into its table, that table still
		// holds the blackhole vpnOutBindEgress parked there, and so the carried tunnel
		// is dropped while everything else keeps running.
		if vpnOutIfaceGone(c.Iface) {
			logger.Warning("vpn carrier: no device for", c.Tag,
				"yet, so its bridge is left out of the config and anything riding on it stays blackholed")
			continue
		}
		bridged = append(bridged, c)
	}
	// NOT returned early on an empty list, which is the whole point of the sweep below.
	// The last carrier being deleted is exactly when its inbound and its rule have to
	// come out of the config, and an early return left both behind: an inbound holding
	// a device that no longer exists, and a rule aimed at an outbound the operator may
	// have deleted in the same edit.
	sort.Slice(bridged, func(i, j int) bool { return bridged[i].Tag < bridged[j].Tag })
	want := make(map[string]bool, len(bridged))
	for _, c := range bridged {
		want[vpnOutCarrierTagPrefix+c.Tag] = true
	}
	keptIn := make([]xray.InboundConfig, 0, len(config.InboundConfigs))
	for _, in := range config.InboundConfigs {
		if strings.HasPrefix(in.Tag, vpnOutCarrierTagPrefix) && !want[in.Tag] {
			continue
		}
		keptIn = append(keptIn, in)
	}
	config.InboundConfigs = keptIn

	// Inbounds. Same tag replaces in place so a rebuild cannot accumulate duplicates,
	// which the core refuses the whole config over.
	for _, c := range bridged {
		settings, err := json.Marshal(map[string]any{
			"name": c.Iface,
			"mtu":  vpnOutCarrierMTU,
			// autoSystemRoutingTable and autoOutboundsInterface are deliberately NOT
			// set. The second one installs a PROCESS-GLOBAL dialer controller that
			// would pin every outbound in the core to one device (see the note at the
			// top of vpnoutbound.go), which is the opposite of one carrier per tag.
		})
		if err != nil {
			return err
		}
		in := xray.InboundConfig{
			Protocol: "tun",
			Tag:      vpnOutCarrierTagPrefix + c.Tag,
			Settings: json_util.RawMessage(settings),
			// The core ignores listen and port for this inbound (it never listens on
			// one), but the field is not optional in the config shape.
			Listen: json_util.RawMessage(`"127.0.0.1"`),
			Port:   0,
		}
		replaced := false
		for i := range config.InboundConfigs {
			if config.InboundConfigs[i].Tag == in.Tag {
				config.InboundConfigs[i] = in
				replaced = true
				break
			}
		}
		if !replaced {
			config.InboundConfigs = append(config.InboundConfigs, in)
		}
	}

	// Routing.
	routing := map[string]any{}
	if len(config.RouterConfig) > 0 {
		if err := json.Unmarshal(config.RouterConfig, &routing); err != nil {
			return err
		}
	}
	var rules []any
	if existing, ok := routing["rules"].([]any); ok {
		rules = existing
	}
	// Drop any rule this function wrote before, so a carrier that was deleted does not
	// leave a rule aimed at an outbound that may no longer exist.
	kept := make([]any, 0, len(rules))
	for _, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			kept = append(kept, r)
			continue
		}
		if vpnOutRuleIsCarrier(m) {
			continue
		}
		kept = append(kept, r)
	}
	mine := make([]any, 0, len(bridged))
	for _, c := range bridged {
		mine = append(mine, map[string]any{
			"type":        "field",
			"inboundTag":  []any{vpnOutCarrierTagPrefix + c.Tag},
			"outboundTag": c.Tag,
		})
	}
	// Untouched when there is nothing of ours in it and nothing of ours to add, which is
	// every panel that uses no carriers at all. Re-marshalling regardless would rewrite
	// the operator's routing section on every config build for no reason, and
	// Config.Equals compares RouterConfig with bytes.Equal, so a rewrite that changes
	// only key order is a restart nobody asked for.
	if len(mine) == 0 && len(kept) == len(rules) {
		return nil
	}
	routing["rules"] = append(mine, kept...)
	out, err := json.Marshal(routing)
	if err != nil {
		return err
	}
	config.RouterConfig = json_util.RawMessage(out)
	return nil
}

// vpnOutRuleIsCarrier reports whether a routing rule is one applyCarrierBridgesWith
// wrote, identified by its inboundTag naming a carrier inbound. Recognised by shape
// rather than by a marker key, because the core refuses a rule carrying a field it
// does not know.
func vpnOutRuleIsCarrier(rule map[string]any) bool {
	tags, ok := rule["inboundTag"].([]any)
	if !ok || len(tags) != 1 {
		return false
	}
	tag, _ := tags[0].(string)
	return strings.HasPrefix(tag, vpnOutCarrierTagPrefix)
}

// vpnOutTemplateOutbounds reads the operator's outbound list off the stored template.
//
// Returns nil and says nothing when the template cannot be read: a carrier that cannot
// be resolved is refused by its caller with a sentence of its own, and a warning here
// would fire on every save of every tunnel that has no carrier at all.
func vpnOutTemplateOutbounds() []map[string]any {
	var settingService SettingService
	raw, err := settingService.GetXrayConfigTemplate()
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var parsed struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		logger.Warning("vpn carrier: the stored Xray template does not parse, so no outbound can be a carrier:", err)
		return nil
	}
	return parsed.Outbounds
}

// vpnOutCarrierNames is every carrier tag anything on this panel names.
//
// Both lists are read because an SSH tunnel may name a carrier too, and its steer rules
// live in the same priority bands: a carrier known only to an SSH tunnel would otherwise
// be absent from the plan, and vpnOutApplyVia deletes every rule in the bands that the
// plan does not contain.
func vpnOutCarrierNames(tunnels []VpnOutboundConfig, sshList []SshOutboundConfig) []string {
	seen := map[string]bool{}
	var out []string
	add := func(via string) {
		via = strings.TrimSpace(via)
		if via == "" || seen[via] {
			return
		}
		seen[via] = true
		out = append(out, via)
	}
	for _, t := range tunnels {
		if t.Enable {
			add(t.Via)
		}
	}
	for _, s := range sshList {
		add(s.Via)
	}
	sort.Strings(out)
	return out
}

// vpnOutCarrierPlan resolves every carrier named on this panel, and assigns the bridged
// ones their addresses.
//
// Tunnel carriers are deliberately LEFT OUT of the returned list: vpnOutViaFactsOf
// already knows everything about them, and a second source for the same fact is how the
// two disagree. What comes back is the carriers the planner could not have known about.
func vpnOutCarrierPlan(tunnels []VpnOutboundConfig, sshList []SshOutboundConfig,
	obs []map[string]any) (carriers []vpnOutCarrier, problems []string) {
	names := vpnOutCarrierNames(tunnels, sshList)
	sshTags := make([]string, 0, len(sshList))
	for _, s := range sshList {
		sshTags = append(sshTags, s.Tag)
	}

	var bridgedTags []string
	resolved := make([]vpnOutCarrier, 0, len(names))
	for _, tag := range names {
		c, err := vpnOutCarrierFor(tag, tunnels, sshTags, obs)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if c.Kind == vpnOutCarrierTunnel || c.Tag == "" {
			continue
		}
		resolved = append(resolved, c)
		if c.Bridged() {
			bridgedTags = append(bridgedTags, c.Tag)
		}
	}

	slots := vpnOutCarrierSlots0(bridgedTags)
	for i := range resolved {
		if !resolved[i].Bridged() {
			continue
		}
		slot, ok := slots[resolved[i].Tag]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s has no address left for a carrier device", resolved[i].Tag))
			continue
		}
		resolved[i].Slot = slot
		resolved[i].Addr = vpnOutCarrierAddr(slot)
	}
	return resolved, problems
}

// vpnOutCarrierExtras turns resolved carriers into the facts the planner speaks.
//
// Table comes from the device, which is what makes the fail-closed value work: a carrier
// whose device is not there yet resolves to table 0, and nothing is ever steered into
// table 0. ServerAddrs are the carrier's own uplink, and they exist to be EXCLUDED from
// the carrier rather than steered into it (see vpnOutOutboundUplinks).
func vpnOutCarrierExtras(carriers []vpnOutCarrier) []vpnOutViaFacts {
	out := make([]vpnOutViaFacts, 0, len(carriers))
	for _, c := range carriers {
		f := vpnOutViaFacts{
			Tag: c.Tag,
			// A carrier resolved from an outbound is never itself carried: an outbound's
			// own chaining is Xray's business (sockopt.dialerProxy on an ordinary row
			// already works, and the core does it inside the process), so there is no
			// second hop for this file to install.
			Via:    "",
			Enable: true,
			Table:  vpnOutTableOf(c.Iface),
		}
		for _, host := range c.Uplink {
			ip := vpnOutLookupHostPrefixes(host)
			f.ServerAddrs = append(f.ServerAddrs, ip...)
		}
		out = append(out, f)
	}
	return out
}

// vpnOutLookupHostPrefixes resolves one host to the /32s it answers with.
//
// Best effort by design. These addresses only ever become EXCLUSIONS, so failing to
// resolve one costs an exclusion that was probably not needed anyway; failing to steer,
// by contrast, is a leak, and nothing here can cause that.
func vpnOutLookupHostPrefixes(host string) []string {
	host = vpnOutHostOf(host)
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if p := vpnOutHostPrefix(ip); p != "" {
			return []string{p}
		}
		return nil
	}
	ips, err := vpnOutLookupIP(host)
	if err != nil {
		return nil
	}
	var out []string
	for _, ip := range ips {
		if p := vpnOutHostPrefix(ip); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// vpnOutResolveCarrier answers the two questions a raise has about a carrier: which
// facts to steer with, and what KIND of carrier it is, because a proxy carrier moves
// only TCP and UDP and a device carrier moves anything.
//
// The bridged carrier's device is created here rather than left to the reconciler, for
// the same reason vpnOutSteerVia runs before the client starts: the table has to exist
// before a rule points into it, or the first packet finds an empty table and falls
// through to main, which is the leak this scheme exists to close.
func vpnOutResolveCarrier(tag string, tunnels []VpnOutboundConfig,
	sshList []SshOutboundConfig) (vpnOutCarrier, vpnOutViaFacts, error) {
	sshTags := make([]string, 0, len(sshList))
	for _, s := range sshList {
		sshTags = append(sshTags, s.Tag)
	}
	c, err := vpnOutCarrierFor(tag, tunnels, sshTags, vpnOutTemplateOutbounds())
	if err != nil {
		return vpnOutCarrier{}, vpnOutViaFacts{}, err
	}

	// A tunnel carrier keeps answering through its driver, which is the only thing that
	// knows where that protocol dials and is already the source vpnOutViaFactsOf uses.
	if c.Kind == vpnOutCarrierTunnel {
		cfg, ok := findVpnTunnel(tunnels, tag)
		if !ok {
			return c, vpnOutViaFacts{}, fmt.Errorf("%s is not a tunnel on this panel", tag)
		}
		addrs, _, err := vpnOutServerAddrs(cfg)
		if err != nil {
			return c, vpnOutViaFacts{}, err
		}
		return c, vpnOutViaFacts{
			Tag:         cfg.Tag,
			Via:         strings.TrimSpace(cfg.Via),
			Enable:      cfg.Enable,
			ServerAddrs: addrs,
			Table:       vpnOutTableOf(cfg.Iface),
		}, nil
	}

	if c.Bridged() {
		// The slot is resolved against every other bridged carrier so two of them can
		// never claim one address, which means the whole set has to be planned even
		// when only one of them is being raised.
		plan, _ := vpnOutCarrierPlan(tunnels, sshList, vpnOutTemplateOutbounds())
		for _, p := range plan {
			if p.Tag == c.Tag {
				c = p
				break
			}
		}
		if err := vpnOutEnsureCarrierDev(c); err != nil {
			return c, vpnOutViaFacts{}, err
		}
	}

	// An SSH tunnel answers through the SSH facts rather than the carrier's uplink,
	// which for it is empty. The difference is one exclusion: without the SSH server's
	// own address pinned to main, a tunnel whose server resolves to the same address as
	// the SSH server would wrap the SSH tunnel's handshake inside itself. The reconcile
	// gets this right either way, but the raise installs its rules first and a rule that
	// is only right after the next reconcile is a window.
	for _, f := range vpnOutSshViaFacts(sshList, []vpnOutCarrier{c}) {
		if f.Tag == c.Tag {
			return c, f, nil
		}
	}

	facts := vpnOutCarrierExtras([]vpnOutCarrier{c})
	if len(facts) == 0 {
		return c, vpnOutViaFacts{}, fmt.Errorf("%s could not be made into a carrier", tag)
	}
	return c, facts[0], nil
}

// vpnOutApplyCarriers brings every carrier device into existence and collects the ones
// no carrier claims any more. Returns the facts the planner needs.
//
// Called from the same places vpnOutApplyVia is, and BEFORE it: a steer rule naming a
// table that has no device route is the measured leak this whole scheme exists to
// prevent, so the device and its table have to be there before any rule points into
// them.
func vpnOutApplyCarriers(tunnels []VpnOutboundConfig, sshList []SshOutboundConfig) []vpnOutViaFacts {
	carriers, problems := vpnOutCarrierPlan(tunnels, sshList, vpnOutTemplateOutbounds())
	for _, p := range problems {
		logger.Warning("vpn carrier:", p+", so nothing riding on it is being carried")
	}
	keep := map[string]bool{}
	for _, c := range carriers {
		if !c.Bridged() {
			continue
		}
		if err := vpnOutEnsureCarrierDev(c); err != nil {
			logger.Warning("vpn carrier:", err)
			continue
		}
		keep[c.Iface] = true
	}
	vpnOutSweepCarrierDevs(keep)

	// The SSH tunnels' facts REPLACE any carrier entry of the same tag rather than
	// joining it. An SSH tag can be both a rider and a carrier, and two facts for one
	// tag would leave the planner picking whichever it met first: one says the tunnel
	// is carried and the other says it is not, and only one of them installs the steer.
	ssh := vpnOutSshViaFacts(sshList, carriers)
	isSsh := make(map[string]bool, len(ssh))
	for _, f := range ssh {
		isSsh[f.Tag] = true
	}
	extra := make([]vpnOutViaFacts, 0, len(carriers)+len(ssh))
	for _, f := range vpnOutCarrierExtras(carriers) {
		if !isSsh[f.Tag] {
			extra = append(extra, f)
		}
	}
	return append(extra, ssh...)
}

// vpnOutSshViaFacts is what the planner needs to know about the SSH tunnels.
//
// They belong in the plan whether or not any of them names a carrier, and that is not an
// optimisation: vpnOutApplyVia deletes every rule in its two priority bands that the plan
// does not contain, so an SSH tunnel's steer rule that the plan never mentions would be
// installed by the raise and swept by the next reconcile of anything else.
//
// ONE entry per tunnel, carrying both roles. An SSH tunnel can be carried (Via) and can
// itself be a carrier (its tag named by something else, which gives it a carrier tun and
// therefore a Table), and the same ServerAddrs are right for both: as a rider they are
// what gets steered, and as a carrier they are what gets excluded, because in both cases
// they are the address this tunnel's own TCP connection goes to.
func vpnOutSshViaFacts(sshList []SshOutboundConfig, carriers []vpnOutCarrier) []vpnOutViaFacts {
	table := map[string]int{}
	for _, c := range carriers {
		if c.Bridged() {
			table[c.Tag] = vpnOutTableOf(c.Iface)
		}
	}
	out := make([]vpnOutViaFacts, 0, len(sshList))
	for _, s := range sshList {
		if s.Tag == "" {
			continue
		}
		out = append(out, vpnOutViaFacts{
			Tag: s.Tag,
			Via: strings.TrimSpace(s.Via),
			// An SSH tunnel has no enable switch of its own: a stored one is dialled.
			Enable:      true,
			ServerAddrs: vpnOutLookupHostPrefixes(s.Address),
			Table:       table[s.Tag],
		})
	}
	return out
}

// InitVpnOutCarriers makes every carrier device before anything dials.
//
// Called from the panel's boot sequence AHEAD of the tunnels, because a carrier has to
// exist before the thing riding on it sends its first packet. A WireGuard client sends
// its handshake the instant its peer is configured and the SSH manager dials as soon as
// its listener binds, so a device created afterwards arrives after the packet it was
// meant to carry has already left in the clear.
//
// Best effort, exactly like the daemon Inits it sits beside: a carrier that cannot be
// made is a warning and a blackholed rider, not a panel that refuses to start.
func InitVpnOutCarriers() {
	tunnels := (&VpnOutboundService{}).List()
	sshList := (&SshOutboundService{}).List()
	extra := vpnOutApplyCarriers(tunnels, sshList)
	if len(extra) == 0 && len(sshList) == 0 {
		return
	}
	vpnOutApplyVia(tunnels, extra)
}

// vpnOutReassertCarriers puts every carrier device's egress routing back after the core
// has restarted.
//
// Called from RestartXray, which is the moment the device comes back up: the core sets
// the tun DOWN when it stops, the kernel drops the table's device route with it, and
// nothing else in this package ever re-writes that route (vpnOutApplyVia reconciles
// rules only). Without this the carrier's table holds nothing but its blackhole and
// every tunnel riding on it stays dropped until somebody re-saves it.
//
// Best effort and quiet about a carrier that is simply not there: a panel with no
// carriers at all restarts the core constantly for reasons that have nothing to do with
// this file.
func vpnOutReassertCarriers() {
	tunnels := (&VpnOutboundService{}).List()
	sshList := (&SshOutboundService{}).List()
	carriers, _ := vpnOutCarrierPlan(tunnels, sshList, vpnOutTemplateOutbounds())
	for _, c := range carriers {
		if !c.Bridged() {
			continue
		}
		if err := vpnOutEnsureCarrierDev(c); err != nil {
			logger.Warning("vpn carrier: could not restore the egress routing for", c.Tag+":", err)
		}
	}
}

// VpnOutCarriable is an OPTIONAL interface a driver implements when whether its outer
// transport can survive a TCP/UDP-only carrier depends on how it is configured.
//
// Declared by the driver for the same reason VpnOutServer is: Settings is opaque to
// the framework, and "does this tunnel put anything but TCP and UDP on the wire" is a
// question only the protocol can answer. A driver that does not implement it is taken
// as carriable, which is right for the six whose outer is already TCP or UDP.
type VpnOutCarriable interface {
	// CarriableOverProxy reports whether this tunnel, as configured, puts nothing but
	// TCP and UDP on the wire, and if not, one line an operator can act on.
	CarriableOverProxy(cfg VpnOutboundConfig) (bool, string)
}

// vpnOutCarrierRefusal says why this tunnel cannot ride this carrier, or "".
//
// A device carrier never refuses: steering into a netdev is L4-agnostic, so GRE and
// ESP travel as happily as TCP. Only a bridged carrier asks the question, and only
// the driver can answer it.
func vpnOutCarrierRefusal(cfg VpnOutboundConfig, c vpnOutCarrier) string {
	if !c.Bridged() {
		return ""
	}
	d, err := vpnOutDriverFor(cfg.Kind)
	if err != nil {
		return ""
	}
	ask, ok := d.(VpnOutCarriable)
	if !ok {
		return ""
	}
	if can, why := ask.CarriableOverProxy(cfg); !can {
		// The frame names the two ends and the driver's sentence says what to do about
		// it. The alternative carrier is deliberately NOT repeated here: each driver's
		// answer is different (GRE has a setting to change, PPTP has none), so the
		// advice belongs with the driver that knows which one applies, and adding a
		// generic tail here only made the operator read it twice.
		return fmt.Sprintf("%s cannot be carried by the %q outbound: %s", cfg.Tag, c.Tag, why)
	}
	return ""
}
