package service

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/hasan1808/pro-ui/logger"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Carrying one tunnel INSIDE a carrier: tunnel A's own outer transport (its WireGuard
// UDP, its GRE, its ESP, its OpenVPN TCP) travels through carrier B's netdev, so the
// server A dials never sees this host's address. B is another VPN tunnel, or any Xray
// outbound vpnoutcarrier.go could resolve to a device; from here down it is a TABLE and
// nothing else.
//
// The operator asks for it with the outbound row's DIALER PROXY, which is the panel's
// one chaining control on every outbound, tunnels included. On a tunnel row that field
// names the carrier: the save copies it into Via, this file turns it into rules, and
// vpnOutStreamSettings strips the key out of the emitted Xray config, where it would
// mean the opposite thing (see its comment). Via is the stored name for the same answer.
//
// Pure policy routing. No proxy, no extra process, nothing asked of the nine client
// daemons, because the selector is the one thing every one of them has in common: the
// ADDRESS they dial.
//
//	pref 1xxxx: to <B's server>  lookup main          <- B's own outer stays outside B
//	pref 2xxxx: to <A's server>  lookup <B's table>   <- A's outer goes through B
//
// `ip rule` steers locally generated TCP, UDP, GRE (proto 47) and ESP (proto 50)
// alike, which is why it is this and not TPROXY: TPROXY is PREROUTING-only and cannot
// see a locally generated packet at all. It is also the only mechanism that works for
// charon's kernel ESP, which has no mark knob in this build.
//
// A NETDEV is STILL required at both ends. That has not changed and cannot: the
// selector is a routing table, and a table holds device routes. What changed is where
// the carrier's device comes from. It no longer has to be a tunnel's own, because
// vpnoutcarrier.go can SYNTHESIZE one for an Xray outbound - a tun inbound the panel
// creates and the core attaches to, routed to that outbound - or hand over the device a
// freedom outbound is already pinned to. Nothing below notices: this file is given a
// carrier's TABLE and steers into it, and a table is a table whichever device filled it.
//
// The measurement that used to make an Xray outbound impossible as a carrier is still
// true, and it is exactly why the per-kind gate exists. A tun inbound moves TCP and UDP
// ONLY. Re-measured 2026-08-12 against the bundled core 26.4.17: ICMP is dropped (ping
// through it, 100% loss), and so are the raw IP protocols - GRE (47) and ESP (50) are
// counted on RX, zero leave, and nothing is logged. A tunnel's own netdev has no such
// limit, which is why the two kinds of carrier stay distinct rather than collapsing into
// one. That gate is VpnOutCarriable, in vpnoutcarrier.go, where the kind of device is
// known; this file refuses only a carrier it cannot RESOLVE.
//
// THE WHOLE SCHEME FAILS OPEN WITHOUT THE BLACKHOLE. Naming a TABLE rather than a
// DEVICE is what introduces the hazard: with B's device gone, the steer rule still
// matches, B's table no longer holds its device route, the lookup falls through to
// main, and 100% of A's traffic leaves in the clear out the host's WAN with nothing
// logged. Measured. vpnOutBindEgress parks `blackhole default metric 1000` in every
// tunnel table for exactly this: the metric-0 device route wins while the tunnel is
// up, and the blackhole catches everything the moment the device is not.

const (
	// vpnOutExcludeRuleBase and vpnOutSteerRuleBase are the two priority bands the via
	// rules live in.
	//
	// Both are well below the 30000 oif block so the ordering is deterministic and does
	// not depend on which ifindex a device happened to get: exclusions are considered
	// first, then steers, then the per-device egress rules. Exclusion below steer is
	// load-bearing rather than tidy - it is what stops a carried tunnel that resolves to
	// its carrier's own address (round-robin DNS at the same provider) from wrapping the
	// carrier's handshake inside the carrier.
	vpnOutExcludeRuleBase = 10000
	vpnOutSteerRuleBase   = 20000
	// vpnOutRuleBandSpan is how wide each band is. It bounds the per-tunnel slot below,
	// and keeps the two bands from touching each other or the oif block.
	vpnOutRuleBandSpan = 10000
	// vpnOutMainTable is where a carrier's own outer transport goes: out of the host,
	// the ordinary way. Spelled out rather than left as unix.RT_TABLE_MAIN inline
	// because it is a decision the tests assert on.
	vpnOutMainTable = unix.RT_TABLE_MAIN
	// vpnOutBlackholeMetric is the metric of the fail-closed default route parked in
	// every tunnel table. Any positive number above the device route's 0 would do; 1000
	// is high enough to read as "last resort" in `ip route show table N`.
	vpnOutBlackholeMetric = 1000
	// vpnOutRuleProto stamps every rule this file installs, so the reconcile can tell
	// them apart from whatever else lives on the host.
	//
	// It matters because the reconcile deletes by BAND: everything in the two priority
	// ranges that is not in the plan. Without a stamp that is a promise that nothing
	// else on the box ever puts a rule at priority 10000-29999, which is not a promise
	// this panel is in a position to make. FRA_PROTOCOL is the kernel's own field for
	// exactly this question and `ip rule show` prints it, so an operator can see whose
	// rule they are looking at.
	//
	// 149 is unassigned in rtnetlink.h, between KEEPALIVED (18) and OPENR (99)/BGP (186)
	// and clear of every routing daemon's number.
	//
	// Kernels before 5.0 have no FRA_PROTOCOL and ignore the attribute, so the stamp
	// reads back as zero there. vpnOutRuleIsOurs handles that: a steer rule is still
	// identifiable without it (nothing else on the host knows about table 30000+ifindex),
	// and an exclusion that lingers is inert - it says "reach this address normally",
	// which is what would happen anyway with no rule at all.
	vpnOutRuleProto = 149
)

// VpnOutServer is an OPTIONAL interface a driver implements to name the remote address
// its OUTER transport dials.
//
// Declared by the driver rather than guessed by the framework, for the same reason
// VpnOutSecrets is: Settings is opaque here, every protocol spells its server
// differently ("server", "endpoint", a `remote` line inside a pasted .ovpn), and three
// of them can be pointed at a proxy instead, which moves the address the packets
// actually go to. A name list held out here could not be right.
//
// Returns a HOST, not an address: a name is resolved by the framework, in one place,
// so every driver's answer is treated the same way. A driver that cannot answer
// (nothing configured yet) returns an empty string and no error; a driver that cannot
// be carried at all does not implement this, and Save refuses to carry it.
type VpnOutServer interface {
	ServerHost(cfg VpnOutboundConfig) (string, error)
}

// vpnOutHostOf reduces whatever a driver stores as its server to a bare host.
//
// The drivers accept three shapes between them and they all end up here: a full URL
// (openconnect's portal, sstp's proxy), a host:port (wireguard's endpoint), and a bare
// host or address (gre, l2tp, pptp, ikev2). Doing this once is what stops nine
// almost-identical string manglings from disagreeing about `[2001:db8::1]:51820`.
func vpnOutHostOf(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	// Before SplitHostPort, not after: a bare IPv6 address is full of colons and
	// SplitHostPort would take the last group for a port.
	if net.ParseIP(s) != nil {
		return s
	}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		return host
	}
	// A host with a path and no scheme ("vpn.example.com/gp"), which openconnect takes.
	if i := strings.IndexByte(s, '/'); i > 0 {
		return vpnOutHostOf(s[:i])
	}
	return strings.Trim(s, "[]")
}

// vpnOutLookupIP resolves a carried or carrying server's name. A var so the planner can
// be tested without a resolver.
//
// Bounded, unlike a bare net.LookupIP. This runs inside InitVpnOutbound, which holds the
// config lock while the panel is still starting, so a nameserver that is down would hold
// the boot for as long as the resolver's own retries take - per tunnel. Five seconds is
// long enough for a slow answer and short enough that the panel still comes up; a name
// that does not resolve in time means the tunnel is not raised, which is the fail-closed
// answer anyway.
var vpnOutLookupIP = func(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// vpnOutServerAddrs answers "which addresses does this tunnel's outer transport go to",
// as the /32 prefixes a rule matches on.
//
// EVERY A record is steered, not just the first. A provider behind round-robin DNS
// hands out a different address per lookup, and steering one of them leaves the other
// three leaving in the clear the first time the client retries - which is the failure
// this whole file exists to prevent, arrived at by a different road.
//
// IPv4 only, because the rules this framework installs are FAMILY_V4 (vpnOutBindEgress
// has always been). A tunnel whose server is v6-only is refused rather than carried
// halfway.
func vpnOutServerAddrs(cfg VpnOutboundConfig) (addrs []string, host string, err error) {
	drv, err := vpnOutDriverFor(cfg.Kind)
	if err != nil {
		return nil, "", err
	}
	named, ok := drv.(VpnOutServer)
	if !ok {
		return nil, "", fmt.Errorf("a %s tunnel does not say which server it dials, so it cannot be carried", cfg.Kind)
	}
	raw, err := named.ServerHost(cfg)
	if err != nil {
		return nil, "", err
	}
	host = vpnOutHostOf(raw)
	if host == "" {
		return nil, "", fmt.Errorf("%s has no server address yet", cfg.Tag)
	}
	if ip := net.ParseIP(host); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return nil, host, fmt.Errorf("%s dials the IPv6 address %s, and a carried tunnel is steered by an IPv4 rule", cfg.Tag, host)
		}
		return []string{vpnOutHostPrefix(v4)}, host, nil
	}
	ips, err := vpnOutLookupIP(host)
	if err != nil {
		return nil, host, fmt.Errorf("cannot resolve %s, which %s dials: %w", host, cfg.Tag, err)
	}
	seen := map[string]bool{}
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		p := vpnOutHostPrefix(v4)
		if seen[p] {
			continue
		}
		seen[p] = true
		addrs = append(addrs, p)
	}
	if len(addrs) == 0 {
		return nil, host, fmt.Errorf("%s resolves to no IPv4 address, and a carried tunnel is steered by an IPv4 rule", host)
	}
	// Sorted so the same name produces the same rule set every time. Without it the
	// resolver's rotation alone would make the reconcile below delete and re-add the
	// steers on every save.
	sort.Strings(addrs)
	// RECORDED, because the rule keys on the address and not on the name: from here on
	// the panel is steering these four numbers, and if the name moves to a fifth
	// nothing notices until the next save, delete or panel restart re-resolves it. The
	// log line and `ip rule show` are the only two places that say which answer is in
	// force, so this one is written even when nothing changed.
	logger.Info("vpn outbound:", cfg.Tag, "dials", host, "which resolves to", strings.Join(addrs, ", "),
		"- the carry rules key on those addresses until the next save or restart")
	return addrs, host, nil
}

// vpnOutHostPrefix spells one address the way a rule's destination is spelled, which is
// also how netlink hands it back when the rules are read.
func vpnOutHostPrefix(ip net.IP) string {
	return (&net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}).String()
}

// vpnOutRule is one ip rule as a DECISION rather than as a netlink call.
//
// The split is what makes this testable at all: deciding which rules a set of tunnels
// implies, and which of the kernel's current rules are stale, are the two places a
// mistake becomes a silent leak, and neither of them needs a kernel to be wrong in.
type vpnOutRule struct {
	Priority int
	// OifName is set on the per-device egress rules only. The via rules select on the
	// destination, which is the whole point: it asks nothing of the client daemon.
	OifName string
	// IifName is never set by this file. It is read back from the kernel so a host rule
	// that selects on an incoming device is never mistaken for one of ours.
	IifName string
	// Dst is a prefix ("203.0.113.10/32"), or empty for a rule that matches everything.
	Dst   string
	Table int
	// Protocol is FRA_PROTOCOL: vpnOutRuleProto on the rules this file owns. Deliberately
	// NOT part of the identity a diff compares on, or a kernel too old to store it would
	// see every rule as missing and churn the whole set on every reconcile.
	Protocol uint8
	// Why is one line for the log, naming the tunnels rather than the numbers.
	Why string
}

// vpnOutRuleIsOurs decides whether a rule sitting in one of the via bands was put there
// by this panel. Only these are ever deleted; a host rule that happens to share the band
// is left exactly where it is.
func vpnOutRuleIsOurs(r vpnOutRule) bool {
	if !vpnOutInViaBand(r.Priority) {
		return false
	}
	// Ours select on the destination and nothing else. Anything naming a device belongs
	// to somebody with a different scheme.
	if r.OifName != "" || r.IifName != "" || r.Dst == "" {
		return false
	}
	if r.Protocol == vpnOutRuleProto {
		return true
	}
	// No stamp: a kernel older than 5.0, or a rule from a panel that predates the stamp.
	// A steer is still unmistakable, because the table it points at is one this file
	// invented and nothing else on the host allocates.
	return r.Protocol == 0 && r.Table >= vpnOutRouteTableBase
}

// vpnOutViaFacts is what the planner needs to know about one CARRIER and cannot work out
// from a config: where its own outer transport goes, and which table its device is on.
//
// Deliberately not a tunnel. Everything from vpnOutViaRules down works on this tuple and
// nothing else, which is what let a carrier stop having to be another VPN tunnel without
// touching the planner: vpnoutcarrier.go resolves an outbound tag to a device, the device
// gives a table, and a table fills this in exactly like a tunnel's does. A tunnel fills
// it from its own row (vpnOutViaFactsOf); anything else arrives as `extra`.
type vpnOutViaFacts struct {
	Tag    string
	Via    string
	Enable bool
	// ServerAddrs are the /32 prefixes this end's own outer transport dials: a tunnel's
	// server, or the addresses an Xray outbound itself connects to. They are what the
	// exclusion rule pins to the main table so a carrier cannot end up inside itself.
	//
	// May be empty, and that is not an error: an outbound whose protocol does not spell
	// its server in a shape vpnOutOutboundUplinks knows about yields none. The exclusion
	// is a belt for an unlikely collision (the carrier's own uplink sharing an address
	// with what it carries), not the thing that makes carrying work.
	ServerAddrs []string
	// Table is this end's own egress table, or 0 when its device is not up. Zero is the
	// fail-closed value: nothing is ever steered into table 0.
	Table int
}

// vpnOutViaSlot is the per-tunnel offset inside each priority band.
//
// Derived from the TAG rather than from the ifindex the existing oif rules use, and
// that is deliberate. The steer rule has to be installed BEFORE the carried client is
// started, or its first handshake leaves in the clear while the rule is still being
// added; at that moment the device does not exist and has no index. The tag is the one
// identifier a tunnel has at every point in its life.
//
// A collision between two tags is harmless: two rules may share a priority, they carry
// different destinations, and the bands are ordered against each other rather than
// within themselves.
func vpnOutViaSlot(tag string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tag))
	return int(h.Sum32() % uint32(vpnOutRuleBandSpan))
}

// vpnOutViaRules is the rule set that carries `carried` inside `carrier`.
//
// Two kinds, and the exclusion is the subtle one. It pins the carrier's OWN outer
// transport to the main table so it cannot end up inside itself, and it is emitted only
// when the carrier is not itself carried: in a chain A via B via C, B's outer transport
// belongs in C's table, and an exclusion sending it to main would sit at a LOWER
// priority than B's own steer rule and quietly un-carry B.
func vpnOutViaRules(carried, carrier vpnOutViaFacts) []vpnOutRule {
	if carried.Tag == "" || carrier.Tag == "" || carrier.Table == 0 {
		return nil
	}
	out := make([]vpnOutRule, 0, len(carried.ServerAddrs)+len(carrier.ServerAddrs))
	if carrier.Via == "" {
		for _, dst := range carrier.ServerAddrs {
			out = append(out, vpnOutRule{
				Priority: vpnOutExcludeRuleBase + vpnOutViaSlot(carried.Tag),
				Dst:      dst,
				Table:    vpnOutMainTable,
				Protocol: vpnOutRuleProto,
				Why:      carrier.Tag + " dials " + dst + " from the host, not through itself",
			})
		}
	}
	for _, dst := range carried.ServerAddrs {
		out = append(out, vpnOutRule{
			Priority: vpnOutSteerRuleBase + vpnOutViaSlot(carried.Tag),
			Dst:      dst,
			Table:    carrier.Table,
			Protocol: vpnOutRuleProto,
			Why:      carried.Tag + " dials " + dst + " through " + carrier.Tag,
		})
	}
	return out
}

// vpnOutViaPlan is the COMPLETE set of via rules a list of tunnels implies, plus one
// line per tunnel that asked to be carried and cannot be.
//
// Whole-set rather than incremental, and that is the design. A tunnel rebuilt on a
// different ifindex moves its table, and an incremental scheme has no way to find the
// steer rule that now points at the old number - it names neither the device nor the
// tag. Recomputing the set and deleting everything in the two bands that is not in it
// cannot strand one.
func vpnOutViaPlan(facts []vpnOutViaFacts) (rules []vpnOutRule, problems []string) {
	byTag := make(map[string]vpnOutViaFacts, len(facts))
	for _, f := range facts {
		byTag[f.Tag] = f
	}
	ordered := append([]vpnOutViaFacts(nil), facts...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Tag < ordered[j].Tag })
	for _, f := range ordered {
		if f.Via == "" || !f.Enable {
			continue
		}
		carrier, ok := byTag[f.Via]
		if !ok {
			problems = append(problems, f.Tag+" is carried by "+f.Via+", which is not a tunnel and not an outbound on this panel")
			continue
		}
		if !carrier.Enable {
			problems = append(problems, f.Tag+" is carried by "+f.Via+", which is disabled")
			continue
		}
		if carrier.Table == 0 {
			problems = append(problems, f.Tag+" is carried by "+f.Via+", whose device is not up")
			continue
		}
		rules = append(rules, vpnOutViaRules(f, carrier)...)
	}
	return rules, problems
}

// vpnOutViaDiff compares the rules that should exist against the ones that do.
//
// `have` is the kernel's list restricted to the two via bands, in the order it was read,
// so the deletions come back as indices into it: a rule is deleted by handing netlink
// the object it was enumerated as, never a template, for the reason vpnOutSweepRules
// already documents.
func vpnOutViaDiff(want, have []vpnOutRule) (add []vpnOutRule, del []int) {
	key := func(r vpnOutRule) string {
		return fmt.Sprintf("%d|%s|%s|%d", r.Priority, r.OifName, r.Dst, r.Table)
	}
	present := make(map[string]bool, len(have))
	for _, r := range have {
		present[key(r)] = true
	}
	wanted := make(map[string]bool, len(want))
	for _, r := range want {
		k := key(r)
		if wanted[k] {
			// The same rule asked for twice, which happens when two carried tunnels
			// share a carrier and the slot hash collides. One is enough.
			continue
		}
		wanted[k] = true
		if !present[k] {
			add = append(add, r)
		}
	}
	for i, r := range have {
		if !wanted[key(r)] {
			del = append(del, i)
		}
	}
	return add, del
}

// vpnOutInViaBand reports that a priority belongs to this file rather than to the oif
// block or to whatever else the host has in its rule list. Nothing outside the two
// bands is ever touched.
func vpnOutInViaBand(priority int) bool {
	return priority >= vpnOutExcludeRuleBase && priority < vpnOutSteerRuleBase+vpnOutRuleBandSpan
}

// vpnOutStaleRuleIdx picks the rules belonging to one tunnel out of the kernel's list,
// for a rebind or a teardown.
//
// Two kinds are matched, and the second is the one that was missing:
//
//   - the oif rules naming this device, all but keepTable. These are the existing
//     scheme's, and a leftover one points at a table emptied by a rebuild.
//   - the via rules pointing INTO this tunnel's table. These belong to OTHER tunnels,
//     the ones this one carries, and they are exactly what turns a teardown into the
//     measured leak: delete the carrier's table with a steer rule still pointing at it
//     and every byte of the carried tunnel falls through to main, in the clear.
//
// Pass table 0 to skip the second kind, which is what a rebind wants: the reconcile
// that follows it owns the bands, and deleting a live steer here only to add it back a
// moment later would open the window this is meant to close.
func vpnOutStaleRuleIdx(have []vpnOutRule, iface string, table, keepTable int) []int {
	var out []int
	for i, r := range have {
		switch {
		case iface != "" && r.OifName == iface && (keepTable == 0 || r.Table != keepTable):
			out = append(out, i)
		case table != 0 && r.Table == table && vpnOutRuleIsOurs(r):
			out = append(out, i)
		}
	}
	return out
}

// vpnOutViaCheck refuses a Via the operator is about to save, before anything is raised.
//
// Pure: it answers from the stored list, the resolved carriers and the incoming config
// alone, which is what lets every refusal below be tested without a kernel, a resolver or
// a database.
//
// `carriers` are the carriers that are NOT tunnels, already resolved by
// vpnOutCarrierFor: a freedom outbound's pinned device, or a synthesized carrier tun.
// They are passed in rather than looked up here for the reason `all` is: the outbound
// template is not this function's to read, and every refusal below is a sentence an
// operator reads and is worth testing without a database behind it.
//
// Two questions only, and both are about the SHAPE of the chain. Whether this particular
// KIND of tunnel can survive this particular kind of carrier is vpnOutCarrierRefusal's
// question, asked where the carrier's device kind is known (a tun moves TCP and UDP, a
// netdev moves anything), and answering it here would mean answering it with less
// information.
func vpnOutViaCheck(all []VpnOutboundConfig, carriers []vpnOutViaFacts, cfg VpnOutboundConfig) error {
	via := strings.TrimSpace(cfg.Via)
	if via == "" {
		return nil
	}
	if via == cfg.Tag {
		return fmt.Errorf("%s cannot be carried by itself", cfg.Tag)
	}
	// The incoming config wins over the stored copy of the same tag: this is being
	// asked about the save that is happening, not the one that happened.
	byTag := map[string]string{cfg.Tag: via}
	known := map[string]bool{cfg.Tag: true}
	for _, c := range all {
		if c.Tag == cfg.Tag {
			continue
		}
		byTag[c.Tag] = strings.TrimSpace(c.Via)
		known[c.Tag] = true
	}
	// Seeded SECOND, and never over a tunnel of the same tag. A tunnel already has a row
	// in the outbound template - applyVpnOutboundsWith writes it there as a freedom
	// outbound pinned to the tunnel's device - so one tag can arrive from both sides, and
	// the tunnel's own Via is the one that says whether this is a chain.
	//
	// A carrier that is not a tunnel gets whatever Via its facts carry, which is empty
	// for everything vpnOutCarrierFor resolves today: an Xray outbound chains through
	// dialerProxy inside the core, where this file cannot see it and does not need to -
	// the core dials it, not a client daemon, so no rule of ours is involved.
	for _, f := range carriers {
		if f.Tag == "" || known[f.Tag] {
			continue
		}
		known[f.Tag] = true
		byTag[f.Tag] = strings.TrimSpace(f.Via)
	}
	if !known[via] {
		return fmt.Errorf("the %s tunnel %s cannot be carried by %q, which is not a tunnel and not an "+
			"outbound on this panel", cfg.Kind, cfg.Tag, via)
	}
	if path := vpnOutViaCycle(byTag, cfg.Tag); len(path) > 0 {
		return fmt.Errorf("this would loop: %s", strings.Join(path, " -> "))
	}
	return nil
}

// vpnOutViaCycle walks the carrier chain from `start` and returns the loop it lands in,
// spelled out, or nil.
//
// The path is NAMED rather than reported as "a cycle", because with three or four
// tunnels the operator cannot see it from the one field they are editing: the tunnel
// that closes the loop is two screens away.
func vpnOutViaCycle(byTag map[string]string, start string) []string {
	path := []string{start}
	seen := map[string]int{start: 0}
	for cur := byTag[start]; cur != ""; cur = byTag[cur] {
		if at, loop := seen[cur]; loop {
			return append(path[at:], cur)
		}
		seen[cur] = len(path)
		path = append(path, cur)
		if _, known := byTag[cur]; !known {
			return nil
		}
	}
	return nil
}

// vpnOutViaOrder sorts tunnels so a carrier is raised before anything it carries, and
// names the ones it had to drop.
//
// Boot order is not cosmetic. InitVpnOutbound walks the list as stored, so a carried
// tunnel listed before its carrier would be started with the carrier's table still
// empty; the steer rule would match, find nothing, and fall through to main. Refusing
// to raise a tunnel whose carrier is not up yet would be correct but would also make
// the tunnels come up or not depending on the order they were added in.
//
// A cycle cannot be saved through the panel, so one here came from a hand-edited
// setting. Its members are dropped rather than raised in some arbitrary order: every
// one of them is a tunnel whose outer transport has nowhere fail-closed to go.
func vpnOutViaOrder(list []VpnOutboundConfig) (order []int, dropped []string) {
	idx := make(map[string]int, len(list))
	for i, c := range list {
		idx[c.Tag] = i
	}
	const (
		white = 0 // not visited
		grey  = 1 // on the stack
		black = 2 // emitted
	)
	state := make([]int, len(list))
	var visit func(i int) bool
	visit = func(i int) bool {
		switch state[i] {
		case black:
			return true
		case grey:
			return false
		}
		state[i] = grey
		if via := strings.TrimSpace(list[i].Via); via != "" {
			if j, ok := idx[via]; ok && !visit(j) {
				state[i] = white
				return false
			}
		}
		state[i] = black
		order = append(order, i)
		return true
	}
	for i := range list {
		if !visit(i) {
			dropped = append(dropped, list[i].Tag)
		}
	}
	return order, dropped
}

// vpnOutViaClash refuses a carried tunnel that dials the same address as its carrier.
//
// A rule selects on the destination and nothing else, so two tunnels sharing one server
// address cannot be told apart: whichever rule sits lower wins for both. The exclusion
// is the lower one, so the carried tunnel would leave in the clear while every screen
// in the panel called it carried. Refusing is the only answer that is not silent.
func vpnOutViaClash(carriedTag string, carried []string, carrierTag string, carrier []string) error {
	have := make(map[string]bool, len(carrier))
	for _, a := range carrier {
		have[a] = true
	}
	for _, a := range carried {
		if have[a] {
			addr := strings.TrimSuffix(a, "/32")
			return fmt.Errorf("%s and %s both dial %s, and a routing rule cannot tell two tunnels to one address apart",
				carriedTag, carrierTag, addr)
		}
	}
	return nil
}

// vpnOutViaOverhead is what one kind's own encapsulation costs, in bytes, on top of
// whatever carries it.
//
// Approximate on purpose, and only ever used to WARN. The exact number depends on the
// cipher, on whether the peer negotiated compression, and for ESP on the SA that was
// agreed; a panel that derived an MTU from a guess and wrote it into the tunnel would
// be wrong in the direction that is hard to notice (a tunnel that carries small packets
// and black-holes full-size ones). Saying the number out loud and leaving the field to
// the operator is the honest version.
//
// The two ESP entries were WRONG and are corrected here. Both are keyed on the kind
// alone, which is all this function is given, so where a figure has to choose it chooses
// the LARGER one: an overhead that is too small hands the operator an MTU that passes a
// ping and drops full-size packets, which is the exact silent failure this advice exists
// to name, while one that is too large costs a little payload per packet and nothing
// else.
var vpnOutViaOverhead = map[string]int{
	VpnOutWireguard:   60, // IPv4 20 + UDP 8 + WireGuard 32
	VpnOutAmneziaWG:   60, // same framing; the junk packets are not on the data path
	VpnOutGre:         24, // IPv4 20 + GRE 4
	VpnOutOpenVPN:     69, // IPv4 20 + UDP 8 + OpenVPN header/HMAC/IV ~41
	VpnOutPPTP:        36, // IPv4 20 + GRE 12 + PPP 4
	VpnOutOpenConnect: 65, // IPv4 20 + UDP 8 + DTLS record ~29 + CSTP 8
	VpnOutSSTP:        60, // IPv4 20 + TCP 20 + TLS record ~16 + SSTP 4

	// Was 73 (IPv4 20 + ESP 8 + IV 16 + pad 15 + trailer 2 + ICV 12), which counted the
	// worst-case block padding but left out the 8-byte UDP header NAT-T adds. That header
	// is not optional in the case this advice is about: a carried IKEv2 tunnel is raised
	// with CarriedOverProxy set whenever its carrier is an Xray outbound, and the driver
	// FORCES UDP encapsulation then, because raw ESP (proto 50) is one of the things a
	// carrier tun drops. On a device carrier it is present on any path with a NAT in it,
	// which is most of them. 73 + 8.
	VpnOutIKEv2: 81,

	// Was 44 (IPv4 20 + UDP 8 + L2TP 12 + PPP 4), which is plain L2TP and ignores the
	// IPsec leg entirely. A PSK turns this into L2TP/IPsec, and the transport-mode ESP
	// around it costs ESP 8 + IV 16 + trailer 2 + ICV 12 = 38 more. 44 + 38.
	//
	// NOT CONDITIONAL, and the shortfall is worth stating rather than hiding: whether a
	// PSK is set lives in the l2tp driver's own Settings, which the framework does not
	// parse (see VpnOutServer on why Settings is opaque here), and this function is handed
	// a KIND and two MTUs. So a plain L2TP tunnel with no PSK is warned 38 bytes early,
	// and told to set an MTU 38 smaller than it needs. In the other direction 82 is still
	// optimistic: NAT-T's 8 (forced, as for IKEv2, when the carrier is an Xray outbound)
	// and up to 15 bytes of padding to the cipher's block put the true worst case at 105.
	// Treat it as a middle figure, not an authority.
	VpnOutL2TP: 82,
}

// vpnOutViaMtuAdvice compares a carried tunnel's MTU against what its carrier can
// actually hold, and returns one sentence when it does not fit, or "" when it does.
//
// Double encapsulation is the whole reason this exists: the carried tunnel's OUTER
// packets are payload to the carrier, so the carried device's MTU has to leave room for
// its own headers inside the carrier's MTU. Left alone, the carried tunnel comes up,
// passes a ping, and drops every full-size packet - which reads as a working tunnel
// with a broken internet behind it.
func vpnOutViaMtuAdvice(carriedTag, carriedKind string, carriedMtu, carrierMtu int) string {
	if carriedMtu <= 0 || carrierMtu <= 0 {
		return ""
	}
	overhead, known := vpnOutViaOverhead[carriedKind]
	if !known {
		overhead = 60
	}
	fits := carrierMtu - overhead
	if carriedMtu <= fits {
		return ""
	}
	return fmt.Sprintf("%s has MTU %d but only %d fits inside its carrier (MTU %d less %d bytes of %s framing), "+
		"so full-size packets will be dropped; set its MTU to %d",
		carriedTag, carriedMtu, fits, carrierMtu, overhead, carriedKind, fits)
}

// ---- the impure half: reading the kernel, and writing to it -----------------------

// vpnOutTableOf is the egress table of a tunnel's device, or 0 when the device is not
// there. A var so the reconcile can be tested on a host with no tunnels.
var vpnOutTableOf = func(iface string) int {
	if strings.TrimSpace(iface) == "" {
		return 0
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return 0
	}
	return vpnOutRouteTableBase + link.Attrs().Index
}

// vpnOutListRules reads the kernel's IPv4 rules as decisions, keeping the netlink
// objects alongside so a deletion is issued against the rule that was enumerated.
var vpnOutListRules = func() ([]vpnOutRule, []netlink.Rule, error) {
	live, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return nil, nil, err
	}
	out := make([]vpnOutRule, len(live))
	for i, r := range live {
		out[i] = vpnOutRule{
			Priority: r.Priority,
			OifName:  r.OifName,
			IifName:  r.IifName,
			Table:    r.Table,
			Protocol: r.Protocol,
		}
		if r.Dst != nil && r.Dst.IP != nil {
			out[i].Dst = r.Dst.String()
		}
	}
	return out, live, nil
}

// vpnOutAddRule installs one via rule. A var for the same reason.
var vpnOutAddRule = func(r vpnOutRule) error {
	rule := netlink.NewRule()
	rule.Priority = r.Priority
	rule.Table = r.Table
	rule.Family = netlink.FAMILY_V4
	rule.Protocol = r.Protocol
	if r.Dst != "" {
		_, dst, err := net.ParseCIDR(r.Dst)
		if err != nil {
			return err
		}
		rule.Dst = dst
	}
	return netlink.RuleAdd(rule)
}

// vpnOutDelRule removes one, by the object it was enumerated as.
var vpnOutDelRule = func(r netlink.Rule) error { return netlink.RuleDel(&r) }

// vpnOutViaFactsOf gathers what the planner needs about every stored tunnel, and appends
// the carriers that are not tunnels.
//
// A tunnel whose server cannot be worked out (nothing typed yet, a name that does not
// resolve) is recorded with no addresses rather than dropped: it still has a table, so
// it can still be a CARRIER, and only its own carrying is impossible.
//
// `extra` are the carriers vpnOutCarrierFor resolved out of the outbound template - a
// freedom outbound's pinned device, or a synthesized carrier tun. They are appended
// rather than merged because the planner only ever looks a carrier up BY TAG: an entry
// with no Via of its own is a leaf of the chain and produces no rules by itself, and one
// a tunnel names becomes that tunnel's carrier exactly as another tunnel would.
func vpnOutViaFactsOf(list []VpnOutboundConfig, extra []vpnOutViaFacts) []vpnOutViaFacts {
	out := make([]vpnOutViaFacts, 0, len(list)+len(extra))
	seen := make(map[string]bool, len(list)+len(extra))
	for _, c := range list {
		f := vpnOutViaFacts{
			Tag:    c.Tag,
			Via:    strings.TrimSpace(c.Via),
			Enable: c.Enable,
			Table:  vpnOutTableOf(c.Iface),
		}
		// Only resolved for the tunnels a rule will name: the carried ones and the
		// carriers they name. Everything else would be a DNS lookup per tunnel on every
		// save for an answer nobody reads.
		if f.Via != "" || vpnOutIsCarrier(list, c.Tag) {
			addrs, _, err := vpnOutServerAddrs(c)
			if err != nil {
				logger.Warning("vpn outbound: cannot work out which server", c.Tag, "dials:", err)
			}
			f.ServerAddrs = addrs
		}
		seen[c.Tag] = true
		out = append(out, f)
	}
	// A TUNNEL WINS a tag collision. It should not happen - vpnOutCarrierFor answers with
	// the tunnel first and never reaches the outbound list for a tag that is one - but two
	// entries for one tag would make the plan depend on map order, and the tunnel's facts
	// are the ones read from the live device rather than from a template that also
	// contains a row this panel synthesized for that same tunnel.
	for _, f := range extra {
		if f.Tag == "" || seen[f.Tag] {
			continue
		}
		seen[f.Tag] = true
		f.Via = strings.TrimSpace(f.Via)
		out = append(out, f)
	}
	return out
}

func vpnOutIsCarrier(list []VpnOutboundConfig, tag string) bool {
	return len(vpnOutCarries(list, tag)) > 0
}

// vpnOutCarries names the enabled tunnels riding on this one.
func vpnOutCarries(list []VpnOutboundConfig, tag string) []string {
	if tag == "" {
		return nil
	}
	var out []string
	for _, c := range list {
		if c.Enable && c.Tag != tag && strings.TrimSpace(c.Via) == tag {
			out = append(out, c.Tag)
		}
	}
	sort.Strings(out)
	return out
}

// vpnOutViaInUse refuses to remove or disable a tunnel that is carrying others.
//
// Not a nicety. Taking a carrier away leaves the tunnels it carried RUNNING with their
// steer rules swept: their clients keep talking to their servers, straight out of the
// host's WAN, and every screen in the panel still shows them up. That is the same silent
// leak the blackhole exists to prevent, arrived at from the configuration side instead
// of the kernel side, and the blackhole cannot catch it because the rule pointing into
// the table is exactly what has been removed.
//
// Refusing rather than cascading: taking three other tunnels down because one was
// deleted is a bigger surprise than a refusal that names them.
func vpnOutViaInUse(list []VpnOutboundConfig, tag string) error {
	riders := vpnOutCarries(list, tag)
	if len(riders) == 0 {
		return nil
	}
	return fmt.Errorf("%s carries %s, which would egress in the clear without it, so clear their Dialer Proxy first",
		tag, strings.Join(riders, ", "))
}

// vpnOutApplyVia reconciles the two priority bands against the stored tunnels and the
// carriers that are not tunnels.
//
// Called after every save, delete and boot. Whole-set, so it is also the repair path:
// a steer rule left behind by a crash, or pointing at a table number a rebuilt device
// has since given up, is not in the plan and is removed here.
//
// `extra` has to arrive on EVERY call, not only the ones that touched a carrier. The
// reconcile deletes everything in the two bands that is not in the plan, so a call made
// without the carriers a tunnel rides on would compute a plan missing those steers and
// then remove them - taking a working carried tunnel out to the host's WAN, which is the
// one failure this whole file is built to prevent.
func vpnOutApplyVia(list []VpnOutboundConfig, extra []vpnOutViaFacts) {
	want, problems := vpnOutViaPlan(vpnOutViaFactsOf(list, extra))
	for _, p := range problems {
		logger.Warning("vpn outbound:", p+", so its traffic is not being carried")
	}
	have, live, err := vpnOutListRules()
	if err != nil {
		logger.Warning("vpn outbound: cannot read the routing rules, leaving the carried tunnels alone:", err)
		return
	}
	// Only the rules this panel put there. The reconcile deletes everything in the bands
	// that is not in the plan, so without this filter it would be promising that nothing
	// else on the host ever uses priority 10000-29999.
	band := make([]vpnOutRule, 0, len(have))
	bandIdx := make([]int, 0, len(have))
	for i, r := range have {
		if vpnOutRuleIsOurs(r) {
			band = append(band, r)
			bandIdx = append(bandIdx, i)
		}
	}
	add, del := vpnOutViaDiff(want, band)
	// Added BEFORE anything is removed. The two orders differ by one leak: remove first
	// and a tunnel whose rule is about to be re-added has a window with no rule at all,
	// and a carried tunnel with no steer rule egresses out of the host's WAN.
	for _, r := range add {
		if err := vpnOutAddRule(r); err != nil {
			logger.Warning("vpn outbound: cannot install the rule that carries traffic -", r.Why+":", err)
			continue
		}
		logger.Info("vpn outbound: carrying traffic -", r.Why)
	}
	for _, i := range del {
		if err := vpnOutDelRule(live[bandIdx[i]]); err != nil {
			logger.Warning("vpn outbound: cannot remove a stale carry rule:", err)
		}
	}
}

// vpnOutSteerVia installs the rules that carry one tunnel inside a carrier, and is called
// BEFORE the carried client is started.
//
// The ordering is the point. The steer rule needs the carried tunnel's SERVER address
// and the carrier's TABLE, and neither of them depends on the carried device existing,
// so there is no reason to wait - and every reason not to: a WireGuard client sends its
// first handshake the instant its peer is configured, and a rule added a moment later
// would arrive after that packet had already left in the clear.
//
// The carrier arrives as FACTS rather than as a tunnel, which is the whole of what this
// function gave up to let a carrier be an Xray outbound. The caller resolves it once -
// carrier.Enable from the tunnel or the outbound, carrier.Table from vpnOutTableOf of
// whichever device vpnOutCarrierFor named, carrier.ServerAddrs from vpnOutServerAddrs or
// from the outbound's own uplinks - and every refusal below is unchanged, because none of
// them was ever about the carrier being a tunnel.
func vpnOutSteerVia(carried VpnOutboundConfig, carrier vpnOutViaFacts) error {
	if !carrier.Enable {
		return fmt.Errorf("%s is carried by %s, which is disabled", carried.Tag, carrier.Tag)
	}
	if carrier.Table == 0 {
		return fmt.Errorf("%s is carried by %s, which is not up", carried.Tag, carrier.Tag)
	}
	carriedAddrs, _, err := vpnOutServerAddrs(carried)
	if err != nil {
		return err
	}
	// Trimmed here as well as at the caller, because a Via of one space is not "" and
	// vpnOutViaRules reads it as "this carrier is itself carried" - which silently drops
	// the exclusion that keeps the carrier's own outer transport out of itself.
	carrier.Via = strings.TrimSpace(carrier.Via)
	if err := vpnOutViaClash(carried.Tag, carriedAddrs, carrier.Tag, carrier.ServerAddrs); err != nil {
		return err
	}
	rules := vpnOutViaRules(
		vpnOutViaFacts{Tag: carried.Tag, Via: carrier.Tag, Enable: true, ServerAddrs: carriedAddrs},
		carrier,
	)
	have, _, err := vpnOutListRules()
	if err != nil {
		return fmt.Errorf("cannot read the routing rules: %w", err)
	}
	add, _ := vpnOutViaDiff(rules, have)
	for _, r := range add {
		if err := vpnOutAddRule(r); err != nil {
			return fmt.Errorf("cannot install the rule that carries %s inside %s: %w", carried.Tag, carrier.Tag, err)
		}
		logger.Info("vpn outbound: carrying traffic -", r.Why)
	}
	return nil
}

// vpnOutViaMtuCheck logs the MTU advice once both devices are up. Best effort: an
// unreadable link is not a reason to refuse a tunnel that is otherwise working.
func vpnOutViaMtuCheck(carried VpnOutboundConfig, carriedIface, carrierIface string) {
	carriedLink, err := netlink.LinkByName(carriedIface)
	if err != nil {
		return
	}
	carrierLink, err := netlink.LinkByName(carrierIface)
	if err != nil {
		return
	}
	if advice := vpnOutViaMtuAdvice(carried.Tag, carried.Kind,
		carriedLink.Attrs().MTU, carrierLink.Attrs().MTU); advice != "" {
		logger.Warning("vpn outbound:", advice)
	}
}
