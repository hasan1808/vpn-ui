package service

import (
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Carrying a tunnel inside a carrier is entirely a set of routing rules, so the whole
// feature is testable as two pure questions: which rules a set of carriers and tunnels
// implies, and which of the kernel's current rules are stale. Everything below asks one of
// those. No database, no netlink, no kernel.
//
// A carrier is no longer required to be another tunnel: vpnoutcarrier.go resolves an Xray
// outbound tag to a device and hands the planner the same fact tuple a tunnel produces. So
// the tests that follow carry the carrier in as vpnOutViaFacts wherever the planner does.

func viaCfg(tag, kind, via string) VpnOutboundConfig {
	return VpnOutboundConfig{Tag: tag, Kind: kind, Enable: true, Via: via, Iface: "if-" + tag}
}

func init() {
	// Registered from init, like vpnoutbound_test.go's fakes, so it is there however the
	// tests are ordered or filtered. The host is a LITERAL address: vpnOutViaFactsOf
	// resolves a carried tunnel's server, and a fake that needed a resolver for that would
	// be testing the resolver.
	RegisterVpnOutDriver("testviafixed", &fakeViaDriver{host: "203.0.113.10"})
}

// ---- refusals ---------------------------------------------------------------------

func TestVpnOutViaCheckRefusesSelf(t *testing.T) {
	all := []VpnOutboundConfig{viaCfg("wg-a", VpnOutWireguard, "")}
	cfg := viaCfg("wg-a", VpnOutWireguard, "wg-a")
	err := vpnOutViaCheck(all, nil, cfg)
	if err == nil {
		t.Fatal("a tunnel carried by itself was accepted")
	}
	if !strings.Contains(err.Error(), "wg-a") || !strings.Contains(err.Error(), "itself") {
		t.Errorf("the refusal does not name the tunnel or say what is wrong: %v", err)
	}
}

// The Dialer Proxy is offered on every outbound, tunnels included, so an operator can name
// anything there. What can be DELIVERED is now anything vpnOutCarrierFor resolves to a
// device - another tunnel, a freedom outbound's interface pin, or a carrier tun in front of
// a proxy outbound - and those arrive here already resolved, in `carriers`. So the only
// thing left for this function to refuse is a tag that is neither.
//
// This test used to assert the opposite: that every non-tunnel was refused, with a sentence
// explaining that an Xray outbound has no device to steer into. That sentence is now FALSE,
// and a false refusal is worse than none - it sends an operator to change a field that was
// right, over a limit the panel no longer has.
func TestVpnOutViaCheckRefusesATagThatIsNeitherTunnelNorCarrier(t *testing.T) {
	all := []VpnOutboundConfig{viaCfg("wg-a", VpnOutWireguard, "")}
	carriers := []vpnOutViaFacts{{Tag: "proxy-vless", Enable: true, Table: 30042}}

	t.Run("a tag nothing on this panel answers to", func(t *testing.T) {
		err := vpnOutViaCheck(all, carriers, viaCfg("gre-b", VpnOutGre, "proxy-vles"))
		if err == nil {
			t.Fatal("a Dialer Proxy naming neither a tunnel nor an outbound was accepted")
		}
		msg := err.Error()
		// The typo is named, because that is the whole of what the operator has to fix.
		for _, want := range []string{"proxy-vles", "gre-b", VpnOutGre, "not a tunnel and not an outbound"} {
			if !strings.Contains(msg, want) {
				t.Errorf("the refusal does not mention %q, so the operator cannot act on it: %v", want, err)
			}
		}
		if strings.Contains(msg, "no device to steer into") || strings.Contains(msg, "SOCKS5 Proxy") {
			t.Errorf("the refusal still claims an Xray outbound cannot be a carrier: %v", err)
		}
	})

	// The behaviour that was removed, pinned from the other side. A resolved carrier is
	// accepted whatever kind names it, INCLUDING the kinds the old refusal had a special
	// sentence for. Whether this kind survives this carrier is vpnOutCarrierRefusal's
	// question, asked in vpnoutcarrier.go where the carrier's device kind is known: a
	// netdev moves GRE and ESP, a carrier tun moves TCP and UDP, and this function can see
	// neither.
	t.Run("a carrier that is not a tunnel is accepted", func(t *testing.T) {
		for _, kind := range []string{VpnOutGre, VpnOutOpenVPN, VpnOutPPTP, VpnOutWireguard} {
			if err := vpnOutViaCheck(all, carriers, viaCfg("carried-"+kind, kind, "proxy-vless")); err != nil {
				t.Errorf("a %s tunnel was refused a carrier that resolves to a device: %v", kind, err)
			}
		}
	})

	// Same tag, no carriers: nothing resolved it, so it is refused again. This is what
	// makes the check fail-closed rather than permissive - the tag is accepted because a
	// carrier was RESOLVED for it, not because it looks like an outbound name.
	t.Run("an unresolved carrier is still refused", func(t *testing.T) {
		if err := vpnOutViaCheck(all, nil, viaCfg("gre-b", VpnOutGre, "proxy-vless")); err == nil {
			t.Fatal("a carrier tag that resolved to nothing was accepted")
		}
	})

	// A carrier is not a tunnel, so naming one must not make it look like one to the rest
	// of the panel: a tunnel tag of the same name still wins, and a chain THROUGH a
	// carrier is still walked for loops.
	t.Run("a loop closed through a carrier is still caught", func(t *testing.T) {
		err := vpnOutViaCheck(
			[]VpnOutboundConfig{viaCfg("a", VpnOutWireguard, "b"), viaCfg("b", VpnOutGre, "")},
			[]vpnOutViaFacts{{Tag: "proxy-vless", Enable: true, Table: 30042}},
			viaCfg("b", VpnOutGre, "a"))
		if err == nil || !strings.Contains(err.Error(), "b -> a -> b") {
			t.Errorf("the loop was not caught with carriers in play: %v", err)
		}
	})
}

// A three-tunnel loop is the case the operator cannot see from the field they are
// editing: the tunnel that closes it is two screens away, so the path has to be spelled
// out rather than reported as "a cycle".
func TestVpnOutViaCheckRefusesCyclesAndNamesThePath(t *testing.T) {
	t.Run("two", func(t *testing.T) {
		all := []VpnOutboundConfig{
			viaCfg("a", VpnOutWireguard, "b"),
			viaCfg("b", VpnOutGre, ""),
		}
		err := vpnOutViaCheck(all, nil, viaCfg("b", VpnOutGre, "a"))
		if err == nil {
			t.Fatal("a two-tunnel loop was accepted")
		}
		if got := err.Error(); !strings.Contains(got, "b -> a -> b") {
			t.Errorf("the path is not named: %v", err)
		}
	})

	t.Run("three", func(t *testing.T) {
		all := []VpnOutboundConfig{
			viaCfg("a", VpnOutWireguard, "b"),
			viaCfg("b", VpnOutGre, "c"),
			viaCfg("c", VpnOutL2TP, ""),
		}
		err := vpnOutViaCheck(all, nil, viaCfg("c", VpnOutL2TP, "a"))
		if err == nil {
			t.Fatal("a three-tunnel loop was accepted")
		}
		if got := err.Error(); !strings.Contains(got, "c -> a -> b -> c") {
			t.Errorf("the whole path is not named, so the operator cannot see which link to break: %v", err)
		}
	})

	t.Run("a chain that does not close is fine", func(t *testing.T) {
		all := []VpnOutboundConfig{
			viaCfg("a", VpnOutWireguard, "b"),
			viaCfg("b", VpnOutGre, "c"),
			viaCfg("c", VpnOutL2TP, ""),
		}
		if err := vpnOutViaCheck(all, nil, viaCfg("a", VpnOutWireguard, "b")); err != nil {
			t.Errorf("a -> b -> c was refused: %v", err)
		}
	})

	t.Run("a blank Via is always fine", func(t *testing.T) {
		if err := vpnOutViaCheck(nil, nil, viaCfg("a", VpnOutWireguard, "")); err != nil {
			t.Errorf("a tunnel with no carrier was refused: %v", err)
		}
	})
}

// The incoming config wins over the stored copy of the same tag. Without that, editing
// the tunnel that CLOSES a loop to break it would be refused for the loop it is being
// edited out of.
func TestVpnOutViaCheckReadsTheIncomingEdit(t *testing.T) {
	all := []VpnOutboundConfig{
		viaCfg("a", VpnOutWireguard, "b"),
		viaCfg("b", VpnOutGre, "a"), // the stored loop
	}
	if err := vpnOutViaCheck(all, nil, viaCfg("b", VpnOutGre, "")); err != nil {
		t.Errorf("breaking a stored loop was refused: %v", err)
	}
}

func TestVpnOutViaClash(t *testing.T) {
	carried := []string{"203.0.113.10/32"}
	t.Run("a shared server address is refused", func(t *testing.T) {
		err := vpnOutViaClash("a", carried, "b", []string{"198.51.100.1/32", "203.0.113.10/32"})
		if err == nil {
			t.Fatal("two tunnels dialling one address were accepted; a rule cannot tell them apart")
		}
		for _, want := range []string{"a", "b", "203.0.113.10"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not mention %q: %v", want, err)
			}
		}
		if strings.Contains(err.Error(), "/32") {
			t.Errorf("the operator is shown a prefix rather than the address they typed: %v", err)
		}
	})
	t.Run("different addresses are fine", func(t *testing.T) {
		if err := vpnOutViaClash("a", carried, "b", []string{"198.51.100.1/32"}); err != nil {
			t.Errorf("unrelated servers were refused: %v", err)
		}
	})
}

// Taking a carrier away is the refusal that is not about the tunnel being edited: the
// tunnels riding on it keep running with their steer rules swept, and the blackhole
// cannot catch that because the rule pointing into the table is what has been removed.
func TestVpnOutViaInUse(t *testing.T) {
	all := []VpnOutboundConfig{
		viaCfg("carrier", VpnOutGre, ""),
		viaCfg("rider-a", VpnOutWireguard, "carrier"),
		viaCfg("rider-b", VpnOutL2TP, "carrier"),
		{Tag: "off", Kind: VpnOutPPTP, Via: "carrier"}, // disabled: nothing running to leak
		viaCfg("unrelated", VpnOutSSTP, ""),
	}

	err := vpnOutViaInUse(all, "carrier")
	if err == nil {
		t.Fatal("a carrier with live riders was allowed to go away")
	}
	for _, want := range []string{"carrier", "rider-a", "rider-b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator cannot act on it: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "off") {
		t.Errorf("a disabled rider was counted: %v", err)
	}
	if err := vpnOutViaInUse(all, "unrelated"); err != nil {
		t.Errorf("a tunnel nothing rides on was refused: %v", err)
	}
	if err := vpnOutViaInUse(all, "rider-a"); err != nil {
		t.Errorf("a leaf tunnel was refused: %v", err)
	}
}

// ---- the rules themselves ----------------------------------------------------------

// The worked example, and the one measured end to end: gre-b carries wg-a.
func TestVpnOutViaRulesPrioritiesAndTables(t *testing.T) {
	carried := vpnOutViaFacts{Tag: "wg-a", Via: "gre-b", Enable: true,
		ServerAddrs: []string{"203.0.113.10/32"}}
	carrier := vpnOutViaFacts{Tag: "gre-b", Enable: true,
		ServerAddrs: []string{"198.51.100.7/32"}, Table: vpnOutRouteTableBase + 42}

	got := vpnOutViaRules(carried, carrier)
	if len(got) != 2 {
		t.Fatalf("got %d rules, want the exclusion and the steer: %+v", len(got), got)
	}
	slot := vpnOutViaSlot("wg-a")

	exclude, steer := got[0], got[1]
	if exclude.Dst != "198.51.100.7/32" {
		t.Errorf("the exclusion matches %q, want the CARRIER's own server", exclude.Dst)
	}
	if exclude.Table != vpnOutMainTable {
		t.Errorf("the exclusion looks up table %d, want main (%d): the carrier's own outer transport leaves the host normally",
			exclude.Table, vpnOutMainTable)
	}
	if exclude.Priority != vpnOutExcludeRuleBase+slot {
		t.Errorf("the exclusion is at priority %d, want %d", exclude.Priority, vpnOutExcludeRuleBase+slot)
	}
	if steer.Dst != "203.0.113.10/32" {
		t.Errorf("the steer matches %q, want the CARRIED tunnel's server", steer.Dst)
	}
	if steer.Table != carrier.Table {
		t.Errorf("the steer looks up table %d, want the carrier's table %d", steer.Table, carrier.Table)
	}
	if steer.Priority != vpnOutSteerRuleBase+slot {
		t.Errorf("the steer is at priority %d, want %d", steer.Priority, vpnOutSteerRuleBase+slot)
	}

	// The ORDER is the property, not the numbers. The exclusion has to be considered
	// first, or a carried tunnel that resolves to its carrier's own address wraps the
	// carrier's handshake inside the carrier.
	if !(exclude.Priority < steer.Priority) {
		t.Errorf("the exclusion (%d) does not sort before the steer (%d)", exclude.Priority, steer.Priority)
	}
	// And both have to be considered before the per-device egress rules, which live at
	// vpnOutRouteTableBase + ifindex.
	if steer.Priority >= vpnOutRouteTableBase {
		t.Errorf("the steer at %d collides with the oif block at %d and up", steer.Priority, vpnOutRouteTableBase)
	}
	// Neither rule names a device: that is what lets one rule serve TCP, UDP, GRE and
	// ESP alike and ask nothing of the client daemon.
	for _, r := range got {
		if r.OifName != "" {
			t.Errorf("a via rule selects on the device %q; it must select on the destination", r.OifName)
		}
		// Stamped, so the reconcile can delete by band without promising that nothing
		// else on the host uses these priorities.
		if r.Protocol != vpnOutRuleProto {
			t.Errorf("rule %+v carries no ownership stamp", r)
		}
	}
}

func TestVpnOutRuleIsOurs(t *testing.T) {
	ours := []vpnOutRule{
		{Priority: 20001, Dst: "203.0.113.10/32", Table: 30042, Protocol: vpnOutRuleProto},
		{Priority: 10001, Dst: "198.51.100.7/32", Table: vpnOutMainTable, Protocol: vpnOutRuleProto},
		// No stamp: a kernel older than 5.0 drops FRA_PROTOCOL. A steer is still
		// unmistakable, because nothing else on the host allocates table 30000+ifindex.
		{Priority: 20001, Dst: "203.0.113.10/32", Table: 30042},
	}
	for _, r := range ours {
		if !vpnOutRuleIsOurs(r) {
			t.Errorf("%+v was not recognised as this panel's, so it would never be cleaned up", r)
		}
	}

	theirs := []vpnOutRule{
		// Somebody else's rule that happens to share the band. Deleting it would be a
		// routing change this panel was never asked to make.
		{Priority: 15000, Dst: "192.0.2.1/32", Table: vpnOutMainTable},
		{Priority: 15000, Dst: "192.0.2.1/32", Table: 100, Protocol: 4},
		// Outside the bands entirely: the host's own, and our oif block.
		{Priority: 32766, Table: vpnOutMainTable, Protocol: vpnOutRuleProto},
		{Priority: 30042, OifName: "cgre-b", Table: 30042, Protocol: vpnOutRuleProto},
		// In band and stamped, but selecting on a device, which ours never do.
		{Priority: 20001, IifName: "eth0", Dst: "203.0.113.10/32", Table: 30042, Protocol: vpnOutRuleProto},
		// In band with no destination: ours always carry one.
		{Priority: 20001, Table: 30042, Protocol: vpnOutRuleProto},
	}
	for _, r := range theirs {
		if vpnOutRuleIsOurs(r) {
			t.Errorf("%+v was claimed by this panel and would be deleted", r)
		}
	}
}

// A kernel that cannot store the stamp must not make every reconcile delete and re-add
// the whole set, which would open the leak window on a timer.
func TestVpnOutViaDiffIgnoresTheStamp(t *testing.T) {
	want := []vpnOutRule{{Priority: 20001, Dst: "203.0.113.10/32", Table: 30042, Protocol: vpnOutRuleProto}}
	have := []vpnOutRule{{Priority: 20001, Dst: "203.0.113.10/32", Table: 30042}}
	add, del := vpnOutViaDiff(want, have)
	if len(add) != 0 || len(del) != 0 {
		t.Errorf("add = %+v, del = %v; an unstamped but otherwise identical rule was churned", add, del)
	}
}

// Every address a name resolves to gets a steer. One of four is not "carried", it is
// three leaks waiting for a retry.
func TestVpnOutViaRulesCoverEveryResolvedAddress(t *testing.T) {
	got := vpnOutViaRules(
		vpnOutViaFacts{Tag: "a", Via: "b", Enable: true,
			ServerAddrs: []string{"203.0.113.10/32", "203.0.113.11/32"}},
		vpnOutViaFacts{Tag: "b", Enable: true, ServerAddrs: []string{"198.51.100.7/32"}, Table: 30042},
	)
	var steered []string
	for _, r := range got {
		if r.Table == 30042 {
			steered = append(steered, r.Dst)
		}
	}
	want := []string{"203.0.113.10/32", "203.0.113.11/32"}
	if !reflect.DeepEqual(steered, want) {
		t.Errorf("steered %v, want every resolved address %v", steered, want)
	}
}

// In a chain the middle tunnel's own outer transport belongs in ITS carrier's table, so
// nothing may put a main-table exclusion for it at a lower priority.
func TestVpnOutViaRulesSkipTheExclusionForACarriedCarrier(t *testing.T) {
	got := vpnOutViaRules(
		vpnOutViaFacts{Tag: "a", Via: "b", Enable: true, ServerAddrs: []string{"203.0.113.10/32"}},
		vpnOutViaFacts{Tag: "b", Via: "c", Enable: true, ServerAddrs: []string{"198.51.100.7/32"}, Table: 30042},
	)
	for _, r := range got {
		if r.Table == vpnOutMainTable {
			t.Fatalf("b is itself carried, but an exclusion sends its outer transport to main: %+v", r)
		}
	}
	if len(got) != 1 {
		t.Fatalf("got %d rules, want only the steer: %+v", len(got), got)
	}
}

func TestVpnOutViaRulesRefuseACarrierWithNoTable(t *testing.T) {
	got := vpnOutViaRules(
		vpnOutViaFacts{Tag: "a", Via: "b", Enable: true, ServerAddrs: []string{"203.0.113.10/32"}},
		vpnOutViaFacts{Tag: "b", Enable: true, ServerAddrs: []string{"198.51.100.7/32"}, Table: 0},
	)
	if got != nil {
		t.Fatalf("rules were built for a carrier whose device is down: %+v", got)
	}
}

func TestVpnOutViaPlan(t *testing.T) {
	facts := []vpnOutViaFacts{
		{Tag: "wg-a", Via: "gre-b", Enable: true, ServerAddrs: []string{"203.0.113.10/32"}, Table: 30011},
		{Tag: "gre-b", Enable: true, ServerAddrs: []string{"198.51.100.7/32"}, Table: 30042},
		{Tag: "l2tp-c", Via: "nope", Enable: true, ServerAddrs: []string{"192.0.2.5/32"}, Table: 30013},
		{Tag: "l2tp-d", Via: "gre-b", Enable: false, ServerAddrs: []string{"192.0.2.6/32"}, Table: 0},
		{Tag: "pptp-e", Via: "down-f", Enable: true, ServerAddrs: []string{"192.0.2.7/32"}, Table: 30015},
		{Tag: "down-f", Enable: true, ServerAddrs: []string{"192.0.2.8/32"}, Table: 0},
	}
	rules, problems := vpnOutViaPlan(facts)

	if len(rules) != 2 {
		t.Fatalf("got %d rules, want only wg-a's pair: %+v", len(rules), rules)
	}
	// A disabled tunnel gets nothing: it has no client running, so there is nothing to
	// carry, and a rule left behind would steer whatever else reaches that address.
	for _, r := range rules {
		if strings.Contains(r.Why, "l2tp-d") {
			t.Errorf("a disabled tunnel was given a rule: %+v", r)
		}
	}
	// Every refusal is reported, and each one names both ends so the log line is
	// actionable on its own.
	joined := strings.Join(problems, "; ")
	for _, want := range []string{"l2tp-c", "nope", "pptp-e", "down-f"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the problems do not mention %q: %v", want, problems)
		}
	}
	// A carrier that is absent from the facts is now absent from BOTH catalogues - the
	// tunnels and the resolved carriers - so the line no longer says "not a tunnel", which
	// would read as "pick a tunnel" when an outbound would have done.
	if !strings.Contains(joined, "not a tunnel and not an outbound on this panel") {
		t.Errorf("the unknown-carrier problem still tells the operator it has to be a tunnel: %v", problems)
	}
	if strings.Contains(joined, "l2tp-d") {
		t.Errorf("a deliberately disabled tunnel was reported as a problem: %v", problems)
	}
}

// A carrier that is not a tunnel reaches the planner as `extra` facts, and from there the
// planner cannot tell it apart from a tunnel: the steer names a TABLE, and a table is a
// table whichever device filled it. This is the whole of what widening the carrier cost
// this file.
func TestVpnOutViaFactsOfAppendsCarriersThatAreNotTunnels(t *testing.T) {
	defer swapVia(&vpnOutTableOf, func(iface string) int {
		switch iface {
		case "if-wg-a":
			return 30011
		case "if-dup":
			return 30022
		}
		return 0
	})()

	list := []VpnOutboundConfig{
		{Tag: "wg-a", Kind: "testviafixed", Enable: true, Iface: "if-wg-a"},
		{Tag: "dup", Kind: "testviafixed", Enable: true, Iface: "if-dup", Via: "proxy-vless"},
	}
	extra := []vpnOutViaFacts{
		{Tag: "proxy-vless", Enable: true, Table: 30042},
		// Should never happen: vpnOutCarrierFor answers with the tunnel before it ever
		// reads the outbound list, and vpnOutCarrierPlan drops tunnel carriers. Pinned
		// anyway, because two entries for one tag would make the plan depend on map order.
		{Tag: "dup", Enable: true, Table: 39999},
		// A carrier with no tag can never be named, so it could only ever collide.
		{Tag: "", Enable: true, Table: 30077},
	}

	got := vpnOutViaFactsOf(list, extra)
	byTag := map[string]vpnOutViaFacts{}
	for _, f := range got {
		if _, dup := byTag[f.Tag]; dup {
			t.Errorf("%q appears twice in the facts: %+v", f.Tag, got)
		}
		byTag[f.Tag] = f
	}
	if len(got) != 3 {
		t.Fatalf("got %d facts, want the two tunnels and the one carrier: %+v", len(got), got)
	}
	if _, blank := byTag[""]; blank {
		t.Error("a carrier with no tag was added to the facts")
	}
	if c := byTag["proxy-vless"]; c.Table != 30042 || !c.Enable {
		t.Errorf("the carrier's facts did not survive being appended: %+v", c)
	}
	if d := byTag["dup"]; d.Table != 30022 || d.Via != "proxy-vless" {
		t.Errorf("an extra won a tag collision with a tunnel: %+v; the tunnel's table is read from its live device", d)
	}
}

func TestVpnOutViaPlanSteersIntoACarrierThatIsNotATunnel(t *testing.T) {
	defer swapVia(&vpnOutTableOf, func(iface string) int {
		if iface == "if-wg-a" {
			return 30011
		}
		return 0
	})()
	list := []VpnOutboundConfig{
		{Tag: "wg-a", Kind: "testviafixed", Enable: true, Iface: "if-wg-a", Via: "proxy-vless"},
	}

	t.Run("the steer looks up the carrier's table", func(t *testing.T) {
		rules, problems := vpnOutViaPlan(vpnOutViaFactsOf(list, []vpnOutViaFacts{
			{Tag: "proxy-vless", Enable: true, ServerAddrs: []string{"198.51.100.7/32"}, Table: 30042},
		}))
		if len(problems) != 0 {
			t.Fatalf("a carrier that is not a tunnel was reported as a problem: %v", problems)
		}
		var steers, excludes []vpnOutRule
		for _, r := range rules {
			switch r.Table {
			case 30042:
				steers = append(steers, r)
			case vpnOutMainTable:
				excludes = append(excludes, r)
			default:
				t.Errorf("a rule looks up table %d, which is neither the carrier's nor main: %+v", r.Table, r)
			}
		}
		if len(steers) != 1 || steers[0].Dst != "203.0.113.10/32" {
			t.Fatalf("steers = %+v, want wg-a's own server steered into the carrier's table", steers)
		}
		// The carrier's own uplink is pinned to main exactly as a tunnel carrier's server
		// is. Without it the core would dial the address that feeds the carrier THROUGH
		// the carrier, which is the loop proxy/tun/README.md warns about.
		if len(excludes) != 1 || excludes[0].Dst != "198.51.100.7/32" {
			t.Fatalf("excludes = %+v, want the carrier's own uplink pinned to main", excludes)
		}
	})

	// Table 0 is the fail-closed value and it means "the device is not there": for a
	// bridged carrier that is Xray stopped, or the tun not created yet. Nothing may be
	// steered into it - a rule naming table 0 would be a rule with no route in it, and the
	// lookup falls through to main and out of the host's WAN in the clear.
	t.Run("a carrier with no table carries nothing", func(t *testing.T) {
		rules, problems := vpnOutViaPlan(vpnOutViaFactsOf(list, []vpnOutViaFacts{
			{Tag: "proxy-vless", Enable: true, ServerAddrs: []string{"198.51.100.7/32"}},
		}))
		if len(rules) != 0 {
			t.Fatalf("rules were built for a carrier with no device: %+v", rules)
		}
		joined := strings.Join(problems, "; ")
		for _, want := range []string{"wg-a", "proxy-vless", "not up"} {
			if !strings.Contains(joined, want) {
				t.Errorf("the problem does not mention %q: %v", want, problems)
			}
		}
	})
}

// vpnOutSteerVia takes the carrier as FACTS now, so the two guards that used to be derived
// from a tunnel row - its Enable flag, and vpnOutTableOf of its device - are read off the
// tuple instead. Both are fail-closed, and neither may reach netlink: a rule installed for
// a carrier that cannot carry is a rule pointing into an empty table.
func TestVpnOutViaSteerTakesCarrierFacts(t *testing.T) {
	var added []vpnOutRule
	defer swapVia(&vpnOutListRules, func() ([]vpnOutRule, []netlink.Rule, error) { return nil, nil, nil })()
	defer swapVia(&vpnOutAddRule, func(r vpnOutRule) error {
		added = append(added, r)
		return nil
	})()

	carried := VpnOutboundConfig{Tag: "wg-a", Kind: "testviafixed", Enable: true, Iface: "if-wg-a"}

	for _, tc := range []struct {
		name    string
		carrier vpnOutViaFacts
		want    string
	}{
		{"disabled", vpnOutViaFacts{Tag: "proxy-vless", Table: 30042}, "disabled"},
		{"no device", vpnOutViaFacts{Tag: "proxy-vless", Enable: true}, "not up"},
		// One address, two tunnels: a rule selects on the destination and cannot tell them
		// apart, and the exclusion is the lower rule, so the carried tunnel would leave in
		// the clear while every screen called it carried.
		{"a shared address", vpnOutViaFacts{Tag: "proxy-vless", Enable: true, Table: 30042,
			ServerAddrs: []string{"203.0.113.10/32"}}, "203.0.113.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := vpnOutSteerVia(carried, tc.carrier)
			if err == nil {
				t.Fatalf("a carrier that is %s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not say %q: %v", tc.want, err)
			}
		})
	}
	if len(added) != 0 {
		t.Fatalf("a refused carrier still installed %+v", added)
	}

	t.Run("a resolved carrier gets the exclusion and the steer", func(t *testing.T) {
		added = nil
		err := vpnOutSteerVia(carried, vpnOutViaFacts{Tag: "proxy-vless", Enable: true,
			Table: 30042, ServerAddrs: []string{"198.51.100.7/32"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(added) != 2 {
			t.Fatalf("installed %+v, want the carrier's exclusion and wg-a's steer", added)
		}
		if added[0].Table != vpnOutMainTable || added[0].Dst != "198.51.100.7/32" {
			t.Errorf("the first rule is %+v, want the carrier's own uplink pinned to main", added[0])
		}
		if added[1].Table != 30042 || added[1].Dst != "203.0.113.10/32" {
			t.Errorf("the second rule is %+v, want wg-a's server steered into table 30042", added[1])
		}
	})

	// A carrier that is ITSELF carried must not have its uplink pinned to main: that
	// exclusion sits below its own steer rule and would quietly un-carry it. Whitespace
	// counts as a Via, or one stray space in a stored field turns the chain back off.
	t.Run("a carried carrier keeps its own steer", func(t *testing.T) {
		for _, via := range []string{"upstream", "  upstream  "} {
			added = nil
			if err := vpnOutSteerVia(carried, vpnOutViaFacts{Tag: "proxy-vless", Via: via, Enable: true,
				Table: 30042, ServerAddrs: []string{"198.51.100.7/32"}}); err != nil {
				t.Fatal(err)
			}
			if len(added) != 1 || added[0].Table != 30042 {
				t.Errorf("via %q installed %+v, want only the steer", via, added)
			}
		}
	})
}

// ---- the diff, which is what makes the reconcile safe -------------------------------

func TestVpnOutViaDiff(t *testing.T) {
	want := []vpnOutRule{
		{Priority: 10001, Dst: "198.51.100.7/32", Table: vpnOutMainTable},
		{Priority: 20001, Dst: "203.0.113.10/32", Table: 30042},
	}
	have := []vpnOutRule{
		{Priority: 20001, Dst: "203.0.113.10/32", Table: 30042}, // already right
		{Priority: 20001, Dst: "203.0.113.10/32", Table: 30007}, // stale: the ifindex moved
		{Priority: 20099, Dst: "192.0.2.9/32", Table: 30042},    // a tunnel that is gone
	}
	add, del := vpnOutViaDiff(want, have)

	if len(add) != 1 || add[0].Priority != 10001 {
		t.Errorf("add = %+v, want only the missing exclusion", add)
	}
	if !reflect.DeepEqual(del, []int{1, 2}) {
		t.Errorf("del = %v, want the stale table pointer and the orphan (indices 1 and 2)", del)
	}
}

func TestVpnOutViaDiffDoesNotAskForTheSameRuleTwice(t *testing.T) {
	dup := vpnOutRule{Priority: 10001, Dst: "198.51.100.7/32", Table: vpnOutMainTable}
	add, del := vpnOutViaDiff([]vpnOutRule{dup, dup}, nil)
	if len(add) != 1 {
		t.Errorf("add = %+v, want one rule: two carried tunnels sharing a carrier and a slot must not stack rules", add)
	}
	if del != nil {
		t.Errorf("del = %v, want nothing", del)
	}
}

func TestVpnOutInViaBandLeavesTheHostAlone(t *testing.T) {
	// The host's own rules, which this framework must never touch.
	for _, p := range []int{0, 100, 32766, 32767, vpnOutRouteTableBase, vpnOutRouteTableBase + 42} {
		if vpnOutInViaBand(p) {
			t.Errorf("priority %d was claimed by the via bands", p)
		}
	}
	for _, p := range []int{vpnOutExcludeRuleBase, vpnOutSteerRuleBase, vpnOutSteerRuleBase + 9999} {
		if !vpnOutInViaBand(p) {
			t.Errorf("priority %d is a via rule but was not recognised as one", p)
		}
	}
}

// ---- the sweep, and its ordering ----------------------------------------------------

func TestVpnOutStaleRuleIdx(t *testing.T) {
	const table = 30042
	have := []vpnOutRule{
		{Priority: 30042, OifName: "cgre-b", Table: 30042}, // the current oif rule
		{Priority: 30007, OifName: "cgre-b", Table: 30007}, // left from a previous ifindex
		{Priority: 20001, Dst: "203.0.113.10/32", Table: table},
		{Priority: 10001, Dst: "198.51.100.7/32", Table: vpnOutMainTable},
		{Priority: 30099, OifName: "vwg-other", Table: 30099}, // somebody else's
		{Priority: 32766, Table: vpnOutMainTable},             // the host's own
	}

	t.Run("a rebind keeps the current rule and the live steers", func(t *testing.T) {
		got := vpnOutStaleRuleIdx(have, "cgre-b", 0, table)
		if !reflect.DeepEqual(got, []int{1}) {
			t.Errorf("got %v, want only the leftover oif rule at index 1", got)
		}
	})

	t.Run("a teardown takes the steers pointing into this table too", func(t *testing.T) {
		got := vpnOutStaleRuleIdx(have, "cgre-b", table, 0)
		// Indices 0 and 1 are this device's oif rules; index 2 is the steer belonging to
		// a tunnel this one CARRIES, and it is the one that turns the teardown into a
		// leak if it outlives the table.
		if !reflect.DeepEqual(got, []int{0, 1, 2}) {
			t.Errorf("got %v, want the two oif rules and the steer into this table", got)
		}
	})

	t.Run("nothing outside the bands or this device is touched", func(t *testing.T) {
		for _, i := range vpnOutStaleRuleIdx(have, "cgre-b", table, 0) {
			if i == 4 || i == 5 {
				t.Errorf("rule %d belongs to another tunnel or to the host and was swept", i)
			}
		}
	})
}

// The measured leak is an ordering bug: delete the carrier's table while a steer rule
// still points at it and the lookup falls through to main. This pins the order down.
func TestVpnOutUnbindEgressSweepsSteersBeforeFlushingTheTable(t *testing.T) {
	const table = 30042
	live := []netlink.Rule{
		{Priority: 30042, OifName: "cgre-b", Table: table},
		{Priority: 20001, Table: table, Dst: &net.IPNet{IP: net.IPv4(203, 0, 113, 10), Mask: net.CIDRMask(32, 32)}},
	}
	seen := []vpnOutRule{{Priority: 30042, OifName: "cgre-b", Table: table},
		{Priority: 20001, Table: table, Dst: "203.0.113.10/32"}}

	var events []string
	defer swapVia(&vpnOutTableOf, func(iface string) int {
		if iface == "cgre-b" {
			return table
		}
		return 0
	})()
	defer swapVia(&vpnOutListRules, func() ([]vpnOutRule, []netlink.Rule, error) {
		return seen, live, nil
	})()
	defer swapVia(&vpnOutDelRule, func(r netlink.Rule) error {
		events = append(events, "del rule "+itoaVia(r.Priority))
		return nil
	})()
	defer swapVia(&vpnOutFlushTable, func(int) { events = append(events, "flush table") })()

	vpnOutUnbindEgress("cgre-b")

	want := []string{"del rule 30042", "del rule 20001", "flush table"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v: the steer at 20001 belongs to a tunnel this one CARRIES, "+
			"and it has to go before the table (with its blackhole) is emptied", events, want)
	}
}

// A tunnel that is being rebound must NOT have the live steers pointing into its table
// removed: the reconcile that follows a raise owns them, and deleting one here to add it
// back a moment later opens exactly the window this scheme exists to close.
func TestVpnOutBindEgressSweepLeavesLiveSteersAlone(t *testing.T) {
	const table = 30042
	have := []vpnOutRule{
		{Priority: 30042, OifName: "cgre-b", Table: table},
		{Priority: 20001, Dst: "203.0.113.10/32", Table: table},
	}
	// This is the call vpnOutBindEgress makes: table 0 turns the steer half off.
	if got := vpnOutStaleRuleIdx(have, "cgre-b", 0, table); len(got) != 0 {
		t.Errorf("a rebind would delete %v; the live steer must survive it", got)
	}
}

// ---- the fail-closed route -----------------------------------------------------------

func TestVpnOutEgressRoutesAlwaysCarryTheBlackhole(t *testing.T) {
	const table = 30042
	got := vpnOutEgressRoutes(table, 42)
	if len(got) != 2 {
		t.Fatalf("got %d routes, want the blackhole and the device route: %+v", len(got), got)
	}

	blackhole, device := got[0], got[1]
	if blackhole.Type != unix.RTN_BLACKHOLE {
		t.Errorf("the first route is type %d, want RTN_BLACKHOLE (%d)", blackhole.Type, unix.RTN_BLACKHOLE)
	}
	if blackhole.Priority != vpnOutBlackholeMetric {
		t.Errorf("the blackhole is at metric %d, want %d", blackhole.Priority, vpnOutBlackholeMetric)
	}
	if blackhole.LinkIndex != 0 {
		t.Errorf("the blackhole names device %d; it has to survive the device going away", blackhole.LinkIndex)
	}
	if blackhole.Table != table {
		t.Errorf("the blackhole is in table %d, want %d", blackhole.Table, table)
	}
	if device.LinkIndex != 42 || device.Table != table {
		t.Errorf("the device route is %+v, want dev 42 in table %d", device, table)
	}
	// Inert while the tunnel is up: the kernel prefers the lower metric, so the device
	// route wins every lookup and the blackhole is only ever reached once the device
	// route is gone with its device.
	if !(device.Priority < blackhole.Priority) {
		t.Errorf("the device route (metric %d) does not beat the blackhole (metric %d), so the tunnel would black-hole itself",
			device.Priority, blackhole.Priority)
	}
	// The blackhole is installed FIRST, so a failure halfway leaves a table that drops
	// traffic rather than one that leaks it.
	if got[0].Type != unix.RTN_BLACKHOLE {
		t.Error("the blackhole is not installed first")
	}
	for _, r := range got {
		if r.Dst == nil || r.Dst.String() != "0.0.0.0/0" {
			t.Errorf("route %+v does not cover everything; a table with a hole in it falls through to main", r)
		}
	}
}

// Every tunnel, not only the carriers. A tunnel that becomes a carrier later must not
// need re-binding to be safe, and the plain oif path wants it too.
func TestVpnOutEgressRoutesDoNotDependOnBeingACarrier(t *testing.T) {
	for _, table := range []int{30001, 30500, 39999} {
		got := vpnOutEgressRoutes(table, 7)
		if len(got) != 2 || got[0].Type != unix.RTN_BLACKHOLE {
			t.Errorf("table %d got %+v, want a blackhole in every tunnel table", table, got)
		}
	}
}

// ---- storage compatibility ------------------------------------------------------------

// Every stored tunnel predates this field, and the whole list is re-marshalled whenever
// anything in it changes. Without omitempty that write would add `"via":""` to rows
// nobody touched, and the list is what the Xray outbounds are derived from.
func TestVpnOutboundConfigWithNoViaReMarshalsByteIdentically(t *testing.T) {
	const stored = `[{"tag":"wg-a","kind":"wireguard","remark":"home","enable":true,` +
		`"iface":"vwg-wg-a","settings":{"endpoint":"203.0.113.10:51820","mtu":1420}}]`

	var list []VpnOutboundConfig
	if err := json.Unmarshal([]byte(stored), &list); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != stored {
		t.Errorf("a stored tunnel did not survive a load/save round trip unchanged:\n got %s\nwant %s", out, stored)
	}
}

func TestVpnOutboundConfigCarriesViaWhenSet(t *testing.T) {
	out, err := json.Marshal([]VpnOutboundConfig{{
		Tag: "wg-a", Kind: "wireguard", Enable: true, Iface: "vwg-wg-a", Via: "gre-b",
		Settings: json.RawMessage(`{}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"via":"gre-b"`) {
		t.Errorf("via was dropped from the stored form: %s", out)
	}
}

// ---- boot order --------------------------------------------------------------------

func TestVpnOutViaOrderRaisesCarriersFirst(t *testing.T) {
	// Stored worst-case: the carried tunnel is listed before its carrier, and the chain
	// runs backwards through the list.
	list := []VpnOutboundConfig{
		viaCfg("a", VpnOutWireguard, "b"),
		viaCfg("b", VpnOutGre, "c"),
		viaCfg("c", VpnOutL2TP, ""),
		viaCfg("solo", VpnOutPPTP, ""),
	}
	order, dropped := vpnOutViaOrder(list)
	if len(dropped) != 0 {
		t.Fatalf("dropped %v from a list with no loop in it", dropped)
	}
	var tags []string
	for _, i := range order {
		tags = append(tags, list[i].Tag)
	}
	pos := map[string]int{}
	for i, tag := range tags {
		pos[tag] = i
	}
	if len(tags) != len(list) {
		t.Fatalf("order = %v, want every tunnel", tags)
	}
	if !(pos["c"] < pos["b"] && pos["b"] < pos["a"]) {
		t.Errorf("order = %v, want c before b before a: a carried tunnel raised before its carrier finds an empty table", tags)
	}
}

func TestVpnOutViaOrderDropsAHandEditedLoop(t *testing.T) {
	list := []VpnOutboundConfig{
		viaCfg("a", VpnOutWireguard, "b"),
		viaCfg("b", VpnOutGre, "a"),
		viaCfg("ok", VpnOutL2TP, ""),
		viaCfg("downstream", VpnOutPPTP, "a"), // hangs off the loop
	}
	order, dropped := vpnOutViaOrder(list)
	if len(order) != 1 || list[order[0]].Tag != "ok" {
		var tags []string
		for _, i := range order {
			tags = append(tags, list[i].Tag)
		}
		t.Errorf("order = %v, want only the tunnel that is not entangled", tags)
	}
	want := map[string]bool{"a": true, "b": true, "downstream": true}
	for _, tag := range dropped {
		if !want[tag] {
			t.Errorf("dropped %q, which is not part of the loop or downstream of it", tag)
		}
		delete(want, tag)
	}
	if len(want) != 0 {
		t.Errorf("these were raised despite having nowhere fail-closed to go: %v", want)
	}
}

// ---- hostnames and MTU ----------------------------------------------------------------

func TestVpnOutHostOf(t *testing.T) {
	cases := map[string]string{
		"203.0.113.10":                    "203.0.113.10",
		"203.0.113.10:51820":              "203.0.113.10",
		"vpn.example.com":                 "vpn.example.com",
		"vpn.example.com:443":             "vpn.example.com",
		"https://vpn.example.com/portal":  "vpn.example.com",
		"https://vpn.example.com:8443/gp": "vpn.example.com",
		"socks5://10.0.0.1:1080":          "10.0.0.1",
		"vpn.example.com/gp":              "vpn.example.com",
		"[2001:db8::1]:51820":             "2001:db8::1",
		"2001:db8::1":                     "2001:db8::1",
		"  203.0.113.10  ":                "203.0.113.10",
		"":                                "",
	}
	for in, want := range cases {
		if got := vpnOutHostOf(in); got != want {
			t.Errorf("vpnOutHostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVpnOutServerAddrsResolvesAndSorts(t *testing.T) {
	RegisterVpnOutDriver("testvia", &fakeViaDriver{host: "vpn.example.com"})
	defer swapVia(&vpnOutLookupIP, func(host string) ([]net.IP, error) {
		if host != "vpn.example.com" {
			return nil, errors.New("unexpected host " + host)
		}
		// Deliberately out of order and with a v6 answer mixed in, which is what a real
		// resolver hands back.
		return []net.IP{
			net.ParseIP("203.0.113.20"),
			net.ParseIP("2001:db8::1"),
			net.ParseIP("203.0.113.10"),
			net.ParseIP("203.0.113.10"),
		}, nil
	})()

	got, host, err := vpnOutServerAddrs(VpnOutboundConfig{Tag: "a", Kind: "testvia"})
	if err != nil {
		t.Fatal(err)
	}
	if host != "vpn.example.com" {
		t.Errorf("host = %q", host)
	}
	want := []string{"203.0.113.10/32", "203.0.113.20/32"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v: every v4 answer, deduplicated and in a stable order", got, want)
	}
}

func TestVpnOutServerAddrsRefusesADriverThatCannotSayWhereItDials(t *testing.T) {
	// "testplain" is the bare fake from vpnoutbound_test.go: no ServerHost.
	_, _, err := vpnOutServerAddrs(VpnOutboundConfig{Tag: "a", Kind: "testplain"})
	if err == nil {
		t.Fatal("a driver with no server was accepted; there is no address to build a rule from")
	}
}

// Every shipped protocol has to be able to say where it dials, or it can be picked as a
// carrier in the UI and refused at save.
func TestEveryVpnOutDriverNamesItsServer(t *testing.T) {
	for _, kind := range VpnOutKinds() {
		if strings.HasPrefix(kind, "test") {
			continue
		}
		drv, err := vpnOutDriverFor(kind)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := drv.(VpnOutServer); !ok {
			t.Errorf("the %s driver does not implement VpnOutServer, so it can be neither carried nor a carrier", kind)
		}
	}
}

// A proxied tunnel never sends a packet to its VPN server, so a rule naming the server
// would match nothing and the tunnel would quietly not be carried. Three drivers can be
// pointed at a proxy and all three have to answer with the proxy.
func TestVpnOutDriverServerHostPrefersTheProxy(t *testing.T) {
	for _, tc := range []struct {
		kind     string
		settings string
		want     string
	}{
		{VpnOutOpenVPN, `{"server":"vpn.example.com","socksProxy":"10.0.0.1"}`, "10.0.0.1"},
		{VpnOutOpenVPN, `{"server":"vpn.example.com"}`, "vpn.example.com"},
		// The profile is where a real .ovpn keeps the remote, and it has to be read out
		// of one without being fooled by a `remote` inside a PEM body.
		{VpnOutOpenVPN, `{"profile":"client\n<ca>\nremote notthis 1\n</ca>\nremote 203.0.113.9 1194 udp\nremote 203.0.113.99 1194\n"}`, "203.0.113.9"},
		{VpnOutOpenConnect, `{"server":"https://vpn.example.com/gp","proxy":"socks5://10.0.0.2:1080"}`, "socks5://10.0.0.2:1080"},
		{VpnOutOpenConnect, `{"server":"https://vpn.example.com/gp"}`, "https://vpn.example.com/gp"},
		{VpnOutSSTP, `{"server":"vpn.example.com","proxy":"http://10.0.0.3:3128"}`, "http://10.0.0.3:3128"},
		{VpnOutSSTP, `{"server":"vpn.example.com"}`, "vpn.example.com"},
		{VpnOutWireguard, `{"endpoint":"203.0.113.10:51820","privateKey":"k","peerPublicKey":"p"}`, "203.0.113.10:51820"},
		{VpnOutGre, `{"server":"203.0.113.11"}`, "203.0.113.11"},
		{VpnOutIKEv2, `{"server":"vpn.example.com"}`, "vpn.example.com"},
	} {
		drv, err := vpnOutDriverFor(tc.kind)
		if err != nil {
			t.Fatal(err)
		}
		named, ok := drv.(VpnOutServer)
		if !ok {
			t.Fatalf("%s does not implement VpnOutServer", tc.kind)
		}
		got, err := named.ServerHost(VpnOutboundConfig{
			Tag: "t", Kind: tc.kind, Settings: json.RawMessage(tc.settings),
		})
		if err != nil {
			t.Errorf("%s %s: %v", tc.kind, tc.settings, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s %s: ServerHost = %q, want %q", tc.kind, tc.settings, got, tc.want)
		}
	}
}

func TestVpnOutViaMtuAdvice(t *testing.T) {
	t.Run("too big is named with the number that fits", func(t *testing.T) {
		got := vpnOutViaMtuAdvice("wg-a", VpnOutWireguard, 1420, 1420)
		if got == "" {
			t.Fatal("a carried WireGuard tunnel at the carrier's own MTU was passed as fine")
		}
		if !strings.Contains(got, "1360") {
			t.Errorf("the advice does not name the MTU that fits (1420 - 60): %q", got)
		}
		if !strings.Contains(got, "wg-a") {
			t.Errorf("the advice does not name the tunnel: %q", got)
		}
	})
	t.Run("a fitting MTU says nothing", func(t *testing.T) {
		if got := vpnOutViaMtuAdvice("wg-a", VpnOutWireguard, 1360, 1420); got != "" {
			t.Errorf("got %q, want silence", got)
		}
	})
	t.Run("an unknown MTU says nothing", func(t *testing.T) {
		if got := vpnOutViaMtuAdvice("wg-a", VpnOutWireguard, 0, 1420); got != "" {
			t.Errorf("got %q, want silence when there is nothing to compare", got)
		}
	})
	t.Run("an unknown kind still gets an answer", func(t *testing.T) {
		if got := vpnOutViaMtuAdvice("x", "something-new", 1500, 1420); got == "" {
			t.Error("a kind with no overhead entry was silently passed")
		}
	})
	// The two ESP figures were WRONG and are corrected. IKEv2's left out the 8 bytes NAT-T
	// adds, and NAT-T is not optional here: the driver forces UDP encapsulation whenever
	// the carrier is an Xray outbound, because raw ESP is one of the things a carrier tun
	// drops. The L2TP figure counted no IPsec leg at all. Both fitted MTUs move DOWN, which
	// is the direction that matters - an overhead that is too small hands back an MTU that
	// passes a ping and black-holes full-size packets.
	t.Run("the ESP kinds count their own encapsulation", func(t *testing.T) {
		for _, tc := range []struct{ kind, fits string }{
			{VpnOutIKEv2, "1339"}, // 1420 - 81
			{VpnOutL2TP, "1338"},  // 1420 - 82
		} {
			got := vpnOutViaMtuAdvice("t", tc.kind, 1420, 1420)
			if !strings.Contains(got, tc.fits) {
				t.Errorf("%s: the advice %q does not name %s as the MTU that fits", tc.kind, got, tc.fits)
			}
		}
	})
}

func TestVpnOutViaSlotIsStableAndInBand(t *testing.T) {
	for _, tag := range []string{"a", "wg-home", "a rather long tag with spaces"} {
		got := vpnOutViaSlot(tag)
		if got < 0 || got >= vpnOutRuleBandSpan {
			t.Errorf("slot(%q) = %d, outside the band", tag, got)
		}
		if again := vpnOutViaSlot(tag); again != got {
			t.Errorf("slot(%q) moved between calls: %d then %d", tag, got, again)
		}
		if vpnOutExcludeRuleBase+got >= vpnOutSteerRuleBase {
			t.Errorf("slot(%q) = %d pushes an exclusion into the steer band", tag, got)
		}
		if vpnOutSteerRuleBase+got >= vpnOutRouteTableBase {
			t.Errorf("slot(%q) = %d pushes a steer into the oif block", tag, got)
		}
	}
}

// ---- helpers -------------------------------------------------------------------------

// swapVia replaces a package-level function var for the duration of one test and returns
// the restore. Package state, so a test that forgets to restore poisons the next one.
func swapVia[T any](ptr *T, with T) func() {
	old := *ptr
	*ptr = with
	return func() { *ptr = old }
}

func itoaVia(n int) string { return strconv.Itoa(n) }

type fakeViaDriver struct{ host string }

func (f *fakeViaDriver) Up(VpnOutboundConfig) (string, error)    { return "fakevia0", nil }
func (f *fakeViaDriver) Down(VpnOutboundConfig) error            { return nil }
func (f *fakeViaDriver) Status(VpnOutboundConfig) (bool, string) { return true, "" }
func (f *fakeViaDriver) Validate(VpnOutboundConfig) error        { return nil }
func (f *fakeViaDriver) ServerHost(VpnOutboundConfig) (string, error) {
	return f.host, nil
}
