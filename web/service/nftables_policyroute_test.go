package service

import (
	"net"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
)

// The bug these tests pin down: nine copies of
//
//	strings.Contains(ipRuleShow(), "fwmark 0x1 lookup 100")
//
// could never match on a host whose /etc/iproute2 names table 100, because
// iproute2 prints the NAME. The guard therefore added another identical rule on
// every SetupRouting call, nine per panel start. The host it was found on had 195.
//
// Both fixtures below are real `ip rule show` output, captured from a throwaway
// network namespace: the first from a host that names table 100 `wanpolicy`, the
// second from one that does not.

// namedTokens is what vpnPolicyRuleTableTokens builds on a host carrying
// /etc/iproute2/rt_tables.d/wanpolicy.conf ("100 wanpolicy").
var namedTokens = map[string]bool{"100": true, "wanpolicy": true}

// numericTokens is the same on a host with no alias for table 100.
var numericTokens = map[string]bool{"100": true}

// Three copies of the policy rule (76, 1000, 32765) among decoys that all have
// to survive: an operator rule pointing at the same table, a marked rule with a
// src selector, a masked one, and a vpnOutBindEgress per-tunnel rule.
const namedTableText = `0:	from all lookup local
76:	from all fwmark 0x1 lookup wanpolicy
100:	from 192.168.130.100 lookup wanpolicy
200:	from 10.9.9.9 fwmark 0x1 lookup wanpolicy
201:	from all fwmark 0x1/0xff lookup wanpolicy
1000:	from all fwmark 0x1 lookup wanpolicy
30064:	from all oif cgre-gggg [detached] lookup 30064
32765:	from all fwmark 0x1 lookup wanpolicy
32766:	from all lookup main
32767:	from all lookup default`

// The same rule set on a host with no alias for table 100.
const numericTableText = `0:	from all lookup local
76:	from all fwmark 0x1 lookup 100
100:	from 192.168.130.100 lookup 100
200:	from 10.9.9.9 fwmark 0x1 lookup 100
201:	from all fwmark 0x1/0xff lookup 100
1000:	from all fwmark 0x1 lookup 100
30064:	from all oif cgre-gggg [detached] lookup 30064
32765:	from all fwmark 0x1 lookup 100
32766:	from all lookup main
32767:	from all lookup default`

const namedTableJSON = `[{"priority":0,"src":"all","table":"local"},` +
	`{"priority":76,"src":"all","fwmark":"0x1","table":"wanpolicy"},` +
	`{"priority":100,"src":"192.168.130.100","table":"wanpolicy"},` +
	`{"priority":200,"src":"10.9.9.9","fwmark":"0x1","table":"wanpolicy"},` +
	`{"priority":201,"src":"all","fwmark":"0x1","fwmask":"0xff","table":"wanpolicy"},` +
	`{"priority":1000,"src":"all","fwmark":"0x1","table":"wanpolicy"},` +
	`{"priority":30064,"src":"all","oif":"cgre-gggg","oif_detached":null,"table":"30064"},` +
	`{"priority":32765,"src":"all","fwmark":"0x1","table":"wanpolicy"},` +
	`{"priority":32766,"src":"all","table":"main"},` +
	`{"priority":32767,"src":"all","table":"default"}]`

const numericTableJSON = `[{"priority":0,"src":"all","table":"local"},` +
	`{"priority":76,"src":"all","fwmark":"0x1","table":"100"},` +
	`{"priority":100,"src":"192.168.130.100","table":"100"},` +
	`{"priority":200,"src":"10.9.9.9","fwmark":"0x1","table":"100"},` +
	`{"priority":201,"src":"all","fwmark":"0x1","fwmask":"0xff","table":"100"},` +
	`{"priority":1000,"src":"all","fwmark":"0x1","table":"100"},` +
	`{"priority":30064,"src":"all","oif":"cgre-gggg","oif_detached":null,"table":"30064"},` +
	`{"priority":32765,"src":"all","fwmark":"0x1","table":"100"},` +
	`{"priority":32766,"src":"all","table":"main"},` +
	`{"priority":32767,"src":"all","table":"default"}]`

func TestVpnPolicyRuleMatchesNamedAndNumericTable(t *testing.T) {
	cases := []struct {
		name   string
		out    string
		tokens map[string]bool
		want   []int
	}{
		{"text, table named wanpolicy", namedTableText, namedTokens, []int{76, 1000, 32765}},
		{"text, table numeric", numericTableText, numericTokens, []int{76, 1000, 32765}},
		{"json, table named wanpolicy", namedTableJSON, namedTokens, []int{76, 1000, 32765}},
		{"json, table numeric", numericTableJSON, numericTokens, []int{76, 1000, 32765}},
		// The regression itself: a named-table host read with only the numeric
		// token finds nothing, which is exactly what the old substring did.
		{"named table, alias not resolved", namedTableText, numericTokens, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := vpnPolicyRulePrefsFromOutput([]byte(tc.out), tc.tokens)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("prefs = %v, want %v", got, tc.want)
			}
		})
	}
}

// Nothing that is not exactly `from all fwmark 0x1 lookup <policy table>` may be
// claimed, because a claimed rule is a rule this code will delete. Every line
// here looks enough like the policy rule to be caught by a lazier matcher.
func TestVpnPolicyRuleRejectsEverythingElse(t *testing.T) {
	lines := []string{
		"100:\tfrom 10.9.9.9 fwmark 0x1 lookup wanpolicy",        // has a src selector
		"101:\tfrom all fwmark 0x1 oif eth0 lookup wanpolicy",    // per-tunnel oif rule
		"102:\tfrom all fwmark 0x1 iif eth0 lookup wanpolicy",    // has an iif selector
		"103:\tfrom all to 10.8.8.8 fwmark 0x1 lookup wanpolicy", // has a dst selector
		"104:\tfrom all fwmark 0x1/0xff lookup wanpolicy",        // masked fwmark
		"105:\tfrom all fwmark 0x2 lookup wanpolicy",             // another mark
		"106:\tfrom all lookup wanpolicy",                        // no fwmark at all
		"107:\tfrom all fwmark 0x1 lookup 199",                   // another table
		"108:\tfrom all not fwmark 0x1 lookup wanpolicy",         // inverted
		"30064:\tfrom all oif cgre-gggg lookup 30064",            // vpnOutBindEgress rule
		"109:\tfrom all fwmark 0x1 lookup wanpolicy suppress_prefixlength 0",
		"32766:\tfrom all lookup main",
	}
	for _, line := range lines {
		if pref, ok := vpnPolicyRuleTextMatch(line, namedTokens); ok {
			t.Errorf("claimed a rule that is not ours (pref %d): %s", pref, line)
		}
	}
}

// The JSON reader checks the KEY SET, so a selector it has never heard of still
// disqualifies the entry rather than being silently dropped by a struct decode.
func TestVpnPolicyRuleJSONRejectsUnknownSelectors(t *testing.T) {
	const out = `[
	    {"priority":10,"src":"all","fwmark":"0x1","table":"wanpolicy","uid_range":"1000-2000"},
	    {"priority":11,"src":"all","fwmark":"0x1","table":"wanpolicy","ipproto":"tcp"},
	    {"priority":12,"src":"all","fwmark":"0x1","fwmask":"0xff","table":"wanpolicy"},
	    {"priority":13,"src":"10.9.9.9","fwmark":"0x1","table":"wanpolicy"},
	    {"priority":14,"src":"all","fwmark":"0x1","table":"wanpolicy","oif":"cgre-gggg"},
	    {"priority":15,"src":"all","fwmark":"0x1","table":"wanpolicy","protocol":"boot"}
	]`
	// Only the last one is ours: `protocol` is provenance, not a selector.
	if got := vpnPolicyRulePrefsFromOutput([]byte(out), namedTokens); !reflect.DeepEqual(got, []int{15}) {
		t.Fatalf("prefs = %v, want [15]", got)
	}
}

// isVpnPolicyNetlinkRule is what actually gates the deletes, so it gets the same
// treatment. netlink is naming-immune by construction: the kernel stores the
// table as an integer and only iproute2 ever renders a name.
func TestIsVpnPolicyNetlinkRule(t *testing.T) {
	// The full mask is how the KERNEL reports the rule we installed with a plain
	// `ip rule add fwmark 1`: it fills mark_mask in for any non-zero mark and
	// dumps it back, so RuleList never returns a nil Mask on a marked rule.
	// Measured in a throwaway namespace; a matcher requiring nil here matched
	// nothing at all.
	fullMask := uint32(0xffffffff)
	ours := func() netlink.Rule {
		r := *netlink.NewRule()
		r.Priority = 32765
		r.Family = netlink.FAMILY_V4
		r.Table = 100
		r.Mark = 1
		r.Mask = &fullMask
		return r
	}
	if !isVpnPolicyNetlinkRule(ours()) {
		t.Fatal("did not recognise its own rule as the kernel reports it")
	}
	// A rule with no mask attribute at all is still ours.
	noMask := ours()
	noMask.Mask = nil
	if !isVpnPolicyNetlinkRule(noMask) {
		t.Fatal("did not recognise its own rule when the mask is absent")
	}

	mask := uint32(0xff)
	_, cidr, _ := net.ParseCIDR("10.9.9.9/32")
	decoys := map[string]func(*netlink.Rule){
		"src selector":     func(r *netlink.Rule) { r.Src = cidr },
		"dst selector":     func(r *netlink.Rule) { r.Dst = cidr },
		"oif selector":     func(r *netlink.Rule) { r.OifName = "cgre-gggg" },
		"iif selector":     func(r *netlink.Rule) { r.IifName = "eth0" },
		"fwmask":           func(r *netlink.Rule) { r.Mask = &mask },
		"other mark":       func(r *netlink.Rule) { r.Mark = 2 },
		"no mark":          func(r *netlink.Rule) { r.Mark = 0 },
		"other table":      func(r *netlink.Rule) { r.Table = 199 },
		"inverted":         func(r *netlink.Rule) { r.Invert = true },
		"suppress prefix":  func(r *netlink.Rule) { r.SuppressPrefixlen = 0 },
		"suppress ifgroup": func(r *netlink.Rule) { r.SuppressIfgroup = 0 },
		"goto action":      func(r *netlink.Rule) { r.Goto = 32000 },
		"tos":              func(r *netlink.Rule) { r.Tos = 4 },
		"uid range":        func(r *netlink.Rule) { r.UIDRange = netlink.NewRuleUIDRange(1000, 2000) },
		"dport range":      func(r *netlink.Rule) { r.Dport = netlink.NewRulePortRange(80, 443) },
	}
	for name, mutate := range decoys {
		r := ours()
		mutate(&r)
		if isVpnPolicyNetlinkRule(r) {
			t.Errorf("claimed a rule that is not ours: %s", name)
		}
	}

	// The rules vpnOutBindEgress installs, verbatim, must never be touched.
	perTunnel := *netlink.NewRule()
	perTunnel.OifName = "ovpnc-fi_tcp"
	perTunnel.Table = 30065
	perTunnel.Priority = 30065
	perTunnel.Family = netlink.FAMILY_V4
	if isVpnPolicyNetlinkRule(perTunnel) {
		t.Error("claimed a vpnOutBindEgress per-tunnel rule")
	}
}

// The self-heal decision: keep the lowest priority (the one the kernel is
// actually consulting today), drop the rest, and only add when there are none.
func TestVpnPolicyCollapsePlan(t *testing.T) {
	cases := []struct {
		name     string
		prefs    []int
		wantKeep int
		wantDrop []int
		wantAdd  bool
	}{
		{"nothing installed yet", nil, -1, nil, true},
		{"already exactly one", []int{32765}, 0, nil, false},
		// The measured shape of the leak on the affected host.
		{"a pile, keep the first the kernel hits", []int{76, 32764, 32765}, 0, []int{1, 2}, false},
		// Kernel order is not sorted order; the lowest pref wins wherever it sits.
		{"unsorted", []int{32765, 76, 32764}, 1, []int{0, 2}, false},
		// Duplicate priorities are legal; exactly one survives.
		{"same priority twice", []int{500, 500}, 0, []int{1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keep, drop, add := vpnPolicyCollapsePlan(tc.prefs)
			if keep != tc.wantKeep || add != tc.wantAdd || !reflect.DeepEqual(drop, tc.wantDrop) {
				t.Fatalf("keep=%d drop=%v add=%v, want keep=%d drop=%v add=%v",
					keep, drop, add, tc.wantKeep, tc.wantDrop, tc.wantAdd)
			}
			// Whatever the input, exactly one rule is left standing unless one
			// has to be added.
			if !add && len(tc.prefs)-len(drop) != 1 {
				t.Fatalf("collapse left %d rules, want 1", len(tc.prefs)-len(drop))
			}
		})
	}
}

// The 195-duplicate host, end to end through the pure layer: read the real
// output, plan the collapse, and confirm one survivor and no add.
func TestVpnPolicyCollapseRepairsTheLeakedHost(t *testing.T) {
	var text string
	for i := 0; i < 195; i++ {
		text += "0:\tfrom all lookup local\n" // interleaved noise is ignored
		text += "76:\tfrom all fwmark 0x1 lookup wanpolicy\n"
	}
	text += "30064:\tfrom all oif cgre-gggg lookup 30064\n"
	text += "100:\tfrom 192.168.130.100 lookup wanpolicy\n"

	prefs := vpnPolicyRulePrefsFromOutput([]byte(text), namedTokens)
	if len(prefs) != 195 {
		t.Fatalf("found %d policy rules, want 195", len(prefs))
	}
	keep, drop, add := vpnPolicyCollapsePlan(prefs)
	if add || keep != 0 || len(drop) != 194 {
		t.Fatalf("keep=%d, dropped %d, add=%v; want keep=0, dropped 194, add=false", keep, len(drop), add)
	}
}
