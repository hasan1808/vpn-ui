package service

import "testing"

// The whole point of the name-shape ownership test is that it separates the names
// WE generate from the names an operator plausibly picks. This table is the
// contract: every "ours" entry must be reclaimable (or the reconcilers leak
// netdevs), and every "theirs" entry must be untouchable (or the panel deletes
// someone's live tunnel, which is the bug this replaced).
//
// The "theirs" side is drawn from what people actually have on a box: `ip tunnel
// add gre1`, the kernel's own gre0/gretap0, a hand-named "gre-office", an
// outbound tunnel of our own from vpnout_gre.go ("cgre0"), and WireGuard
// interfaces called wg0/wgc-home.
func TestIfaceOwnershipNameShapes(t *testing.T) {
	cases := []struct {
		name  string
		ours  bool
		match func(string) bool
		who   string
	}{
		// GRE, ours: the point-to-point shape, its IFNAMSIZ hash fallback, and the
		// catch-all.
		{"gre1_0_0", true, greOwnedName, "gre"},
		{"gre42_7_3", true, greOwnedName, "gre"},
		{"gre9999_254_63", true, greOwnedName, "gre"},
		{"gre1a2b3c4d", true, greOwnedName, "gre"},
		{"grecat1f2e", true, greOwnedName, "gre"},

		// GRE, theirs.
		{"gre0", false, greOwnedName, "gre"}, // the kernel's own fallback device
		{"gre1", false, greOwnedName, "gre"}, // `ip tunnel add gre1 mode gre`
		{"gre2", false, greOwnedName, "gre"}, // the user's second one
		{"gre-office", false, greOwnedName, "gre"},
		{"gretap0", false, greOwnedName, "gre"},
		{"gre_office", false, greOwnedName, "gre"},
		{"gre_wan", false, greOwnedName, "gre"},
		{"gre-wan0", false, greOwnedName, "gre"},
		{"cgre0", false, greOwnedName, "gre"},  // our own OUTBOUND tunnels, vpnout_gre.go
		{"gre1_0", false, greOwnedName, "gre"}, // two fields, not three
		{"gre1_0_0_0", false, greOwnedName, "gre"},
		{"gre1_0_0x", false, greOwnedName, "gre"},
		{"gre1A2B3C4D", false, greOwnedName, "gre"}, // %08x is lowercase
		{"gre1a2b3c4", false, greOwnedName, "gre"},  // seven hex digits, not eight
		{"grecat", false, greOwnedName, "gre"},
		{"grecat1f2eff", false, greOwnedName, "gre"},

		// wg-c.
		{"wgc0", true, wgcOwnedName, "wgc"},
		{"wgc17", true, wgcOwnedName, "wgc"},
		{"wgc", false, wgcOwnedName, "wgc"},
		{"wgc-home", false, wgcOwnedName, "wgc"},
		{"wgc0x", false, wgcOwnedName, "wgc"},
		{"wg0", false, wgcOwnedName, "wgc"},
		{"wgcorp", false, wgcOwnedName, "wgc"},

		// AmneziaWG.
		{"awg0", true, awgOwnedName, "awg"},
		{"awg7", true, awgOwnedName, "awg"},
		{"awg", false, awgOwnedName, "awg"},
		{"awg_office", false, awgOwnedName, "awg"},
		{"awgo123", false, awgOwnedName, "awg"}, // vpnout_wireguard.go's client links
		{"awg-vpn", false, awgOwnedName, "awg"},
	}

	for _, c := range cases {
		got := c.match(c.name)
		if got != c.ours {
			verb := "claimed"
			if c.ours {
				verb = "disowned"
			}
			t.Errorf("%s ownership %s %q (ours=%v, got=%v)", c.who, verb, c.name, c.ours, got)
		}
	}
}

// Every name the generators can emit must be reclaimable by the ownership test,
// or the reconcilers leak a netdev per inbound. Generated here rather than
// hard-coded so a change to the naming scheme fails this test instead of silently
// stranding devices.
func TestGeneratedIfaceNamesAreOwned(t *testing.T) {
	for _, id := range []int{0, 1, 9, 42, 4095, 99999} {
		for _, slot := range []int{0, 1, 254} {
			for _, peer := range []int{0, 3, 63} {
				name := greP2pName(id, slot, peer)
				if len(name) > 15 {
					t.Fatalf("greP2pName(%d,%d,%d) = %q exceeds IFNAMSIZ", id, slot, peer, name)
				}
				if !greOwnedName(name) {
					t.Errorf("greP2pName(%d,%d,%d) = %q is not recognised as ours", id, slot, peer, name)
				}
			}
		}
		if n := wgIfaceName(id); !wgcOwnedName(n) {
			t.Errorf("wgIfaceName(%d) = %q is not recognised as ours", id, n)
		}
		if n := awgIfaceName(id); !awgOwnedName(n) {
			t.Errorf("awgIfaceName(%d) = %q is not recognised as ours", id, n)
		}
	}
	for _, ip := range []string{"1.2.3.4", "10.0.0.1", "203.0.113.99"} {
		if n := greCatName(parseIP4(t, ip)); !greOwnedName(n) {
			t.Errorf("greCatName(%s) = %q is not recognised as ours", ip, n)
		}
	}
}

// A device the manifest says predates us is never ours, however exactly its name
// matches. This is the second gate, and the only thing standing between a genuine
// name collision and a deleted tunnel.
func TestManifestVetoBeatsNameShape(t *testing.T) {
	useTempOwnership(t)

	const name = "wgc3"
	if !wgcOwnedName(name) {
		t.Fatalf("%q should match the wg-c name shape", name)
	}
	ownNote(ownIface, name, "wgc", "the operator's own interface")
	if !ownForbidsDelete(ownIface, name) {
		t.Fatalf("a pre-existing %q must veto deletion", name)
	}

	// And a device we created ourselves is not vetoed.
	ownClaim(ownIface, "wgc4", "wgc")
	if ownForbidsDelete(ownIface, "wgc4") {
		t.Fatal("an interface we created must stay deletable")
	}
}
