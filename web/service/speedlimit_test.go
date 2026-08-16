package service

import (
	"bytes"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

const kb = 1024

// limited builds an enabled per-inbound limiter policy. separate=false leaves up
// unread, matching the UI's single-box mode.
func limited(separate bool, down, up int, after int64) *model.Inbound {
	return &model.Inbound{
		SpeedLimitEnable:   true,
		SpeedLimitSeparate: separate,
		SpeedLimitDown:     down,
		SpeedLimitUp:       up,
		SpeedLimitAfter:    after,
	}
}

// pol covers emails with one inbound's policy, none of them IP-capped.
func pol(inb *model.Inbound, emails ...string) speedLimitPolicy {
	p := speedLimitPolicy{inbound: inb}
	for _, e := range emails {
		p.clients = append(p.clients, speedLimitClient{email: e})
	}
	return p
}

// capped covers one IP-capped email on an inbound of the given protocol that carries NO
// speed limit. This is the ipLimit-only shape, which is the one the resolution used to
// drop on the floor.
func capped(proto model.Protocol, email string, ipLimit int) speedLimitPolicy {
	return cappedOn(&model.Inbound{Protocol: proto}, proto, email, ipLimit)
}

// cappedOn is capped() on an inbound that also carries a speed limit.
func cappedOn(inb *model.Inbound, proto model.Protocol, email string, ipLimit int) speedLimitPolicy {
	inb.Protocol = proto
	return speedLimitPolicy{inbound: inb, clients: []speedLimitClient{{email: email, ipLimit: ipLimit}}}
}

// defaulted covers one client on an inbound carrying an IP Limit DEFAULT, with the
// client's own override passed separately: 0 is the override every client that never
// touched the field carries, and is what must inherit the default.
func defaulted(proto model.Protocol, email string, inboundDefault, clientOverride int) speedLimitPolicy {
	return cappedOn(&model.Inbound{IPLimit: inboundDefault}, proto, email, clientOverride)
}

// cappedWith is capped() on an inbound carrying an explicit IP Limit Strategy. The
// strategy is passed as a raw string, not a constant, so the tests can feed it the values
// only a hand-edited DB or a direct API POST produces ("", a typo).
func cappedWith(proto model.Protocol, email string, ipLimit int, strategy string) speedLimitPolicy {
	return cappedOn(&model.Inbound{IPLimitStrategy: strategy}, proto, email, ipLimit)
}

// find returns the published entry for email, or nil when the account is absent
// (which is how "unlimited" is expressed on the wire).
func find(users []speedLimitUser, email string) *speedLimitUser {
	for i := range users {
		if users[i].Email == email {
			return &users[i]
		}
	}
	return nil
}

func TestComputeSpeedLimits(t *testing.T) {
	tests := []struct {
		name     string
		policies []speedLimitPolicy
		usage    map[string]int64
		// wantAbsent asserts the account is unlimited (absent from the file).
		wantAbsent       bool
		wantDown, wantUp int64
	}{
		// Off / no-op cases: nothing to publish.
		{"limiter disabled", []speedLimitPolicy{pol(&model.Inbound{SpeedLimitDown: 100}, "a")}, nil, true, 0, 0},
		{"enabled but both rates zero", []speedLimitPolicy{pol(limited(true, 0, 0, 0), "a")}, nil, true, 0, 0},
		{"no policies at all", nil, nil, true, 0, 0},

		// separate=false: the single box caps EACH direction at that value. It is not a
		// combined bucket, and SpeedLimitUp is not read.
		{"combined mirrors down onto up", []speedLimitPolicy{pol(limited(false, 640, 0, 0), "a")}, nil, false, 640 * kb, 640 * kb},
		{"combined ignores the up field", []speedLimitPolicy{pol(limited(false, 640, 999, 0), "a")}, nil, false, 640 * kb, 640 * kb},

		// separate=true: the two directions are independent, including the asymmetric
		// states a single box cannot express.
		{"separate keeps directions independent", []speedLimitPolicy{pol(limited(true, 640, 256, 0), "a")}, nil, false, 640 * kb, 256 * kb},
		{"separate down only", []speedLimitPolicy{pol(limited(true, 640, 0, 0), "a")}, nil, false, 640 * kb, 0},
		{"separate up only", []speedLimitPolicy{pol(limited(true, 0, 256, 0), "a")}, nil, false, 0, 256 * kb},

		// Limit After: below the threshold the account is not yet armed, so it must be
		// absent (unlimited), and armed at or above it.
		{"usage below threshold is unarmed", []speedLimitPolicy{pol(limited(true, 640, 256, gb), "a")}, map[string]int64{"a": gb - 1}, true, 0, 0},
		{"usage at threshold arms", []speedLimitPolicy{pol(limited(true, 640, 256, gb), "a")}, map[string]int64{"a": gb}, false, 640 * kb, 256 * kb},
		{"usage above threshold arms", []speedLimitPolicy{pol(limited(true, 640, 256, gb), "a")}, map[string]int64{"a": 5 * gb}, false, 640 * kb, 256 * kb},
		{"no usage row is unarmed", []speedLimitPolicy{pol(limited(true, 640, 256, gb), "a")}, nil, true, 0, 0},
		// Threshold 0 (the column default) applies from the very first byte.
		{"zero threshold applies immediately", []speedLimitPolicy{pol(limited(true, 640, 256, 0), "a")}, nil, false, 640 * kb, 256 * kb},
		{"zero threshold with zero usage", []speedLimitPolicy{pol(limited(true, 640, 256, 0), "a")}, map[string]int64{"a": 0}, false, 640 * kb, 256 * kb},

		// One email on two inbounds: minimum non-zero wins, per direction.
		{
			"min wins across two inbounds",
			[]speedLimitPolicy{pol(limited(true, 640, 256, 0), "a"), pol(limited(true, 320, 512, 0), "a")},
			nil, false, 320 * kb, 256 * kb,
		},
		// 0 means unlimited, so it must LOSE the min against a real rate. A plain min()
		// would return 0 here and silently unlimit an account the other inbound limits.
		{
			"unlimited direction does not win the min",
			[]speedLimitPolicy{pol(limited(true, 640, 0, 0), "a"), pol(limited(true, 0, 256, 0), "a")},
			nil, false, 640 * kb, 256 * kb,
		},
		{
			"zero loses the min in both orders",
			[]speedLimitPolicy{pol(limited(true, 0, 256, 0), "a"), pol(limited(true, 640, 0, 0), "a")},
			nil, false, 640 * kb, 256 * kb,
		},
		// An inbound below its own threshold contributes nothing, so it must not unlimit
		// an account that an armed inbound limits. Same rule as above, different route.
		{
			"unarmed inbound does not unlimit an armed one",
			[]speedLimitPolicy{pol(limited(true, 640, 256, 0), "a"), pol(limited(true, 320, 128, gb), "a")},
			map[string]int64{"a": 0}, false, 640 * kb, 256 * kb,
		},
		{
			"both armed takes the stricter",
			[]speedLimitPolicy{pol(limited(true, 640, 256, 0), "a"), pol(limited(true, 320, 128, gb), "a")},
			map[string]int64{"a": 2 * gb}, false, 320 * kb, 128 * kb,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := find(computeSpeedLimits(tc.policies, tc.usage, nil), "a")
			if tc.wantAbsent {
				if got != nil {
					t.Fatalf("account is unlimited but was published as %+v; it must be absent", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want down=%d up=%d; account absent from output", tc.wantDown, tc.wantUp)
			}
			if got.DownBps != tc.wantDown || got.UpBps != tc.wantUp {
				t.Errorf("got down=%d up=%d; want down=%d up=%d", got.DownBps, got.UpBps, tc.wantDown, tc.wantUp)
			}
		})
	}
}

// The UI is KB/s and the wire is bytes/s. 1 KB = 1024 B, decided once, here.
func TestSpeedLimitUsesBinaryKB(t *testing.T) {
	users := computeSpeedLimits([]speedLimitPolicy{pol(limited(true, 1, 1000, 0), "a")}, nil, nil)
	got := find(users, "a")
	if got == nil {
		t.Fatal("account absent")
	}
	if got.DownBps != 1024 {
		t.Errorf("1 KB/s = %d B/s; want 1024 (binary KB, not 1000)", got.DownBps)
	}
	if got.UpBps != 1024000 {
		t.Errorf("1000 KB/s = %d B/s; want 1024000", got.UpBps)
	}
}

// Only limited accounts are published: an unlimited one must not cost the core a
// bucket, and the file must not name it at all.
func TestSpeedLimitOmitsUnlimitedAccounts(t *testing.T) {
	policies := []speedLimitPolicy{
		pol(limited(true, 640, 256, 0), "limited@x"),
		pol(limited(true, 640, 256, gb), "unarmed@x"),     // below threshold
		pol(&model.Inbound{SpeedLimitDown: 640}, "off@x"), // limiter switched off
		pol(limited(true, 0, 0, 0), "enabled-but-zero@x"), // enabled, no rates
	}
	users := computeSpeedLimits(policies, map[string]int64{"unarmed@x": 1}, nil)
	if len(users) != 1 {
		t.Fatalf("published %d users (%+v); want only the limited one", len(users), users)
	}
	if users[0].Email != "limited@x" {
		t.Errorf("published %q; want limited@x", users[0].Email)
	}
}

// The email->IP index only ever indexes onto the email, which is the real bucket key.
func TestSpeedLimitIPs(t *testing.T) {
	ipMap := map[string][]string{
		// The ppp-family paths hand back bare addresses, unsorted, and OpenVPN can repeat
		// one per enabled transport. The block paths (ikev2 psk/eap-tls, wg-c) hand back
		// a CIDR already.
		"ppp@x":   {"10.2.0.7", "10.2.0.5", "10.2.0.5"},
		"block@x": {"10.6.0.0/24"},
	}
	policies := []speedLimitPolicy{
		pol(limited(true, 640, 0, 0), "ppp@x", "block@x", "relay@x"),
	}
	users := computeSpeedLimits(policies, nil, ipMap)

	want := map[string][]string{
		// Bare addresses widen to host routes so the core parses one shape.
		"ppp@x":   {"10.2.0.5/32", "10.2.0.7/32"},
		"block@x": {"10.6.0.0/24"},
		// ssh/mtproto/native carry the email on the session itself, so they are published
		// with no addresses rather than not published at all.
		"relay@x": {},
	}
	for email, wantIPs := range want {
		got := find(users, email)
		if got == nil {
			t.Fatalf("%s absent from output", email)
		}
		if got.IPs == nil {
			t.Errorf("%s: ips is nil; it must serialize as [], not null", email)
		}
		if len(got.IPs) != len(wantIPs) {
			t.Fatalf("%s: ips = %v; want %v", email, got.IPs, wantIPs)
		}
		for i := range wantIPs {
			if got.IPs[i] != wantIPs[i] {
				t.Errorf("%s: ips = %v; want %v (sorted, deduplicated)", email, got.IPs, wantIPs)
			}
		}
	}
}

// The writer skips the write when the bytes match, so identical input MUST render
// identical bytes. Map iteration order is randomized per run, so without the sorts
// this fails and the core reloads its rate table every 10s forever.
func TestSpeedLimitDocumentIsDeterministic(t *testing.T) {
	policies := []speedLimitPolicy{
		pol(limited(true, 640, 256, 0), "c@x", "a@x", "b@x"),
		pol(limited(false, 320, 0, 0), "e@x", "d@x"),
	}
	ipMap := map[string][]string{
		"a@x": {"10.2.0.9", "10.2.0.3", "10.2.0.6"},
		"b@x": {"10.6.0.0/24"},
	}
	usage := map[string]int64{"a@x": 5 * gb, "b@x": 1}

	first, err := speedLimitDocument(policies, usage, ipMap)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := speedLimitDocument(policies, usage, ipMap)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("run %d differs from run 1; the output must be byte-identical\nfirst:\n%s\nagain:\n%s", i+2, first, again)
		}
	}
}

// The sidecar's schema is a contract with the patched core: field names, field order,
// bytes/s, and [] rather than null for an account with no addresses.
func TestSpeedLimitDocumentShape(t *testing.T) {
	policies := []speedLimitPolicy{pol(limited(true, 640, 256, 0), "a@x")}
	ipMap := map[string][]string{"a@x": {"10.0.0.5"}}

	got, err := speedLimitDocument(policies, nil, ipMap)
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "users": [
    {
      "email": "a@x",
      "downBps": 655360,
      "upBps": 262144,
      "ips": [
        "10.0.0.5/32"
      ]
    }
  ]
}
`
	if string(got) != want {
		t.Errorf("sidecar shape drifted\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// With nothing limited the file is an empty user list, NOT an absent or null one: it
// has to be able to tell the core that the last limit was removed.
func TestSpeedLimitDocumentEmpty(t *testing.T) {
	got, err := speedLimitDocument(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"users\": []\n}\n"
	if string(got) != want {
		t.Errorf("empty document = %q; want %q", got, want)
	}
}

// Which protocols may carry an ipLimit, and it is the whole feature: the core enforces
// what it finds here, so a cap published for a protocol whose source addresses it cannot
// see rejects real devices, and a cap NOT published for one it can see does nothing.
func TestComputeIPLimits(t *testing.T) {
	tests := []struct {
		name     string
		policies []speedLimitPolicy
		// wantAbsent asserts the account is uncapped and unlimited (absent from the file).
		wantAbsent  bool
		wantIPLimit int
	}{
		// Xray-native: the core terminates the client connection itself, so the source
		// address it counts is the client's own.
		{"vless publishes the cap", []speedLimitPolicy{capped(model.VLESS, "a", 2)}, false, 2},
		{"vmess publishes the cap", []speedLimitPolicy{capped(model.VMESS, "a", 3)}, false, 3},
		{"trojan publishes the cap", []speedLimitPolicy{capped(model.Trojan, "a", 1)}, false, 1},
		{"shadowsocks publishes the cap", []speedLimitPolicy{capped(model.Shadowsocks, "a", 4)}, false, 4},

		// The VPN backends enforce K at RADIUS auth, keyed by Calling-Station-Id +
		// NAS-Port, and the address the core sees is the tunnel address that allocator
		// just assigned. wg-c and ikev2 psk/eap-tls are the ones that would actively
		// break: one account owns a CIDR block, so a router behind it presents many
		// legitimate source addresses.
		{"l2tp never publishes a cap", []speedLimitPolicy{capped(model.L2TP, "a", 2)}, true, 0},
		{"pptp never publishes a cap", []speedLimitPolicy{capped(model.PPTP, "a", 2)}, true, 0},
		{"openvpn never publishes a cap", []speedLimitPolicy{capped(model.OPENVPN, "a", 2)}, true, 0},
		{"openconnect never publishes a cap", []speedLimitPolicy{capped(model.OPENCONNECT, "a", 2)}, true, 0},
		{"sstp never publishes a cap", []speedLimitPolicy{capped(model.SSTP, "a", 2)}, true, 0},
		{"ikev2 never publishes a cap", []speedLimitPolicy{capped(model.IKEV2, "a", 2)}, true, 0},
		{"wg-c never publishes a cap", []speedLimitPolicy{capped(model.WGC, "a", 2)}, true, 0},

		// ssh and mtproto reach Xray over the loopback, so the core would see one source
		// address for the whole protocol. They cap it in the relay, where the client's
		// real address exists. isVpnProtocol does not cover these two, so they are the
		// pair most likely to be let through by accident.
		{"ssh never publishes a cap", []speedLimitPolicy{capped(model.SSH, "a", 2)}, true, 0},
		{"mtproto never publishes a cap", []speedLimitPolicy{capped(model.MTPROTO, "a", 2)}, true, 0},

		// 0 is the column default and means uncapped, so the account is absent rather
		// than published with an ipLimit of 0.
		{"zero cap is uncapped", []speedLimitPolicy{capped(model.VLESS, "a", 0)}, true, 0},
		// A negative cap cannot arrive through the panel, only through an imported or
		// hand-edited DB. Published as-is it would mean "refuse everything".
		{"negative cap is uncapped", []speedLimitPolicy{capped(model.VLESS, "a", -1)}, true, 0},

		// One email on two native inbounds: minimum non-zero wins, exactly like the rates.
		{
			"min cap wins across two inbounds",
			[]speedLimitPolicy{capped(model.VLESS, "a", 5), capped(model.VMESS, "a", 2)},
			false, 2,
		},
		// 0 means uncapped, so it must LOSE the min. A plain min() would return 0 here and
		// silently uncap an account the other inbound caps.
		{
			"zero does not win the min",
			[]speedLimitPolicy{capped(model.VLESS, "a", 3), capped(model.VMESS, "a", 0)},
			false, 3,
		},
		{
			"zero does not win the min in either order",
			[]speedLimitPolicy{capped(model.VLESS, "a", 0), capped(model.VMESS, "a", 3)},
			false, 3,
		},
		// An account on both a native and a VPN inbound keeps the native cap: the VPN
		// inbound contributes nothing, it does not uncap.
		{
			"a vpn inbound does not uncap a native one",
			[]speedLimitPolicy{capped(model.VLESS, "a", 2), capped(model.L2TP, "a", 9)},
			false, 2,
		},

		// The inbound's DEFAULT cap. It applies to a client that carries no override of
		// its own, which is every client until an operator sets one.
		{"the inbound default is published", []speedLimitPolicy{defaulted(model.VLESS, "a", 3, 0)}, false, 3},
		// The override wins in BOTH directions. Only testing the tighter one would pass
		// against an implementation that quietly took the min of the two, which is the
		// plausible wrong answer here: the per-client value is an ENTITLEMENT, so a client
		// granted more than the inbound's baseline must actually get more.
		{"a lower client override beats the default", []speedLimitPolicy{defaulted(model.VLESS, "a", 5, 2)}, false, 2},
		{"a higher client override beats the default", []speedLimitPolicy{defaulted(model.VLESS, "a", 2, 5)}, false, 5},
		// LimitIP is a plain int, so an untouched field and an explicit 0 are the same
		// value: 0 inherits the default rather than forcing "unlimited".
		{"a client zero inherits the default", []speedLimitPolicy{defaulted(model.VLESS, "a", 4, 0)}, false, 4},
		// Both at 0 is the pre-existing state of every inbound, and must stay unlimited.
		{"both zero is uncapped", []speedLimitPolicy{defaulted(model.VLESS, "a", 0, 0)}, true, 0},
		// A negative default cannot arrive through the panel (validateInboundConfig has no
		// rule for the column, so nothing rejects it either), only through an imported or
		// hand-edited DB. Published as-is it would mean "refuse everything".
		{"a negative default is uncapped", []speedLimitPolicy{defaulted(model.VLESS, "a", -1, 0)}, true, 0},
		// A negative default is absent, not a value, so it does not stop an override.
		{"a negative default does not suppress the override", []speedLimitPolicy{defaulted(model.VLESS, "a", -1, 2)}, false, 2},
		// The protocol gate applies to the resolved value however it was resolved: an
		// inbound default is exactly as unpublishable as a client override on these.
		{"a vpn inbound default is never published", []speedLimitPolicy{defaulted(model.L2TP, "a", 3, 0)}, true, 0},
		{"an ssh inbound default is never published", []speedLimitPolicy{defaulted(model.SSH, "a", 3, 0)}, true, 0},
		{"an mtproto inbound default is never published", []speedLimitPolicy{defaulted(model.MTPROTO, "a", 3, 0)}, true, 0},
		// The cross-inbound merge runs on the RESOLVED value, so a default on one inbound
		// and an override on the other still meet in minNonZero.
		{
			"min wins across a default and an override",
			[]speedLimitPolicy{defaulted(model.VLESS, "a", 5, 0), defaulted(model.VMESS, "a", 0, 2)},
			false, 2,
		},
		{
			"min wins across two defaults",
			[]speedLimitPolicy{defaulted(model.VLESS, "a", 4, 0), defaulted(model.VMESS, "a", 2, 0)},
			false, 2,
		},
		// The resolution happens BEFORE the merge, so the tighter default loses to the
		// override that beat it on its own inbound. Resolving after the merge would return
		// 2 here and silently ignore the entitlement the operator granted.
		{
			"an override beats its own inbound default before the min",
			[]speedLimitPolicy{defaulted(model.VLESS, "a", 2, 9), defaulted(model.VMESS, "a", 5, 0)},
			false, 5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := find(computeSpeedLimits(tc.policies, nil, nil), "a")
			if tc.wantAbsent {
				if got != nil {
					t.Fatalf("account is uncapped and unlimited but was published as %+v; it must be absent", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want ipLimit=%d; account absent from output", tc.wantIPLimit)
			}
			if got.IPLimit != tc.wantIPLimit {
				t.Errorf("got ipLimit=%d; want %d", got.IPLimit, tc.wantIPLimit)
			}
		})
	}
}

// The account with a cap and no speed limit is the whole point of the feature and the
// easiest one to lose: the resolution used to skip any inbound whose rates were both 0,
// which is every inbound an operator caps without throttling.
func TestComputeIPLimitOnlyAccountIsPublished(t *testing.T) {
	users := computeSpeedLimits([]speedLimitPolicy{capped(model.VLESS, "a", 2)}, nil, nil)
	got := find(users, "a")
	if got == nil {
		t.Fatal("an account with only an ipLimit must still be published; it was absent")
	}
	if got.DownBps != 0 || got.UpBps != 0 {
		t.Errorf("got down=%d up=%d; an ipLimit must not imply a rate", got.DownBps, got.UpBps)
	}
	if got.IPLimit != 2 {
		t.Errorf("got ipLimit=%d; want 2", got.IPLimit)
	}
}

// The two limits are independent: they resolve from different columns (one per inbound,
// one per client) and neither may gate the other.
func TestComputeIPLimitAndRateAreIndependent(t *testing.T) {
	t.Run("a rate and a cap coexist", func(t *testing.T) {
		got := find(computeSpeedLimits([]speedLimitPolicy{
			cappedOn(limited(true, 640, 256, 0), model.VLESS, "a", 2),
		}, nil, nil), "a")
		if got == nil {
			t.Fatal("account absent")
		}
		if got.DownBps != 640*kb || got.UpBps != 256*kb || got.IPLimit != 2 {
			t.Errorf("got down=%d up=%d ipLimit=%d; want 655360/262144/2", got.DownBps, got.UpBps, got.IPLimit)
		}
	})

	// "Limit After" arms the RATES. A cap is a concurrency rule, not a quota, so it
	// applies from the first connection whatever the account has used.
	t.Run("limit after does not gate the cap", func(t *testing.T) {
		got := find(computeSpeedLimits([]speedLimitPolicy{
			cappedOn(limited(true, 640, 256, gb), model.VLESS, "a", 2),
		}, map[string]int64{"a": 1}, nil), "a")
		if got == nil {
			t.Fatal("an unarmed rate must not withhold the cap; account absent")
		}
		if got.DownBps != 0 || got.UpBps != 0 {
			t.Errorf("got down=%d up=%d; the account is below the threshold and must be unlimited", got.DownBps, got.UpBps)
		}
		if got.IPLimit != 2 {
			t.Errorf("got ipLimit=%d; want 2", got.IPLimit)
		}
	})

	// A VPN inbound's rate is still published (the email->IP index is what the core
	// resolves those accounts by); only the cap is withheld.
	t.Run("a vpn inbound keeps its rate and loses its cap", func(t *testing.T) {
		got := find(computeSpeedLimits([]speedLimitPolicy{
			cappedOn(limited(true, 640, 0, 0), model.L2TP, "a", 2),
		}, nil, nil), "a")
		if got == nil {
			t.Fatal("account absent")
		}
		if got.DownBps != 640*kb {
			t.Errorf("got down=%d; want %d", got.DownBps, 640*kb)
		}
		if got.IPLimit != 0 {
			t.Errorf("got ipLimit=%d; a vpn account's K is RADIUS's to enforce, it must not be published", got.IPLimit)
		}
	})
}

// Same guarantee as TestSpeedLimitDocumentIsDeterministic, with caps in the mix: the
// writer skips the write when the bytes match, and the core reloads when they do not.
func TestIPLimitDocumentIsDeterministic(t *testing.T) {
	policies := []speedLimitPolicy{
		cappedOn(limited(true, 640, 256, 0), model.VLESS, "c@x", 2),
		capped(model.VMESS, "a@x", 5),
		capped(model.Trojan, "b@x", 1),
		capped(model.L2TP, "d@x", 3),
		pol(limited(false, 320, 0, 0), "e@x"),
		// Caps resolved from the inbound default rather than an override: the resolution
		// runs per tick, so a default that resolved unstably would rewrite the file (and
		// make the core reload) forever, exactly as an unstable rate would.
		defaulted(model.Shadowsocks, "f@x", 4, 0),
		defaulted(model.VLESS, "g@x", 4, 2),
	}
	usage := map[string]int64{"a@x": 5 * gb}
	ipMap := map[string][]string{"d@x": {"10.2.0.5"}}

	first, err := speedLimitDocument(policies, usage, ipMap)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := speedLimitDocument(policies, usage, ipMap)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("run %d differs from run 1; the output must be byte-identical\nfirst:\n%s\nagain:\n%s", i+2, first, again)
		}
	}
}

// The sidecar's schema is a contract with the patched core: ipLimit sits between the
// rates and the addresses, and an uncapped account carries no ipLimit key at all rather
// than an explicit 0.
func TestIPLimitDocumentShape(t *testing.T) {
	policies := []speedLimitPolicy{
		cappedOn(limited(true, 640, 256, 0), model.VLESS, "capped@x", 2),
		pol(limited(true, 640, 0, 0), "uncapped@x"),
	}

	got, err := speedLimitDocument(policies, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "users": [
    {
      "email": "capped@x",
      "downBps": 655360,
      "upBps": 262144,
      "ipLimit": 2,
      "ips": []
    },
    {
      "email": "uncapped@x",
      "downBps": 655360,
      "upBps": 0,
      "ips": []
    }
  ]
}
`
	if string(got) != want {
		t.Errorf("sidecar shape drifted\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// The strategy decides what the core does to a LIVE connection at the cap, so the two
// mistakes are not symmetric: publishing "accept" where the operator meant "reject" tears
// down sessions that should have been left alone, while the reverse only refuses a
// newcomer. Everything here is written from that asymmetry.
func TestComputeIPLimitStrategy(t *testing.T) {
	tests := []struct {
		name     string
		policies []speedLimitPolicy
		// wantStrategy is the published value, so "" means the key is absent, which is how
		// the default (reject) is expressed on the wire.
		wantStrategy string
	}{
		// The only value that reaches the file. Its absence is the other one.
		{"accept is published", []speedLimitPolicy{cappedWith(model.VLESS, "a", 2, "accept")}, "accept"},
		{"reject is the default and is omitted", []speedLimitPolicy{cappedWith(model.VLESS, "a", 2, "reject")}, ""},

		// A row that predates the column, or an API POST that omitted the field, carries
		// "". It must read as reject, not as "unset, so do whatever".
		{"empty is reject", []speedLimitPolicy{cappedWith(model.VLESS, "a", 2, "")}, ""},
		// An imported or hand-edited DB is the only way these arrive. Any of them killing
		// live sessions would be the worst possible reading of a typo.
		{"unknown word is reject", []speedLimitPolicy{cappedWith(model.VLESS, "a", 2, "evict")}, ""},
		{"case is not folded, so ACCEPT is reject", []speedLimitPolicy{cappedWith(model.VLESS, "a", 2, "ACCEPT")}, ""},
		{"whitespace is not trimmed, so accept with a space is reject", []speedLimitPolicy{cappedWith(model.VLESS, "a", 2, " accept")}, ""},

		// One email on two inbounds: reject wins, in both orders. The order is the whole
		// test: a merge that just took the last (or first) writer would pass one of these
		// and silently ship the other.
		{
			"reject wins over accept",
			[]speedLimitPolicy{cappedWith(model.VLESS, "a", 2, "reject"), cappedWith(model.VMESS, "a", 3, "accept")},
			"",
		},
		{
			"reject wins over accept in the other order",
			[]speedLimitPolicy{cappedWith(model.VLESS, "a", 2, "accept"), cappedWith(model.VMESS, "a", 3, "reject")},
			"",
		},
		// accept survives only when every capping inbound asks for it.
		{
			"accept wins only unanimously",
			[]speedLimitPolicy{cappedWith(model.VLESS, "a", 2, "accept"), cappedWith(model.VMESS, "a", 3, "accept")},
			"accept",
		},
		// An unknown word is a reject, so it wins the merge exactly like one.
		{
			"an unknown word beats accept, like the reject it is",
			[]speedLimitPolicy{cappedWith(model.VLESS, "a", 2, "accept"), cappedWith(model.VMESS, "a", 3, "typo")},
			"",
		},

		// A strategy without a cap governs nothing: an inbound the account is NOT capped
		// on must not decide what happens at a cap set on another inbound.
		{
			"an uncapped inbound contributes no strategy",
			[]speedLimitPolicy{
				cappedWith(model.VLESS, "a", 2, "reject"),
				cappedWith(model.VMESS, "a", 0, "accept"),
			},
			"",
		},
		{
			"an uncapped accept inbound does not loosen a capped reject one",
			[]speedLimitPolicy{
				cappedWith(model.VLESS, "a", 0, "accept"),
				cappedWith(model.VMESS, "a", 2, "reject"),
			},
			"",
		},
		// Same rule from the other side: the cap is what carries the strategy, so an
		// inbound whose cap is withheld (ipLimitEnforcedInCore) withholds its strategy too.
		{
			"a vpn inbound contributes no strategy",
			[]speedLimitPolicy{
				cappedWith(model.VLESS, "a", 2, "reject"),
				cappedWith(model.L2TP, "a", 3, "accept"),
			},
			"",
		},
		{
			"ssh and mtproto contribute no strategy either",
			[]speedLimitPolicy{
				cappedWith(model.VLESS, "a", 2, "accept"),
				cappedWith(model.SSH, "a", 3, "reject"),
				cappedWith(model.MTPROTO, "a", 3, "reject"),
			},
			"accept",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := find(computeSpeedLimits(tc.policies, nil, nil), "a")
			if got == nil {
				t.Fatalf("want strategy=%q; account absent from output", tc.wantStrategy)
			}
			if got.Strategy != tc.wantStrategy {
				t.Errorf("got strategy=%q; want %q", got.Strategy, tc.wantStrategy)
			}
		})
	}
}

// A strategy qualifies a cap. Published without one it would describe a limit that does
// not exist, and the core would have a policy for a rule it is not enforcing.
func TestComputeIPLimitStrategyNeedsACap(t *testing.T) {
	t.Run("a rate-limited account with no cap carries no strategy", func(t *testing.T) {
		inb := limited(true, 640, 256, 0)
		inb.IPLimitStrategy = "accept"
		got := find(computeSpeedLimits([]speedLimitPolicy{pol(inb, "a")}, nil, nil), "a")
		if got == nil {
			t.Fatal("account absent")
		}
		if got.IPLimit != 0 {
			t.Fatalf("got ipLimit=%d; the account is uncapped", got.IPLimit)
		}
		if got.Strategy != "" {
			t.Errorf("got strategy=%q; an uncapped account must carry none", got.Strategy)
		}
	})

	// A 0 cap is the column default (uncapped), so an accept strategy beside it is an
	// operator's leftover, not an instruction.
	t.Run("a zero cap carries no strategy", func(t *testing.T) {
		got := find(computeSpeedLimits([]speedLimitPolicy{
			cappedOn(limited(true, 640, 0, 0), model.VLESS, "a", 0),
		}, nil, nil), "a")
		if got == nil {
			t.Fatal("account absent")
		}
		if got.Strategy != "" {
			t.Errorf("got strategy=%q; want none", got.Strategy)
		}
	})

	// A cap is a cap however it was resolved: the strategy qualifies the inbound's own
	// default exactly as it qualifies a client's override, or an operator who sets both on
	// one inbound would get the default silently governed by "reject".
	t.Run("a cap from the inbound default carries the strategy", func(t *testing.T) {
		inb := &model.Inbound{IPLimit: 3, IPLimitStrategy: "accept"}
		got := find(computeSpeedLimits([]speedLimitPolicy{
			cappedOn(inb, model.VLESS, "a", 0),
		}, nil, nil), "a")
		if got == nil {
			t.Fatal("account absent")
		}
		if got.IPLimit != 3 {
			t.Fatalf("got ipLimit=%d; want the inbound default of 3", got.IPLimit)
		}
		if got.Strategy != "accept" {
			t.Errorf("got strategy=%q; want accept", got.Strategy)
		}
	})

	// A VPN account is published for its RATE, so it is the account most likely to carry a
	// strategy it should not: it reaches the emit path with the strategy column set and
	// only the cap withheld.
	t.Run("a vpn account keeps its rate and carries no strategy", func(t *testing.T) {
		inb := limited(true, 640, 0, 0)
		inb.IPLimitStrategy = "accept"
		got := find(computeSpeedLimits([]speedLimitPolicy{
			cappedOn(inb, model.L2TP, "a", 2),
		}, nil, nil), "a")
		if got == nil {
			t.Fatal("account absent")
		}
		if got.DownBps != 640*kb {
			t.Errorf("got down=%d; want %d", got.DownBps, 640*kb)
		}
		if got.IPLimit != 0 || got.Strategy != "" {
			t.Errorf("got ipLimit=%d strategy=%q; a vpn account's K is RADIUS's to enforce, neither may be published", got.IPLimit, got.Strategy)
		}
	})
}

// Same guarantee as the other determinism tests, with strategies in the mix. The merge
// walks a map, so a strategy resolved from map order would produce a document that
// flip-flops between ticks, and the compare-then-write would rewrite the file (and make
// the core reload) forever.
func TestIPLimitStrategyDocumentIsDeterministic(t *testing.T) {
	policies := []speedLimitPolicy{
		cappedWith(model.VLESS, "c@x", 2, "accept"),
		cappedWith(model.VMESS, "c@x", 4, "reject"),
		cappedWith(model.Trojan, "a@x", 1, "accept"),
		cappedWith(model.Shadowsocks, "b@x", 3, ""),
		cappedWith(model.L2TP, "d@x", 3, "accept"),
	}

	first, err := speedLimitDocument(policies, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := speedLimitDocument(policies, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("run %d differs from run 1; the output must be byte-identical\nfirst:\n%s\nagain:\n%s", i+2, first, again)
		}
	}
}

// The sidecar's schema is a contract with the patched core: strategy sits between the cap
// it qualifies and the addresses, spells the same words the VPN User Limit does, and is
// absent (not "reject", and not "") on every account that takes the default.
func TestIPLimitStrategyDocumentShape(t *testing.T) {
	policies := []speedLimitPolicy{
		cappedWith(model.VLESS, "accept@x", 2, "accept"),
		cappedWith(model.VMESS, "reject@x", 3, "reject"),
	}

	got, err := speedLimitDocument(policies, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "users": [
    {
      "email": "accept@x",
      "downBps": 0,
      "upBps": 0,
      "ipLimit": 2,
      "strategy": "accept",
      "ips": []
    },
    {
      "email": "reject@x",
      "downBps": 0,
      "upBps": 0,
      "ipLimit": 3,
      "ips": []
    }
  ]
}
`
	if string(got) != want {
		t.Errorf("sidecar shape drifted\ngot:\n%s\nwant:\n%s", got, want)
	}
}
