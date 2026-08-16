package service

import (
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/hasan1808/pro-ui/xray"
)

// The synthesis is the only writer of these outbounds, so anything it does not carry
// across is gone from the running core while the panel still shows it in the
// template. Two things were being dropped: the operator's sockopts, and the policy
// switch without which Xray counts no outbound bytes at all.

// shippedPolicy is the policy block from web/service/config.json, the template every
// fresh install starts from. Both outbound stat switches ship OFF.
const shippedPolicy = `{
	"levels": {"0": {"statsUserDownlink": true, "statsUserUplink": true}},
	"system": {
		"statsInboundDownlink": true,
		"statsInboundUplink": true,
		"statsOutboundDownlink": false,
		"statsOutboundUplink": false
	}
}`

// pinAnyIface makes every device look present for the duration of one test, so the
// synthesis can be exercised without the host actually having a wg0 or a ppp7.
func pinAnyIface(t *testing.T) {
	t.Helper()
	prev := vpnOutIfaceGone
	vpnOutIfaceGone = func(string) bool { return false }
	t.Cleanup(func() { vpnOutIfaceGone = prev })
}

// pinIfaceAddrs gives the test's devices the addresses it says they have. Without it
// the address lookup fails on the build host and every sendThrough decision takes the
// inconclusive branch, which is the one path that changes nothing and therefore the
// one that proves nothing.
func pinIfaceAddrs(t *testing.T, addrs map[string][]string) {
	t.Helper()
	prev := vpnOutIfaceAddrs
	vpnOutIfaceAddrs = func(iface string) ([]net.IP, error) {
		have, ok := addrs[iface]
		if !ok {
			return nil, errors.New("no such device")
		}
		out := make([]net.IP, 0, len(have))
		for _, a := range have {
			out = append(out, net.ParseIP(a))
		}
		return out, nil
	}
	t.Cleanup(func() { vpnOutIfaceAddrs = prev })
}

func outboundsByTag(t *testing.T, raw []byte) map[string]map[string]any {
	t.Helper()
	var obs []map[string]any
	if err := json.Unmarshal(raw, &obs); err != nil {
		t.Fatalf("outbounds are not JSON: %v", err)
	}
	out := map[string]map[string]any{}
	for _, ob := range obs {
		tag, _ := ob["tag"].(string)
		out[tag] = ob
	}
	return out
}

// sockoptOf digs the sockopt object out of one outbound, failing the test rather than
// panicking when the shape is not what the merge is supposed to guarantee.
func sockoptOf(t *testing.T, ob map[string]any) map[string]any {
	t.Helper()
	stream, ok := ob["streamSettings"].(map[string]any)
	if !ok {
		t.Fatalf("streamSettings is %T, want an object: %v", ob["streamSettings"], ob)
	}
	sockopt, ok := stream["sockopt"].(map[string]any)
	if !ok {
		t.Fatalf("sockopt is %T, want an object: %v", stream["sockopt"], stream)
	}
	return sockopt
}

func policySystem(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var policy map[string]any
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatalf("policy is not JSON: %v", err)
	}
	system, ok := policy["system"].(map[string]any)
	if !ok {
		t.Fatalf("policy.system is %T, want an object: %v", policy["system"], policy)
	}
	return system
}

// The operator configures sockopts on a VPN outbound the same way as on any other.
// Rebuilding the row from scratch each config build discarded all of them, and
// discarded the rest of the row with them.
func TestApplyVpnOutboundsKeepsOperatorSockopts(t *testing.T) {
	pinAnyIface(t)
	// The tunnel negotiated 10.0.0.1, which is what makes the operator's sendThrough
	// below a legitimate one rather than a silent kill (see vpnOutSendThrough).
	pinIfaceAddrs(t, map[string][]string{"ppp7": {"10.0.0.1"}})
	cfg := &xray.Config{OutboundConfigs: []byte(`[
		{"tag":"direct","protocol":"freedom"},
		{
			"tag":"vpn1",
			"protocol":"freedom",
			"settings":{"domainStrategy":"AsIs"},
			"streamSettings":{"sockopt":{
				"mark":255,
				"tcpFastOpen":true,
				"tcpMptcp":true,
				"dialerProxy":"warp",
				"tcpKeepAliveInterval":15,
				"interface":"stale0"
			}},
			"mux":{"enabled":true,"concurrency":8},
			"sendThrough":"10.0.0.1"
		}
	]`)}

	if err := applyVpnOutboundsWith(cfg, []VpnOutboundConfig{
		{Tag: "vpn1", Kind: VpnOutL2TP, Enable: true, Iface: "ppp7"},
	}); err != nil {
		t.Fatal(err)
	}

	byTag := outboundsByTag(t, cfg.OutboundConfigs)
	if len(byTag) != 2 {
		t.Fatalf("got %d outbounds, want 2 (direct, vpn1): %v", len(byTag), byTag)
	}
	ob := byTag["vpn1"]

	sockopt := sockoptOf(t, ob)
	// The one field the tunnel owns. The operator's value is a promise about the
	// kernel that nothing checks, so it loses.
	if sockopt["interface"] != "ppp7" {
		t.Errorf("interface = %v, want the tunnel's own device to override the row", sockopt["interface"])
	}
	for key, want := range map[string]any{
		"mark":                 float64(255),
		"tcpFastOpen":          true,
		"tcpMptcp":             true,
		"tcpKeepAliveInterval": float64(15),
	} {
		if sockopt[key] != want {
			t.Errorf("sockopt.%s = %v, want %v to survive the synthesis", key, sockopt[key], want)
		}
	}

	// Everything else the row carried is the operator's too. sendThrough survives
	// because it names an address the tunnel actually has: it binds the source and the
	// interface pin still binds the device, and the two compose.
	if ob["sendThrough"] != "10.0.0.1" {
		t.Errorf("sendThrough = %v, want the tunnel's own address kept", ob["sendThrough"])
	}

	// Not negotiable: a freedom outbound resolving on the host's resolver before the
	// socket is pinned answers for the host's network, not the tunnel's.
	if ob["protocol"] != "freedom" {
		t.Errorf("protocol = %v, want freedom", ob["protocol"])
	}
	settings, ok := ob["settings"].(map[string]any)
	if !ok || settings["domainStrategy"] != "UseIP" {
		t.Errorf("settings = %v, want the operator's AsIs overridden with UseIP", ob["settings"])
	}
}

// The two settings that do not merely sit alongside the interface pin but cancel it,
// each of them silently. Both are reachable on a stored row: saved by an older panel,
// or typed into the JSON tab, which the merge reads either way.
func TestApplyVpnOutboundsDropsWhatCancelsThePin(t *testing.T) {
	pinAnyIface(t)
	cfg := &xray.Config{OutboundConfigs: []byte(`[{
		"tag":"vpn1",
		"protocol":"freedom",
		"streamSettings":{"sockopt":{"dialerProxy":"warp","mark":7}},
		"mux":{"enabled":true,"concurrency":8}
	}]`)}

	if err := applyVpnOutboundsWith(cfg, []VpnOutboundConfig{
		{Tag: "vpn1", Kind: VpnOutOpenConnect, Enable: true, Iface: "tun9"},
	}); err != nil {
		t.Fatal(err)
	}
	ob := outboundsByTag(t, cfg.OutboundConfigs)["vpn1"]

	// dialerProxy makes DialSystem return before the interface is ever bound, so the
	// tunnel outbound would quietly egress through another tag instead.
	if proxy, still := sockoptOf(t, ob)["dialerProxy"]; still {
		t.Errorf("dialerProxy = %v survived; it bypasses the interface pin entirely", proxy)
	}
	// Mux dials the marker host v1.mux.cool:9527, which a freedom outbound cannot
	// resolve, so the tag carries nothing at all and says nothing about it.
	if mux, still := ob["mux"]; still {
		t.Errorf("mux = %v survived; it makes the tunnel outbound carry zero bytes", mux)
	}
	// Dropping those two must not take the operator's other sockopts with them.
	if got := sockoptOf(t, ob)["mark"]; got != float64(7) {
		t.Errorf("mark = %v, want 7 kept", got)
	}
	if got := sockoptOf(t, ob)["interface"]; got != "tun9" {
		t.Errorf("interface = %v, want tun9", got)
	}
}

// sendThrough pins the local source address and is applied alongside the interface
// pin, not instead of it, so on a tunnel it is only ever right when it names one of
// that tunnel's own addresses. Every other value binds a source the far end cannot
// answer and kills the tag outright, silently: measured against the shipped core with
// the host's WAN address on a pinned outbound, the inbound answered the client
// SUCCESS, 0 of 1,000,000 bytes were counted, the connection was reset 81 seconds
// later, and nothing was logged at the loglevel the panel ships.
func TestApplyVpnOutboundsGuardsSendThrough(t *testing.T) {
	cases := []struct {
		name string
		via  string
		want string
	}{
		// The one shape worth having: a device that negotiated two addresses, with the
		// operator choosing which one connections leave from.
		{"an address the tunnel has is kept", "10.8.0.6", "10.8.0.6"},
		{"the tunnel's other address is kept too", "10.8.0.7", "10.8.0.7"},
		// The likely typo, and the reason this guard exists at all: a box labelled
		// "send through" invites one of the host's own addresses.
		{"a host address that is not on the tunnel is dropped", "192.0.2.10", ""},
		{"an address on no device at all is dropped", "203.0.113.7", ""},
		// A hostname does not merely break this tag: the core refuses the WHOLE config
		// with "unable to send through" and every inbound goes down with it.
		{"a hostname is dropped before the core refuses the config", "vpn.example.com", ""},
		// origin is the panel listener's own address and srcip is the remote client's.
		// Neither is ever on a tunnel.
		{"origin is dropped", "origin", ""},
		{"srcip is dropped", "srcip", ""},
		// The core reads a CIDR as "pick a random address out of this prefix", which
		// the host does not have, so the bind fails on nearly every dial.
		{"a CIDR is dropped even around a real address", "10.8.0.6/24", ""},
		{"blank stays blank", "", ""},
		{"whitespace is not an address", "   ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pinAnyIface(t)
			pinIfaceAddrs(t, map[string][]string{"tun0": {"10.8.0.6", "10.8.0.7"}})
			row := map[string]any{"tag": "vpn1", "protocol": "freedom"}
			if tc.via != "" {
				row["sendThrough"] = tc.via
			}
			raw, err := json.Marshal([]map[string]any{row})
			if err != nil {
				t.Fatal(err)
			}
			cfg := &xray.Config{OutboundConfigs: raw}
			if err := applyVpnOutboundsWith(cfg, []VpnOutboundConfig{
				{Tag: "vpn1", Kind: VpnOutOpenVPN, Enable: true, Iface: "tun0"},
			}); err != nil {
				t.Fatal(err)
			}
			ob := outboundsByTag(t, cfg.OutboundConfigs)["vpn1"]
			got, _ := ob["sendThrough"].(string)
			if got != tc.want {
				t.Errorf("sendThrough = %q, want %q", got, tc.want)
			}
			if tc.want == "" {
				// Dropped, not blanked. An empty string is a value the core still tries
				// to parse, and `sendThrough: ""` is a domain as far as the config
				// loader is concerned, which is the whole-config refusal again.
				if _, still := ob["sendThrough"]; still {
					t.Errorf("sendThrough was blanked rather than removed: %v", ob["sendThrough"])
				}
			}
			// Dropping the source pin must never drop the device pin with it: the tag
			// still has to leave through the tunnel, which is the property the operator
			// is actually relying on.
			if got := sockoptOf(t, ob)["interface"]; got != "tun0" {
				t.Errorf("interface = %v, want the tunnel still pinned", got)
			}
		})
	}
}

// A netlink lookup that fails is not evidence that the address is wrong. Dropping on
// an inconclusive answer would silently change which address a working tunnel dials
// from, and there is nothing to gain by it: the interface pin holds either way, so an
// unverifiable sendThrough cannot leak.
func TestApplyVpnOutboundsKeepsSendThroughWhenAddressesCannotBeRead(t *testing.T) {
	pinAnyIface(t)
	pinIfaceAddrs(t, map[string][]string{}) // every lookup errors
	cfg := &xray.Config{OutboundConfigs: []byte(
		`[{"tag":"vpn1","protocol":"freedom","sendThrough":"10.8.0.6"}]`)}
	if err := applyVpnOutboundsWith(cfg, []VpnOutboundConfig{
		{Tag: "vpn1", Kind: VpnOutIKEv2, Enable: true, Iface: "xfrm1"},
	}); err != nil {
		t.Fatal(err)
	}
	ob := outboundsByTag(t, cfg.OutboundConfigs)["vpn1"]
	if got := ob["sendThrough"]; got != "10.8.0.6" {
		t.Errorf("sendThrough = %v, want it left alone when the device cannot be read", got)
	}
	// A hostname is refused whatever netlink says: it is wrong for reasons that have
	// nothing to do with which addresses the device holds.
	cfg = &xray.Config{OutboundConfigs: []byte(
		`[{"tag":"vpn1","protocol":"freedom","sendThrough":"vpn.example.com"}]`)}
	if err := applyVpnOutboundsWith(cfg, []VpnOutboundConfig{
		{Tag: "vpn1", Kind: VpnOutIKEv2, Enable: true, Iface: "xfrm1"},
	}); err != nil {
		t.Fatal(err)
	}
	ob = outboundsByTag(t, cfg.OutboundConfigs)["vpn1"]
	if _, still := ob["sendThrough"]; still {
		t.Errorf("sendThrough = %v survived; a hostname makes the core refuse the whole config",
			ob["sendThrough"])
	}
}

// The core swallows a failed BindToDevice (system_dialer.go logs it at Info and dials
// anyway) and the panel ships loglevel warning, so a device that has gone away since
// the tunnel was saved leaks every byte out of the host's WAN with no log line. The
// panel has to notice it, because nothing else will.
func TestApplyVpnOutboundsBlackholesAVanishedDevice(t *testing.T) {
	prev := vpnOutIfaceGone
	vpnOutIfaceGone = func(iface string) bool { return iface == "ppp0" }
	t.Cleanup(func() { vpnOutIfaceGone = prev })

	cfg := &xray.Config{OutboundConfigs: []byte(`[
		{"tag":"gone","protocol":"freedom","streamSettings":{"sockopt":{"interface":"ppp0"}}},
		{"tag":"live","protocol":"freedom"}
	]`)}
	if err := applyVpnOutboundsWith(cfg, []VpnOutboundConfig{
		{Tag: "gone", Kind: VpnOutL2TP, Enable: true, Iface: "ppp0"},
		{Tag: "live", Kind: VpnOutL2TP, Enable: true, Iface: "ppp1"},
	}); err != nil {
		t.Fatal(err)
	}

	byTag := outboundsByTag(t, cfg.OutboundConfigs)
	if got := byTag["gone"]["protocol"]; got != "blackhole" {
		t.Errorf("protocol = %v for a tunnel whose device is gone, want blackhole", got)
	}
	if got := byTag["live"]["protocol"]; got != "freedom" {
		t.Errorf("protocol = %v for a tunnel whose device is present, want freedom", got)
	}
	if got := sockoptOf(t, byTag["live"])["interface"]; got != "ppp1" {
		t.Errorf("the live tunnel lost its pin: %v", got)
	}
}

// Every shape the raw JSON can hand back, none of which may panic. `streamSettings`
// and `sockopt` are unmarshalled out of an operator-editable blob, so absent,
// explicitly null and hand-edited-to-a-string are all reachable.
func TestApplyVpnOutboundsSockoptShapes(t *testing.T) {
	pinAnyIface(t)
	cases := []struct {
		name string
		row  string
	}{
		{"no streamSettings at all", `{"tag":"vpn1","protocol":"freedom"}`},
		{"streamSettings is null", `{"tag":"vpn1","protocol":"freedom","streamSettings":null}`},
		{"streamSettings is not an object", `{"tag":"vpn1","protocol":"freedom","streamSettings":"eth0"}`},
		{"sockopt is null", `{"tag":"vpn1","protocol":"freedom","streamSettings":{"sockopt":null}}`},
		{"sockopt is not an object", `{"tag":"vpn1","protocol":"freedom","streamSettings":{"sockopt":42}}`},
		{"sockopt is empty", `{"tag":"vpn1","protocol":"freedom","streamSettings":{"sockopt":{}}}`},
		{"no row for this tag", `{"tag":"somebody-else","protocol":"freedom"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &xray.Config{OutboundConfigs: []byte("[" + tc.row + "]")}
			if err := applyVpnOutboundsWith(cfg, []VpnOutboundConfig{
				{Tag: "vpn1", Kind: VpnOutWireguard, Enable: true, Iface: "wgo0"},
			}); err != nil {
				t.Fatal(err)
			}
			ob := outboundsByTag(t, cfg.OutboundConfigs)["vpn1"]
			if ob == nil {
				t.Fatal("the tunnel produced no outbound at all")
			}
			if got := sockoptOf(t, ob)["interface"]; got != "wgo0" {
				t.Errorf("interface = %v, want wgo0", got)
			}
		})
	}
}

// A tunnel with nothing to bind to must not leave a plain freedom outbound behind:
// that is not an error to Xray, it is an unbound socket, so traffic the operator
// believes is inside a VPN leaves through the host's own WAN instead.
func TestApplyVpnOutboundsFailsClosedWithoutAnInterface(t *testing.T) {
	cases := []struct {
		name   string
		tunnel VpnOutboundConfig
	}{
		{"disabled", VpnOutboundConfig{Tag: "vpn1", Kind: VpnOutPPTP, Enable: false, Iface: ""}},
		{"enabled but never came up", VpnOutboundConfig{Tag: "vpn1", Kind: VpnOutPPTP, Enable: true, Iface: ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &xray.Config{
				Policy: []byte(shippedPolicy),
				OutboundConfigs: []byte(`[
					{"tag":"direct","protocol":"freedom"},
					{"tag":"vpn1","protocol":"freedom","settings":{"domainStrategy":"UseIP"}}
				]`),
			}
			if err := applyVpnOutboundsWith(cfg, []VpnOutboundConfig{tc.tunnel}); err != nil {
				t.Fatal(err)
			}
			byTag := outboundsByTag(t, cfg.OutboundConfigs)
			if got := byTag["vpn1"]["protocol"]; got != "blackhole" {
				t.Errorf("protocol = %v, want blackhole so the tag refuses traffic rather than leaking it", got)
			}
			if _, ok := byTag["direct"]; !ok {
				t.Error("the unrelated 'direct' outbound was dropped")
			}
			// Nothing was pinned, so there is no counter to register either.
			if got := policySystem(t, cfg.Policy)["statsOutboundUplink"]; got != false {
				t.Errorf("statsOutboundUplink = %v, want the operator's setting untouched", got)
			}
		})
	}
}

// A tag with no row at all is left alone rather than getting a blackhole: the
// operator never asked for that tag to exist in the config, and inventing one would
// put a dead outbound in their table.
func TestApplyVpnOutboundsDoesNotInventABlackhole(t *testing.T) {
	cfg := &xray.Config{OutboundConfigs: []byte(`[{"tag":"direct","protocol":"freedom"}]`)}
	if err := applyVpnOutboundsWith(cfg, []VpnOutboundConfig{
		{Tag: "vpn1", Kind: VpnOutGre, Enable: false},
	}); err != nil {
		t.Fatal(err)
	}
	if byTag := outboundsByTag(t, cfg.OutboundConfigs); len(byTag) != 1 {
		t.Errorf("got %d outbounds, want only 'direct': %v", len(byTag), byTag)
	}
}

// The Traffic column of the outbounds table is filled from Xray's per-outbound stats,
// and the core registers no counter for ANY outbound while these two switches are
// off. The shipped template ships them off, so every VPN row read 0 B / 0 B for ever.
func TestApplyVpnOutboundsEnablesTheOutboundCounters(t *testing.T) {
	pinAnyIface(t)
	cfg := &xray.Config{
		Policy:          []byte(shippedPolicy),
		OutboundConfigs: []byte(`[{"tag":"direct","protocol":"freedom"}]`),
	}
	if err := applyVpnOutboundsWith(cfg, []VpnOutboundConfig{
		{Tag: "vpn1", Kind: VpnOutOpenVPN, Enable: true, Iface: "tun3"},
	}); err != nil {
		t.Fatal(err)
	}

	system := policySystem(t, cfg.Policy)
	if system["statsOutboundUplink"] != true || system["statsOutboundDownlink"] != true {
		t.Errorf("statsOutbound{Up,Down}link = %v/%v, want both on or the tunnel bills nothing",
			system["statsOutboundUplink"], system["statsOutboundDownlink"])
	}
	// Only those two. The rest of the policy is the operator's, and rewriting the
	// block wholesale would take their user and inbound accounting with it.
	if system["statsInboundUplink"] != true || system["statsInboundDownlink"] != true {
		t.Errorf("the inbound counters were disturbed: %v", system)
	}
	var policy map[string]any
	if err := json.Unmarshal(cfg.Policy, &policy); err != nil {
		t.Fatal(err)
	}
	levels, ok := policy["levels"].(map[string]any)
	if !ok || levels["0"] == nil {
		t.Errorf("policy.levels was dropped: %v", policy)
	}
}

// The policy block is operator-editable text, so it can be missing or malformed. It
// must never cost the tunnels their pinning: an unpinned freedom outbound is the leak
// this whole file exists to prevent, and failing here would leave the outbound list
// untouched.
func TestApplyVpnOutboundsSurvivesABadPolicy(t *testing.T) {
	pinAnyIface(t)
	for _, policy := range []string{``, `null`, `{}`, `{"system":null}`, `{"system":"nonsense"}`, `not json`} {
		t.Run(policy, func(t *testing.T) {
			cfg := &xray.Config{
				Policy:          []byte(policy),
				OutboundConfigs: []byte(`[{"tag":"vpn1","protocol":"freedom"}]`),
			}
			if err := applyVpnOutboundsWith(cfg, []VpnOutboundConfig{
				{Tag: "vpn1", Kind: VpnOutSSTP, Enable: true, Iface: "ppp0"},
			}); err != nil {
				t.Fatal(err)
			}
			ob := outboundsByTag(t, cfg.OutboundConfigs)["vpn1"]
			if got := sockoptOf(t, ob)["interface"]; got != "ppp0" {
				t.Fatalf("interface = %v, want the tunnel pinned regardless of the policy block", got)
			}
		})
	}
}
