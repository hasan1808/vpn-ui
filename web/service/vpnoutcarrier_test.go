package service

import (
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/xray"

	"github.com/goccy/go-json"
)

// pinDevAddr says which device holds which address, so the sendThrough lookup can be
// tested without depending on the devices this build host happens to have.
func pinDevAddr(t *testing.T, byAddr map[string]string) {
	t.Helper()
	prev := vpnOutDevWithAddr
	vpnOutDevWithAddr = func(addr string) string { return byAddr[strings.TrimSpace(addr)] }
	t.Cleanup(func() { vpnOutDevWithAddr = prev })
}

// carrierObs parses an outbound template fragment the way vpnOutCarrierFor takes it.
func carrierObs(t *testing.T, raw string) []map[string]any {
	t.Helper()
	var obs []map[string]any
	if err := json.Unmarshal([]byte(raw), &obs); err != nil {
		t.Fatalf("test outbounds do not parse: %v", err)
	}
	return obs
}

// A carrier is resolved to a DEVICE, and which of the three ways it got there decides
// what it can carry. This pins all four answers plus every refusal, because the refusals
// are the part an operator reads.
func TestVpnOutCarrierFor(t *testing.T) {
	pinAnyIface(t)
	tunnels := []VpnOutboundConfig{
		{Tag: "wg-a", Kind: VpnOutWireguard, Enable: true, Iface: "wg0"},
		{Tag: "off", Kind: VpnOutWireguard, Enable: false, Iface: "wg1"},
		{Tag: "never-up", Kind: VpnOutWireguard, Enable: true},
	}
	obs := carrierObs(t, `[
		{"tag":"pinned","protocol":"freedom","streamSettings":{"sockopt":{"interface":"eth1"}}},
		{"tag":"bare","protocol":"freedom"},
		{"tag":"vlessout","protocol":"vless","settings":{"vnext":[{"address":"203.0.113.9","port":443}]}},
		{"tag":"blocked","protocol":"blackhole","settings":{}},
		{"tag":"dnsout","protocol":"dns"}
	]`)

	t.Run("a tunnel carries with its own device", func(t *testing.T) {
		c, err := vpnOutCarrierFor("wg-a", tunnels, nil, obs)
		if err != nil {
			t.Fatalf("wg-a: %v", err)
		}
		if c.Kind != vpnOutCarrierTunnel || c.Iface != "wg0" {
			t.Errorf("kind=%v iface=%q, want a tunnel carrier on wg0", c.Kind, c.Iface)
		}
		if c.Bridged() {
			t.Error("a tunnel carrier must not be bridged; it would lose GRE and ESP")
		}
	})

	t.Run("a pinned freedom outbound is already a device", func(t *testing.T) {
		c, err := vpnOutCarrierFor("pinned", tunnels, nil, obs)
		if err != nil {
			t.Fatalf("pinned: %v", err)
		}
		if c.Kind != vpnOutCarrierPinned || c.Iface != "eth1" {
			t.Errorf("kind=%v iface=%q, want a pinned carrier on eth1", c.Kind, c.Iface)
		}
		if c.Bridged() {
			t.Error("a pinned carrier must not be bridged; nothing is synthesized for it")
		}
	})

	t.Run("any other outbound gets a carrier tun", func(t *testing.T) {
		c, err := vpnOutCarrierFor("vlessout", tunnels, nil, obs)
		if err != nil {
			t.Fatalf("vlessout: %v", err)
		}
		if !c.Bridged() {
			t.Fatalf("kind=%v, want a bridged carrier", c.Kind)
		}
		if c.Iface != vpnOutCarrierDev("vlessout") {
			t.Errorf("iface=%q, want the carrier device for the tag", c.Iface)
		}
		// The uplink is what must never be steered into the carrier's own tun, or the
		// core dials itself and the traffic goes round forever.
		if len(c.Uplink) != 1 || c.Uplink[0] != "203.0.113.9" {
			t.Errorf("uplink=%v, want the vless server so it can be excluded", c.Uplink)
		}
	})

	t.Run("an ssh tunnel is bridged like any other proxy", func(t *testing.T) {
		c, err := vpnOutCarrierFor("jump", tunnels, []string{"jump"}, obs)
		if err != nil {
			t.Fatalf("jump: %v", err)
		}
		if !c.Bridged() {
			t.Errorf("kind=%v, want a bridged carrier for an ssh tunnel", c.Kind)
		}
	})

	t.Run("a freedom outbound that names a source address carries too", func(t *testing.T) {
		pinDevAddr(t, map[string]string{"192.0.2.55": "eth2"})
		obs := carrierObs(t, `[{"tag":"viaAddr","protocol":"freedom","sendThrough":"192.0.2.55"}]`)
		c, err := vpnOutCarrierFor("viaAddr", tunnels, nil, obs)
		if err != nil {
			t.Fatalf("viaAddr: %v", err)
		}
		if c.Kind != vpnOutCarrierPinned || c.Iface != "eth2" {
			t.Errorf("kind=%v iface=%q, want the device holding the address", c.Kind, c.Iface)
		}
	})

	t.Run("a source address on no device is refused", func(t *testing.T) {
		pinDevAddr(t, map[string]string{"192.0.2.55": "eth2"})
		obs := carrierObs(t, `[{"tag":"ghostAddr","protocol":"freedom","sendThrough":"203.0.113.77"}]`)
		_, err := vpnOutCarrierFor("ghostAddr", tunnels, nil, obs)
		if err == nil {
			t.Fatal("an address on no device was accepted; the bind would succeed and leave from the wrong place")
		}
		if !strings.Contains(err.Error(), "not an address on any") {
			t.Errorf("refusal %q does not say the address is not here", err)
		}
	})

	refusals := []struct {
		name, tag string
		wants     []string
	}{
		// A bare freedom dials straight out of the host, so carrying through it would
		// carry nothing, and it is also the one shape that loops.
		{"a freedom with no interface", "bare", []string{"straight out of this host", "no interface and no sendThrough"}},
		{"a blackhole", "blocked", []string{"discards everything"}},
		{"a dns outbound", "dnsout", []string{"only answers DNS"}},
		{"a disabled tunnel", "off", []string{"switched off"}},
		{"a tunnel that never came up", "never-up", []string{"no network device"}},
		// The saved-template caveat is load-bearing: the modal offers tags the PAGE
		// holds, so this is reachable with a tag the operator can see on screen.
		{"a tag nobody has", "ghost", []string{"not a tunnel", "save the Xray page first"}},
	}
	for _, r := range refusals {
		t.Run(r.name+" is refused", func(t *testing.T) {
			_, err := vpnOutCarrierFor(r.tag, tunnels, nil, obs)
			if err == nil {
				t.Fatalf("%s was accepted as a carrier", r.tag)
			}
			for _, want := range r.wants {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not say %q", err, want)
				}
			}
		})
	}

	t.Run("no carrier at all is not an error", func(t *testing.T) {
		c, err := vpnOutCarrierFor("", tunnels, nil, obs)
		if err != nil || c.Tag != "" {
			t.Errorf("empty via gave (%v, %v), want the zero carrier and no error", c, err)
		}
	})
}

// A tunnel row in the template is a freedom outbound pinned to its device, so reading it
// as a PINNED carrier instead of a tunnel would work by accident until the tunnel went
// down, when the same row is a blackhole.
func TestVpnOutCarrierForPrefersTheStoredTunnel(t *testing.T) {
	pinAnyIface(t)
	tunnels := []VpnOutboundConfig{{Tag: "wg-a", Kind: VpnOutWireguard, Enable: true, Iface: "wg0"}}
	obs := carrierObs(t, `[{"tag":"wg-a","protocol":"freedom","streamSettings":{"sockopt":{"interface":"stale0"}}}]`)

	c, err := vpnOutCarrierFor("wg-a", tunnels, nil, obs)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != vpnOutCarrierTunnel || c.Iface != "wg0" {
		t.Errorf("kind=%v iface=%q, want the stored tunnel's own device and not the row's stale pin",
			c.Kind, c.Iface)
	}
}

// The device name is the carrier's identity: it has to be stable across reboots, fit the
// kernel's limit, and match the shape the ownership sweep will delete by.
func TestVpnOutCarrierDevIsStableAndOwnable(t *testing.T) {
	for _, tag := range []string{"vlessout", "warp", "a", strings.Repeat("long", 40)} {
		name := vpnOutCarrierDev(tag)
		if name != vpnOutCarrierDev(tag) {
			t.Errorf("%q: the device name is not stable across calls", tag)
		}
		if len(name) > 15 {
			t.Errorf("%q: device name %q is %d characters, over the kernel's IFNAMSIZ limit",
				tag, name, len(name))
		}
		if !vpnOutCarrierOwnedName(name) {
			t.Errorf("%q: device name %q does not match the ownership pattern, so the sweep "+
				"would never collect it", tag, name)
		}
	}
	if vpnOutCarrierDev("one") == vpnOutCarrierDev("two") {
		t.Error("two tags produced one device name")
	}
	// The gate is a positive test: a device somebody else named must never match.
	for _, theirs := range []string{"xcar", "xcar0", "xcarZZZZZZZZ", "xcar1a2b3c4d5", "eth0"} {
		if vpnOutCarrierOwnedName(theirs) {
			t.Errorf("%q matched the ownership pattern; that is somebody else's device", theirs)
		}
	}
}

// Two carriers must never claim one address, and resolving a collision must not move
// every other carrier's address with it.
func TestVpnOutCarrierSlotsAreUniqueAndStable(t *testing.T) {
	tags := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	slots := vpnOutCarrierSlots0(tags)
	if len(slots) != len(tags) {
		t.Fatalf("got %d slots for %d tags", len(slots), len(tags))
	}
	seen := map[int]string{}
	for tag, slot := range slots {
		if slot < 1 || slot > vpnOutCarrierSlots {
			t.Errorf("%s got slot %d, outside the block", tag, slot)
		}
		if other, dup := seen[slot]; dup {
			t.Errorf("%s and %s both claim slot %d, so they would share an address", tag, other, slot)
		}
		seen[slot] = tag
	}
	// Adding a carrier must leave the others where they were, or every unrelated
	// tunnel's routing moves for a change it had nothing to do with.
	grown := vpnOutCarrierSlots0(append(append([]string{}, tags...), "zeta"))
	for _, tag := range tags {
		if grown[tag] != slots[tag] {
			t.Errorf("%s moved from slot %d to %d when another carrier was added",
				tag, slots[tag], grown[tag])
		}
	}
	if addr := vpnOutCarrierAddr(7); addr != "10.11.7.1/30" {
		t.Errorf("slot 7 addressed as %q, want 10.11.7.1/30 inside vpnAddrSpace", addr)
	}
}

// Every shape the core accepts for "where does this outbound dial", because each one
// that is missed is an exclusion that is not installed.
func TestVpnOutOutboundUplinks(t *testing.T) {
	cases := []struct {
		name, raw string
		want      []string
	}{
		{"vless vnext", `{"settings":{"vnext":[{"address":"198.51.100.1"}]}}`, []string{"198.51.100.1"}},
		{"trojan servers", `{"settings":{"servers":[{"address":"198.51.100.2"}]}}`, []string{"198.51.100.2"}},
		{"wireguard endpoint", `{"settings":{"peers":[{"endpoint":"198.51.100.3:51820"}]}}`, []string{"198.51.100.3"}},
		{"flat address", `{"settings":{"address":"198.51.100.4"}}`, []string{"198.51.100.4"}},
		{"nothing to find", `{"settings":{}}`, nil},
		{"no settings at all", `{}`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ob map[string]any
			if err := json.Unmarshal([]byte(c.raw), &ob); err != nil {
				t.Fatal(err)
			}
			got := vpnOutOutboundUplinks(ob)
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}

// The bridge inbound and its rule, and the two properties that decide whether a carried
// tunnel works at all: the rule must come FIRST, and a carrier with no device must not
// reach the config.
func TestApplyCarrierBridges(t *testing.T) {
	pinAnyIface(t)
	cfg := &xray.Config{
		InboundConfigs: []xray.InboundConfig{{Tag: "api", Protocol: "dokodemo-door"}},
		RouterConfig: []byte(`{"rules":[
			{"type":"field","inboundTag":["api"],"outboundTag":"api"},
			{"type":"field","source":["10.0.0.0/12"],"outboundTag":"blocked"}
		]}`),
	}
	carriers := []vpnOutCarrier{
		{Tag: "vlessout", Kind: vpnOutCarrierBridged, Iface: vpnOutCarrierDev("vlessout"), Addr: "10.11.9.1/30"},
		{Tag: "wg-a", Kind: vpnOutCarrierTunnel, Iface: "wg0"},
		{Tag: "pinned", Kind: vpnOutCarrierPinned, Iface: "eth1"},
	}
	if err := applyCarrierBridgesWith(cfg, carriers); err != nil {
		t.Fatal(err)
	}

	// Exactly one bridge: a tunnel and a pinned outbound are already devices.
	var bridges []xray.InboundConfig
	for _, in := range cfg.InboundConfigs {
		if in.Protocol == "tun" {
			bridges = append(bridges, in)
		}
	}
	if len(bridges) != 1 {
		t.Fatalf("got %d tun inbounds, want 1 (only the bridged carrier needs one)", len(bridges))
	}
	if bridges[0].Tag != vpnOutCarrierTagPrefix+"vlessout" {
		t.Errorf("bridge tag is %q", bridges[0].Tag)
	}
	if !strings.Contains(string(bridges[0].Settings), vpnOutCarrierDev("vlessout")) {
		t.Errorf("bridge settings %s do not name the device", bridges[0].Settings)
	}
	// autoOutboundsInterface installs a PROCESS-GLOBAL dialer controller that would pin
	// every outbound in the core to one device.
	for _, forbidden := range []string{"autoOutboundsInterface", "autoSystemRoutingTable"} {
		if strings.Contains(string(bridges[0].Settings), forbidden) {
			t.Errorf("bridge settings carry %s, which is process-global", forbidden)
		}
	}

	var routing struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(cfg.RouterConfig, &routing); err != nil {
		t.Fatal(err)
	}
	// FIRST. Routing is first-match, and translateVpnRoutingRules appends a backstop
	// that blackholes every source inside 10.0.0.0/12, which is where carrier devices
	// are addressed. A rule behind that backstop is a carried tunnel that never works.
	if len(routing.Rules) != 3 {
		t.Fatalf("got %d rules, want the two that were there plus one", len(routing.Rules))
	}
	if got, _ := routing.Rules[0]["outboundTag"].(string); got != "vlessout" {
		t.Errorf("rule 0 sends to %q, want the carrier rule prepended ahead of every other rule", got)
	}

	// Rebuilt, the config must not grow: same tag replaces in place, and a duplicate
	// tag makes the core refuse the WHOLE config.
	before := len(cfg.InboundConfigs)
	if err := applyCarrierBridgesWith(cfg, carriers); err != nil {
		t.Fatal(err)
	}
	if len(cfg.InboundConfigs) != before {
		t.Errorf("a second build added an inbound (%d -> %d)", before, len(cfg.InboundConfigs))
	}
	if err := json.Unmarshal(cfg.RouterConfig, &routing); err != nil {
		t.Fatal(err)
	}
	if len(routing.Rules) != 3 {
		t.Errorf("a second build left %d rules, want 3", len(routing.Rules))
	}

	// A carrier that goes away takes its rule with it, or the config points at an
	// outbound that may no longer exist.
	if err := applyCarrierBridgesWith(cfg, nil); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(cfg.RouterConfig, &routing); err != nil {
		t.Fatal(err)
	}
	for _, r := range routing.Rules {
		if vpnOutRuleIsCarrier(r) {
			t.Errorf("a carrier rule survived after its carrier was gone: %v", r)
		}
	}
}

// A tun inbound naming a device the core cannot open does not fail by itself: the core
// refuses to start AT ALL, taking every inbound and every other tunnel down with it.
func TestApplyCarrierBridgesSkipsACarrierWithNoDevice(t *testing.T) {
	prev := vpnOutIfaceGone
	vpnOutIfaceGone = func(iface string) bool { return iface == vpnOutCarrierDev("notyet") }
	t.Cleanup(func() { vpnOutIfaceGone = prev })

	cfg := &xray.Config{}
	err := applyCarrierBridgesWith(cfg, []vpnOutCarrier{
		{Tag: "notyet", Kind: vpnOutCarrierBridged, Iface: vpnOutCarrierDev("notyet")},
		{Tag: "ready", Kind: vpnOutCarrierBridged, Iface: vpnOutCarrierDev("ready")},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range cfg.InboundConfigs {
		if in.Tag == vpnOutCarrierTagPrefix+"notyet" {
			t.Error("a carrier with no device reached the config; the core would refuse to start")
		}
	}
	if len(cfg.InboundConfigs) != 1 {
		t.Fatalf("got %d inbounds, want only the carrier whose device exists", len(cfg.InboundConfigs))
	}
}

// The SSH tunnels have to be in the plan whether or not any of them names a carrier.
// vpnOutApplyVia deletes every rule in its bands that the plan does not contain, so an
// SSH steer rule the plan never mentions is installed by the raise and swept by the next
// reconcile of anything else.
func TestVpnOutSshViaFacts(t *testing.T) {
	// Literal addresses only: this must not depend on a resolver.
	sshList := []SshOutboundConfig{
		{Tag: "jump", Address: "198.51.100.7", Port: 22, Via: "vlessout"},
		{Tag: "plain", Address: "198.51.100.8", Port: 22},
		{Tag: "", Address: "198.51.100.9"},
	}
	carriers := []vpnOutCarrier{
		{Tag: "vlessout", Kind: vpnOutCarrierBridged, Iface: vpnOutCarrierDev("vlessout")},
	}
	facts := vpnOutSshViaFacts(sshList, carriers)
	if len(facts) != 2 {
		t.Fatalf("got %d facts, want one per tagged tunnel", len(facts))
	}
	byTag := map[string]vpnOutViaFacts{}
	for _, f := range facts {
		byTag[f.Tag] = f
	}
	jump := byTag["jump"]
	if jump.Via != "vlessout" {
		t.Errorf("jump.Via = %q, want the carrier it named", jump.Via)
	}
	if !jump.Enable {
		t.Error("a stored ssh tunnel is dialled, so it must plan as enabled")
	}
	if len(jump.ServerAddrs) != 1 || jump.ServerAddrs[0] != "198.51.100.7/32" {
		t.Errorf("jump.ServerAddrs = %v, want the ssh server as a /32 to steer", jump.ServerAddrs)
	}
	// An untouched tunnel still has to appear, or the reconcile has nothing to keep.
	if _, ok := byTag["plain"]; !ok {
		t.Error("an ssh tunnel with no carrier is missing from the plan")
	}
	if byTag["plain"].Via != "" {
		t.Errorf("plain.Via = %q, want none", byTag["plain"].Via)
	}
}

// Steering into a netdev is L4-agnostic, so a device carrier takes GRE and ESP whole.
// Only a bridged carrier asks the per-kind question.
func TestVpnOutCarrierRefusalOnlyAppliesToABridgedCarrier(t *testing.T) {
	pptp := VpnOutboundConfig{Tag: "p", Kind: VpnOutPPTP, Enable: true}
	for _, c := range []vpnOutCarrier{
		{Tag: "wg-a", Kind: vpnOutCarrierTunnel, Iface: "wg0"},
		{Tag: "pinned", Kind: vpnOutCarrierPinned, Iface: "eth1"},
	} {
		if why := vpnOutCarrierRefusal(pptp, c); why != "" {
			t.Errorf("a device carrier refused pptp: %q", why)
		}
	}
	if why := vpnOutCarrierRefusal(pptp, vpnOutCarrier{Tag: "vlessout", Kind: vpnOutCarrierBridged}); why == "" {
		t.Error("a bridged carrier accepted pptp, whose data channel is raw GRE and would be dropped")
	}
}
