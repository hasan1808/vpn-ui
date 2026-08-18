package service

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

// Clients on the Xray-native wireguard inbound.
//
// The bug these pin: an operator could create one of these inbounds and then had no
// way at all to put an account on it. Its settings carry `peers`, not `clients`, so
// AssignableInboundsFor never offered it and the accounts layer had nothing to splice
// into.

func wgxrayInbound(t *testing.T, settings map[string]any) *model.Inbound {
	t.Helper()
	blob, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		UserId: 1, Tag: "wireguard-inbound", Port: 51820,
		Protocol: model.WireGuard, Enable: true, Settings: string(blob),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	return inbound
}

func wgxraySettings(t *testing.T, inbound *model.Inbound) map[string]any {
	t.Helper()
	out := map[string]any{}
	if err := json.Unmarshal([]byte(inbound.Settings), &out); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	return out
}

// The headline: the picker offers a wireguard inbound at all. It used to be filtered
// out by settingsHoldClients, which is why nothing could be assigned to one.
func TestWireguardInboundIsAssignable(t *testing.T) {
	newAccountsDB(t)
	wgxrayInbound(t, map[string]any{"secretKey": "", "peers": []any{}})

	svc := &AccountService{}
	rows, err := svc.AssignableInboundsFor(&model.User{Id: 1, IsSuperAdmin: true})
	if err != nil {
		t.Fatalf("AssignableInboundsFor: %v", err)
	}
	for _, r := range rows {
		if r.Protocol == string(model.WireGuard) {
			return
		}
	}
	t.Fatalf("the wireguard inbound is not offered as assignable (got %v). An operator can "+
		"create the inbound and then has no way to put an account on it, which is the bug.", rows)
}

// One keypair and one tunnel address per device slot, both minted server-side, and
// neither moves on a later pass.
func TestReconcileWireguardXrayMintsKeysAndAddresses(t *testing.T) {
	newAccountsDB(t)
	inbound := wgxrayInbound(t, map[string]any{
		"clientNetwork": "10.10.0.0/24",
		"userLimit":     2,
		"clients": []any{
			map[string]any{"email": "wg@example.com", "enable": true},
		},
	})

	changed, err := ReconcileWireguardXrayKeys(inbound)
	if err != nil {
		t.Fatalf("ReconcileWireguardXrayKeys: %v", err)
	}
	if !changed {
		t.Fatal("the first reconcile changed nothing; there were no keys to start with")
	}

	settings := wgxraySettings(t, inbound)
	if strings.TrimSpace(settings["secretKey"].(string)) == "" {
		t.Error("the inbound has no device key")
	}
	clients := settings["clients"].([]any)
	c := clients[0].(map[string]any)
	devices := c["devices"].([]any)
	addrs := c["addresses"].([]any)
	if len(devices) != 2 || len(addrs) != 2 {
		t.Fatalf("got %d device(s) and %d address(es); want 2 and 2 (the inbound's User Limit)",
			len(devices), len(addrs))
	}
	if addrs[0] != "10.10.0.2/32" || addrs[1] != "10.10.0.3/32" {
		t.Errorf("addresses = %v; want 10.10.0.2/32 and 10.10.0.3/32. .1 is the inbound's own "+
			"address and must never be handed to a peer.", addrs)
	}
	for i, d := range devices {
		dev := d.(map[string]any)
		if strings.TrimSpace(dev["privKey"].(string)) == "" || strings.TrimSpace(dev["pubKey"].(string)) == "" {
			t.Errorf("device %d has no keypair", i)
		}
	}

	// Idempotent. Anything else would re-key a customer on every save.
	before := inbound.Settings
	if changed, err := ReconcileWireguardXrayKeys(inbound); err != nil || changed {
		t.Errorf("the second reconcile reported changed=%v err=%v; it must be a no-op", changed, err)
	}
	if inbound.Settings != before {
		t.Error("the second reconcile rewrote the settings, so every save would re-key the account")
	}
}

// A second account does not take an address the first already holds, and neither
// touches one an operator pinned by hand.
func TestReconcileWireguardXrayAvoidsTakenAddresses(t *testing.T) {
	newAccountsDB(t)
	inbound := wgxrayInbound(t, map[string]any{
		"clientNetwork": "10.10.0.0/24",
		"userLimit":     1,
		"peers": []any{
			map[string]any{"publicKey": "manual", "allowedIPs": []any{"10.10.0.2/32"}},
		},
		"clients": []any{
			map[string]any{"email": "first@example.com", "enable": true},
			map[string]any{"email": "second@example.com", "enable": true},
		},
	})

	if _, err := ReconcileWireguardXrayKeys(inbound); err != nil {
		t.Fatalf("ReconcileWireguardXrayKeys: %v", err)
	}
	clients := wgxraySettings(t, inbound)["clients"].([]any)
	first := clients[0].(map[string]any)["addresses"].([]any)
	second := clients[1].(map[string]any)["addresses"].([]any)
	if first[0] == second[0] {
		t.Fatalf("both accounts were given %v", first[0])
	}
	for _, got := range []any{first[0], second[0]} {
		if got == "10.10.0.2/32" {
			t.Errorf("an account was given 10.10.0.2/32, which a hand-added peer already holds; "+
				"that breaks a working tunnel the accounts layer knows nothing about (got %v/%v)",
				first[0], second[0])
		}
	}
}

// The translation to what the core actually takes: peers out, clients gone.
func TestApplyWireguardClientsBuildsPeers(t *testing.T) {
	settings := map[string]any{
		"secretKey": "server-key",
		"peers": []any{
			map[string]any{"publicKey": "manual", "allowedIPs": []any{"10.10.0.9/32"}},
		},
		"clients": []any{
			map[string]any{
				"email": "on@example.com", "enable": true,
				"devices":   []any{map[string]any{"pubKey": "pub-a", "psk": "shared"}},
				"addresses": []any{"10.10.0.2/32"},
			},
			map[string]any{
				"email": "off@example.com", "enable": false,
				"devices":   []any{map[string]any{"pubKey": "pub-b"}},
				"addresses": []any{"10.10.0.3/32"},
			},
		},
	}
	applyWireguardClients(settings, func(email string, entryEnabled bool) bool { return entryEnabled })

	if _, still := settings["clients"]; still {
		t.Error("`clients` is still in the generated settings; it means nothing to the core")
	}
	peers := settings["peers"].([]any)
	if len(peers) != 2 {
		t.Fatalf("got %d peer(s); want 2 (the hand-added one plus the enabled account)", len(peers))
	}
	if peers[0].(map[string]any)["publicKey"] != "manual" {
		t.Error("the hand-added peer was dropped; an account edit must not delete it")
	}
	managed := peers[1].(map[string]any)
	if managed["publicKey"] != "pub-a" {
		t.Errorf("managed peer key = %v; want pub-a", managed["publicKey"])
	}
	if managed["preSharedKey"] != "shared" {
		t.Errorf("preSharedKey = %v; want it carried through", managed["preSharedKey"])
	}
	if ips := managed["allowedIPs"].([]any); len(ips) != 1 || ips[0] != "10.10.0.2/32" {
		t.Errorf("allowedIPs = %v; want exactly this device's own address", ips)
	}
}

// A depleted or expired account is dropped from the peer list, which is the whole of
// enforcement for this protocol: Xray reports nothing per peer, so there is nothing
// to disconnect and the only lever is not admitting it in the first place.
func TestApplyWireguardClientsDropsDisabledAccounts(t *testing.T) {
	settings := map[string]any{
		"clients": []any{
			map[string]any{
				"email": "depleted@example.com", "enable": true,
				"devices":   []any{map[string]any{"pubKey": "pub-a"}},
				"addresses": []any{"10.10.0.2/32"},
			},
		},
	}
	applyWireguardClients(settings, func(email string, entryEnabled bool) bool { return false })
	if peers := settings["peers"].([]any); len(peers) != 0 {
		t.Errorf("got %d peer(s); want none. A client the panel has switched off must not be "+
			"able to complete a handshake.", len(peers))
	}
}

// A device with no address gets NO peer. Xray's default for a peer with no allowedIPs
// is 0.0.0.0/0, so emitting one would authorise it to source every other client's
// address.
func TestApplyWireguardClientsSkipsAddresslessDevices(t *testing.T) {
	settings := map[string]any{
		"clients": []any{
			map[string]any{
				"email": "half@example.com", "enable": true,
				"devices": []any{
					map[string]any{"pubKey": "pub-a"},
					map[string]any{"pubKey": "pub-b"},
				},
				"addresses": []any{"10.10.0.2/32"},
			},
		},
	}
	applyWireguardClients(settings, func(string, bool) bool { return true })
	peers := settings["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("got %d peer(s); want 1. A device with no address must be left out rather than "+
			"emitted with Xray's 0.0.0.0/0 default, which would let it source any client's address.",
			len(peers))
	}
	if peers[0].(map[string]any)["publicKey"] != "pub-a" {
		t.Errorf("the wrong device was served: %v", peers[0])
	}
}

// The .conf a customer installs, one per device.
func TestRenderWireguardXrayConfigs(t *testing.T) {
	newAccountsDB(t)
	inbound := wgxrayInbound(t, map[string]any{
		"clientNetwork": "10.10.0.0/24",
		"userLimit":     2,
		"mtu":           1380,
		"clients": []any{
			map[string]any{"email": "conf@example.com", "enable": true},
		},
	})
	if _, err := ReconcileWireguardXrayKeys(inbound); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	configs, err := RenderWireguardXrayConfigs(inbound, "conf@example.com", "vpn.example.com")
	if err != nil {
		t.Fatalf("RenderWireguardXrayConfigs: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("got %d config(s); want one per device slot (2)", len(configs))
	}
	serverPub := wgxraySettings(t, inbound)["pubKey"].(string)
	for i, cfg := range configs {
		for _, want := range []string{
			"Address = " + cfg.IP,
			"MTU = 1380",
			"PublicKey = " + serverPub,
			"Endpoint = vpn.example.com:51820",
			"AllowedIPs = 0.0.0.0/0",
		} {
			if !strings.Contains(cfg.Config, want) {
				t.Errorf("config %d does not contain %q:\n%s", i, want, cfg.Config)
			}
		}
	}
	if configs[0].IP == configs[1].IP {
		t.Error("both devices were given the same address, so only one of them can connect")
	}

	// An email that is not on the inbound is an error, not an empty config that looks
	// like a working one with nothing in it.
	if _, err := RenderWireguardXrayConfigs(inbound, "stranger@example.com", "vpn.example.com"); err == nil {
		t.Error("rendering a config for an account that is not a client returned no error")
	}
}

// A pool that has run out reports it rather than wrapping onto an address somebody
// else already holds.
func TestWgxrayHostAtRefusesToWrap(t *testing.T) {
	_, network, err := net.ParseCIDR("10.10.0.0/30")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := wgxrayHostAt(network, 1); got != "10.10.0.1/32" {
		t.Errorf("host 1 = %q; want 10.10.0.1/32", got)
	}
	if got := wgxrayHostAt(network, 2); got != "10.10.0.2/32" {
		t.Errorf("host 2 = %q; want 10.10.0.2/32", got)
	}
	// .3 is the broadcast address of a /30 and is not a host.
	if got := wgxrayHostAt(network, 3); got != "" {
		t.Errorf("host 3 = %q; want empty, the pool is exhausted", got)
	}
}

// The device's own address has to be in the pool its peers are addressed from.
// Xray's default when the field is absent is the bogon 10.0.0.1, so an inbound
// handing its clients 10.10.0.x had its device in a different subnet from all of
// them.
func TestApplyWireguardClientsAddressesTheDevice(t *testing.T) {
	settings := map[string]any{
		"clientNetwork": "10.77.0.0/24",
		"clients":       []any{},
	}
	applyWireguardClients(settings, func(string, bool) bool { return true })
	addr, _ := settings["address"].([]any)
	if len(addr) != 1 || addr[0] != "10.77.0.1" {
		t.Errorf("address = %v; want [10.77.0.1], the first host of the pool", settings["address"])
	}

	// The default pool when the inbound does not name one.
	bare := map[string]any{"clients": []any{}}
	applyWireguardClients(bare, func(string, bool) bool { return true })
	if addr, _ := bare["address"].([]any); len(addr) != 1 || addr[0] != "10.10.0.1" {
		t.Errorf("address = %v; want [10.10.0.1]", bare["address"])
	}
}

// An imported inbound, or one configured by hand, may already name an address, and
// that one is the truth about what its existing peers are talking to.
func TestApplyWireguardClientsKeepsAConfiguredAddress(t *testing.T) {
	settings := map[string]any{
		"clientNetwork": "10.77.0.0/24",
		"address":       []any{"192.168.9.1"},
		"clients":       []any{},
	}
	applyWireguardClients(settings, func(string, bool) bool { return true })
	if addr, _ := settings["address"].([]any); len(addr) != 1 || addr[0] != "192.168.9.1" {
		t.Errorf("address = %v; want the configured 192.168.9.1 untouched", settings["address"])
	}
}

// An inbound imported from upstream 3x-ui has peers and NO clients key at all. Its
// hand-authored peers must survive the rewrite, and its device key must not be
// re-minted: every peer already installed is authorised against it.
func TestUpstreamWireguardInboundSurvivesImport(t *testing.T) {
	newAccountsDB(t)
	const upstreamKey = "UPSTREAMSECRETKEYAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const peerKey = "HANDAUTHOREDPEERPUBKEYAAAAAAAAAAAAAAAAAAAAA="
	inbound := wgxrayInbound(t, map[string]any{
		"mtu":         1420,
		"secretKey":   upstreamKey,
		"noKernelTun": false,
		"peers": []any{
			map[string]any{"publicKey": peerKey, "allowedIPs": []any{"10.0.0.2/32"}, "keepAlive": 25},
		},
	})

	if _, err := ReconcileWireguardXrayKeys(inbound); err != nil {
		t.Fatalf("ReconcileWireguardXrayKeys: %v", err)
	}
	settings := wgxraySettings(t, inbound)

	if settings["secretKey"] != upstreamKey {
		t.Errorf("the device key was re-minted (%v); every peer already installed is "+
			"authorised against the imported one", settings["secretKey"])
	}
	peers, _ := settings["peers"].([]any)
	if len(peers) != 1 || peers[0].(map[string]any)["publicKey"] != peerKey {
		t.Errorf("the hand-authored peer did not survive: %v", settings["peers"])
	}
	if _, ok := settings["clients"].([]any); !ok {
		t.Error("no clients array was added, so the inbound stays unassignable")
	}
	// An absent userLimit is legacy and means ONE device per account, not the
	// 64-device maximum that an explicit 0 means.
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(inbound.Settings), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := wgxrayEffectiveDevices(raw); got != 1 {
		t.Errorf("devices per account = %d; want 1 for an inbound that names no user limit", got)
	}

	// And the generated config keeps the peer while dropping the clients key.
	gen := wgxraySettings(t, inbound)
	applyWireguardClients(gen, func(string, bool) bool { return true })
	if _, still := gen["clients"]; still {
		t.Error("clients reached the generated config")
	}
	out, _ := gen["peers"].([]any)
	if len(out) != 1 || out[0].(map[string]any)["publicKey"] != peerKey {
		t.Errorf("generated peers = %v; want the hand-authored one preserved", gen["peers"])
	}
}
