package service

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// User Limit K must yield K SEPARATE configs: K keypairs and K distinct tunnel IPs.
//
// The bug this pins: at K=2 the panel minted one keypair and rendered one config, so
// importing it on two machines gave both the same Address (and, sharing a keypair, they
// could not both stay connected -- the server keeps one endpoint per peer).
func TestAwgUserLimitYieldsOneConfigPerDevice(t *testing.T) {
	k := 2
	inb := &model.Inbound{
		Id: 7, Protocol: model.AWG, Port: 51821, Enable: true,
		Settings: `{"ipRanges":["10.8.7.2-10.8.7.254"],"userLimit":2,
			"clients":[{"email":"two@t","enable":true}]}`,
	}

	var s AwgService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}

	// K device slots, each with its own keypair.
	var parsed awgSettings
	if err := json.Unmarshal([]byte(inb.Settings), &parsed); err != nil {
		t.Fatalf("settings: %v", err)
	}
	devs := parsed.Clients[0].deviceList()
	if len(devs) != k {
		t.Fatalf("device slots = %d, want %d (User Limit must provision one keypair per device)", len(devs), k)
	}
	if devs[0].PrivKey == devs[1].PrivKey || devs[0].PubKey == devs[1].PubKey {
		t.Fatal("devices share a keypair: both would fight over the peer's single endpoint, so only one could stay online")
	}

	cfgs, err := s.RenderClientConfigs(inb, "two@t", "example.test")
	if err != nil {
		t.Fatalf("RenderClientConfigs: %v", err)
	}
	if len(cfgs) != k {
		t.Fatalf("configs = %d, want %d (one per device to import on separate machines)", len(cfgs), k)
	}

	// The load-bearing assertion: distinct Address per device, each a /32.
	seenIP := map[string]bool{}
	for i, c := range cfgs {
		if seenIP[c.IP] {
			t.Fatalf("config %d reuses tunnel IP %s: two devices would be assigned the same IPv4", i, c.IP)
		}
		seenIP[c.IP] = true
		if !strings.HasSuffix(c.IP, "/32") {
			t.Errorf("config %d IP = %s, want a /32 (a block-wide Address is what collided before)", i, c.IP)
		}
		if !strings.Contains(c.Config, "Address = "+c.IP) {
			t.Errorf("config %d Address line does not carry %s", i, c.IP)
		}
		// Obfuscation must still be present on every device's config.
		if !strings.Contains(c.Config, "Jc = ") || !strings.Contains(c.Config, "H1 = ") {
			t.Errorf("config %d lost its AmneziaWG obfuscation params", i)
		}
	}

	// Each config must carry its OWN private key, else they are the same credential.
	keyOf := func(cfg string) string {
		for _, line := range strings.Split(cfg, "\n") {
			if v, ok := strings.CutPrefix(line, "PrivateKey = "); ok {
				return v
			}
		}
		return ""
	}
	if keyOf(cfgs[0].Config) == keyOf(cfgs[1].Config) {
		t.Fatal("both configs carry the same PrivateKey")
	}
}

// Every device IP must fall inside the account's block CIDR. That CIDR is the single key
// used for nft accounting, Xray source routing and the speed-limit sidecar, so a device
// outside it would browse untracked: unbilled, unrouted and unlimited.
func TestAwgAccountBlockCoversEveryDevice(t *testing.T) {
	inb := &model.Inbound{
		Id: 11, Protocol: model.AWG, Port: 51821, Enable: true,
		Settings: `{"ipRanges":["10.8.11.2-10.8.11.254"],"userLimit":4,
			"clients":[{"email":"cover@t","enable":true}]}`,
	}
	var s AwgService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}
	settings, err := s.parseSettings(inb)
	if err != nil {
		t.Fatalf("parseSettings: %v", err)
	}
	cidr := s.awgAccountCIDR(inb, settings, 0)
	_, block, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("account CIDR %q: %v", cidr, err)
	}
	ips := s.awgDeviceIPs(inb, settings, 0)
	if len(ips) != 4 {
		t.Fatalf("device IPs = %d, want 4", len(ips))
	}
	for _, ip := range ips {
		if !block.Contains(net.ParseIP(ip)) {
			t.Errorf("device IP %s is outside the account block %s: its traffic would be unbilled and unlimited", ip, cidr)
		}
	}
}

// Lowering the User Limit must revoke the surplus device keys, or the limit is unenforceable.
func TestAwgLoweringUserLimitTrimsDevices(t *testing.T) {
	inb := &model.Inbound{
		Id: 8, Protocol: model.AWG, Port: 51821, Enable: true,
		Settings: `{"ipRanges":["10.8.8.2-10.8.8.254"],"userLimit":4,
			"clients":[{"email":"trim@t","enable":true}]}`,
	}
	var s AwgService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}

	// Drop to 2 and reconcile again.
	inb.Settings = strings.Replace(inb.Settings, `"userLimit":4`, `"userLimit":2`, 1)
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys (lowered): %v", err)
	}
	var parsed awgSettings
	if err := json.Unmarshal([]byte(inb.Settings), &parsed); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if got := len(parsed.Clients[0].deviceList()); got != 2 {
		t.Fatalf("device slots after lowering = %d, want 2 (stale keys would still connect)", got)
	}
}

// A single-device account (K<=1) keeps exactly one config, so the common case is unchanged.
func TestAwgSingleDeviceUnchanged(t *testing.T) {
	inb := &model.Inbound{
		Id: 9, Protocol: model.AWG, Port: 51821, Enable: true,
		Settings: `{"ipRanges":["10.8.9.2-10.8.9.254"],"userLimit":1,
			"clients":[{"email":"one@t","enable":true}]}`,
	}
	var s AwgService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}
	cfgs, err := s.RenderClientConfigs(inb, "one@t", "example.test")
	if err != nil {
		t.Fatalf("RenderClientConfigs: %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("configs = %d, want 1", len(cfgs))
	}
	if cfgs[0].Remark != "" {
		t.Errorf("single-device config should not be labelled a device slot, got %q", cfgs[0].Remark)
	}
}

// wg-c carries the SAME per-device contract as awg (it had the identical collision: one
// keypair per account meant two devices got one config, one IP, and could not both stay
// online). These mirror the awg cases against WgcService.
func TestWgcUserLimitYieldsOneConfigPerDevice(t *testing.T) {
	inb := &model.Inbound{
		Id: 21, Protocol: model.WGC, Port: 51820, Enable: true,
		Settings: `{"ipRanges":["10.7.21.2-10.7.21.254"],"userLimit":2,
			"clients":[{"email":"wtwo@t","enable":true}]}`,
	}
	var s WgcService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}
	cfgs, err := s.RenderClientConfigs(inb, "wtwo@t", "example.test")
	if err != nil {
		t.Fatalf("RenderClientConfigs: %v", err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("configs = %d, want 2 (one per device)", len(cfgs))
	}
	if cfgs[0].IP == cfgs[1].IP {
		t.Fatalf("both devices got tunnel IP %s", cfgs[0].IP)
	}
	for i, c := range cfgs {
		if !strings.HasSuffix(c.IP, "/32") {
			t.Errorf("config %d IP = %s, want /32", i, c.IP)
		}
	}
	keyOf := func(cfg string) string {
		for _, line := range strings.Split(cfg, "\n") {
			if v, ok := strings.CutPrefix(line, "PrivateKey = "); ok {
				return v
			}
		}
		return ""
	}
	if keyOf(cfgs[0].Config) == keyOf(cfgs[1].Config) {
		t.Fatal("both wg-c configs carry the same PrivateKey")
	}
}

// An account that predates per-device keys must keep its ORIGINAL key as device 0, so a
// config already deployed on a customer's machine keeps working across the upgrade.
func TestWgcLegacyKeyAdoptedAsDeviceZero(t *testing.T) {
	legacyPriv := "aFq4hJ4Zt0nJ1r3vQq6mB8pQ2xY7wKcW9dE5sT1uZ0g="
	inb := &model.Inbound{
		Id: 22, Protocol: model.WGC, Port: 51820, Enable: true,
		Settings: `{"ipRanges":["10.7.22.2-10.7.22.254"],"userLimit":2,
			"clients":[{"email":"legacy@t","enable":true,"privKey":"` + legacyPriv + `","pubKey":"x"}]}`,
	}
	var s WgcService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}
	var parsed wgcSettings
	if err := json.Unmarshal([]byte(inb.Settings), &parsed); err != nil {
		t.Fatalf("settings: %v", err)
	}
	devs := parsed.Clients[0].deviceList()
	if len(devs) != 2 {
		t.Fatalf("device slots = %d, want 2", len(devs))
	}
	if devs[0].PrivKey != legacyPriv {
		t.Errorf("device 0 key = %q, want the pre-existing account key (deployed configs would break)", devs[0].PrivKey)
	}
}
