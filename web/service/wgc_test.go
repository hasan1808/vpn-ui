package service

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

// TestWgcRenderDiag mirrors the E2E harness wg-c inbound (2 clients, userLimit 6, no keys
// sent) to check that ReconcileKeys mints keys and RenderClientConfigs returns a config.
func TestWgcRenderDiag(t *testing.T) {
	settings := `{"dns1":"1.1.1.1","dns2":"8.8.8.8","mtu":1420,"pskEnable":false,` +
		`"clientToClient":true,"crossInbound":true,"userLimit":6,"ipRanges":["10.7.7.2-10.7.7.254"],` +
		`"clients":[{"email":"wg-ca@t","enable":true,"id":"wg-ca"},` +
		`{"email":"wg-cb@t","enable":true,"id":"wg-cb"}]}`
	ib := &model.Inbound{Id: 12, Port: 51820, Protocol: model.WGC, Enable: true, Tag: "inbound-51820", Settings: settings}
	s := &WgcService{}

	changed, err := s.ReconcileKeys(ib)
	if err != nil {
		t.Fatalf("ReconcileKeys err: %v", err)
	}
	t.Logf("ReconcileKeys changed=%v", changed)
	cfgs, err := s.RenderClientConfigs(ib, "wg-ca@t", "1.2.3.4")
	t.Logf("RenderClientConfigs -> %d configs, err=%v", len(cfgs), err)
	if len(cfgs) == 0 {
		t.Fatalf("EXPECTED >=1 config for wg-ca@t, got 0")
	}
}

// TestWgcConfigFetchDB reproduces the getWgcConfigs endpoint flow against a real DB with a
// harness-style wg-c inbound (clients with id!=email, NO keys): ReconcileAllKeys mints +
// persists, reload, then RenderClientConfigs must return a config. Reproduces "0 configs".
func TestWgcConfigFetchDB(t *testing.T) {
	dir := t.TempDir()
	if err := database.InitDB(filepath.Join(dir, "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	// harness payload: id != email, password present, NO keys, no ipRanges (panel assigns)
	settings := `{"userLimit":6,"clientToClient":true,"crossInbound":true,"pskEnable":false,` +
		`"dns1":"1.1.1.1","dns2":"8.8.8.8","mtu":1420,` +
		`"clients":[{"id":"wg-ca","password":"Pw-wg-cA-9k","email":"wg-ca@t","enable":true},` +
		`{"id":"wg-cb","password":"Pw-wg-cB-9k","email":"wg-cb@t","enable":true}]}`
	ib := &model.Inbound{UserId: 1, Enable: true, Port: 51820, Protocol: model.WGC, Settings: settings, Tag: "inbound-51820"}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	// mirror addInbound: assign ranges
	if err := normalizeRanges(ib, ib.Id); err != nil {
		t.Logf("normalizeRanges err: %v", err)
	} else {
		db.Model(&model.Inbound{}).Where("id = ?", ib.Id).Update("settings", ib.Settings)
	}
	t.Logf("settings after normalizeRanges: %s", ib.Settings)

	wgc := &WgcService{}
	wgc.ReconcileAllKeys()

	var reloaded model.Inbound
	if err := db.First(&reloaded, ib.Id).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	t.Logf("settings after ReconcileAllKeys (persisted): %s", reloaded.Settings)

	cfgs, err := wgc.RenderClientConfigs(&reloaded, "wg-ca@t", "1.2.3.4")
	t.Logf("RenderClientConfigs -> %d configs, err=%v", len(cfgs), err)
	for i, c := range cfgs {
		t.Logf("cfg[%d] ip=%s\n%s", i, c.IP, c.Config)
	}
	if len(cfgs) == 0 {
		t.Fatalf("REPRODUCED: 0 configs from getWgcConfigs flow")
	}
}

// TestWgcXrayConfig builds the full Xray config with a wg-c inbound present and validates
// it with the real xray binary (-test), reproducing the E2E "xray not running" failure.
func TestWgcXrayConfig(t *testing.T) {
	dir := t.TempDir()
	if err := database.InitDB(filepath.Join(dir, "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	wgcSettings := `{"dns1":"1.1.1.1","dns2":"8.8.8.8","mtu":1420,"pskEnable":false,` +
		`"clientToClient":true,"crossInbound":true,"userLimit":6,"ipRanges":["10.7.7.2-10.7.7.254"],` +
		`"serverPrivKey":"WJBYsg2KO4OHc00UkfDXi79cawNyZNJfPWdtF6vb1mw=",` +
		`"serverPubKey":"W6WUZ4OXkeTjygoaWIlMnbZBqibaP2lSFzhUeOQ2kVY=",` +
		`"clients":[{"email":"wg-ca@t","enable":true,"id":"wg-ca","privKey":"CBi/NbmtWR2Uk2jA0KAc4ZM+Q3WkKdBAm0jNs2K5XW4=","pubKey":"dVBgJcQqfo6rb1K+OKSqvr0IuOX21iRz/lFsfcZAdEg="},` +
		`{"email":"wg-cb@t","enable":true,"id":"wg-cb","privKey":"EHquh7LAo51hLXTKfT8NMXzsFe0ZxhSvy267C6gDlF8=","pubKey":"IWSTPBD/PqehQA0RwU8L2BvPINNuI/huXD5KQ2YEyXU="}]}`
	ib := &model.Inbound{
		UserId: 1, Up: 0, Down: 0, Total: 0, Remark: "test-wgc",
		Enable: true, Listen: "", Port: 51820, Protocol: model.WGC,
		Settings: wgcSettings, StreamSettings: "", Tag: "inbound-51820", Sniffing: "",
	}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	s := &XrayService{}
	cfg, err := s.GetXrayConfig()
	if err != nil {
		t.Fatalf("GetXrayConfig: %v", err)
	}
	blob, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, blob, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Logf("generated config (%d bytes)", len(blob))

	xrayBin := "../../corebundle/core/amd64/xray"
	if _, err := os.Stat(xrayBin); err != nil {
		t.Skipf("xray binary not found at %s: %v", xrayBin, err)
	}
	out, err := exec.Command(xrayBin, "-test", "-c", cfgPath).CombinedOutput()
	t.Logf("xray -test output:\n%s", string(out))
	if err != nil {
		// dump the routing + dokodemo portion of the config for diagnosis
		var pretty map[string]any
		_ = json.Unmarshal(blob, &pretty)
		if rp, e := json.MarshalIndent(pretty["routing"], "", "  "); e == nil {
			t.Logf("routing:\n%s", string(rp))
		}
		t.Fatalf("xray -test FAILED: %v", err)
	}
	if strings.Contains(strings.ToLower(string(out)), "error") {
		t.Fatalf("xray -test reported error")
	}
}

// The fixtures above carry an explicit ipRanges. They used to write it as a CIDR
// ("10.7.7.0/24"), which parseRange rejects outright (a range needs a hyphen), so
// subnetsOf saw nothing, vpnBlock silently fell back to the id-derived 10.7.{id}
// and the tests exercised the fallback while appearing to cover stored ranges.
// That gap matters now that an inbound KEEPS its stored block instead of
// re-deriving it (keepOwnedBlock in vpnrange.go).
//
// The inbound id here is deliberately 12 while the stored block is 10.7.7, so this
// can only pass if the STORED range is the one being honoured.
func TestWgcHonoursItsStoredRangeNotTheIdFallback(t *testing.T) {
	settings := `{"mtu":1420,"userLimit":6,"ipRanges":["10.7.7.2-10.7.7.254"],` +
		`"clients":[{"email":"wg-ca@t","enable":true,"id":"wg-ca"}]}`
	ib := &model.Inbound{Id: 12, Port: 51820, Protocol: model.WGC, Enable: true, Settings: settings}
	s := &WgcService{}

	parsed, err := s.parseSettings(ib)
	if err != nil {
		t.Fatalf("parseSettings: %v", err)
	}
	if got := parsed.effectiveRanges(); len(got) != 1 {
		t.Fatalf("stored ranges did not survive parsing: %v", got)
	}
	netAddr, prefix := wgcBlockFor(ib, parsed)
	if netAddr.String() != "10.7.7.0" || prefix != 24 {
		t.Errorf("block = %s/%d, want 10.7.7.0/24 (10.7.12.x means the stored range was ignored)",
			netAddr, prefix)
	}
	if got := s.GetSubnetForInbound(ib); got != "10.7.7.0/24" {
		t.Errorf("GetSubnetForInbound = %q, want 10.7.7.0/24", got)
	}
}
