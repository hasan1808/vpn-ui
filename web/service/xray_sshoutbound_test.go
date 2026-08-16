package service

import (
	"encoding/json"
	"testing"

	"github.com/hasan1808/pro-ui/xray"
)

func tags(t *testing.T, raw []byte) map[string]map[string]any {
	t.Helper()
	var obs []map[string]any
	if err := json.Unmarshal(raw, &obs); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, ob := range obs {
		tag, _ := ob["tag"].(string)
		out[tag] = ob
	}
	return out
}

func port(t *testing.T, ob map[string]any) float64 {
	t.Helper()
	s := ob["settings"].(map[string]any)
	srv := s["servers"].([]any)[0].(map[string]any)
	return srv["port"].(float64)
}

// The synthesized outbound must REPLACE a stale template entry with the same tag,
// never duplicate it (a duplicate tag makes Xray refuse the whole config), and
// must leave every unrelated outbound untouched.
func TestApplySshOutboundsReplacesStaleAndKeepsOthers(t *testing.T) {
	cfg := &xray.Config{OutboundConfigs: []byte(`[
		{"tag":"direct","protocol":"freedom"},
		{"tag":"ssh-out-1","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":10810}]}},
		{"tag":"blocked","protocol":"blackhole"}
	]`)}

	// Stand in for the stored tunnel list.
	got := applySshOutboundsWith(cfg, []SshOutboundConfig{
		{Tag: "ssh-out-1", SocksPort: 11001}, // stale port in the template
		{Tag: "ssh-out-2", SocksPort: 11002}, // never in the template
		{Tag: "ssh-out-3", SocksPort: 0},     // never bound; must be skipped
	})
	if got != nil {
		t.Fatal(got)
	}

	byTag := tags(t, cfg.OutboundConfigs)
	if len(byTag) != 4 {
		t.Fatalf("got %d outbounds, want 4 (direct, blocked, ssh-out-1, ssh-out-2): %v", len(byTag), byTag)
	}
	if _, ok := byTag["direct"]; !ok {
		t.Fatal("unrelated outbound 'direct' was dropped")
	}
	if _, ok := byTag["blocked"]; !ok {
		t.Fatal("unrelated outbound 'blocked' was dropped")
	}
	if p := port(t, byTag["ssh-out-1"]); p != 11001 {
		t.Fatalf("stale template port not corrected: got %v want 11001", p)
	}
	if p := port(t, byTag["ssh-out-2"]); p != 11002 {
		t.Fatalf("missing outbound not synthesized: got %v", p)
	}
	if _, ok := byTag["ssh-out-3"]; ok {
		t.Fatal("a tunnel with no bound port must not get an outbound")
	}
	// Exactly one entry per tag, i.e. no duplicates in the raw array.
	var obs []map[string]any
	if err := json.Unmarshal(cfg.OutboundConfigs, &obs); err != nil {
		t.Fatal(err)
	}
	if len(obs) != 4 {
		t.Fatalf("duplicate tags present: %d entries for 4 tags", len(obs))
	}
}
