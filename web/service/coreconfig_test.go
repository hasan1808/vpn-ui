package service

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
)

// TestApplyCoreConfigOverrideRoundTrip closes the loop the unit tests above only cover
// halfway: an override the editor stores has to come back out of the settings row and
// into the generator's output, keyed to the right file.
//
// It also pins the reason the whole map lives under ONE setting key: getString treats a
// key that is not in defaultValueMap as an ERROR rather than as unset, so a per-file key
// could never be declared up front and the first read on a fresh install would fail.
func TestApplyCoreConfigOverrideRoundTrip(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	// A fresh install has never written the row. This must read as "no overrides",
	// not as a failure that leaves the generators unable to write anything.
	resetCoreConfigCacheForTest()
	if got := applyCoreConfigOverride("l2tp", 0, "xl2tpd.conf", "body\n"); got != "body\n" {
		t.Fatalf("an unset override changed the render: %q", got)
	}

	if err := setCoreConfigOverrides(map[string]CoreConfigOverride{
		coreConfigKey("openvpn", 7, "server-udp.conf"): {Mode: CoreConfigModeAppend, Text: "verb 4"},
		coreConfigKey("mtproto", 3, "config.toml"):     {Mode: CoreConfigModeReplace, Text: "[general]\n"},
	}); err != nil {
		t.Fatalf("store: %v", err)
	}
	// Drop the cache so this really re-reads the row rather than the map just written.
	resetCoreConfigCacheForTest()

	udp := applyCoreConfigOverride("openvpn", 7, "server-udp.conf", "port 1194\n")
	if !strings.Contains(udp, "port 1194") || !strings.Contains(udp, "verb 4") {
		t.Fatalf("the openvpn override did not round-trip:\n%s", udp)
	}
	// The other transport of the SAME inbound must be untouched.
	if tcp := applyCoreConfigOverride("openvpn", 7, "server-tcp.conf", "port 1194\n"); tcp != "port 1194\n" {
		t.Fatalf("the override leaked onto the other transport:\n%s", tcp)
	}
	// And another inbound of the same core.
	if other := applyCoreConfigOverride("openvpn", 8, "server-udp.conf", "port 1194\n"); other != "port 1194\n" {
		t.Fatalf("the override leaked onto another inbound:\n%s", other)
	}
	if toml := applyCoreConfigOverride("mtproto", 3, "config.toml", "generated\n"); toml != "[general]\n" {
		t.Fatalf("replace mode did not round-trip: %q", toml)
	}

	ClearCoreConfigOverrides("openvpn")
	resetCoreConfigCacheForTest()
	if got := applyCoreConfigOverride("openvpn", 7, "server-udp.conf", "port 1194\n"); got != "port 1194\n" {
		t.Fatalf("uninstall did not clear the openvpn override:\n%s", got)
	}
	if got := applyCoreConfigOverride("mtproto", 3, "config.toml", "generated\n"); got != "[general]\n" {
		t.Fatal("clearing one core's overrides took another core's with it")
	}
}

// resetCoreConfigCacheForTest forces the next read to go back to the database.
func resetCoreConfigCacheForTest() {
	coreConfigCache.Lock()
	coreConfigCache.loaded = false
	coreConfigCache.m = nil
	coreConfigCache.Unlock()
}

// TestMergeCoreConfigAppendKeepsTheRender is the property the whole append mode rests
// on: whatever the generator wrote is still there afterwards, so a new inbound or client
// keeps being served.
//
// No UI reaches this any more (the editor posts replace over the whole file), but the
// endpoint still accepts the mode and the generators still merge it, so it is still
// covered rather than left to rot.
func TestMergeCoreConfigAppendKeepsTheRender(t *testing.T) {
	rendered := "[lns default]\nip range = 10.0.2.10-10.0.2.250\n"
	out := mergeCoreConfig(rendered, CoreConfigModeAppend, "flow bit = no")
	if !strings.Contains(out, "ip range = 10.0.2.10-10.0.2.250") {
		t.Fatalf("append dropped the generated body:\n%s", out)
	}
	if !strings.Contains(out, "flow bit = no\n") {
		t.Fatalf("append dropped the override:\n%s", out)
	}
	if !strings.Contains(out, coreConfigBanner) {
		t.Fatalf("append did not mark where the override starts:\n%s", out)
	}
	if strings.Index(out, "ip range") > strings.Index(out, "flow bit") {
		t.Fatalf("the override must come AFTER the render:\n%s", out)
	}
}

// TestMergeCoreConfigIsStable guards mtproto's write-only-on-change check: telemt
// watches config.toml with inotify and the traffic job regenerates it every 10s, so an
// output that differed between two identical runs would make it hot-reload forever.
func TestMergeCoreConfigIsStable(t *testing.T) {
	rendered := "[general]\nlog_level = \"normal\"\n"
	first := mergeCoreConfig(rendered, CoreConfigModeAppend, "[extra]\nkey = 1")
	second := mergeCoreConfig(rendered, CoreConfigModeAppend, "[extra]\nkey = 1")
	if first != second {
		t.Fatalf("merge is not deterministic:\n%q\nvs\n%q", first, second)
	}
	// Trailing-newline differences in the render must not move the result either: the
	// generators are not consistent about it.
	if mergeCoreConfig("a\n", CoreConfigModeAppend, "b") != mergeCoreConfig("a\n\n\n", CoreConfigModeAppend, "b") {
		t.Fatal("a differing number of trailing newlines changed the merged output")
	}
}

// TestMergeCoreConfigReplaceDropsTheRender is the dangerous half, asserted so it stays
// deliberate: replace mode really does discard everything the generator produced, and it
// is what the editor posts, which is why the modal's one warning is about being frozen at
// what you save.
func TestMergeCoreConfigReplaceDropsTheRender(t *testing.T) {
	out := mergeCoreConfig("generated body\n", CoreConfigModeReplace, "mine only")
	if strings.Contains(out, "generated body") {
		t.Fatalf("replace kept the generated body:\n%s", out)
	}
	if out != "mine only\n" {
		t.Fatalf("replace should be the override verbatim, got %q", out)
	}
}

// TestMergeCoreConfigEmptyIsNoOverride: clearing the text is how "Reset to default"
// works, so blank input must leave the render untouched rather than append a banner
// over nothing.
func TestMergeCoreConfigEmptyIsNoOverride(t *testing.T) {
	rendered := "name l2tp\n"
	for _, text := range []string{"", "   ", "\n\t\n"} {
		if got := mergeCoreConfig(rendered, CoreConfigModeAppend, text); got != rendered {
			t.Fatalf("blank override changed the file: %q -> %q", text, got)
		}
		if got := mergeCoreConfig(rendered, CoreConfigModeReplace, text); got != rendered {
			t.Fatalf("blank replace-mode override changed the file: %q -> %q", text, got)
		}
	}
}

func TestValidateSwanctlBraces(t *testing.T) {
	ok := `connections {
    l2tp-psk {
        version = 1   # a comment with an unbalanced { in it
    }
}
`
	if err := validateSwanctlBraces(ok); err != nil {
		t.Fatalf("a balanced config was rejected: %v", err)
	}
	if err := validateSwanctlBraces("connections {\n    x {\n    }\n"); err == nil {
		t.Fatal("an unclosed section was accepted")
	}
	if err := validateSwanctlBraces("}\n"); err == nil {
		t.Fatal("a stray closing brace was accepted")
	}
}

// TestCoreConfigKeyDistinguishesOpenVpnTransports is why the key carries a file name on
// top of the inbound id: OpenVPN writes TWO configs for one inbound, and an override on
// the UDP one must not land on the TCP one.
func TestCoreConfigKeyDistinguishesOpenVpnTransports(t *testing.T) {
	udp := coreConfigKey("openvpn", 12, "server-udp.conf")
	tcp := coreConfigKey("openvpn", 12, "server-tcp.conf")
	if udp == tcp {
		t.Fatalf("both transports share the key %q", udp)
	}
	if coreConfigKey("l2tp", 0, "xl2tpd.conf") == coreConfigKey("pptp", 0, "xl2tpd.conf") {
		t.Fatal("two cores share a key for the same file name")
	}
}

// TestCoreConfigProcNamesCoverTheHookedCores: the apply-and-watch revert is only a real
// check for cores it can actually observe, so a core with an editor and no process name
// would silently accept a config that kills its daemon.
func TestCoreConfigProcNamesCoverTheHookedCores(t *testing.T) {
	for _, core := range []string{"l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "gre", "mtproto", "ipsec"} {
		if len(coreConfigProcNames(core, 1)) == 0 {
			t.Errorf("core %q has an editor but no process to watch after a save", core)
		}
	}
}
