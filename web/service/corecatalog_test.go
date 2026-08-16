package service

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/hasan1808/pro-ui/database"
)

// The catalog is what decides which host state a setup run touches and, more
// importantly, which host state an uninstall is allowed to take away. These
// tests pin the sharing arithmetic, because getting it wrong does not fail
// loudly: it silently removes a dependency another installed core is standing
// on, and that only shows up as a protocol going dark.

func TestCatalogNamesAreUniqueAndTitled(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range coreCatalog {
		if c.name == "" || c.title == "" {
			t.Errorf("catalog row %q has an empty name or title", c.name)
		}
		if seen[c.name] {
			t.Errorf("duplicate catalog entry %q", c.name)
		}
		seen[c.name] = true
	}
	// Every core the Core Settings page renders must be in the catalog, or it
	// gets forced to "not installed" by GetCoresStatus with nothing to install.
	for _, name := range []string{
		"xray", "l2tp", "pptp", "openvpn", "openconnect",
		"sstp", "ikev2", "wgc", "awg", "mtproto", "ssh", "radius",
	} {
		if coreSpecFor(name) == nil {
			t.Errorf("core %q is shown by the panel but missing from the catalog", name)
		}
	}
}

func TestRequiredModulesAlwaysIncludeTproxy(t *testing.T) {
	// Every protocol's traffic is steered into Xray with TPROXY, so its module
	// is not optional for any selection, including an empty one.
	for _, sel := range [][]string{nil, {"wgc"}, {"l2tp"}, installableCores()} {
		if !slices.Contains(requiredModulesFor(sel), "nf_tproxy_ipv4") {
			t.Errorf("selection %v did not require nf_tproxy_ipv4", sel)
		}
	}
}

func TestWireguardOnlySelectionSkipsPppAndIpsec(t *testing.T) {
	mods := requiredModulesFor([]string{"wgc"})
	for _, unwanted := range []string{"ppp_generic", "l2tp_ppp", "ip_gre", "tun"} {
		if slices.Contains(mods, unwanted) {
			t.Errorf("a WireGuard-only setup should not require %s, got %v", unwanted, mods)
		}
	}
	for _, feat := range []string{featPppd, featStrongswan, featAccel, featKernelMods, featPptpCtrl} {
		if needsFeature([]string{"wgc"}, feat) {
			t.Errorf("a WireGuard-only setup should not need %s", feat)
		}
	}
	if len(daemonsFor([]string{"wgc"})) != 0 {
		t.Errorf("WireGuard needs no bundled daemon, got %v", daemonsFor([]string{"wgc"}))
	}
}

func TestIpsecIsSharedByL2tpAndIkev2(t *testing.T) {
	if !needsFeature([]string{"l2tp"}, featStrongswan) {
		t.Error("l2tp must claim the shared strongSwan/IPsec feature")
	}
	if !needsFeature([]string{"ikev2"}, featStrongswan) {
		t.Error("ikev2 must claim the shared strongSwan/IPsec feature")
	}
}

// The headline requirement: removing IKEv2 while L2TP stays installed must not
// take IPsec away.
func TestRemovingIkev2KeepsIpsecForL2tp(t *testing.T) {
	removed := []string{"ikev2"}
	remaining := []string{"l2tp", "openvpn"}

	if !needsFeature(remaining, featStrongswan) {
		t.Fatal("l2tp still needs strongSwan, so the uninstall must keep it")
	}
	if keeper := sharedDaemonKeeper("ikev2", remaining); keeper != "l2tp" {
		t.Errorf("charon is shared with l2tp; want keeper %q, got %q", "l2tp", keeper)
	}
	// L2TP must be reconciled afterwards so charon reloads without IKEv2's
	// connection files.
	if got := coresSharingWith(removed, remaining); !slices.Contains(got, "l2tp") {
		t.Errorf("l2tp should be reconciled after removing ikev2, got %v", got)
	}
}

// The mirror case: removing L2TP while IKEv2 stays must also keep IPsec.
func TestRemovingL2tpKeepsIpsecForIkev2(t *testing.T) {
	remaining := []string{"ikev2"}
	if !needsFeature(remaining, featStrongswan) {
		t.Fatal("ikev2 still needs strongSwan")
	}
	if keeper := sharedDaemonKeeper("l2tp", remaining); keeper != "ikev2" {
		t.Errorf("want keeper ikev2, got %q", keeper)
	}
}

// With neither IPsec user left, the bundle is genuinely free to go.
func TestRemovingBothIpsecCoresReleasesIt(t *testing.T) {
	remaining := []string{"openvpn", "wgc"}
	if needsFeature(remaining, featStrongswan) {
		t.Error("nothing left needs strongSwan, so it must not be reported as still needed")
	}
	if keeper := sharedDaemonKeeper("ikev2", remaining); keeper != "" {
		t.Errorf("no core left runs charon; want no keeper, got %q", keeper)
	}
}

// pppd is shared by L2TP and PPTP the same way IPsec is shared by L2TP and IKEv2.
func TestPppdIsSharedByL2tpAndPptp(t *testing.T) {
	if !needsFeature([]string{"l2tp"}, featPppd) || !needsFeature([]string{"pptp"}, featPppd) {
		t.Fatal("both l2tp and pptp drive kernel PPP through pppd")
	}
	if !needsFeature([]string{"pptp"}, featPppd) {
		t.Error("removing l2tp must keep pppd while pptp is installed")
	}
	// SSTP implements PPP in-process, so it must NOT claim pppd: doing so would
	// keep the bundle alive for a core that never used it.
	if needsFeature([]string{"sstp"}, featPppd) {
		t.Error("sstp uses accel-ppp's own PPP, not the pppd bundle")
	}
}

func TestDaemonsAreDroppedOnlyWhenNoSurvivorRunsThem(t *testing.T) {
	// L2TP and PPTP ship different binaries, so removing one frees only its own.
	keep := daemonsFor([]string{"pptp"})
	for _, d := range daemonsFor([]string{"l2tp"}) {
		if slices.Contains(keep, d) {
			t.Errorf("%s is not exclusive to l2tp", d)
		}
	}
	if !slices.Contains(daemonsFor([]string{"l2tp"}), "xl2tpd") {
		t.Error("l2tp must own xl2tpd")
	}
	if !slices.Contains(daemonsFor([]string{"pptp"}), "pptpd") {
		t.Error("pptp must own pptpd")
	}
}

// Every daemon a catalog row claims has to exist in the embedded manifest, or
// the extract step would silently skip it and the core would never install.
func TestCatalogDaemonsExistInTheBundleManifest(t *testing.T) {
	known := bundledDaemonNames()
	for _, c := range coreCatalog {
		for _, d := range c.daemons {
			if !slices.Contains(known, d) {
				t.Errorf("core %s claims daemon %q, which is not in backend.Daemons", c.name, d)
			}
		}
	}
}

func TestProtocolCoreNameMapping(t *testing.T) {
	cases := map[string]string{
		"wg-c":        "wgc", // the one protocol whose id differs from its core
		"l2tp":        "l2tp",
		"ikev2":       "ikev2",
		"mtproto":     "mtproto",
		"openconnect": "openconnect",
		"vless":       "", // Xray-native: no core to install
		"vmess":       "",
		"ssh":         "", // built into the panel
		"radius":      "",
		"xray":        "",
	}
	for protocol, want := range cases {
		if got := protocolCoreName(protocol); got != want {
			t.Errorf("protocolCoreName(%q) = %q, want %q", protocol, got, want)
		}
	}
}

func TestValidCoreNamesRejectsBuiltinsAndJunk(t *testing.T) {
	got := validCoreNames([]string{"l2tp", "xray", "ssh", "nonsense", "l2tp", "ikev2"})
	want := []string{"l2tp", "ikev2"}
	if !slices.Equal(got, want) {
		t.Errorf("validCoreNames = %v, want %v", got, want)
	}
}

func TestOrderedCoreNamesIsCatalogOrderAndDeduped(t *testing.T) {
	got := orderedCoreNames([]string{"mtproto", "l2tp", "mtproto", "pptp"})
	want := []string{"l2tp", "pptp", "mtproto"}
	if !slices.Equal(got, want) {
		t.Errorf("orderedCoreNames = %v, want %v", got, want)
	}
}

func TestSharersOfNamesTheOtherClaimants(t *testing.T) {
	if got := sharersOf("ikev2"); !slices.Contains(got, "l2tp") {
		t.Errorf("ikev2 shares with l2tp; got %v", got)
	}
	if got := sharersOf("l2tp"); !slices.Contains(got, "ikev2") || !slices.Contains(got, "pptp") {
		t.Errorf("l2tp shares IPsec with ikev2 and pppd with pptp; got %v", got)
	}
	// A core with no shared features owes nobody anything.
	if got := sharersOf("mtproto"); len(got) != 0 {
		t.Errorf("mtproto shares nothing; got %v", got)
	}
	if got := sharersOf("openvpn"); len(got) != 0 {
		t.Errorf("openvpn shares nothing; got %v", got)
	}
}

// The installed-core set is persisted as a string, and "" already means "this
// install predates per-core tracking, credit it with the frozen baseline". So
// recording "the operator removed everything" as "" would collide with that and
// silently resurrect the baseline cores as installed. These two tests pin the
// sentinel that keeps the two cases apart.
func TestProvisionedProtocolsRoundTrip(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	var ss SettingService

	if ss.HasRecordedProvisionedProtocols() {
		t.Error("a fresh install must not claim to have recorded a core set")
	}

	if err := ss.SetProvisionedProtocols([]string{"l2tp", "ikev2"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := ss.GetProvisionedProtocols(); !slices.Equal(got, []string{"l2tp", "ikev2"}) {
		t.Errorf("got %v, want [l2tp ikev2]", got)
	}
	if !ss.HasRecordedProvisionedProtocols() {
		t.Error("a written set must be reported as recorded")
	}
}

func TestUninstallingEveryCoreIsRecordedAsNone(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	var ss SettingService
	var cs CoreService

	if err := ss.SetVpnProvisioned(true); err != nil {
		t.Fatalf("set provisioned: %v", err)
	}
	if err := ss.SetProvisionedProtocols(nil); err != nil {
		t.Fatalf("set none: %v", err)
	}

	if got := ss.GetProvisionedProtocols(); len(got) != 0 {
		t.Errorf("an empty set must read back empty, got %v", got)
	}
	if !ss.HasRecordedProvisionedProtocols() {
		t.Error("recording none is still a recording")
	}
	// The regression: without the sentinel this falls through to
	// provisionBaseline and reports l2tp/pptp/openvpn/openconnect as installed.
	if set := cs.provisionedProtocolSet(); len(set) != 0 {
		t.Errorf("removing every core must leave nothing installed, got %v", set)
	}
	if got := cs.installedCoreNames(); len(got) != 0 {
		t.Errorf("installedCoreNames = %v, want none", got)
	}
}

// RefreshInstalledDaemons runs on every panel start and decides what lands in
// bin/. Since "installed" is decided by the binary being on disk, getting it
// wrong silently re-installs every core on restart (or strands a legacy host on
// stale daemons). The three states below need three different answers.
func TestRefreshInstalledDaemonsScope(t *testing.T) {
	t.Run("fresh install extracts nothing", func(t *testing.T) {
		if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
			t.Fatalf("InitDB: %v", err)
		}
		var ss SettingService
		if ss.HasRecordedProvisionedProtocols() {
			t.Fatal("fresh install must have no recorded core set")
		}
		var cs CoreService
		if cs.IsProvisioned() {
			t.Skip("host looks provisioned (ip_forward + openvpn present); cannot test the fresh path here")
		}
		files, err := RefreshInstalledDaemons()
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if len(files) != 0 {
			t.Errorf("a never-set-up install must extract no daemons, got %v", files)
		}
	})

	t.Run("recorded set extracts only that set", func(t *testing.T) {
		if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
			t.Fatalf("InitDB: %v", err)
		}
		var ss SettingService
		if err := ss.SetProvisionedProtocols([]string{"mtproto"}); err != nil {
			t.Fatalf("set: %v", err)
		}
		// Asserted through the catalog rather than the filesystem: the point is
		// the SCOPE handed to the extractor, and bin/ is not writable in a test.
		want := daemonsFor([]string{"mtproto"})
		if !slices.Equal(want, []string{"telemt"}) {
			t.Fatalf("mtproto should own exactly telemt, got %v", want)
		}
		var cs CoreService
		if got := daemonsFor(cs.installedCoreNames()); !slices.Equal(got, []string{"telemt"}) {
			t.Errorf("refresh scope = %v, want [telemt]", got)
		}
	})

	t.Run("everything uninstalled extracts nothing", func(t *testing.T) {
		if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
			t.Fatalf("InitDB: %v", err)
		}
		var ss SettingService
		if err := ss.SetVpnProvisioned(true); err != nil {
			t.Fatalf("set provisioned: %v", err)
		}
		if err := ss.SetProvisionedProtocols(nil); err != nil {
			t.Fatalf("set none: %v", err)
		}
		files, err := RefreshInstalledDaemons()
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if len(files) != 0 {
			t.Errorf("nothing installed must extract nothing, got %v", files)
		}
	})
}

// TestDerivedCoresFollowTheirConsumers guards the two cards that used to answer from a
// host probe instead of from what the operator installed. On a fresh box the strongSwan
// bundle is embedded in the binary whether or not setup ever extracted it, so ipsec read
// "Stopped", and the in-binary RADIUS server binds :1812 from panel start, so radius read
// "Running". Both were reporting on something the host had never been set up for.
func TestDerivedCoresFollowTheirConsumers(t *testing.T) {
	set := func(names ...string) (map[string]bool, []string) {
		m := map[string]bool{}
		for _, n := range names {
			m[n] = true
		}
		return m, coreNamesFromSet(m)
	}

	for _, tc := range []struct {
		name      string
		installed []string
		ipsec     bool
		radius    bool
	}{
		{"fresh box, nothing installed", nil, false, false},
		{"l2tp brings both", []string{"l2tp"}, true, true},
		{"ikev2 brings both", []string{"ikev2"}, true, true},
		{"pptp needs radius but not ipsec", []string{"pptp"}, false, true},
		{"openvpn needs radius but not ipsec", []string{"openvpn"}, false, true},
		{"openconnect needs radius but not ipsec", []string{"openconnect"}, false, true},
		{"sstp needs radius but not ipsec", []string{"sstp"}, false, true},
		{"wgc alone needs neither", []string{"wgc"}, false, false},
		{"mtproto alone needs neither", []string{"mtproto"}, false, false},
		{"gre alone needs neither", []string{"gre"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, names := set(tc.installed...)
			if got := coreInstalled("ipsec", m, names); got != tc.ipsec {
				t.Errorf("ipsec installed = %v, want %v", got, tc.ipsec)
			}
			if got := coreInstalled("radius", m, names); got != tc.radius {
				t.Errorf("radius installed = %v, want %v", got, tc.radius)
			}
			// The panel's own cores are never "not installed": they are the binary.
			for _, builtin := range []string{"xray", "ssh"} {
				if !coreInstalled(builtin, m, names) {
					t.Errorf("built-in core %q reported as not installed", builtin)
				}
			}
		})
	}
}

// TestRadiusConsumersMatchTheSecretHandout keeps the usesRadius flags honest: the cores
// marked here must be exactly the ones the panel hands the RADIUS secret to at startup.
// A new dial-in core that forgets the flag would make the radius card read "not
// installed" on a host that is actively authenticating against it.
func TestRadiusConsumersMatchTheSecretHandout(t *testing.T) {
	want := map[string]bool{
		"l2tp": true, "pptp": true, "openvpn": true,
		"openconnect": true, "sstp": true, "ikev2": true,
	}
	for _, c := range coreCatalog {
		if c.usesRadius != want[c.name] {
			t.Errorf("core %q: usesRadius = %v, want %v", c.name, c.usesRadius, want[c.name])
		}
	}
}

// TestEveryVpnProtocolMapsToItsCore is the guard for "I uninstalled GRE and could still
// create GRE inbounds". The add/update/import gate asks ProtocolNeedsSetup, which is
// only as good as protocolCoreName: a protocol that maps to "" is treated as needing no
// host setup and is never gated. The gate used to be a hardcoded list of six protocols
// instead, so four cores were ungated and uninstalling any core left its protocol just
// as creatable as before.
func TestEveryVpnProtocolMapsToItsCore(t *testing.T) {
	// Every protocol served by an installable core, and the core that serves it.
	for protocol, core := range map[string]string{
		"l2tp":        "l2tp",
		"pptp":        "pptp",
		"openvpn":     "openvpn",
		"openconnect": "openconnect",
		"sstp":        "sstp",
		"ikev2":       "ikev2",
		"wg-c":        "wgc", // the one name that differs, and the one that used to slip through
		"awg":         "awg",
		"gre":         "gre",
		"mtproto":     "mtproto",
	} {
		if got := protocolCoreName(protocol); got != core {
			t.Errorf("protocolCoreName(%q) = %q, want %q: a protocol with no core is never gated", protocol, got, core)
		}
	}

	// Protocols that genuinely need no host setup: the Xray-native ones and the
	// in-binary cores. Gating these would block an inbound that works perfectly.
	for _, protocol := range []string{
		"ssh", "xray", "vmess", "vless", "trojan", "shadowsocks", "hysteria",
		"anytls", "tuic", "naive", "",
	} {
		if got := protocolCoreName(protocol); got != "" {
			t.Errorf("protocolCoreName(%q) = %q, want \"\": it needs no core install", protocol, got)
		}
	}

	// And every installable core must be reachable from some protocol, or installing it
	// is the only thing the operator can ever do with it.
	served := map[string]bool{}
	for _, p := range []string{"l2tp", "pptp", "openvpn", "openconnect", "sstp",
		"ikev2", "wg-c", "awg", "gre", "mtproto"} {
		served[protocolCoreName(p)] = true
	}
	for _, core := range installableCores() {
		if !served[core] {
			t.Errorf("core %q is installable but no protocol maps to it, so its gate can never fire", core)
		}
	}
}
