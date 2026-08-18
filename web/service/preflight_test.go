package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hasan1808/pro-ui/database"
)

// withStubConflictProbe swaps the pre-flight probe for one that records which
// cores were asked about and answers with a synthetic conflict for each. The real
// probe stats absolute host paths, which a test can neither create nor depend on;
// what is worth pinning is WHICH CORES get probed.
func withStubConflictProbe(t *testing.T) *[]string {
	t.Helper()
	var probed []string
	orig := coreConflictProbe
	coreConflictProbe = func(core string) []coreHostConflict {
		probed = append(probed, core)
		return []coreHostConflict{{Kind: ownFile, What: "/etc/" + core + ".conf", Detail: "already present"}}
	}
	t.Cleanup(func() { coreConflictProbe = orig })
	return &probed
}

func containsCore(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// The decision table, pinned directly because the interesting row cannot be
// produced from a test host on demand.
//
// installed=true + recorded=false is the bug: the panel THINKS the core is
// installed, on the strength of the baseline guess alone, having provisioned
// nothing. The old rule was `!builtin && !installed`, which answers false there
// and skips the probe; this test fails against it. The other rows exist so a
// future simplification to "always probe" also fails, because that would warn the
// operator about the panel's own files.
func TestCoreShouldProbeConflictsDecisionTable(t *testing.T) {
	cases := []struct {
		builtin, installed, recorded bool
		want                         bool
		why                          string
	}{
		{installed: true, recorded: false, want: true,
			why: "the baseline GUESS said installed but nothing was provisioned: this is the hole"},
		{installed: false, recorded: false, want: true,
			why: "nothing provisioned and nothing claimed installed"},
		{installed: true, recorded: true, want: false,
			why: "genuinely installed: the artifacts are ours and the manifest is the record"},
		{installed: false, recorded: true, want: true,
			why: "recorded state, core not installed: still offered, so still probed"},
		{builtin: true, installed: false, recorded: false, want: false,
			why: "a built-in core installs nothing, so it collides with nothing"},
		{builtin: true, installed: true, recorded: true, want: false,
			why: "built-in, whatever else is true"},
	}
	for _, c := range cases {
		got := coreShouldProbeConflicts(c.builtin, c.installed, c.recorded)
		if got != c.want {
			t.Errorf("coreShouldProbeConflicts(builtin=%v, installed=%v, recorded=%v) = %v, want %v: %s",
				c.builtin, c.installed, c.recorded, got, c.want, c.why)
		}
	}
}

// The bug this pins: a panel that has provisioned NOTHING still reported zero
// conflicts for l2tp, pptp, openvpn and openconnect.
//
// IsProvisioned falls back to `ip_forward==1 && daemonInstalled("openvpn")`, and
// daemonInstalled is a PATH lookup, so a box with a distro OpenVPN and
// ip_forward=1 reads as provisioned on a fresh database. provisionedProtocolSet
// then credits the frozen baseline, and the conflict probe was skipped for a core
// the panel merely GUESSED it had installed. Those four are precisely the cores
// whose shared config files a distro install is most likely to own already, so
// the warning went missing exactly where it was worth having.
func TestConflictsAreProbedWhenNothingIsProvisioned(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	probed := withStubConflictProbe(t)

	var cs CoreService
	if cs.coreInstallStateIsRecorded() {
		t.Fatal("a fresh database must not claim a recorded install state")
	}

	opts := cs.CoreCatalog()
	byName := map[string]CoreOption{}
	for _, o := range opts {
		byName[o.Name] = o
	}

	// Every baseline core, i.e. every core the guess would have marked installed.
	for _, name := range provisionBaseline {
		if !containsCore(*probed, name) {
			t.Errorf("core %q was not probed for host conflicts on a not-yet-provisioned panel", name)
		}
		if len(byName[name].Conflicts) == 0 {
			t.Errorf("core %q reported no conflicts even though the probe found one", name)
		}
	}
	// A non-baseline core was already working and must not regress.
	if !containsCore(*probed, "ikev2") {
		t.Error("ikev2 was not probed on a not-yet-provisioned panel")
	}
	// Built-in cores have nothing to install, so nothing to collide with.
	for _, name := range []string{"xray", "radius", "ssh"} {
		if containsCore(*probed, name) {
			t.Errorf("built-in core %q should never be probed", name)
		}
	}
}

// The other half of the rule: once the operator has really installed a core, its
// artifacts are ours and the manifest is the record that matters, so the probe is
// skipped. Without this the fix would just be "always probe", which would warn
// about our own files.
func TestConflictsAreNotProbedForAGenuinelyInstalledCore(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	var ss SettingService
	if err := ss.SetProvisionedProtocols([]string{"l2tp", "openvpn"}); err != nil {
		t.Fatalf("SetProvisionedProtocols: %v", err)
	}
	probed := withStubConflictProbe(t)

	var cs CoreService
	if !cs.coreInstallStateIsRecorded() {
		t.Fatal("a written core set must count as a recorded install state")
	}

	opts := cs.CoreCatalog()
	byName := map[string]CoreOption{}
	for _, o := range opts {
		byName[o.Name] = o
	}
	for _, name := range []string{"l2tp", "openvpn"} {
		if containsCore(*probed, name) {
			t.Errorf("installed core %q was probed; its artifacts are ours", name)
		}
		if len(byName[name].Conflicts) != 0 {
			t.Errorf("installed core %q reported conflicts", name)
		}
	}
	// Still offered for install, so still probed.
	for _, name := range []string{"pptp", "ikev2"} {
		if !containsCore(*probed, name) {
			t.Errorf("core %q is not installed and should have been probed", name)
		}
	}
}

// A pre-tracking upgrade (vpnProvisioned set, no recorded list) is the case the
// baseline fallback exists for, and it must keep behaving charitably: those four
// cores really were installed by the old all-or-nothing setup run, so their files
// are ours and warning about them would be noise.
func TestBaselineIsTrustedOnAPreTrackingUpgrade(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	var ss SettingService
	if err := ss.SetVpnProvisioned(true); err != nil {
		t.Fatalf("SetVpnProvisioned: %v", err)
	}
	probed := withStubConflictProbe(t)

	var cs CoreService
	if !cs.coreInstallStateIsRecorded() {
		t.Fatal("vpnProvisioned must count as a recorded install state")
	}
	if ss.HasRecordedProvisionedProtocols() {
		t.Fatal("this test needs the pre-tracking shape: no recorded core list")
	}

	cs.CoreCatalog()
	for _, name := range provisionBaseline {
		if containsCore(*probed, name) {
			t.Errorf("baseline core %q was probed on a pre-tracking upgrade; its files are ours", name)
		}
	}
	if !containsCore(*probed, "ikev2") {
		t.Error("a core outside the baseline is not installed and should have been probed")
	}
}

// And the probe itself does detect an existing shared file. Kept separate from
// the gating tests above because this one is about the stat, not about which
// cores reach it.
func TestPreflightProbeDetectsAnExistingFileAndDirectory(t *testing.T) {
	dir := t.TempDir()

	file := filepath.Join(dir, "ipsec.secrets")
	if err := os.WriteFile(file, []byte(": PSK \"theirs\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if c := preflightFile(file); c == nil {
		t.Error("an existing shared config file was not reported as a conflict")
	} else if c.Kind != ownFile || c.What != file || c.Detail == "" {
		t.Errorf("malformed conflict for a file: %+v", c)
	}
	if c := preflightFile(filepath.Join(dir, "absent.conf")); c != nil {
		t.Errorf("a file that is not there was reported as a conflict: %+v", c)
	}

	sub := filepath.Join(dir, "ocserv")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if c := preflightDir(sub); c == nil {
		t.Error("an existing config directory was not reported as a conflict")
	} else if c.Kind != ownDir {
		t.Errorf("directory conflict reported as kind %q", c.Kind)
	}
	// A plain file is not a directory conflict, so a stat that lands on the wrong
	// kind reports nothing rather than the wrong thing.
	if c := preflightDir(file); c != nil {
		t.Errorf("a regular file was reported as a directory conflict: %+v", c)
	}
}
