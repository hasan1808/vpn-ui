package service

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/corebundle"
	"github.com/hasan1808/pro-ui/database"
)

// binDirForTest points config.GetBinFolderPath() at an empty temp directory and
// returns it, so a test can decide exactly which geo files "exist".
func binDirForTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("VPNUI_BIN_FOLDER", dir)
	return dir
}

// writeGeofile creates a file that clears the size floor for a real geo file
// (sparse, so it costs nothing). Anything smaller is treated as a truncated
// download, which is the whole point of the floor.
func writeGeofile(t *testing.T, dir, name string) {
	t.Helper()
	writeGeofileOfSize(t, dir, name, 2<<20)
}

func writeGeofileOfSize(t *testing.T, dir, name string, size int64) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatalf("truncate %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

func TestExtGeoFileRef(t *testing.T) {
	cases := []struct {
		token string
		want  string
	}{
		// The reference the routing editor writes for "Iran", and the one that
		// started all this.
		{"ext:geoip_IR.dat:ir", "geoip_IR.dat"},
		{"ext:geosite_IR.dat:category-ads-all", "geosite_IR.dat"},
		{"ext:geosite_RU.dat:ru-available-only-inside", "geosite_RU.dat"},
		// Negation is stripped the way the core's cutReversePrefix does it, on the
		// file side and however many times it appears.
		{"!ext:geoip_IR.dat:ir", "geoip_IR.dat"},
		{"!!ext:geoip_IR.dat:ir", "geoip_IR.dat"},
		// The explicit ip/domain spellings of the same thing.
		{"ext-ip:geoip_RU.dat:ru", "geoip_RU.dat"},
		{"ext-domain:geosite_IR.dat:ir", "geosite_IR.dat"},
		// Shorthand: the core rewrites these to the bundled files, so they need
		// those files on disk just the same.
		{"geoip:cn", "geoip.dat"},
		{"geoip:private", "geoip.dat"},
		{"geosite:category-ads-all", "geosite.dat"},
		// Not geo references at all.
		{"regexp:.*\\.ir$", ""},
		{"domain:example.com", ""},
		{"full:www.example.com", ""},
		{"1.1.1.1/32", ""},
		{"", ""},
		// Malformed: no tag separator at all, or an empty file part.
		{"ext:geoip_IR.dat", ""},
		{"ext::x", ""},
		// Names this package cannot manage are still REPORTED, not dropped. The core
		// applies no filename rule (common/geodata just joins and opens), so a
		// reference we refuse to look at is a config that dies with nothing said
		// about it. geofileInstalled/ensureGeofiles classify them; extGeoFileRef only
		// answers "does this token name a file".
		{"ext:../../etc/shadow.dat:x", "../../etc/shadow.dat"},
		{"ext:/abs/path.dat:x", "/abs/path.dat"},
		{"ext:notadatfile:x", "notadatfile"},
		{"ext:geo/ir.dat:x", "geo/ir.dat"},
	}
	for _, c := range cases {
		if got := extGeoFileRef(c.token); got != c.want {
			t.Errorf("extGeoFileRef(%q) = %q, want %q", c.token, got, c.want)
		}
	}
}

func TestExtGeoRefsWalksWholeConfig(t *testing.T) {
	routing := []byte(`{
		"domainStrategy": "IPIfNonMatch",
		"rules": [
			{"type": "field", "outboundTag": "direct", "ip": ["geoip:private", "ext:geoip_IR.dat:ir"]},
			{"type": "field", "outboundTag": "direct", "domain": ["ext:geosite_IR.dat:ir", "regexp:.*\\.ir$"]},
			{"type": "field", "outboundTag": "blocked", "domain": ["ext:geosite_IR.dat:malware"]}
		]
	}`)
	// DNS is the reason this walks the document instead of reading routing.rules:
	// the core accepts the same references here, and the rule editor never shows them.
	dns := []byte(`{"servers": [{"address": "1.1.1.1", "domains": ["ext:geosite_RU.dat:ru"]}]}`)

	got := ExtGeoRefs(routing, dns)
	want := []string{"geoip.dat", "geoip_IR.dat", "geosite_IR.dat", "geosite_RU.dat"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtGeoRefs = %v, want %v (deduplicated and sorted)", got, want)
	}
}

func TestExtGeoRefsFindsSniffingExclusions(t *testing.T) {
	// Per-inbound sniffing, not routing: domainsExcluded/ipsExcluded go through the
	// same geodata parser (infra/conf SniffingConfig.Build) and the inbound form
	// offers `ext:*` for both, so a reference here kills the core exactly as a
	// routing one does.
	sniffing := []byte(`{"enabled":true,"destOverride":["http","tls"],` +
		`"domainsExcluded":["ext:geosite_IR.dat:ir"],"ipsExcluded":["ext:geoip_IR.dat:ir"]}`)

	got := ExtGeoRefs(sniffing)
	want := []string{"geoip_IR.dat", "geosite_IR.dat"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtGeoRefs(sniffing) = %v, want %v", got, want)
	}
}

func TestExtGeoRefsIgnoresUnparseableSections(t *testing.T) {
	if got := ExtGeoRefs(nil, []byte(""), []byte("not json")); len(got) != 0 {
		t.Fatalf("ExtGeoRefs on empty/invalid input = %v, want none", got)
	}
}

func TestEnsureGeofilesLeavesInstalledFilesAlone(t *testing.T) {
	dir := binDirForTest(t)
	writeGeofile(t, dir, "geoip_IR.dat")
	writeGeofile(t, dir, "geosite_IR.dat")

	// No network is reachable from a unit test, so a download attempt here would
	// surface as a "missing" entry.
	fetched, missing := EnsureGeofiles([]string{"geoip_IR.dat", "geosite_IR.dat"})
	if len(fetched) != 0 || len(missing) != 0 {
		t.Fatalf("fetched=%v missing=%v, want both empty for files already on disk", fetched, missing)
	}
}

func TestEnsureGeofilesReportsFilesItCannotFetch(t *testing.T) {
	binDirForTest(t)

	// A custom geo alias: CustomGeoService owns the source URL for these, so
	// EnsureGeofiles must report rather than guess.
	_, missing := EnsureGeofiles([]string{"geosite_myalias.dat"})
	if !reflect.DeepEqual(missing, []string{"geosite_myalias.dat"}) {
		t.Fatalf("missing = %v, want [geosite_myalias.dat]", missing)
	}
}

func TestAutoFetchThrottleSkipsARepeatAttempt(t *testing.T) {
	const name = "geoip_TEST.dat"
	t.Cleanup(func() { clearAutoFetchCooldown(name) })

	if !autoFetchAllowed(name) {
		t.Fatal("the first automatic attempt should be allowed")
	}
	// The health job restarts Xray about once a second for as long as it is down,
	// and a core that is down for a missing geo file comes straight back here.
	if autoFetchAllowed(name) {
		t.Fatal("a second attempt straight away should be throttled")
	}
	clearAutoFetchCooldown(name)
	if !autoFetchAllowed(name) {
		t.Fatal("a successful download should clear the cooldown")
	}
}

func TestEnsureGeofilesAutoDoesNotRetryWhileThrottled(t *testing.T) {
	binDirForTest(t)
	const name = "geoip_IR.dat"
	t.Cleanup(func() { clearAutoFetchCooldown(name) })
	autoFetchAllowed(name) // stands in for an attempt that just failed

	// Reaching the network at all here would be the bug: the point of the throttle
	// is that this call short-circuits before the download.
	fetched, missing := EnsureGeofilesAuto([]string{name})
	if len(fetched) != 0 {
		t.Fatalf("fetched=%v, want no download attempt while throttled", fetched)
	}
	if !reflect.DeepEqual(missing, []string{name}) {
		t.Fatalf("missing=%v, want [%s] so the caller still logs it", missing, name)
	}
}

func TestGetGeofileStatusReportsWhatIsOnDisk(t *testing.T) {
	dir := binDirForTest(t)
	writeGeofile(t, dir, "geoip.dat")
	writeGeofile(t, dir, "geosite.dat")
	// A download killed halfway through. It must NOT read as installed, or the
	// dashboard says the file is there while the core refuses to parse it.
	writeGeofileOfSize(t, dir, "geoip_IR.dat", 4096)

	states := (&ServerService{}).GetGeofileStatus()
	if len(states) != len(builtinGeofileOrder) {
		t.Fatalf("got %d rows, want %d", len(states), len(builtinGeofileOrder))
	}
	for i, st := range states {
		if st.Name != builtinGeofileOrder[i] {
			t.Fatalf("row %d = %q, want %q (display order)", i, st.Name, builtinGeofileOrder[i])
		}
	}
	byName := map[string]GeofileState{}
	for _, st := range states {
		byName[st.Name] = st
	}
	if st := byName["geoip.dat"]; !st.Installed || st.Size != 2<<20 || st.UpdatedAt == 0 {
		t.Errorf("geoip.dat = %+v, want installed with a size and mtime", st)
	}
	if st := byName["geoip_IR.dat"]; st.Installed {
		t.Errorf("geoip_IR.dat = %+v, want NOT installed: it is truncated", st)
	}
	if st := byName["geosite_RU.dat"]; st.Installed {
		t.Errorf("geosite_RU.dat = %+v, want not installed: no file at all", st)
	}
	// Bundled is a property of the build (GEO_LEAN drops the country files) and a
	// bare checkout embeds none, so assert only that it agrees with the bundle.
	for _, st := range states {
		if st.Bundled != corebundle.HasGeofile(st.Name) {
			t.Errorf("%s: Bundled=%v disagrees with the embedded bundle", st.Name, st.Bundled)
		}
	}
}

func TestExtGeoRefsFindsDnsHostsKeys(t *testing.T) {
	// In dns.hosts the reference is the object KEY, not the value: HostsWrapper.Build
	// runs ParseDomainRule over each key. A walker that only visited values would
	// report nothing here and let the core die on a config the panel accepted.
	dns := []byte(`{"hosts":{"ext:geosite_IR.dat:ads":"127.0.0.1","domain:example.com":"1.2.3.4"}}`)

	got := ExtGeoRefs(dns)
	if !reflect.DeepEqual(got, []string{"geosite_IR.dat"}) {
		t.Fatalf("ExtGeoRefs(dns.hosts) = %v, want [geosite_IR.dat]", got)
	}
}

func TestGeofileInstalledTreatsATruncatedFileAsAbsent(t *testing.T) {
	dir := binDirForTest(t)
	// The exact wreckage the old in-place download left behind: present, fresh
	// mtime, far too small. Reporting it as installed is what made it permanent,
	// because the fresh mtime earned a 304 on every later repair attempt.
	writeGeofileOfSize(t, dir, "geoip_IR.dat", 1024)

	if path, ok := geofileInstalled("geoip_IR.dat"); ok {
		t.Fatalf("geofileInstalled = %q, true; a truncated file must read as absent", path)
	}
	writeGeofile(t, dir, "geoip_IR.dat")
	if _, ok := geofileInstalled("geoip_IR.dat"); !ok {
		t.Fatal("a full-size file must read as installed")
	}
}

func TestGeofileInstalledRefusesTraversal(t *testing.T) {
	binDirForTest(t)
	// /etc/passwd certainly exists and is over the floor for an unmanaged name.
	// Resolving `../../etc/passwd` against bin/ must still not count as installed.
	if path, ok := geofileInstalled("../../../../etc/passwd"); ok {
		t.Fatalf("geofileInstalled resolved outside the asset dir: %q", path)
	}
}

func TestSaveXraySettingRefusesConfigNamingAnUnavailableGeofile(t *testing.T) {
	binDirForTest(t)
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	svc := &XraySettingService{}

	cfg := `{"log":{},"inbounds":[],"outbounds":[],"routing":{"rules":[` +
		`{"type":"field","outboundTag":"direct","domain":["ext:geosite_nosuch.dat:ir"]}]}}`
	err := svc.SaveXraySetting(cfg)
	if err == nil {
		t.Fatal("SaveXraySetting accepted a config referencing a geo file that cannot be provided")
	}
	if !strings.Contains(err.Error(), "geosite_nosuch.dat") {
		t.Fatalf("error should name the missing file, got: %v", err)
	}
	// A rejected save must leave the stored config untouched.
	if stored, _ := svc.GetXrayConfigTemplate(); strings.Contains(stored, "geosite_nosuch.dat") {
		t.Fatal("rejected config was persisted anyway")
	}
}

func TestSaveXraySettingAcceptsConfigWhoseGeofilesAreInstalled(t *testing.T) {
	dir := binDirForTest(t)
	writeGeofile(t, dir, "geoip_IR.dat")
	writeGeofile(t, dir, "geosite_IR.dat")
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	svc := &XraySettingService{}

	cfg := `{"log":{},"inbounds":[],"outbounds":[],"routing":{"rules":[` +
		`{"type":"field","outboundTag":"direct","ip":["ext:geoip_IR.dat:ir"],` +
		`"domain":["ext:geosite_IR.dat:ir"]}]}}`
	if err := svc.SaveXraySetting(cfg); err != nil {
		t.Fatalf("SaveXraySetting: %v", err)
	}
	stored, err := svc.GetXrayConfigTemplate()
	if err != nil {
		t.Fatalf("GetXrayConfigTemplate: %v", err)
	}
	if !strings.Contains(stored, "ext:geoip_IR.dat:ir") {
		t.Fatalf("config was not stored: %s", stored)
	}
}

func TestSaveXraySettingAllowsAnEditWhenTheBrokenRefWasAlreadyStored(t *testing.T) {
	binDirForTest(t)
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	svc := &XraySettingService{}

	// A custom geo alias whose source was unreachable when CustomGeoService tried at
	// startup: the reference is stored, the file is not there. Refusing every later
	// save over it would leave no way to edit out of the situation except by
	// hand-deleting the rule from the JSON.
	broken := `{"type":"field","outboundTag":"direct","domain":["ext:geosite_myalias.dat:ir"]}`
	stored := `{"log":{},"inbounds":[],"outbounds":[],"routing":{"rules":[` + broken + `]}}`
	if err := svc.RepairXrayTemplate(stored); err != nil {
		t.Fatalf("seed stored config: %v", err)
	}

	// An unrelated edit that keeps the broken reference untouched.
	edited := `{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[],"routing":{"rules":[` + broken + `]}}`
	if err := svc.SaveXraySetting(edited); err != nil {
		t.Fatalf("SaveXraySetting rejected an edit over a pre-existing broken reference: %v", err)
	}

	// Adding a NEW unfetchable reference is still refused.
	worse := `{"log":{},"inbounds":[],"outbounds":[],"routing":{"rules":[` + broken + `,` +
		`{"type":"field","outboundTag":"direct","domain":["ext:geosite_other.dat:ir"]}]}}`
	err := svc.SaveXraySetting(worse)
	if err == nil {
		t.Fatal("adding a new unfetchable reference should still be refused")
	}
	if !strings.Contains(err.Error(), "geosite_other.dat") {
		t.Fatalf("error should name only the newly added file, got: %v", err)
	}
	if strings.Contains(err.Error(), "geosite_myalias.dat") {
		t.Fatalf("error should not blame the pre-existing reference, got: %v", err)
	}
}

// TestBuiltinGeofileOrderCoversEveryFile pins the two builtin geofile collections
// together.
//
// This is load-bearing, not tidiness: UpdateGeofile("") builds its download queue
// from builtinGeofileOrder, not from the map. A name added to builtinGeofiles and
// forgotten here would be offered in the dashboard list, downloadable one at a
// time, and silently skipped by "Update all" - the one path most operators use.
func TestBuiltinGeofileOrderCoversEveryFile(t *testing.T) {
	if len(builtinGeofileOrder) != len(builtinGeofiles) {
		t.Fatalf("order lists %d files, the map holds %d", len(builtinGeofileOrder), len(builtinGeofiles))
	}
	seen := map[string]bool{}
	for _, name := range builtinGeofileOrder {
		if _, ok := builtinGeofiles[name]; !ok {
			t.Errorf("builtinGeofileOrder names %q, which is not in builtinGeofiles", name)
		}
		if seen[name] {
			t.Errorf("builtinGeofileOrder repeats %q, so it would be downloaded twice", name)
		}
		seen[name] = true
	}
	for name := range builtinGeofiles {
		if !seen[name] {
			t.Errorf("builtinGeofiles holds %q but builtinGeofileOrder does not, so "+
				`UpdateGeofile("") would skip it`, name)
		}
	}
}

// TestGeofileRunStateLifecycle covers the progress record the overview re-attaches
// to after the operator navigated away mid-download.
func TestGeofileRunStateLifecycle(t *testing.T) {
	t.Cleanup(func() { geofileRunEnd(false, ""); geofileRun.done = false })

	var s ServerService
	if st := s.GeofileRunState(); st.Running {
		t.Fatalf("a fresh process reports a run in flight: %+v", st)
	}

	if !geofileRunBegin([]string{"geoip.dat", "geosite.dat"}) {
		t.Fatal("the first claim was refused")
	}
	// A second click must join the first rather than starting a duplicate transfer.
	if geofileRunBegin([]string{"geoip.dat"}) {
		t.Fatal("a second run was allowed to start on top of the first")
	}

	geofileRunCurrent("geoip.dat")
	st := s.GeofileRunState()
	if !st.Running || st.Current != "geoip.dat" || len(st.Files) != 2 {
		t.Fatalf("mid-run state is wrong: %+v", st)
	}

	geofileRunFetched("geoip.dat")
	geofileRunCurrent("")
	geofileRunEnd(false, "")
	st = s.GeofileRunState()
	if st.Running {
		t.Errorf("still running after the end: %+v", st)
	}
	// done survives so a page that arrives after the fact can report the outcome it
	// missed, rather than showing an idle panel.
	if !st.Done || st.Failed || len(st.Fetched) != 1 {
		t.Errorf("finished state is wrong: %+v", st)
	}

	// A new run must clear the previous outcome, not inherit it.
	if !geofileRunBegin([]string{"geoip.dat"}) {
		t.Fatal("a new run was refused after the previous one finished")
	}
	if st := s.GeofileRunState(); st.Done || len(st.Fetched) != 0 {
		t.Errorf("a new run inherited the previous outcome: %+v", st)
	}
	geofileRunEnd(true, "boom")
	if st := s.GeofileRunState(); !st.Failed || st.Summary != "boom" {
		t.Errorf("failure was not recorded: %+v", st)
	}
}
