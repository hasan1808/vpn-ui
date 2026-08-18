package service

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// useTempOwnership points the manifest and its backup directory at a temp dir and
// drops the in-memory cache, so a test never reads or writes the real
// /etc/vpn-ui/ownership.json.
func useTempOwnership(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origFile, origBackups := ownershipFile, ownershipBackupDir
	ownershipFile = filepath.Join(dir, "ownership.json")
	ownershipBackupDir = filepath.Join(dir, "backups")
	ownReset()
	t.Cleanup(func() {
		ownershipFile, ownershipBackupDir = origFile, origBackups
		ownReset()
	})
	return dir
}

func parseIP4(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s).To4()
	if ip == nil {
		t.Fatalf("%q is not an IPv4 address", s)
	}
	return ip
}

// The manifest has to survive a process restart: it is the only record that
// survives one, and everything else keys off it.
func TestOwnershipRoundTrip(t *testing.T) {
	useTempOwnership(t)

	ownClaim(ownFile, "/etc/vpn-ui-sstp/server-3/accel-ppp.conf", "sstp")
	ownNote(ownFile, "/etc/pptpd.conf", "pptp", "already present")
	ownClaimPrev(ownSysctl, "net.ipv4.conf.all.rp_filter", "", "1", "relaxed for TPROXY")
	ownRecordUnit("xl2tpd.service", "l2tp", true, true)

	// Forget everything in memory: the next read comes off disk.
	ownReset()

	if state, found := ownStateOf(ownFile, "/etc/vpn-ui-sstp/server-3/accel-ppp.conf"); !found || state != ownStateNo {
		t.Errorf("claimed file came back as (%v, %v)", state, found)
	}
	if state, found := ownStateOf(ownFile, "/etc/pptpd.conf"); !found || state != ownStateYes {
		t.Errorf("pre-existing file came back as (%v, %v)", state, found)
	}
	if prev, found := ownPrevOf(ownSysctl, "net.ipv4.conf.all.rp_filter"); !found || prev != "1" {
		t.Errorf("sysctl previous value came back as (%q, %v)", prev, found)
	}

	units := ownIDsOfKind(ownUnit)
	if len(units) != 1 || units[0] != "xl2tpd.service" {
		t.Errorf("unit list came back as %v", units)
	}
	_, snap, ok := ownReleaseEntry(ownUnit, "xl2tpd.service", []string{"l2tp"})
	if !ok || snap.WasEnabled == nil || !*snap.WasEnabled || snap.WasActive == nil || !*snap.WasActive {
		t.Errorf("unit state did not survive the round trip: %+v", snap)
	}
}

// The rule the whole file exists for. An artifact the manifest says was here
// before vpn-ui is never deleted, whichever core is being removed.
func TestPreExistingIsNeverDeleted(t *testing.T) {
	dir := useTempOwnership(t)

	theirs := filepath.Join(dir, "ocserv.conf")
	if err := os.WriteFile(theirs, []byte("the operator's config\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ownNote(ownFile, theirs, "openconnect", "already present")

	removed, kept := ownReleasePath(theirs, []string{"openconnect"})
	if removed != "" {
		t.Errorf("a pre-existing file was removed: %q", removed)
	}
	if kept == "" {
		t.Error("a pre-existing file was left with no explanation in the report")
	}
	if _, err := os.Stat(theirs); err != nil {
		t.Fatalf("the operator's file is gone: %v", err)
	}
}

// Unknown provenance behaves exactly like theirs. This is the upgrade path: a
// host provisioned by a build that predates the manifest has artifacts nobody
// recorded, and deleting those is precisely the bug.
func TestUnknownProvenanceIsNeverDeleted(t *testing.T) {
	dir := useTempOwnership(t)

	path := filepath.Join(dir, "xl2tpd.conf")
	if err := os.WriteFile(path, []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ownMu.Lock()
	e := ownUpsertLocked(ownFile, path, ownStateUnknown)
	ownAddCore(e, "l2tp")
	ownSaveLocked()
	ownMu.Unlock()

	removed, kept := ownReleasePath(path, []string{"l2tp"})
	if removed != "" {
		t.Errorf("an unknown-provenance file was removed: %q", removed)
	}
	if kept == "" {
		t.Error("an unknown-provenance file was left with no explanation in the report")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the file is gone: %v", err)
	}
}

// A file with no record at all is the most conservative case of the lot: report
// it, never touch it.
func TestUnrecordedPathIsNeverDeleted(t *testing.T) {
	dir := useTempOwnership(t)

	path := filepath.Join(dir, "someone-elses.conf")
	if err := os.WriteFile(path, []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	removed, kept := ownReleasePath(path, []string{"l2tp"})
	if removed != "" || kept == "" {
		t.Errorf("an unrecorded file gave (removed=%q, kept=%q)", removed, kept)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the file is gone: %v", err)
	}
}

// A file we created ourselves IS removed. Being conservative must not turn
// uninstall into a no-op.
func TestOurOwnFileIsRemoved(t *testing.T) {
	dir := useTempOwnership(t)

	path := filepath.Join(dir, "server-1", "ocserv.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ours\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ownClaim(ownFile, path, "openconnect")

	removed, kept := ownReleasePath(path, []string{"openconnect"})
	if removed == "" {
		t.Errorf("our own file was not removed (kept=%q)", kept)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("our own file is still on disk")
	}
}

// An artifact two cores both claim survives the removal of one of them. Same
// arithmetic as the feature reference counting, applied to real host artifacts.
func TestSharedArtifactSurvivesTheFirstClaimant(t *testing.T) {
	dir := useTempOwnership(t)

	path := filepath.Join(dir, "strongswan.conf")
	if err := os.WriteFile(path, []byte("ours\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ownClaim(ownFile, path, "ikev2")
	ownClaim(ownFile, path, "l2tp")

	if removed, _ := ownReleasePath(path, []string{"ikev2"}); removed != "" {
		t.Errorf("a file L2TP still claims was removed with IKEv2: %q", removed)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the shared file is gone after the first release: %v", err)
	}
	if removed, kept := ownReleasePath(path, []string{"l2tp"}); removed == "" {
		t.Errorf("the last claimant did not release the file (kept=%q)", kept)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the file survived its last claimant")
	}
}

// ownPrepareHostFile is the "look before you write" step. On a file that already
// exists it must take a backup and mark the file theirs; on one that does not it
// must claim the file as ours.
func TestPrepareHostFileBacksUpAndRestores(t *testing.T) {
	dir := useTempOwnership(t)

	path := filepath.Join(dir, "ipsec.secrets")
	const original = ": PSK \"the operator's own key\"\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	ownPrepareHostFile(path, "l2tp")
	if err := os.WriteFile(path, []byte(": PSK \"ours\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if state, found := ownStateOf(ownFile, path); !found || state != ownStateYes {
		t.Fatalf("an existing host file was recorded as (%v, %v), want pre-existing", state, found)
	}

	removed, kept := ownReleasePath(path, []string{"l2tp"})
	if removed == "" {
		t.Fatalf("the restore did not report anything (kept=%q)", kept)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the file is gone after a restore: %v", err)
	}
	if string(got) != original {
		t.Errorf("restored content is %q, want the operator's original %q", got, original)
	}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm() != 0600 {
		t.Errorf("restored /etc/ipsec.secrets as mode %v, want 0600", st.Mode().Perm())
	}
}

func TestPrepareHostFileClaimsAFileWeCreate(t *testing.T) {
	dir := useTempOwnership(t)

	path := filepath.Join(dir, "pptpd.conf")
	ownPrepareHostFile(path, "pptp")
	if err := os.WriteFile(path, []byte("ours\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if state, found := ownStateOf(ownFile, path); !found || state != ownStateNo {
		t.Fatalf("a file we created was recorded as (%v, %v), want ours", state, found)
	}
	if removed, kept := ownReleasePath(path, []string{"pptp"}); removed == "" {
		t.Errorf("a file we created was not removed on uninstall (kept=%q)", kept)
	}
}

// The first sighting decides, and nothing later can talk itself into owning
// something the first pass found on the host. Provisioning re-runs on every panel
// start, so this is not a theoretical ordering.
func TestFirstSightingWins(t *testing.T) {
	dir := useTempOwnership(t)

	path := filepath.Join(dir, "grub")
	if err := os.WriteFile(path, []byte("GRUB_DEFAULT=0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ownPrepareHostFile(path, "")
	ownClaim(ownFile, path, "")  // a later pass trying to claim it
	ownPrepareHostFile(path, "") // and a later prepare
	if state, _ := ownStateOf(ownFile, path); state != ownStateYes {
		t.Fatalf("a pre-existing file was downgraded to %v by a later pass", state)
	}
}

// A directory that was already on the host is never removed, and one we created
// is. This is the /etc/ocserv and /etc/openvpn/server case.
func TestDirectoryOwnership(t *testing.T) {
	dir := useTempOwnership(t)

	theirs := filepath.Join(dir, "ocserv")
	if err := os.MkdirAll(theirs, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(theirs, "ocserv.conf"), []byte("theirs\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ownPrepareDir(theirs, "openconnect")

	ours := filepath.Join(dir, "vpn-ui-sstp")
	ownPrepareDir(ours, "sstp")
	if err := os.MkdirAll(ours, 0755); err != nil {
		t.Fatal(err)
	}

	if removed, kept := ownReleasePath(theirs, []string{"openconnect"}); removed != "" || kept == "" {
		t.Errorf("a pre-existing directory gave (removed=%q, kept=%q)", removed, kept)
	}
	if _, err := os.Stat(filepath.Join(theirs, "ocserv.conf")); err != nil {
		t.Fatalf("the distro's config inside its own directory is gone: %v", err)
	}
	if removed, kept := ownReleasePath(ours, []string{"sstp"}); removed == "" {
		t.Errorf("a directory we created was not removed (kept=%q)", kept)
	}
}

// The panel-private classifier is what lets an upgrade adopt its own files
// instead of leaving every host stuck reporting them forever.
func TestPanelPrivatePathClassification(t *testing.T) {
	private := []string{
		"/etc/vpn-ui-sstp",
		"/etc/vpn-ui-mtproto/server-2",
		"/etc/ocserv/server-7",
		"/etc/openvpn/server-1",
		"/etc/swanctl/conf.d/l2tp.conf",
		"/etc/swanctl/conf.d/ikev2-4.conf",
		"/etc/swanctl/conf.d/gre-9.conf",
		"/var/run/ocserv",
	}
	shared := []string{
		"/etc/ocserv",
		"/etc/openvpn",
		"/etc/openvpn/server",
		"/etc/pptpd.conf",
		"/etc/ppp/options.xl2tpd",
		"/etc/ipsec.secrets",
		"/etc/strongswan.conf",
		"/etc/swanctl/swanctl.conf",
	}
	for _, p := range private {
		if !ownPanelPrivatePath(p) {
			t.Errorf("%q should be recognised as a path only vpn-ui creates", p)
		}
	}
	for _, p := range shared {
		if ownPanelPrivatePath(p) {
			t.Errorf("%q is shared with a distro package and must not be adopted", p)
		}
	}
}

// Every path in the shared-file table must map to a core the catalog knows, or to
// "" for the host-wide ones. A typo here would silently stop a file being
// restored, because nothing would ever release it.
func TestSharedHostFilesNameRealCores(t *testing.T) {
	for path, core := range sharedHostFiles {
		if core == "" {
			continue
		}
		if coreSpecFor(core) == nil {
			t.Errorf("%s is attributed to unknown core %q", path, core)
		}
	}
}
