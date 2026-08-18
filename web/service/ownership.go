package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/logger"
)

// The ownership manifest: a record of what vpn-ui actually put on this host.
//
// Install and uninstall used to work from a static catalog of paths, and that
// catalog cannot answer the only question that matters when removing something:
// was this here BEFORE us? The answer was assumed to be "no" everywhere, so
// uninstall deleted /etc/ocserv wholesale (taking a distro ocserv's ocserv.conf,
// its certificates and its ocpasswd with it), deleted /etc/openvpn/server (the
// distro's own server-config directory, which we only ever mkdir and never write
// into), and overwrote /etc/ipsec.secrets and /etc/swanctl/swanctl.conf with no
// way back. The operator's pre-existing setup was collateral damage of a normal
// install/uninstall cycle.
//
// This file is the record that makes the question answerable. Three properties
// are load-bearing:
//
//   - preExisting means NEVER delete. It is a tri-state, because "we have no
//     idea" (a host provisioned by an older build) has to behave like "it was
//     theirs", not like "it is ours".
//   - createdByUs on a directory is what separates "remove the directory" from
//     "remove our files inside a directory that was already there".
//   - cores is a LIST, so an artifact two cores both asked for is only released
//     when the last claimant goes. This is the same arithmetic the feature
//     reference counting in corecatalog.go does, applied to real host artifacts
//     rather than to feature names.
//
// It is a JSON file rather than a DB table for three reasons specific to this
// codebase: service.Uninstall() must work with the DB missing or corrupt (main.go
// tolerates InitDB failing); a DB import swaps the whole file, so a table would
// arrive describing SOMEONE ELSE'S host; and /etc/vpn-ui already exists and is
// already panel-owned (nftables.go writes vpn.nft there).

// ownershipDir is the panel's own /etc directory. It already holds vpn.nft.
const ownershipDir = "/etc/vpn-ui"

// ownershipVersion is bumped when the on-disk shape changes incompatibly. A
// manifest from the future is treated as unreadable, which fails safe: an
// unreadable manifest deletes nothing.
const ownershipVersion = 1

// These two are vars, not consts, purely so the tests can point the manifest and
// its backups at a temp dir. Nothing in the product changes them.
var (
	ownershipFile = ownershipDir + "/ownership.json"
	// ownershipBackupDir holds a copy of every shared host file we are about to
	// overwrite, so uninstall can put the operator's version back rather than
	// leaving our render behind or deleting the file outright.
	ownershipBackupDir = ownershipDir + "/backups"
)

// Artifact kinds. One string per class of host state we can create or modify,
// because the release action differs per class: a file is restored from backup, a
// unit is re-enabled, a sysctl is put back to its previous value.
const (
	ownPackage = "package" // a distro package we asked the package manager to install
	ownFile    = "file"    // a config file we wrote
	ownDir     = "dir"     // a directory we created (or wrote into)
	ownSymlink = "symlink" // a symlink we planted, e.g. /usr/lib/ipsec
	ownUnit    = "unit"    // a systemd unit we stopped, disabled or wrote
	ownIface   = "iface"   // a network interface we created
	ownFouPort = "fouport" // a FOU (UDP-encapsulation) receive port we registered
	ownSysctl  = "sysctl"  // a sysctl whose value we changed
	ownEthtool = "ethtool" // an ethtool offload setting we turned off

	// ownIpRule is RESERVED, not yet recorded anywhere, and the reason is worth
	// stating so nobody records it half way. The `fwmark 1 lookup 100` policy route
	// is added by SIX SetupRouting functions, each with its own copy of the same
	// "add it unless `ip rule show` already mentions it" guard. Recording it from
	// only some of them is WORSE than not recording it: whichever protocol runs
	// second sees the rule already present and would write down "the operator had
	// this", which is exactly backwards. It needs one shared ensureVpnPolicyRoute
	// helper first; until then the whole-host uninstall keeps deleting the rule
	// unconditionally, which is the safe direction (a stray fwmark rule with a
	// flushed table 100 blackholes traffic).
	ownIpRule = "iprule"
)

// ownState is the tri-state answer to "was this here before vpn-ui?".
//
// The unknown state is the whole reason this is not a bool. A host provisioned by
// a build that predates the manifest has artifacts nobody recorded, and guessing
// "ours" there is exactly the bug this file exists to stop. Unknown therefore
// behaves like yes for deletion and is reported to the operator instead.
type ownState string

const (
	ownStateNo      ownState = "no"      // we created it; it did not exist before
	ownStateYes     ownState = "yes"     // it was already on the host; hands off
	ownStateUnknown ownState = "unknown" // synthesised for a pre-manifest host
)

// mayDelete reports whether an artifact in this state may be removed by us.
func (s ownState) mayDelete() bool { return s == ownStateNo }

// OwnedArtifact is one thing vpn-ui created, modified, or deliberately left alone.
type OwnedArtifact struct {
	// Kind + ID together identify the artifact. ID is the path for a file, the
	// interface name for an iface, the unit name for a unit, and so on.
	Kind string `json:"kind"`
	ID   string `json:"id"`

	// Cores is every core that claims this artifact. Released one at a time; the
	// artifact is only acted on when the list empties.
	Cores []string `json:"cores,omitempty"`

	// PreExisting is the veto. Anything but "no" means we must not delete it.
	PreExisting ownState `json:"preExisting"`

	// CreatedByUs separates a directory we made from a directory we merely wrote
	// into. A directory we did not create is never RemoveAll'd; only our own files
	// inside it are removed.
	CreatedByUs bool `json:"createdByUs,omitempty"`

	// Backup is a copy of the operator's version of a file we overwrote, taken
	// once, before the first overwrite. Sha256 is of the BACKED-UP bytes, so a
	// later restore can say whether the file still holds what we wrote.
	Backup string `json:"backup,omitempty"`
	Sha256 string `json:"sha256,omitempty"`

	// WasEnabled / WasActive record a systemd unit's state before we disabled it,
	// so uninstall can hand a distro daemon back the way it found it.
	WasEnabled *bool `json:"wasEnabled,omitempty"`
	WasActive  *bool `json:"wasActive,omitempty"`

	// Prev is the previous value of reversible host state that is not a file:
	// a sysctl value, an ethtool offload setting ("on"/"off").
	Prev string `json:"prev,omitempty"`

	// Note is operator-facing context for the uninstall report.
	Note string `json:"note,omitempty"`

	RecordedAt string `json:"recordedAt,omitempty"`
}

// ownershipManifest is the file's top-level shape.
type ownershipManifest struct {
	Version   int             `json:"version"`
	UpdatedAt string          `json:"updatedAt"`
	Entries   []OwnedArtifact `json:"entries"`
}

// The manifest is read on every reconcile tick (removeStaleLinks asks it before
// deleting anything), so it is cached in memory and written through. Every
// mutation takes the lock for the whole read-modify-write, because the GRE, wg-c
// and awg reconcilers all run concurrently.
var (
	ownMu     sync.Mutex
	ownCache  *ownershipManifest
	ownLoaded bool
)

// ownLoadLocked returns the manifest, reading it from disk once.
//
// A missing file yields an EMPTY manifest rather than an error: a host that has
// never run a manifest-aware build legitimately has none, and ownSynthesize()
// fills it in. A CORRUPT file also yields an empty manifest, and that is the safe
// direction: with no entries, every "may I delete this?" question is answered no.
func ownLoadLocked() *ownershipManifest {
	if ownLoaded {
		return ownCache
	}
	ownLoaded = true
	ownCache = &ownershipManifest{Version: ownershipVersion}
	data, err := os.ReadFile(ownershipFile)
	if err != nil {
		return ownCache
	}
	var m ownershipManifest
	if err := json.Unmarshal(data, &m); err != nil {
		logger.Warning("ownership: manifest is unreadable, treating every artifact as not ours:", err)
		return ownCache
	}
	if m.Version > ownershipVersion {
		logger.Warning("ownership: manifest version", m.Version, "is newer than this panel understands; treating every artifact as not ours")
		return ownCache
	}
	ownCache = &m
	return ownCache
}

// ownSaveLocked writes the manifest out. Best-effort by design: failing to record
// an artifact must never fail the install step that created it, or a full disk
// would turn into "setup failed" instead of "setup worked, cleanup will be
// conservative".
func ownSaveLocked() {
	m := ownLoadLocked()
	m.Version = ownershipVersion
	m.UpdatedAt = time.Now().Format(time.RFC3339)
	sort.SliceStable(m.Entries, func(i, j int) bool {
		if m.Entries[i].Kind != m.Entries[j].Kind {
			return m.Entries[i].Kind < m.Entries[j].Kind
		}
		return m.Entries[i].ID < m.Entries[j].ID
	})
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		logger.Warning("ownership: could not encode the manifest:", err)
		return
	}
	dir := filepath.Dir(ownershipFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Warning("ownership: could not create", dir, err)
		return
	}
	// Written through a temp file + rename so a crash mid-write cannot leave a
	// truncated manifest, which would read back as "nothing is ours" and quietly
	// disable every cleanup path.
	tmp := ownershipFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		logger.Warning("ownership: could not write the manifest:", err)
		return
	}
	if err := os.Rename(tmp, ownershipFile); err != nil {
		logger.Warning("ownership: could not replace the manifest:", err)
		_ = os.Remove(tmp)
	}
}

// ownFindLocked returns the entry for kind+id, or nil.
func ownFindLocked(kind, id string) *OwnedArtifact {
	m := ownLoadLocked()
	for i := range m.Entries {
		if m.Entries[i].Kind == kind && m.Entries[i].ID == id {
			return &m.Entries[i]
		}
	}
	return nil
}

// ownUpsertLocked returns the entry for kind+id, creating it in the given state
// if it is not there yet. New entries are created ONLY here, so the "first
// sighting decides preExisting" rule has exactly one implementation.
func ownUpsertLocked(kind, id string, initial ownState) *OwnedArtifact {
	if e := ownFindLocked(kind, id); e != nil {
		return e
	}
	m := ownLoadLocked()
	m.Entries = append(m.Entries, OwnedArtifact{
		Kind:        kind,
		ID:          id,
		PreExisting: initial,
		RecordedAt:  time.Now().Format(time.RFC3339),
	})
	return &m.Entries[len(m.Entries)-1]
}

// ownHasCore reports whether an entry already carries this claim. "" is the
// host-wide pseudo-core (grub, our sysctl drop-in), which is never listed, so it
// always counts as present.
func ownHasCore(e *OwnedArtifact, core string) bool {
	if core == "" {
		return true
	}
	for _, c := range e.Cores {
		if c == core {
			return true
		}
	}
	return false
}

// ownAddCore adds a core to an entry's claim list, keeping it sorted and unique.
func ownAddCore(e *OwnedArtifact, core string) {
	if core == "" {
		return
	}
	for _, c := range e.Cores {
		if c == core {
			return
		}
	}
	e.Cores = append(e.Cores, core)
	sort.Strings(e.Cores)
}

// ownClaim records an artifact we created ourselves.
//
// The first sighting wins: if the artifact was already recorded as pre-existing
// (or as unknown), claiming it later does NOT downgrade it to ours. That matters
// because provisioning is re-run on every panel start, so a second pass must not
// be able to talk itself into owning something the first pass found on the host.
func ownClaim(kind, id, core string) {
	ownMu.Lock()
	defer ownMu.Unlock()
	// Steady-state fast path. The reconcilers re-assert the same claims on every
	// tick (ensureFouPort re-registers its port every ten seconds), so a claim that
	// changes nothing must not rewrite the manifest.
	if e := ownFindLocked(kind, id); e != nil && ownHasCore(e, core) &&
		(e.PreExisting != ownStateNo || e.CreatedByUs) {
		return
	}
	e := ownUpsertLocked(kind, id, ownStateNo)
	if e.PreExisting == ownStateNo {
		e.CreatedByUs = true
	}
	ownAddCore(e, core)
	ownSaveLocked()
}

// ownClaimPrev records reversible host state we are about to change, keeping the
// value it had. Used for the settings that are not files and cannot be backed up:
// a sysctl, an ethtool offload flag. The state stays "no" (ours to undo) because
// what we own is the CHANGE, not the setting itself.
func ownClaimPrev(kind, id, core, prev, note string) {
	ownMu.Lock()
	defer ownMu.Unlock()
	e := ownUpsertLocked(kind, id, ownStateNo)
	if e.Prev == "" {
		e.Prev = prev
	}
	if note != "" {
		e.Note = note
	}
	ownAddCore(e, core)
	ownSaveLocked()
}

// ownRecordUnit remembers a systemd unit's state before we disable it. The state
// is captured on the FIRST sighting only: provisioning re-runs on every panel
// start, and by the second run the unit is disabled because we disabled it, so a
// later overwrite would record "was disabled" and lose the operator's setting for
// good.
func ownRecordUnit(unit, core string, enabled, active bool) {
	ownMu.Lock()
	defer ownMu.Unlock()
	e := ownUpsertLocked(ownUnit, unit, ownStateYes)
	if e.WasEnabled == nil {
		wasEnabled, wasActive := enabled, active
		e.WasEnabled = &wasEnabled
		e.WasActive = &wasActive
		e.Note = "disabled so vpn-ui could run this daemon itself"
	}
	ownAddCore(e, core)
	ownSaveLocked()
}

// ownPrevOf returns the recorded previous value of reversible host state.
func ownPrevOf(kind, id string) (prev string, found bool) {
	ownMu.Lock()
	defer ownMu.Unlock()
	e := ownFindLocked(kind, id)
	if e == nil {
		return "", false
	}
	return e.Prev, true
}

// ownIDsOfKind lists the recorded artifacts of one kind, for the uninstall sweeps
// that iterate the manifest rather than a static catalog.
func ownIDsOfKind(kind string) []string {
	ownMu.Lock()
	defer ownMu.Unlock()
	m := ownLoadLocked()
	var out []string
	for _, e := range m.Entries {
		if e.Kind == kind {
			out = append(out, e.ID)
		}
	}
	sort.Strings(out)
	return out
}

// ownNote records an artifact that was ALREADY on the host, so nothing ever
// deletes it. Idempotent, and it never overwrites a stronger record.
func ownNote(kind, id, core, note string) {
	ownMu.Lock()
	defer ownMu.Unlock()
	// Same steady-state fast path as ownClaim, for the same reason: the FOU port
	// reconcile lands here on every tick once the operator has a listener of their
	// own on that port.
	if e := ownFindLocked(kind, id); e != nil && ownHasCore(e, core) && (note == "" || e.Note == note) {
		return
	}
	e := ownUpsertLocked(kind, id, ownStateYes)
	if note != "" {
		e.Note = note
	}
	ownAddCore(e, core)
	ownSaveLocked()
}

// ownStateOf reports what the manifest knows about an artifact.
//
// found=false means "no record at all". Callers must decide what that means for
// them: for a config file it means an older build wrote it and only the
// synthesised entries can speak for it, while for a network interface created
// seconds ago by this very process it means the claim write failed.
func ownStateOf(kind, id string) (state ownState, found bool) {
	ownMu.Lock()
	defer ownMu.Unlock()
	e := ownFindLocked(kind, id)
	if e == nil {
		return ownStateUnknown, false
	}
	return e.PreExisting, true
}

// ownForbidsDelete is the veto used on the hot paths (interface reconciliation).
// It answers only the question "does the manifest positively say hands off?", so
// an artifact nobody recorded is NOT vetoed here; the name-shape ownership test
// in ifaceown.go is what carries that case.
func ownForbidsDelete(kind, id string) bool {
	state, found := ownStateOf(kind, id)
	return found && !state.mayDelete()
}

// ownEntries returns a copy of the manifest, for reporting and for uninstall.
func ownEntries() []OwnedArtifact {
	ownMu.Lock()
	defer ownMu.Unlock()
	m := ownLoadLocked()
	out := make([]OwnedArtifact, len(m.Entries))
	copy(out, m.Entries)
	return out
}

// ownRemoveEntry drops a record entirely. Called after the artifact is actually
// gone, so a reinstall starts from a clean sheet.
func ownRemoveEntry(kind, id string) {
	ownMu.Lock()
	defer ownMu.Unlock()
	m := ownLoadLocked()
	out := m.Entries[:0]
	for _, e := range m.Entries {
		if e.Kind == kind && e.ID == id {
			continue
		}
		out = append(out, e)
	}
	m.Entries = out
	ownSaveLocked()
}

// ownReset drops the in-memory copy so the next read comes from disk. Used by the
// tests and after a restore that rewrote the file behind our back.
func ownReset() {
	ownMu.Lock()
	defer ownMu.Unlock()
	ownCache = nil
	ownLoaded = false
}

// --------------------------------------------------------------------------- //
//  Release: what uninstall is allowed to do
// --------------------------------------------------------------------------- //

// ownAction is the verdict on one artifact when a set of cores is being removed.
// Exactly one of the three outcomes applies.
type ownAction struct {
	// Delete: we created it and no surviving core claims it.
	Delete bool
	// Restore is a backup path to copy back over the artifact. Set when we
	// overwrote a file that was already on the host.
	Restore string
	// Keep is the operator-facing reason we are deliberately leaving it alone.
	// Non-empty exactly when Delete is false and Restore is empty.
	Keep string
}

// ownRelease drops the given cores from an artifact's claim list and returns what
// may now be done with it. This is the single decision point for every
// destructive step in uninstall.
//
// The order of the tests is the safety property:
//
//  1. Another core still claims it -> keep. (The reference count.)
//  2. It was already on the host, or nobody knows -> restore the backup if we
//     took one, otherwise keep. NEVER delete.
//  3. It is ours and unclaimed -> delete.
//
// An artifact with no manifest entry at all lands in case 2 as "unknown", which
// is why ownSynthesize runs first on hosts provisioned by an older build: without
// it every uninstall would decline to remove even the panel's own files.
func ownRelease(kind, id string, cores []string) ownAction {
	act, _, _ := ownReleaseEntry(kind, id, cores)
	return act
}

// ownReleaseEntry is ownRelease plus a copy of the record, for the callers that
// need the state it captured (a unit's wasEnabled/wasActive, a sysctl's prev)
// rather than just the verdict.
func ownReleaseEntry(kind, id string, cores []string) (ownAction, OwnedArtifact, bool) {
	ownMu.Lock()
	defer ownMu.Unlock()

	e := ownFindLocked(kind, id)
	if e == nil {
		return ownAction{Keep: "not recorded as installed by vpn-ui"}, OwnedArtifact{}, false
	}

	removing := map[string]bool{}
	for _, c := range cores {
		removing[c] = true
	}
	var left []string
	for _, c := range e.Cores {
		if !removing[c] {
			left = append(left, c)
		}
	}
	e.Cores = left
	ownSaveLocked()
	snapshot := *e

	if len(left) > 0 {
		return ownAction{Keep: "still claimed by " + strings.Join(coreDisplayNames(left), ", ")}, snapshot, true
	}
	if !e.PreExisting.mayDelete() {
		if e.Backup != "" {
			return ownAction{Restore: e.Backup}, snapshot, true
		}
		if e.PreExisting == ownStateUnknown {
			return ownAction{Keep: "predates ownership tracking; left in place"}, snapshot, true
		}
		return ownAction{Keep: "was already on this host before vpn-ui"}, snapshot, true
	}
	return ownAction{Delete: true}, snapshot, true
}

// --------------------------------------------------------------------------- //
//  Backups
// --------------------------------------------------------------------------- //

// ownBackupName flattens a path into a backup filename: /etc/ipsec.secrets ->
// etc_ipsec.secrets. Flat rather than nested so the backup directory is one
// readable list an operator can restore from by hand.
func ownBackupName(path string) string {
	trimmed := strings.TrimPrefix(filepath.Clean(path), "/")
	return strings.ReplaceAll(trimmed, "/", "_")
}

// ownBackupFile copies path into the backup directory and returns the copy's
// location. Only called for a file that was on the host before we touched it.
func ownBackupFile(path string) (string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(ownershipBackupDir, 0700); err != nil {
		return "", "", err
	}
	dest := filepath.Join(ownershipBackupDir, ownBackupName(path))
	// The original mode is preserved so restoring /etc/ipsec.secrets does not
	// hand a host's PSK file back world-readable.
	mode := os.FileMode(0600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.WriteFile(dest, data, mode); err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(data)
	return dest, hex.EncodeToString(sum[:]), nil
}

// ownPrepareHostFile is the "look before you write" step every generator that
// touches a SHARED host file must call first.
//
// It records the file exactly once, on its first sighting:
//
//   - absent -> ours, and deleting it on uninstall is correct;
//   - present with no record -> the operator's, backed up into
//     /etc/vpn-ui/backups/ and marked preExisting, so uninstall restores their
//     version instead of leaving our render or deleting the file.
//
// Files this reached too late (a host already provisioned by an older build) are
// covered by ownSynthesize, which marks them unknown rather than ours.
func ownPrepareHostFile(path, core string) {
	ownMu.Lock()
	if e := ownFindLocked(ownFile, path); e != nil {
		// Steady state: already recorded, with this core already on it. Return without
		// re-serialising the manifest, because the generators call this on every config
		// regeneration and some of those run every ten seconds.
		if ownHasCore(e, core) {
			ownMu.Unlock()
			return
		}
		ownAddCore(e, core)
		ownSaveLocked()
		ownMu.Unlock()
		return
	}
	ownMu.Unlock()

	if _, err := os.Lstat(path); err != nil {
		ownClaim(ownFile, path, core)
		return
	}

	backup, sum, err := ownBackupFile(path)
	if err != nil {
		// No backup means no safe restore, so the file must never be deleted. That
		// is precisely what preExisting=yes with no Backup encodes.
		logger.Warning("ownership: could not back up", path, "before overwriting it:", err)
		ownNote(ownFile, path, core, "already present; no backup could be taken")
		return
	}
	ownMu.Lock()
	e := ownUpsertLocked(ownFile, path, ownStateYes)
	e.Backup = backup
	e.Sha256 = sum
	e.Note = "already present before vpn-ui; original backed up"
	ownAddCore(e, core)
	ownSaveLocked()
	ownMu.Unlock()
	logger.Info("ownership: backed up the host's own", path, "to", backup)
}

// ownPrepareDir records a directory before we write into it, so uninstall can
// tell "remove the directory" from "remove our files out of the operator's
// directory". /etc/ocserv and /etc/openvpn/server are the two that got this
// wrong: both were deleted wholesale even on a host whose distro package owns
// them.
func ownPrepareDir(path, core string) {
	ownMu.Lock()
	defer ownMu.Unlock()
	if e := ownFindLocked(ownDir, path); e != nil {
		ownAddCore(e, core)
		ownSaveLocked()
		return
	}
	state := ownStateNo
	created := true
	if st, err := os.Lstat(path); err == nil && st.IsDir() {
		state, created = ownStateYes, false
	}
	e := ownUpsertLocked(ownDir, path, state)
	e.CreatedByUs = created
	if !created {
		e.Note = "directory already existed; only vpn-ui's own files inside it are removed"
	}
	ownAddCore(e, core)
	ownSaveLocked()
}

// ownPrepareSymlink records one of the outward symlinks that point a compiled-in
// path at a bundled tree (/usr/sbin/pppd, /usr/lib/pppd, /usr/lib/ipsec,
// /usr/lib/accel-ppp).
//
// Every backend.Link* function already declines when the path exists, so a host
// strongSwan or a native pppd is never clobbered. This adds the RECORD of that
// decision, so the uninstall report can say "we left your /usr/lib/ipsec alone"
// rather than silently doing the right thing. The removal side does not depend on
// it: unlinkIfPointsAt checks the symlink's target, which is a stronger test than
// the manifest could give.
func ownPrepareSymlink(path, target, core string) {
	if _, found := ownStateOf(ownSymlink, path); found {
		return
	}
	if _, err := os.Lstat(path); err == nil {
		ownNote(ownSymlink, path, core, "already present; vpn-ui did not link its bundle here")
		return
	}
	ownMu.Lock()
	e := ownUpsertLocked(ownSymlink, path, ownStateNo)
	e.CreatedByUs = true
	e.Note = "linked at " + target
	ownAddCore(e, core)
	ownSaveLocked()
	ownMu.Unlock()
}

// ownRestoreFile puts a backed-up file back where it came from and forgets the
// entry. Returns false when there is nothing to restore.
func ownRestoreFile(path, backup string) bool {
	data, err := os.ReadFile(backup)
	if err != nil {
		logger.Warning("ownership: backup", backup, "is gone, leaving", path, "as it is:", err)
		return false
	}
	mode := os.FileMode(0600)
	if st, err := os.Stat(backup); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		logger.Warning("ownership: could not restore", path, "from", backup, err)
		return false
	}
	_ = os.Remove(backup)
	ownRemoveEntry(ownFile, path)
	return true
}

// ownReleasePath applies the manifest's verdict to one path on the host and
// reports what happened, as at most one of removed/kept.
//
// This is what replaced the catalog-driven os.RemoveAll in uninstall. The catalog
// still names the paths, but it no longer decides: a path the manifest does not
// positively record as ours is reported and left where it is. That is the whole
// difference between "uninstalling OpenConnect" and "deleting the distro ocserv's
// configuration, certificates and password file".
func ownReleasePath(path string, cores []string) (removed, kept string) {
	kind := ownFile
	if _, found := ownStateOf(ownDir, path); found {
		kind = ownDir
	} else if _, found := ownStateOf(ownFile, path); !found {
		if _, err := os.Lstat(path); err != nil {
			return "", "" // already gone; not worth a line
		}
		// No record either way. A path only vpn-ui ever creates is still ours: the
		// per-inbound directories are created as inbounds are added, long after the
		// manifest was synthesised, and refusing to clean those up would turn
		// uninstall into a no-op for the very files it exists to remove. Anything
		// else is reported and left exactly where it is.
		if !ownPanelPrivatePath(path) {
			return "", path + " (kept: not recorded as installed by vpn-ui)"
		}
		if removeIfPresent(path) {
			return path, ""
		}
		return "", ""
	}

	act := ownRelease(kind, path, cores)
	switch {
	case act.Restore != "":
		if ownRestoreFile(path, act.Restore) {
			return path + " (restored the host's own version)", ""
		}
		return "", path + " (kept: its backup is missing)"
	case act.Delete:
		if removeIfPresent(path) {
			ownRemoveEntry(kind, path)
			return path, ""
		}
		ownRemoveEntry(kind, path)
		return "", ""
	default:
		if _, err := os.Lstat(path); err != nil {
			return "", "" // nothing there to keep; do not report a phantom
		}
		return "", path + " (kept: " + act.Keep + ")"
	}
}

// --------------------------------------------------------------------------- //
//  Migration for hosts already in the field
// --------------------------------------------------------------------------- //

// ownSynthesizeOnce guards the one-time backfill.
var ownSynthesizeOnce sync.Once

// OwnSynthesize backfills the manifest on a host that was provisioned before it
// existed, so a first upgrade does not either (a) delete the operator's files
// because nothing says they were theirs, or (b) refuse to clean up the panel's
// own files because nothing says they were ours.
//
// The classification is by evidence, not by guessing:
//
//   - A path only vpn-ui ever creates (the per-inbound directories, our own
//     /etc/vpn-ui-* roots, our swanctl conf.d drop-ins) is recorded as OURS. No
//     distro ships those names, so uninstall keeps working on upgraded hosts.
//   - A path shared with a distro package (/etc/pptpd.conf, /etc/ipsec.secrets,
//     /etc/ocserv, ...) is recorded as UNKNOWN. Unknown never gets deleted, it
//     gets reported, which is the fail-safe direction: the operator can remove it
//     by hand, and no data of theirs is destroyed to save them the trouble.
//
// Called once per process, from the panel's start-up path. Cheap: a stat per
// catalog path.
func OwnSynthesize() {
	ownSynthesizeOnce.Do(func() {
		// Without the DB there is no way to tell which cores are installed, and both
		// halves of the synthesis hang off that answer. Guessing "none installed"
		// would mark our OWN leftover netdevs as the operator's, after which the
		// reconcilers would refuse to recreate them. Recording nothing leaves the
		// name-shape rule in charge, which is exactly the pre-manifest behaviour.
		if database.GetDB() == nil {
			logger.Warning("ownership: no database, skipping the one-time host survey")
			return
		}
		var cs CoreService
		installedSet := cs.provisionedProtocolSet()

		// The interface scan runs even on a host that has never been set up, and it is
		// the one that matters most: it is what records an operator's own gre/wgc/awg
		// device as theirs BEFORE the core that would sweep it is ever installed.
		if n := ownSynthesizeIfaces(installedSet); n > 0 {
			logger.Info("ownership: recorded", n, "existing network interface(s) matching vpn-ui's own naming")
		}

		var ss SettingService
		if !ss.HasRecordedProvisionedProtocols() && !cs.IsProvisioned() {
			return // never set up: there are no files of ours on this host to describe
		}
		installed := cs.installedCoreNames()
		if len(installed) == 0 {
			// Provisioned by a build with no per-core record: every core's artifacts
			// may be present, so consider them all.
			installed = installableCores()
		}
		n := 0
		for _, core := range installed {
			spec := coreSpecFor(core)
			if spec == nil {
				continue
			}
			for _, p := range spec.paths {
				n += ownSynthesizePath(p, core)
			}
			for _, g := range spec.globs {
				matches, _ := filepath.Glob(g)
				for _, m := range matches {
					n += ownSynthesizePath(m, core)
				}
			}
		}
		for _, p := range sharedHostFilePaths() {
			n += ownSynthesizePath(p, coreForHostPath(p))
		}
		if n > 0 {
			logger.Info("ownership: recorded", n, "existing artifact(s) from a pre-manifest install")
		}
	})
}

// ownSynthesizePath records one existing path, returning 1 when it added an
// entry. Nothing is recorded for a path that is not there: absent state needs no
// protection, and inventing an entry for it would let a later install skip its
// own "was this here before?" check.
func ownSynthesizePath(path, core string) int {
	if path == "" {
		return 0
	}
	st, err := os.Lstat(path)
	if err != nil {
		return 0
	}
	kind := ownFile
	if st.IsDir() {
		kind = ownDir
	}
	if _, found := ownStateOf(kind, path); found {
		return 0
	}
	state := ownStateUnknown
	note := "found on this host by an upgrade; not deleted because nobody recorded who created it"
	if ownPanelPrivatePath(path) {
		state = ownStateNo
		note = "a path only vpn-ui creates; adopted on upgrade"
	}
	ownMu.Lock()
	e := ownUpsertLocked(kind, path, state)
	e.Note = note
	e.CreatedByUs = state == ownStateNo
	ownAddCore(e, core)
	ownSaveLocked()
	ownMu.Unlock()
	return 1
}

// ownPanelPrivatePath reports whether a path is one only this panel ever creates,
// so an upgrade may adopt it instead of leaving it forever unowned. Everything
// else is shared with some distro package and stays unknown.
func ownPanelPrivatePath(path string) bool {
	base := filepath.Base(path)
	switch {
	case strings.HasPrefix(path, "/etc/vpn-ui-"): // our own per-core roots
		return true
	case strings.HasPrefix(path, "/etc/vpn-ui/"):
		return true
	case strings.HasPrefix(base, "server-"): // per-inbound dirs under a shared root
		return true
	case path == "/etc/swanctl/conf.d/l2tp.conf":
		return true
	case strings.HasPrefix(path, "/etc/swanctl/conf.d/ikev2-"),
		strings.HasPrefix(path, "/etc/swanctl/conf.d/gre-"):
		return true
	case strings.HasPrefix(path, "/var/run/"): // runtime dirs, recreated on demand
		return true
	}
	return false
}

// sharedHostFiles maps every host file the panel overwrites but does not own to
// the core that writes it. These are the ones an operator can plausibly have
// configured themselves, which is why each one is backed up before the first
// overwrite and restored on uninstall.
var sharedHostFiles = map[string]string{
	"/etc/xl2tpd/xl2tpd.conf":      "l2tp",
	"/etc/ppp/options.xl2tpd":      "l2tp",
	"/etc/ipsec.conf":              "l2tp",
	"/etc/ipsec.secrets":           "l2tp",
	"/etc/pptpd.conf":              "pptp",
	"/etc/ppp/pptpd-options":       "pptp",
	"/etc/strongswan.conf":         "ikev2",
	"/etc/swanctl/swanctl.conf":    "ikev2",
	"/etc/default/grub":            "",
	"/etc/sysctl.d/99-vpn-ui.conf": "",
}

func sharedHostFilePaths() []string {
	out := make([]string, 0, len(sharedHostFiles))
	for p := range sharedHostFiles {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// coreForHostPath names the core that writes a shared host file, or "" for the
// host-wide ones (grub, our sysctl drop-in) that belong to no single core and are
// only released when the last core goes.
func coreForHostPath(path string) string { return sharedHostFiles[path] }

// --------------------------------------------------------------------------- //
//  Reporting
// --------------------------------------------------------------------------- //

// OwnedArtifactReport is one manifest row rendered for the panel.
type OwnedArtifactReport struct {
	Kind        string   `json:"kind"`
	ID          string   `json:"id"`
	Cores       []string `json:"cores,omitempty"`
	PreExisting string   `json:"preExisting"`
	Note        string   `json:"note,omitempty"`
}

// OwnershipReport lists what vpn-ui believes it owns on this host, so an operator
// can see before an uninstall what will be removed and what will be left alone.
func OwnershipReport() []OwnedArtifactReport {
	entries := ownEntries()
	out := make([]OwnedArtifactReport, 0, len(entries))
	for _, e := range entries {
		out = append(out, OwnedArtifactReport{
			Kind:        e.Kind,
			ID:          e.ID,
			Cores:       e.Cores,
			PreExisting: string(e.PreExisting),
			Note:        e.Note,
		})
	}
	return out
}
