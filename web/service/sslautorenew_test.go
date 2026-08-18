package service

import (
	"os"
	"path/filepath"
	"testing"
)

// Absence means ON. This is the whole safety property: every install that existed
// before the toggle did has no marker, and must keep renewing.
func TestAutoRenewDefaultsOnForAnUntouchedStore(t *testing.T) {
	root := t.TempDir()
	if !sslAutoRenewEnabledAt(root) {
		t.Error("a store with no marker reported auto renew OFF, which would silently stop renewing every existing install")
	}
}

// A store root that does not exist at all must still read as ON, for the same
// reason: failing safe here means renewing something nobody asked us not to.
func TestAutoRenewDefaultsOnForAMissingStore(t *testing.T) {
	if !sslAutoRenewEnabledAt(filepath.Join(t.TempDir(), "not-created")) {
		t.Error("a missing store reported auto renew OFF")
	}
}

func TestAutoRenewMarkerTurnsItOff(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, sslAutoRenewOffFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sslAutoRenewEnabledAt(root) {
		t.Error("the marker is present but auto renew still reported ON")
	}
}

// The marker sits in the store ROOT, never inside a version directory, so rolling
// back to an older certificate cannot drag a stale preference along with it.
func TestAutoRenewMarkerIsNotInsideAVersion(t *testing.T) {
	root := t.TempDir()
	versions := filepath.Join(root, sslVersionsDir)
	if err := os.MkdirAll(versions, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versions, sslAutoRenewOffFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !sslAutoRenewEnabledAt(root) {
		t.Error("a marker inside the versions tree switched the whole store off; it must only count at the root")
	}
}

// Turning it off and back on has to leave the store as it was, so a profile whose
// flag was toggled is indistinguishable from one that never was.
func TestAutoRenewRoundTripsCleanly(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, sslAutoRenewOffFile)

	if err := os.WriteFile(marker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sslAutoRenewEnabledAt(root) {
		t.Fatal("setup: expected OFF")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if !sslAutoRenewEnabledAt(root) {
		t.Error("removing the marker did not restore auto renew")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("the marker outlived being turned back on")
	}
}
