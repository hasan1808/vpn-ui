package job

import (
	"errors"
	"testing"
)

// Every test here is offline by construction: the only path to the network is
// UpdateGeofileJob.updateAll, and each test either proves the job did not reach it
// or substitutes for it. Nothing below downloads anything.

// TestUpdateGeofileJobSkipsWhenAutoUpdateOff proves the switch in the overview's
// Geofiles dialog is what the scheduled tick obeys.
//
// The gate lives inside the job rather than around its registration (web.go adds
// it unconditionally), so that flipping the switch takes effect on the next tick
// instead of on the next panel restart. This test is what holds that arrangement
// honest: move the gate back out to registration and it fails.
func TestUpdateGeofileJobSkipsWhenAutoUpdateOff(t *testing.T) {
	setupIntegrationDB(t)

	var j UpdateGeofileJob
	called := false
	j.update = func() error { called = true; return nil }

	if err := j.settingService.SetGeofileAutoUpdate(false); err != nil {
		t.Fatalf("could not turn auto-update off: %v", err)
	}
	skipped, err := j.tick()
	if err != nil {
		t.Fatalf("tick errored with auto-update off: %v", err)
	}
	if skipped == "" {
		t.Error("tick did not skip with auto-update off")
	}
	if called {
		t.Error("the download ran even though auto-update is off")
	}
}

// TestUpdateGeofileJobRunsWhenOn is the other half: on by default, and the default
// is what an untouched panel gets.
func TestUpdateGeofileJobRunsWhenOn(t *testing.T) {
	setupIntegrationDB(t)

	var j UpdateGeofileJob
	called := false
	j.update = func() error { called = true; return nil }

	// Not set explicitly: this asserts the DEFAULT is on, which is the whole point
	// of the feature. Stale geo data fails silently, so opting in would mean most
	// panels never refresh.
	skipped, err := j.tick()
	if err != nil {
		t.Fatalf("tick errored: %v", err)
	}
	if skipped != "" {
		t.Fatalf("tick skipped on a default panel: %q", skipped)
	}
	if !called {
		t.Error("the refresh did not run on a default panel")
	}
}

// TestUpdateGeofileJobReportsFailure checks a failed download is surfaced rather
// than swallowed. The files already on disk are untouched either way, because
// downloadGeofile only renames a temp file into place once it is complete.
func TestUpdateGeofileJobReportsFailure(t *testing.T) {
	setupIntegrationDB(t)

	var j UpdateGeofileJob
	want := errors.New("upstream said no")
	j.update = func() error { return want }

	skipped, err := j.tick()
	if skipped != "" {
		t.Fatalf("tick skipped instead of running: %q", skipped)
	}
	if !errors.Is(err, want) {
		t.Fatalf("the download error was not returned: got %v", err)
	}
}
