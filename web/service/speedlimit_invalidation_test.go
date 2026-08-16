package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// These cover the CONFIG half of the sidecar: a limit changed in the panel has to reach
// the core on a box where no traffic is flowing at all. The pure-function tests next door
// (speedlimit_test.go) prove the right document is computed; these prove it gets written
// without waiting for a byte to move, which is what the traffic-tick hook could not do.
//
// Every test here writes the DB directly rather than driving the controller, because the
// DB is exactly where the mechanism hooks in: it is the one thing every edit path (panel,
// tgbot, LDAP sync, bulk ops) provably has in common.

// newLimiterSidecar stands up a real SQLite DB with the invalidation callbacks armed and
// the sidecar redirected into a temp dir, and returns the sidecar's path. The env var is
// read on every GetSpeedLimitPath call, so this cannot leak into the developer's bin/.
func newLimiterSidecar(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	t.Setenv("VPNUI_BIN_FOLDER", bin)
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	RegisterSpeedLimitInvalidation()
	path := xray.GetSpeedLimitPath()
	if want := filepath.Join(bin, "speedlimits.json"); path != want {
		t.Fatalf("sidecar path = %q, want %q (test would write outside its temp dir)", path, want)
	}
	return path
}

// publishedIPLimit returns the cap the sidecar publishes for email, and whether the
// account appears at all. Absent means unlimited: a fully unlimited account is dropped
// from the document entirely, so "gone" is the wire form of ipLimit 0.
func publishedIPLimit(t *testing.T, path, email string) (int, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	var doc speedLimitDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse sidecar %q: %v", data, err)
	}
	for _, u := range doc.Users {
		if u.Email == email {
			return u.IPLimit, true
		}
	}
	return 0, false
}

// cappedInbound is one enabled native inbound carrying an IP Limit default and one
// client. Native (vless) on purpose: those are the inbounds whose cap the CORE enforces,
// so they are the ones the sidecar carries an ipLimit for.
func cappedInbound(ipLimit int, email string) *model.Inbound {
	return &model.Inbound{
		UserId:   1,
		Enable:   true,
		Protocol: model.VLESS,
		Tag:      "inbound-443",
		Port:     443,
		IPLimit:  ipLimit,
		Settings: `{"clients":[{"email":"` + email + `","limitIp":0}]}`,
	}
}

// TestConfigChangeReachesSidecarWithoutTraffic is the measured bug, verbatim: set an
// inbound's ipLimit from 1 to 0 and the core kept enforcing 1 until a download happened
// to run the traffic tick's writer. Nothing here generates a single byte.
func TestConfigChangeReachesSidecarWithoutTraffic(t *testing.T) {
	path := newLimiterSidecar(t)
	db := database.GetDB()

	inb := cappedInbound(1, "idle@box")
	if err := db.Create(inb).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	WriteSpeedLimitsIfDirty()
	if got, ok := publishedIPLimit(t, path, "idle@box"); !ok || got != 1 {
		t.Fatalf("first publish: ipLimit = %d (present=%v), want 1", got, ok)
	}

	// The edit. This is the write the panel's updateInbound performs, and it is the exact
	// path that returns needRestart=false when the live del/add API succeeds, so no
	// restart is requested and nothing on the restart path could have republished this.
	if err := db.Model(&model.Inbound{}).Where("id = ?", inb.Id).Update("ip_limit", 0).Error; err != nil {
		t.Fatalf("update ip_limit: %v", err)
	}
	WriteSpeedLimitsIfDirty()
	if got, ok := publishedIPLimit(t, path, "idle@box"); ok {
		t.Fatalf("after clearing the cap: account still published with ipLimit %d, want absent (unlimited)", got)
	}

	// ...and back again, so this cannot pass by simply dropping everyone.
	if err := db.Model(&model.Inbound{}).Where("id = ?", inb.Id).Update("ip_limit", 4).Error; err != nil {
		t.Fatalf("re-set ip_limit: %v", err)
	}
	WriteSpeedLimitsIfDirty()
	if got, ok := publishedIPLimit(t, path, "idle@box"); !ok || got != 4 {
		t.Fatalf("after re-setting the cap: ipLimit = %d (present=%v), want 4", got, ok)
	}
}

// TestClientLimitEditReachesSidecarWithoutTraffic covers the per-client override, which
// lives inside the settings blob rather than in a column. It is the case a hook on
// SetToNeedRestart would miss hardest: a client-only edit is precisely what the hot-add
// path keeps off the restart path on purpose.
func TestClientLimitEditReachesSidecarWithoutTraffic(t *testing.T) {
	path := newLimiterSidecar(t)
	db := database.GetDB()

	inb := cappedInbound(0, "override@box") // no inbound default: the client's own cap is the whole answer
	if err := db.Create(inb).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	WriteSpeedLimitsIfDirty()
	if _, ok := publishedIPLimit(t, path, "override@box"); ok {
		t.Fatalf("uncapped account should be absent from the sidecar")
	}

	if err := db.Model(&model.Inbound{}).Where("id = ?", inb.Id).
		Update("settings", `{"clients":[{"email":"override@box","limitIp":2}]}`).Error; err != nil {
		t.Fatalf("update settings: %v", err)
	}
	WriteSpeedLimitsIfDirty()
	if got, ok := publishedIPLimit(t, path, "override@box"); !ok || got != 2 {
		t.Fatalf("after client cap edit: ipLimit = %d (present=%v), want 2", got, ok)
	}
}

// TestSpeedLimitCleanTickDoesNothing pins the gate that makes a 1s cron affordable.
// Deleting the file and finding it still gone proves the tick short-circuits before it
// reads the DB or the file, rather than merely skipping the write at the end.
func TestSpeedLimitCleanTickDoesNothing(t *testing.T) {
	path := newLimiterSidecar(t)
	db := database.GetDB()
	if err := db.Create(cappedInbound(1, "quiet@box")).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	WriteSpeedLimitsIfDirty()
	if _, ok := publishedIPLimit(t, path, "quiet@box"); !ok {
		t.Fatalf("account should be published before the clean-tick check")
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove sidecar: %v", err)
	}
	for range 5 {
		WriteSpeedLimitsIfDirty()
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a clean tick did work: sidecar was rewritten (stat err = %v)", err)
	}
}

// TestWriteSpeedLimitsConsumesDirty pins the interlock with the traffic tick: the
// unconditional writer recomputes from live DB state, so it satisfies whatever was
// pending and the cron must not then repeat the scan on a busy box.
func TestWriteSpeedLimitsConsumesDirty(t *testing.T) {
	path := newLimiterSidecar(t)
	db := database.GetDB()
	if err := db.Create(cappedInbound(1, "busy@box")).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	WriteSpeedLimits() // the traffic tick's / reset job's call
	if _, ok := publishedIPLimit(t, path, "busy@box"); !ok {
		t.Fatalf("unconditional writer did not publish the account")
	}
	if speedLimitsDirty.Load() {
		t.Fatalf("WriteSpeedLimits left the dirty flag set; the republish cron would redo the scan every tick")
	}
}

// TestRegisterSpeedLimitInvalidationRepublishesAtStartup: the sidecar outlives the
// process, so the DB can disagree with it the moment we come up (restored backup, hand
// edited row, panel down when it was last written). Registration marks dirty once so the
// first tick settles that.
func TestRegisterSpeedLimitInvalidationRepublishesAtStartup(t *testing.T) {
	path := newLimiterSidecar(t)
	db := database.GetDB()
	if err := db.Create(cappedInbound(7, "restart@box")).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	WriteSpeedLimits()
	if err := os.WriteFile(path, []byte(`{"users":[]}`+"\n"), 0o600); err != nil {
		t.Fatalf("stale the sidecar: %v", err)
	}

	// A fresh panel start over the same DB, with a sidecar that no longer agrees.
	RegisterSpeedLimitInvalidation()
	WriteSpeedLimitsIfDirty()
	if got, ok := publishedIPLimit(t, path, "restart@box"); !ok || got != 7 {
		t.Fatalf("startup republish: ipLimit = %d (present=%v), want 7", got, ok)
	}
}
