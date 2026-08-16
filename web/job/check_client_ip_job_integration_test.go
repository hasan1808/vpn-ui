package job

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	xuilogger "github.com/hasan1808/pro-ui/logger"
	"github.com/op/go-logging"
)

// vpn-ui logger must be initialised once before any code path that can
// log a warning. otherwise log.Warningf panics on a nil logger.
var loggerInitOnce sync.Once

// setupIntegrationDB wires a temp sqlite db and log folder so
// updateInboundClientIps can run end to end. closes the db before
// TempDir cleanup so windows doesn't complain about the file being in
// use.
func setupIntegrationDB(t *testing.T) {
	t.Helper()

	loggerInitOnce.Do(func() {
		xuilogger.InitLogger(logging.ERROR)
	})

	dbDir := t.TempDir()
	logDir := t.TempDir()

	t.Setenv("VPNUI_DB_FOLDER", dbDir)
	t.Setenv("VPNUI_LOG_FOLDER", logDir)

	if err := database.InitDB(filepath.Join(dbDir, "vpn-ui.db")); err != nil {
		t.Fatalf("database.InitDB failed: %v", err)
	}
	// LIFO cleanup order: this runs before t.TempDir's own cleanup.
	t.Cleanup(func() {
		if err := database.CloseDB(); err != nil {
			t.Logf("database.CloseDB warning: %v", err)
		}
	})
}

// seed an inbound whose settings json has a single client with the
// given email and ip limit.
func seedInboundWithClient(t *testing.T, tag, email string, limitIp int) {
	t.Helper()
	settings := map[string]any{
		"clients": []map[string]any{
			{
				"email":   email,
				"limitIp": limitIp,
				"enable":  true,
			},
		},
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		Tag:      tag,
		Enable:   true,
		Protocol: model.VLESS,
		Port:     4321,
		Settings: string(settingsJSON),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
}

// seed an InboundClientIps row with the given blob.
func seedClientIps(t *testing.T, email string, ips []IPWithTimestamp) *model.InboundClientIps {
	t.Helper()
	blob, err := json.Marshal(ips)
	if err != nil {
		t.Fatalf("marshal ips: %v", err)
	}
	row := &model.InboundClientIps{
		ClientEmail: email,
		Ips:         string(blob),
	}
	if err := database.GetDB().Create(row).Error; err != nil {
		t.Fatalf("seed InboundClientIps: %v", err)
	}
	return row
}

// read the persisted blob and parse it back.
func readClientIps(t *testing.T, email string) []IPWithTimestamp {
	t.Helper()
	row := &model.InboundClientIps{}
	if err := database.GetDB().Where("client_email = ?", email).First(row).Error; err != nil {
		t.Fatalf("read InboundClientIps for %s: %v", email, err)
	}
	if row.Ips == "" {
		return nil
	}
	var out []IPWithTimestamp
	if err := json.Unmarshal([]byte(row.Ips), &out); err != nil {
		t.Fatalf("unmarshal Ips blob %q: %v", row.Ips, err)
	}
	return out
}

// make a lookup map so asserts don't depend on slice order.
func ipSet(entries []IPWithTimestamp) map[string]int64 {
	out := make(map[string]int64, len(entries))
	for _, e := range entries {
		out[e.IP] = e.Timestamp
	}
	return out
}

// The list is telemetry, so a client under its cap must simply be recorded: the address
// that is connecting now, plus the ones that were connecting recently enough to still be
// worth showing. #4091 is the reason the historical ones must not displace the live one.
func TestUpdateInboundClientIps_RecordsLiveAndRecentIps(t *testing.T) {
	setupIntegrationDB(t)

	const email = "pr4091-repro"
	seedInboundWithClient(t, "inbound-pr4091", email, 3)

	now := time.Now().Unix()
	// Idle, but still inside the retention window.
	row := seedClientIps(t, email, []IPWithTimestamp{
		{IP: "10.0.0.1", Timestamp: now - 20*60},
		{IP: "10.0.0.2", Timestamp: now - 15*60},
		{IP: "10.0.0.3", Timestamp: now - 10*60},
	})

	j := NewCheckClientIpJob()
	live := []IPWithTimestamp{
		{IP: "128.71.1.1", Timestamp: now},
	}

	j.updateInboundClientIps(row, email, live)

	persisted := ipSet(readClientIps(t, email))
	for _, want := range []string{"128.71.1.1", "10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if _, ok := persisted[want]; !ok {
			t.Errorf("expected %s to be persisted in inbound_client_ips.ips; got %v", want, persisted)
		}
	}
	if got := persisted["128.71.1.1"]; got != now {
		t.Errorf("live ip timestamp should match the scan timestamp %d, got %d", now, got)
	}

	assertNoBanLog(t)
}

// The inverted invariant, and the point of the whole change: an address BEYOND the
// client's cap is recorded like any other and nothing is banned. The core refused it at
// admission (or did not, if the account is under its cap on live connections, which this
// job cannot know); either way this job's only job is to say it was seen.
func TestUpdateInboundClientIps_OverLimitIpIsRecordedNotBanned(t *testing.T) {
	setupIntegrationDB(t)

	const email = "pr4091-abuse"
	// limit=1, and two addresses show up. The old code banned the newcomer here.
	seedInboundWithClient(t, "inbound-pr4091-abuse", email, 1)

	now := time.Now().Unix()
	row := seedClientIps(t, email, []IPWithTimestamp{
		{IP: "10.1.0.1", Timestamp: now - 60},
	})

	j := NewCheckClientIpJob()
	live := []IPWithTimestamp{
		{IP: "10.1.0.1", Timestamp: now - 5},
		{IP: "192.0.2.9", Timestamp: now},
	}

	j.updateInboundClientIps(row, email, live)

	persisted := ipSet(readClientIps(t, email))
	for _, want := range []string{"10.1.0.1", "192.0.2.9"} {
		if _, ok := persisted[want]; !ok {
			t.Errorf("%s must be recorded even though the client's cap is 1; got %v", want, persisted)
		}
	}

	// Nothing may reach 3xipl.log: that file existed only for a fail2ban jail to parse,
	// and a ban here would be by ADDRESS, hitting every customer behind the same CGNAT.
	assertNoBanLog(t)
}

// The blob is rewritten on every tick, so its order must not depend on map iteration.
func TestUpdateInboundClientIps_PersistsInStableOrder(t *testing.T) {
	setupIntegrationDB(t)

	const email = "order-stable"
	seedInboundWithClient(t, "inbound-order", email, 2)

	now := time.Now().Unix()
	row := seedClientIps(t, email, nil)
	scan := []IPWithTimestamp{
		{IP: "10.0.0.9", Timestamp: now - 30},
		{IP: "10.0.0.2", Timestamp: now},
		{IP: "10.0.0.1", Timestamp: now}, // same timestamp: the address breaks the tie
	}

	j := NewCheckClientIpJob()
	j.updateInboundClientIps(row, email, scan)
	want := readClientIps(t, email)

	for i := 0; i < 10; i++ {
		j.updateInboundClientIps(row, email, scan)
		got := readClientIps(t, email)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d reordered the list\ngot:  %v\nwant: %v", i+2, got, want)
		}
	}
	if want[0].IP != "10.0.0.9" || want[1].IP != "10.0.0.1" || want[2].IP != "10.0.0.2" {
		t.Errorf("want oldest first, then by address: got %v", want)
	}
}

// assertNoBanLog fails if anything wrote to 3xipl.log. Enforcement is the core's now, so
// the job must never produce a ban line again.
func assertNoBanLog(t *testing.T) {
	t.Helper()
	if info, err := os.Stat(readIpLimitLogPath()); err == nil && info.Size() > 0 {
		body, _ := os.ReadFile(readIpLimitLogPath())
		t.Fatalf("3xipl.log must stay empty; the job no longer bans anything, got:\n%s", body)
	}
}

// readIpLimitLogPath reads the 3xipl.log path the same way xray.GetIPLimitLogPath does
// but without importing xray here just for the path helper (which would pull a lot more
// deps into the test binary). The env-derived log folder is deterministic.
func readIpLimitLogPath() string {
	folder := os.Getenv("VPNUI_LOG_FOLDER")
	if folder == "" {
		folder = filepath.Join(".", "log")
	}
	return filepath.Join(folder, "3xipl.log")
}
