package service

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// seedAccountingDB gives each test its own SQLite file with one inbound and one client,
// and returns the inbound id and the client email.
func seedAccountingDB(t *testing.T, ct *xray.ClientTraffic) (int, string) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	settings, err := json.Marshal(map[string]any{
		"clients": []any{map[string]any{
			"email": ct.Email, "id": "u-1", "enable": true,
			"expiryTime": float64(ct.ExpiryTime),
		}},
	})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	ib := &model.Inbound{
		UserId: 1, Tag: "inbound-20001", Port: 20001, Protocol: model.VMESS,
		Enable: true, Settings: string(settings),
	}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	ct.InboundId = ib.Id
	if err := db.Create(ct).Error; err != nil {
		t.Fatalf("create client_traffic: %v", err)
	}
	return ib.Id, ct.Email
}

func readTraffic(t *testing.T, email string) xray.ClientTraffic {
	t.Helper()
	var got xray.ClientTraffic
	if err := database.GetDB().Where("email = ?", email).First(&got).Error; err != nil {
		t.Fatalf("read back %s: %v", email, err)
	}
	return got
}

// A tick can carry more than one record for one account. Stopping at the first (the old
// `break`) silently discarded the rest AFTER their source counters had already been read
// and reset, so those bytes were billed to nobody.
func TestAddClientTrafficAppliesEveryRecordForAnEmail(t *testing.T) {
	_, email := seedAccountingDB(t, &xray.ClientTraffic{Email: "sum@test", Enable: true})

	s := &InboundService{}
	err := s.addClientTraffic(database.GetDB(), []*xray.ClientTraffic{
		{Email: email, Up: 100, Down: 1000},
		{Email: email, Up: 7, Down: 70},
		{Email: "someone-else@test", Up: 999, Down: 999},
	})
	if err != nil {
		t.Fatalf("addClientTraffic: %v", err)
	}

	got := readTraffic(t, email)
	if got.Up != 107 || got.Down != 1070 {
		t.Errorf("up/down = %d/%d; want 107/1070 (both records applied)", got.Up, got.Down)
	}
	if got.AllTime != 1177 {
		t.Errorf("all_time = %d; want 1177", got.AllTime)
	}
}

// A reset zeroes up/down and re-enables. It must not touch the lifetime counter, which
// exists precisely to survive resets.
//
// Note this asserts the post-conditions, not the race itself: the rollback the fix
// removes only shows up when the 10s accounting job commits between this function's read
// and its write, which a single-threaded test cannot schedule. TestAutoRenewClients...
// below reproduces that interleaving for real.
func TestResetClientTrafficKeepsLifetimeCounter(t *testing.T) {
	id, email := seedAccountingDB(t, &xray.ClientTraffic{
		Email: "reset@test", Enable: true,
		Up: 500, Down: 1500, AllTime: 999_000, LastOnline: 1234, Total: 5000,
	})

	s := &InboundService{}
	if _, err := s.ResetClientTraffic(id, email); err != nil {
		t.Fatalf("ResetClientTraffic: %v", err)
	}

	got := readTraffic(t, email)
	if got.Up != 0 || got.Down != 0 {
		t.Errorf("up/down = %d/%d; want 0/0", got.Up, got.Down)
	}
	if !got.Enable {
		t.Error("client should be re-enabled by a reset")
	}
	if got.AllTime != 999_000 {
		t.Errorf("all_time = %d; want 999000 (a reset must not rewind the lifetime counter)", got.AllTime)
	}
	if got.LastOnline != 1234 {
		t.Errorf("last_online = %d; want 1234 (untouched by a reset)", got.LastOnline)
	}
	if got.Total != 5000 {
		t.Errorf("total = %d; want 5000 (untouched by a reset)", got.Total)
	}
}

// The real interleaving: autoRenewClients reads the traffic rows, writes the inbounds,
// and only then writes the traffic rows. A SQLite trigger on that intermediate inbound
// write stands in for the 10s accounting job committing mid-flight. Writing the whole row
// back (the old tx.Save) discards that commit; updating only the renewed columns keeps it.
// This is the "traffic went BACKWARDS on an idle account" report, made deterministic.
func TestAutoRenewClientsDoesNotRollBackConcurrentTraffic(t *testing.T) {
	past := time.Now().Add(-48*time.Hour).Unix() * 1000
	id, email := seedAccountingDB(t, &xray.ClientTraffic{
		Email: "renew@test", Enable: false, Reset: 30, ExpiryTime: past,
		Up: 10, Down: 20, AllTime: 999_000,
	})
	_ = id

	db := database.GetDB()
	trigger := fmt.Sprintf(`CREATE TRIGGER concurrent_tick AFTER UPDATE ON inbounds
BEGIN
  UPDATE client_traffics SET all_time = all_time + 4242 WHERE email = '%s';
END;`, email)
	if err := db.Exec(trigger).Error; err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	s := &InboundService{}
	if _, _, err := s.autoRenewClients(db); err != nil {
		t.Fatalf("autoRenewClients: %v", err)
	}

	got := readTraffic(t, email)
	if got.AllTime != 999_000+4242 {
		t.Errorf("all_time = %d; want %d (the concurrent commit must survive the renewal)",
			got.AllTime, 999_000+4242)
	}
	if got.Up != 0 || got.Down != 0 {
		t.Errorf("up/down = %d/%d; want 0/0 after a renewal", got.Up, got.Down)
	}
	if !got.Enable {
		t.Error("an expired client should be re-enabled by its renewal")
	}
	if got.ExpiryTime <= time.Now().Unix()*1000 {
		t.Errorf("expiry_time = %d; want a future timestamp after renewal", got.ExpiryTime)
	}
}
