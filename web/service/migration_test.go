package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"

	"gorm.io/gorm"
)

func upsertSetting(t *testing.T, db *gorm.DB, key, value string) {
	t.Helper()
	s := &model.Setting{}
	err := db.Where("key = ?", key).First(s).Error
	switch {
	case database.IsNotFound(err):
		if e := db.Create(&model.Setting{Key: key, Value: value}).Error; e != nil {
			t.Fatalf("create setting %s: %v", key, e)
		}
	case err != nil:
		t.Fatalf("read setting %s: %v", key, err)
	default:
		s.Value = value
		if e := db.Save(s).Error; e != nil {
			t.Fatalf("save setting %s: %v", key, e)
		}
	}
}

func getSetting(t *testing.T, db *gorm.DB, key string) string {
	t.Helper()
	s := &model.Setting{}
	err := db.Where("key = ?", key).First(s).Error
	if database.IsNotFound(err) {
		return ""
	}
	if err != nil {
		t.Fatalf("read setting %s: %v", key, err)
	}
	return s.Value
}

// A stock 3x-ui import must bring the operator's data across (superset schema +
// InitDB's adopt migrations) while keeping THIS panel reachable: its port and
// session secret must survive, but a data setting like the subscription title must
// come from the backup.
func TestImportForeignDBBringsDataAndPreservesPanelSettings(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("VPNUI_DB_FOLDER", tmp) // config.GetDBPath() -> tmp/vpn-ui.db; no legacy paths

	// A foreign backup: one inbound + client, plus settings that differ from this
	// panel (webPort/secret) and one that is pure data (subTitle).
	foreignPath := filepath.Join(tmp, "foreign.db")
	if err := database.InitDB(foreignPath); err != nil {
		t.Fatalf("init foreign: %v", err)
	}
	fdb := database.GetDB()
	fin := &model.Inbound{
		Tag: "imported-tag", Port: 55055, Protocol: model.VMESS, Enable: true,
		Settings: `{"clients":[{"id":"x","email":"imported-client","enable":true}]}`,
	}
	if err := fdb.Create(fin).Error; err != nil {
		t.Fatalf("seed foreign inbound: %v", err)
	}
	if err := fdb.Create(&xray.ClientTraffic{InboundId: fin.Id, Email: "imported-client", Enable: true}).Error; err != nil {
		t.Fatalf("seed foreign client: %v", err)
	}
	upsertSetting(t, fdb, "webPort", "2053")
	upsertSetting(t, fdb, "secret", "foreign-secret-should-not-survive")
	upsertSetting(t, fdb, "subTitle", "from-3xui")
	if err := database.Checkpoint(); err != nil { // flush WAL so the file copy is complete
		t.Fatalf("checkpoint foreign: %v", err)
	}
	if err := database.CloseDB(); err != nil {
		t.Fatalf("close foreign: %v", err)
	}

	// THIS panel, with distinctive reachability settings that must be kept.
	if err := database.InitDB(config.GetDBPath()); err != nil {
		t.Fatalf("init current: %v", err)
	}
	upsertSetting(t, database.GetDB(), "webPort", "8443")
	upsertSetting(t, database.GetDB(), "secret", "current-secret-keep-me")

	src, err := os.Open(foreignPath)
	if err != nil {
		t.Fatalf("open foreign: %v", err)
	}
	defer src.Close()

	var ss ServerService
	report, err := ss.ImportForeignDB(src, false)
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	db := database.GetDB()
	var inb int64
	db.Model(&model.Inbound{}).Where("tag = ?", "imported-tag").Count(&inb)
	if inb != 1 {
		t.Fatalf("imported inbound did not come across (found %d)", inb)
	}
	if got := getSetting(t, db, "webPort"); got != "8443" {
		t.Fatalf("panel webPort not preserved: got %q want 8443", got)
	}
	if got := getSetting(t, db, "secret"); got != "current-secret-keep-me" {
		t.Fatalf("panel secret not preserved: got %q", got)
	}
	if got := getSetting(t, db, "subTitle"); got != "from-3xui" {
		t.Fatalf("data setting subTitle did not come across: got %q", got)
	}
	if report == nil || report.Inbounds < 1 {
		t.Fatalf("report missing imported inbound: %+v", report)
	}
	found := false
	for _, k := range report.PreservedSettings {
		if k == "webPort" {
			found = true
		}
	}
	if !found {
		t.Fatalf("report should list webPort as preserved: %+v", report.PreservedSettings)
	}
}
