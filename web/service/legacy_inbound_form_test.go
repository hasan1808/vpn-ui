package service

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/util/reflect_util"
	"github.com/hasan1808/pro-ui/web/entity"
)

// The panel-wide switch behind the old inbound dialog. Two things about it can
// break silently, and both are here.

// TestLegacyInboundFormDefaultsOffAndRoundTrips covers the first: a key that is
// missing from defaultValueMap does not read as "unset", it reads as an ERROR
// (getString says so), and the inbounds page turns any error into "serve the
// current form". The setting would then be unwritable in practice - saved, and
// never once believed.
func TestLegacyInboundFormDefaultsOffAndRoundTrips(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	s := &SettingService{}

	on, err := s.GetLegacyInboundForm()
	if err != nil {
		t.Fatalf("reading with nothing stored must fall back to the default, got: %v", err)
	}
	if on {
		t.Fatal("a fresh panel must serve the current inbound form")
	}

	for _, want := range []bool{true, false} {
		if err := s.SetLegacyInboundForm(want); err != nil {
			t.Fatalf("SetLegacyInboundForm(%v): %v", want, err)
		}
		got, err := s.GetLegacyInboundForm()
		if err != nil {
			t.Fatalf("GetLegacyInboundForm after setting %v: %v", want, err)
		}
		if got != want {
			t.Fatalf("stored %v, read back %v", want, got)
		}
	}
}

// TestLegacyInboundFormSurvivesAnUnrelatedSettingsSave covers the second: the
// Settings page binds and writes entity.AllSetting WHOLE, so any key that gained
// a field there would be written back as false by the next unrelated save - an
// admin changing the Telegram token would put every operator back on the new
// dialog with no idea why. It is kept out of AllSetting for that reason, and this
// is what holds it there.
func TestLegacyInboundFormSurvivesAnUnrelatedSettingsSave(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	s := &SettingService{}
	if err := s.SetLegacyInboundForm(true); err != nil {
		t.Fatalf("SetLegacyInboundForm: %v", err)
	}

	// What the Settings form posts when the operator changed something else. Read
	// the stored blob first so the save is realistic rather than a wipe.
	all, err := s.GetAllSetting()
	if err != nil {
		t.Fatalf("GetAllSetting: %v", err)
	}
	all.TgBotToken = "token-set-by-some-other-admin"
	if err := s.UpdateAllSetting(all); err != nil {
		t.Fatalf("UpdateAllSetting: %v", err)
	}

	on, err := s.GetLegacyInboundForm()
	if err != nil {
		t.Fatalf("GetLegacyInboundForm: %v", err)
	}
	if !on {
		t.Fatal("an unrelated Settings save turned the old inbound dialog back off; the key has been added to entity.AllSetting")
	}

	// Same claim, stated directly, so the failure names the cause rather than the
	// symptom if the two ever disagree.
	for _, f := range reflect_util.GetFields(reflect.TypeFor[entity.AllSetting]()) {
		if f.Tag.Get("json") == "legacyInboundForm" {
			t.Errorf("entity.AllSetting.%s carries the legacyInboundForm key; AllSetting is written wholesale from the Settings form, so unrelated saves will clear it", f.Name)
		}
	}
}
