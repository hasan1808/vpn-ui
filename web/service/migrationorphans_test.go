package service

import (
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

func trafficEmails(t *testing.T) []string {
	t.Helper()
	var out []string
	if err := database.GetDB().Model(xray.ClientTraffic{}).Order("email ASC").Pluck("email", &out).Error; err != nil {
		t.Fatalf("read client_traffics: %v", err)
	}
	return out
}

// The GC's job: take out the counter rows nothing serves, which are what hold an
// email against a re-create, and leave every claimed row alone.
//
// Both of the ways it used to be wrong are pinned here. A settings entry with no
// email key put a NULL in the old NOT IN subquery and made the delete match nothing
// at all, and a row whose spelling differs from its settings entry only in case is a
// LIVE account that the old byte-exact comparison would have deleted.
func TestMigrationCleanupOrphansRemovesOnlyUnclaimedTrafficRows(t *testing.T) {
	svc := newInboundDB(t)
	seedTaggedInbound(t, model.VLESS, 48101, []map[string]any{
		testClient("claimed@example.com"),
		// Stored as "Bob@Example.com" while its row says "bob@example.com": one
		// account, two spellings, and deleting the row cuts off a paying customer.
		testClient("Bob@Example.com"),
		// No email key at all. This is the NULL that made the old NOT IN inert.
		{"id": "no-email-client", "enable": false},
	})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: 1, Email: "claimed@example.com", Total: 10 * gb, Enable: true})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: 1, Email: "bob@example.com", Total: 20 * gb, Enable: true})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: 1, Email: "ghost@example.com", Up: 5 * gb, Total: 1 * gb})

	svc.MigrationCleanupOrphans()

	got := trafficEmails(t)
	if len(got) != 2 {
		t.Fatalf("client_traffics = %v, want the two claimed rows", got)
	}
	if trafficRow(t, "ghost@example.com") != nil {
		t.Error("the orphan row survived, so the email it holds is still refused on a re-create")
	}
	if row := trafficRow(t, "bob@example.com"); row == nil {
		t.Error("a live account whose settings entry differs only in case was deleted")
	} else if row.Total != 20*gb {
		t.Errorf("total = %d, want it untouched", row.Total)
	}
}

// Case-split entries are REPORTED, never repaired. Both spellings are live accounts
// and picking one moves a customer's quota, so the pass must leave the settings
// exactly as it found them.
func TestMigrationCleanupOrphansNeverTouchesDuplicateIdentities(t *testing.T) {
	svc := newInboundDB(t)
	first := seedTaggedInbound(t, model.VLESS, 48102, []map[string]any{testClient("Split@example.com")})
	second := seedTaggedInbound(t, model.VLESS, 48103, []map[string]any{testClient("split@example.com")})
	// And the same identity twice inside ONE inbound.
	third := seedTaggedInbound(t, model.VLESS, 48104, []map[string]any{
		testClient("twice@example.com"),
		testClient("TWICE@example.com"),
	})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: first.Id, Email: "Split@example.com", Enable: true})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: third.Id, Email: "twice@example.com", Enable: true})

	before := map[int][]map[string]any{
		first.Id:  readClients(t, first.Id),
		second.Id: readClients(t, second.Id),
		third.Id:  readClients(t, third.Id),
	}

	svc.MigrationCleanupOrphans()

	for id, want := range before {
		got := readClients(t, id)
		if len(got) != len(want) {
			t.Errorf("inbound %d has %d client(s) after the pass, had %d", id, len(got), len(want))
			continue
		}
		for i := range want {
			if got[i]["email"] != want[i]["email"] {
				t.Errorf("inbound %d client %d changed from %v to %v", id, i, want[i]["email"], got[i]["email"])
			}
		}
	}
	// The "split" row is claimed by both spellings and must survive; so must the
	// one for the doubled entry.
	if trafficRow(t, "Split@example.com") == nil {
		t.Error("a live case-split account lost its traffic row")
	}
	if trafficRow(t, "twice@example.com") == nil {
		t.Error("an account listed twice in one inbound lost its traffic row")
	}
}

// A membership whose inbound is gone, and the account it leaves behind serving
// nothing, both hold the email against a re-create. Only they go.
func TestMigrationCleanupOrphansPrunesDeadMemberships(t *testing.T) {
	svc := newInboundDB(t)
	live := seedTaggedInbound(t, model.VLESS, 48105, []map[string]any{testClient("live@example.com")})

	liveAccount := model.Account{Email: "live@example.com", Enable: true}
	if err := database.GetDB().Create(&liveAccount).Error; err != nil {
		t.Fatalf("seed live account: %v", err)
	}
	deadAccount := model.Account{Email: "stranded@example.com", Enable: true}
	if err := database.GetDB().Create(&deadAccount).Error; err != nil {
		t.Fatalf("seed stranded account: %v", err)
	}
	db := database.GetDB()
	if err := db.Create(&model.AccountInbound{AccountId: liveAccount.Id, InboundId: live.Id}).Error; err != nil {
		t.Fatalf("seed live membership: %v", err)
	}
	// 9999 is an inbound that no longer exists, which is what a deleted inbound
	// leaves behind: nothing prunes account_inbounds when its inbound goes.
	if err := db.Create(&model.AccountInbound{AccountId: deadAccount.Id, InboundId: 9999}).Error; err != nil {
		t.Fatalf("seed dead membership: %v", err)
	}

	svc.MigrationCleanupOrphans()

	var memberships []model.AccountInbound
	if err := db.Find(&memberships).Error; err != nil {
		t.Fatalf("read memberships: %v", err)
	}
	if len(memberships) != 1 || memberships[0].InboundId != live.Id {
		t.Fatalf("memberships = %#v, want only the live one", memberships)
	}
	var accounts []model.Account
	if err := db.Order("email ASC").Find(&accounts).Error; err != nil {
		t.Fatalf("read accounts: %v", err)
	}
	if len(accounts) != 1 || accounts[0].Email != "live@example.com" {
		t.Fatalf("accounts = %#v, want only the live one", accounts)
	}
}

// It runs once and is safe to run again: the flag stops the second pass, and the
// operations themselves change nothing when repeated.
func TestMigrationCleanupOrphansIsIdempotent(t *testing.T) {
	svc := newInboundDB(t)
	inbound := seedTaggedInbound(t, model.VLESS, 48106, []map[string]any{testClient("kept@example.com")})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: inbound.Id, Email: "kept@example.com", Total: 7 * gb, Enable: true})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: inbound.Id, Email: "ghost@example.com"})

	svc.MigrationCleanupOrphans()
	first := trafficEmails(t)

	var settingService SettingService
	setting, err := settingService.getSetting(orphanCleanupMigratedKey)
	if err != nil || setting == nil || setting.Value == "" {
		t.Fatalf("the migrated flag was not set: %v", err)
	}

	// A fresh orphan appearing afterwards is NOT swept, which is the point of the
	// flag: this is a one-time repair of records the old delete paths left behind,
	// not a sweeper that runs behind the panel forever.
	seedTrafficRow(t, xray.ClientTraffic{InboundId: inbound.Id, Email: "later@example.com"})
	svc.MigrationCleanupOrphans()

	second := trafficEmails(t)
	if len(second) != len(first)+1 {
		t.Fatalf("second pass changed the rows: %v then %v", first, second)
	}
	if row := trafficRow(t, "kept@example.com"); row == nil || row.Total != 7*gb {
		t.Errorf("the live row did not survive two passes: %#v", row)
	}
}
