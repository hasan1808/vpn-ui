package service

import (
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// An account is one identity on SEVERAL inbounds and ONE client_traffics row, and
// that row names one inbound. Both client-access checks used to join through it, so
// they answered "is this admin granted the inbound that account's traffic row
// happens to point at" instead of "does this admin hold an inbound serving it".
//
// The admin holding the OTHER inbound was therefore denied every :email route for a
// client sitting on their own inbound, and dropped from every scoped payload: the
// account is on their page, and acting on it 404s.

// accessFixture is two admins holding one inbound each, and one account served on
// BOTH, whose single traffic row names only the first.
type accessFixture struct {
	first, second   *model.Inbound
	firstAdmin      *model.User
	secondAdmin     *model.User
	strangerAdmin   *model.User
	sharedAccount   string
	firstOnlyClient string
}

func newAccessFixture(t *testing.T) *accessFixture {
	t.Helper()
	newInboundDB(t)
	db := database.GetDB()
	var adminService AdminService

	f := &accessFixture{sharedAccount: "bob@example.com", firstOnlyClient: "alice@example.com"}
	f.first = seedMembershipInbound(t, 44001, model.VMESS, []map[string]any{
		{"id": "uuid-bob", "email": f.sharedAccount, "enable": false, "totalGB": 5 * gb},
		{"id": "uuid-alice", "email": f.firstOnlyClient, "enable": false, "totalGB": 5 * gb},
	})
	f.second = seedMembershipInbound(t, 44002, model.Trojan, []map[string]any{
		{"password": "pw-bob", "email": f.sharedAccount, "enable": false, "totalGB": 5 * gb},
	})
	// ONE traffic row for the account, naming the FIRST inbound. This is the shape
	// the accounts layer creates and the one both checks used to resolve through.
	for _, email := range []string{f.sharedAccount, f.firstOnlyClient} {
		if err := db.Create(&xray.ClientTraffic{
			InboundId: f.first.Id, Email: email, Enable: true,
		}).Error; err != nil {
			t.Fatalf("create traffic %s: %v", email, err)
		}
	}

	for i, spec := range []struct {
		name    string
		inbound *model.Inbound
	}{
		{"first-admin", f.first},
		{"second-admin", f.second},
		{"stranger-admin", nil},
	} {
		u := &model.User{Username: spec.name, Password: "x", Enable: true, Permissions: model.PermAccessInbounds}
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create %s: %v", spec.name, err)
		}
		if spec.inbound != nil {
			if err := adminService.GrantInbound(u.Id, spec.inbound.Id); err != nil {
				t.Fatalf("grant to %s: %v", spec.name, err)
			}
		}
		switch i {
		case 0:
			f.firstAdmin = u
		case 1:
			f.secondAdmin = u
		default:
			f.strangerAdmin = u
		}
	}
	return f
}

// The single check, which every :email route is gated on.
func TestCanAccessClientEmailFollowsEveryInboundServingTheClient(t *testing.T) {
	f := newAccessFixture(t)
	var s AdminService

	if ok, err := s.CanAccessClientEmail(f.sharedAccount, f.firstAdmin.Id); err != nil || !ok {
		t.Errorf("ok=%v err=%v; the admin of the inbound the traffic row names must still reach it", ok, err)
	}
	if ok, err := s.CanAccessClientEmail(f.sharedAccount, f.secondAdmin.Id); err != nil || !ok {
		t.Errorf("ok=%v err=%v; the account is served on this admin's own inbound, so every :email route for it must work",
			ok, err)
	}
	// The wall is still a wall: holding no inbound that serves it grants nothing.
	if ok, _ := s.CanAccessClientEmail(f.sharedAccount, f.strangerAdmin.Id); ok {
		t.Error("an admin holding no inbound that serves the account must not reach it")
	}
	// And an account on the first inbound only stays confined to its admin.
	if ok, _ := s.CanAccessClientEmail(f.firstOnlyClient, f.secondAdmin.Id); ok {
		t.Error("an account on somebody else's inbound must not be reachable")
	}
	// An email nothing serves is not an access question that can resolve to yes.
	if ok, _ := s.CanAccessClientEmail("nobody@example.com", f.firstAdmin.Id); ok {
		t.Error("an unknown email must fail closed")
	}
}

// The bulk producer and the single check answer the same question, so they must
// agree account by account and admin by admin. Disagreement is how a route ends up
// enforcing something the payload was never scoped for, in whichever direction.
func TestClientEmailAccessAgreesWithTheSingleCheck(t *testing.T) {
	f := newAccessFixture(t)
	var s AdminService

	access, err := s.ClientEmailAccess()
	if err != nil {
		t.Fatalf("ClientEmailAccess: %v", err)
	}
	for _, email := range []string{f.sharedAccount, f.firstOnlyClient} {
		for _, admin := range []*model.User{f.firstAdmin, f.secondAdmin, f.strangerAdmin} {
			want, err := s.CanAccessClientEmail(email, admin.Id)
			if err != nil {
				t.Fatalf("CanAccessClientEmail: %v", err)
			}
			if got := access[email][admin.Id]; got != want {
				t.Errorf("%s / admin %s: map says %v, the check says %v",
					email, admin.Username, got, want)
			}
		}
	}
	if !access[f.sharedAccount][f.secondAdmin.Id] {
		t.Error("the traffic broadcast and the online list still hide an account from the admin of the inbound serving it")
	}
}

// The map is indexed with whatever spelling the caller's payload carried: the
// traffic rows use one, an Xray stat name carries the settings' own. Identity is
// case-insensitive across the panel, so a map keyed on one spelling silently hid a
// client from its own admin.
func TestClientEmailAccessIsKeyedByEverySpelling(t *testing.T) {
	newInboundDB(t)
	db := database.GetDB()
	var s AdminService

	inbound := seedMembershipInbound(t, 44101, model.VMESS, []map[string]any{
		{"id": "uuid-mixed", "email": "Mixed-Case", "enable": false, "totalGB": 5 * gb},
	})
	if err := db.Create(&xray.ClientTraffic{
		InboundId: inbound.Id, Email: "mixed-case", Enable: true,
	}).Error; err != nil {
		t.Fatalf("create traffic: %v", err)
	}
	admin := &model.User{Username: "mixed-admin", Password: "x", Enable: true, Permissions: model.PermAccessInbounds}
	if err := db.Create(admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := s.GrantInbound(admin.Id, inbound.Id); err != nil {
		t.Fatalf("grant: %v", err)
	}

	access, err := s.ClientEmailAccess()
	if err != nil {
		t.Fatalf("ClientEmailAccess: %v", err)
	}
	for _, spelling := range []string{"Mixed-Case", "mixed-case"} {
		if !access[spelling][admin.Id] {
			t.Errorf("%q resolves to nothing; the caller cannot know which table its email came from", spelling)
		}
	}
}

// A membership recorded in the accounts tables counts as service too, so an admin is
// not locked out of an account during the window between the membership landing and
// the projection splicing its entry into settings.
func TestClientAccessFollowsAMembershipWithoutASettingsEntry(t *testing.T) {
	newInboundDB(t)
	db := database.GetDB()
	var s AdminService

	// The account is nowhere in this inbound's settings: only account_inbounds says
	// it belongs here.
	pending := seedMembershipInbound(t, 44201, model.VMESS, []map[string]any{
		{"id": "uuid-other", "email": "someone-else", "enable": false, "totalGB": gb},
	})
	account := &model.Account{Email: "bob@example.com", TotalGB: 5 * gb, Enable: true}
	if err := db.Create(account).Error; err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := db.Create(&model.AccountInbound{AccountId: account.Id, InboundId: pending.Id}).Error; err != nil {
		t.Fatalf("create membership: %v", err)
	}
	admin := &model.User{Username: "pending-admin", Password: "x", Enable: true, Permissions: model.PermAccessInbounds}
	if err := db.Create(admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := s.GrantInbound(admin.Id, pending.Id); err != nil {
		t.Fatalf("grant: %v", err)
	}

	if ok, err := s.CanAccessClientEmail("bob@example.com", admin.Id); err != nil || !ok {
		t.Errorf("ok=%v err=%v; a recorded membership on this admin's inbound is service", ok, err)
	}
	access, err := s.ClientEmailAccess()
	if err != nil {
		t.Fatalf("ClientEmailAccess: %v", err)
	}
	if !access["bob@example.com"][admin.Id] {
		t.Error("the two checks disagree about a membership-only account")
	}
}

// A membership or a traffic row that outlived its inbound must grant nothing: an
// inbound id is only evidence while there is an inbound behind it, and a dangling
// one would also read as "this account is still served somewhere", which is the
// answer that withholds a reseller's refund.
func TestServingInboundIdsIgnoresDeadInbounds(t *testing.T) {
	newInboundDB(t)
	db := database.GetDB()

	inbound := seedMembershipInbound(t, 44301, model.VMESS, []map[string]any{
		{"id": "uuid-ghost", "email": "ghost@example.com", "enable": false, "totalGB": gb},
	})
	account := &model.Account{Email: "ghost@example.com", TotalGB: gb, Enable: true}
	if err := db.Create(account).Error; err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := db.Create(&model.AccountInbound{AccountId: account.Id, InboundId: inbound.Id}).Error; err != nil {
		t.Fatalf("create membership: %v", err)
	}
	if err := db.Create(&xray.ClientTraffic{
		InboundId: inbound.Id, Email: "ghost@example.com", Enable: true,
	}).Error; err != nil {
		t.Fatalf("create traffic: %v", err)
	}

	ids, err := servingInboundIds(db, "ghost@example.com")
	if err != nil {
		t.Fatalf("servingInboundIds: %v", err)
	}
	if len(ids) != 1 || ids[0] != inbound.Id {
		t.Fatalf("ids = %v; want the one inbound really serving it", ids)
	}

	// Delete the inbound row alone, leaving the membership and the traffic row
	// pointing at nothing, which is exactly what a delete leaves behind today.
	if err := db.Where("id = ?", inbound.Id).Delete(&model.Inbound{}).Error; err != nil {
		t.Fatalf("delete inbound: %v", err)
	}
	ids, err = servingInboundIds(db, "ghost@example.com")
	if err != nil {
		t.Fatalf("servingInboundIds: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("ids = %v; rows naming a deleted inbound are not service, and reading them as service withholds refunds forever", ids)
	}
}
