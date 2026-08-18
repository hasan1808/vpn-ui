package service

import (
	"errors"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// These cover the cascade-vs-keep delete added on top of the fixture in
// inbound_reseller_test.go. The one property they all turn on: the destructive
// path is never taken unless it is asked for by name.

// seedResellerProfile gives a fixture reseller the profile row DeleteReseller's
// manageable() check requires (a reseller with no profile reads as "not found").
func seedResellerProfile(t *testing.T, fx *resellerFixture) {
	t.Helper()
	if err := database.GetDB().Create(&model.ResellerProfile{
		UserId: fx.reseller.Id, CreatedBy: fx.admin.Id, AllowanceBytes: 1 << 40,
	}).Error; err != nil {
		t.Fatalf("seed reseller profile: %v", err)
	}
}

func resellerExists(t *testing.T, id int) bool {
	t.Helper()
	var n int64
	if err := database.GetDB().Model(&model.User{}).Where("id = ?", id).Count(&n).Error; err != nil {
		t.Fatalf("count reseller: %v", err)
	}
	return n > 0
}

func ownedRowCount(t *testing.T, resellerId int) int64 {
	t.Helper()
	var n int64
	if err := database.GetDB().Model(&model.ResellerClient{}).Where("user_id = ?", resellerId).Count(&n).Error; err != nil {
		t.Fatalf("count owned: %v", err)
	}
	return n
}

// Empty mode with accounts present refuses, so neither an old client nor a script
// can silently destroy or orphan a reseller's accounts.
func TestDeleteResellerEmptyModeRefusesWithAccounts(t *testing.T) {
	fx := newResellerFixture(t, "resellers-client")
	seedResellerProfile(t, fx)
	var svc ResellerService

	_, err := svc.DeleteReseller(&model.User{IsSuperAdmin: true}, fx.reseller.Id, "")
	if !errors.Is(err, ErrResellerHasClients) {
		t.Fatalf("want ErrResellerHasClients, got %v", err)
	}
	if !resellerExists(t, fx.reseller.Id) {
		t.Fatal("reseller was deleted despite the refusal")
	}
	if ownedRowCount(t, fx.reseller.Id) != 1 {
		t.Fatal("ownership row was touched despite the refusal")
	}
}

// Keep drops only the ownership ledger: the accounts stay byte-for-byte and become
// house-owned (absence of a ResellerClient row), while the reseller itself goes.
func TestDeleteResellerKeepReassignsAccountsToHouse(t *testing.T) {
	fx := newResellerFixture(t, "resellers-client")
	seedResellerProfile(t, fx)
	var svc ResellerService

	res, err := svc.DeleteReseller(&model.User{IsSuperAdmin: true}, fx.reseller.Id, DeleteModeKeep)
	if err != nil {
		t.Fatalf("keep delete: %v", err)
	}
	if res.Deleted != 0 || res.Kept != 0 || len(res.Protocols) != 0 {
		t.Fatalf("keep should touch no accounts, got %+v", res)
	}
	if resellerExists(t, fx.reseller.Id) {
		t.Fatal("reseller was not deleted")
	}
	if ownedRowCount(t, fx.reseller.Id) != 0 {
		t.Fatal("ownership rows survived a keep delete")
	}
	// Accounts kept: both clients still in settings, both traffic rows intact.
	inbound, err := fx.svc.GetInbound(fx.inbound.Id)
	if err != nil {
		t.Fatalf("reload inbound: %v", err)
	}
	if emails := clientEmailsIn(t, inbound.Settings); len(emails) != 2 {
		t.Fatalf("keep deleted a client from settings: %v", emails)
	}
	var stats int64
	database.GetDB().Model(&xray.ClientTraffic{}).Where("inbound_id = ?", fx.inbound.Id).Count(&stats)
	if stats != 2 {
		t.Fatalf("keep deleted client traffic rows, left %d", stats)
	}
	if _, err := svc.ProfileFor(fx.reseller.Id); err == nil {
		t.Fatal("reseller profile survived the delete")
	}
}

// A childless reseller deletes straight away, mode or no mode.
func TestDeleteResellerChildlessDeletesRegardlessOfMode(t *testing.T) {
	fx := newResellerFixture(t)
	seedResellerProfile(t, fx)
	var svc ResellerService

	res, err := svc.DeleteReseller(&model.User{IsSuperAdmin: true}, fx.reseller.Id, "")
	if err != nil {
		t.Fatalf("childless delete: %v", err)
	}
	if res.Deleted != 0 || res.Kept != 0 {
		t.Fatalf("childless delete touched accounts: %+v", res)
	}
	if resellerExists(t, fx.reseller.Id) {
		t.Fatal("reseller was not deleted")
	}
}

// Cascade deletes the reseller's account off a shared inbound but never the
// admin's own client sitting beside it.
func TestDeleteResellerCascadeDeletesOnlyTheResellersAccounts(t *testing.T) {
	fx := newResellerFixture(t)
	seedResellerProfile(t, fx)
	db := database.GetDB()

	// A shared inbound holding one admin client and one reseller client, with emails
	// stored consistently across settings and traffic the way a real create writes them.
	shared := &model.Inbound{
		UserId: fx.admin.Id, Tag: "inbound-41003", Port: 41003, Protocol: model.VMESS, Enable: true,
		Settings: `{"clients":[{"id":"a","email":"admin-x","enable":false},{"id":"r","email":"reseller-y","enable":false}]}`,
	}
	if err := db.Create(shared).Error; err != nil {
		t.Fatalf("create shared inbound: %v", err)
	}
	for _, e := range []string{"admin-x", "reseller-y"} {
		if err := db.Create(&xray.ClientTraffic{InboundId: shared.Id, Email: e, Enable: true}).Error; err != nil {
			t.Fatalf("create traffic %s: %v", e, err)
		}
	}
	if err := db.Create(&model.ResellerClient{
		Email: "reseller-y", InboundId: shared.Id, UserId: fx.reseller.Id, ChargedBytes: 1,
	}).Error; err != nil {
		t.Fatalf("own reseller client: %v", err)
	}

	var svc ResellerService
	res, err := svc.DeleteReseller(&model.User{IsSuperAdmin: true}, fx.reseller.Id, DeleteModeCascade)
	if err != nil {
		t.Fatalf("cascade delete: %v", err)
	}
	if res.Deleted != 1 || res.Kept != 0 {
		t.Fatalf("want 1 deleted 0 kept, got %+v", res)
	}
	if !res.Protocols[model.VMESS] {
		t.Fatalf("cascade did not record the touched protocol: %+v", res.Protocols)
	}
	if resellerExists(t, fx.reseller.Id) {
		t.Fatal("reseller was not deleted")
	}
	if ownedRowCount(t, fx.reseller.Id) != 0 {
		t.Fatal("ownership rows survived cascade")
	}
	reloaded, err := fx.svc.GetInbound(shared.Id)
	if err != nil {
		t.Fatalf("reload inbound: %v", err)
	}
	if emails := clientEmailsIn(t, reloaded.Settings); len(emails) != 1 || emails[0] != "admin-x" {
		t.Fatalf("cascade should leave only the admin's client, got %v", emails)
	}
}

// The last client on an admin's inbound is deleted like any other, and the inbound
// is left empty rather than handed a customer nobody is billed for. See
// TestCascadeRemovesAnAccountFromTheInboundItHoldsAlone for why the old refusal
// went: emptying an inbound is a legal state and the guard only stranded accounts.
func TestDeleteResellerCascadeRemovesTheLastClientAndKeepsTheInbound(t *testing.T) {
	fx := newResellerFixture(t)
	seedResellerProfile(t, fx)
	db := database.GetDB()

	solo := &model.Inbound{
		UserId: fx.admin.Id, Tag: "inbound-41002", Port: 41002, Protocol: model.VMESS, Enable: true,
		Settings: `{"clients":[{"id":"solo-uuid","email":"solo-client","enable":false}]}`,
	}
	if err := db.Create(solo).Error; err != nil {
		t.Fatalf("create solo inbound: %v", err)
	}
	if err := db.Create(&model.ResellerClient{
		Email: "solo-client", InboundId: solo.Id, UserId: fx.reseller.Id, ChargedBytes: 1,
	}).Error; err != nil {
		t.Fatalf("own solo client: %v", err)
	}

	var svc ResellerService
	res, err := svc.DeleteReseller(&model.User{IsSuperAdmin: true}, fx.reseller.Id, DeleteModeCascade)
	if err != nil {
		t.Fatalf("cascade delete: %v", err)
	}
	if res.Deleted != 1 || res.Kept != 0 {
		t.Fatalf("want 1 deleted 0 kept, got %+v", res)
	}
	// The inbound still exists (the admin owns it), and it is simply empty.
	reloaded, err := fx.svc.GetInbound(solo.Id)
	if err != nil {
		t.Fatalf("the admin's inbound went with its last client: %v", err)
	}
	if emails := clientEmailsIn(t, reloaded.Settings); len(emails) != 0 {
		t.Fatalf("the cascaded account still serves on the inbound: %v", emails)
	}
	if resellerExists(t, fx.reseller.Id) {
		t.Fatal("reseller was not deleted")
	}
	if ownedRowCount(t, fx.reseller.Id) != 0 {
		t.Fatal("ledger rows survived")
	}
}
