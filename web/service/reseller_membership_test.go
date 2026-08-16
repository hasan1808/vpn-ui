package service

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// One account is now one identity on SEVERAL inbounds, with one quota, one traffic
// row and one ledger row. The reseller ledger was written when that was impossible,
// so every one of these tests is a way the old shape leaks money or leaves an
// account running that nobody is billed for:
//
//	the account is deleted off one inbound of three and refunded in full;
//	the reseller is deleted and two of its three memberships keep serving;
//	an inbound is deleted and either everything or nothing is refunded, depending
//	on which of the account's inbounds the ledger row happened to name;
//	a bulk top-up is charged once and applied three times.
//
// The fixture is deliberately the awkward shape: the ledger row's home inbound is
// NOT the only one serving the account, because a ledger that reads that column as
// "the inbound" passes every test where it happens to be the only one.

// membershipFixture is one reseller-sold account on TWO inbounds, an admin's
// account beside it on each (so neither inbound is the last-client case), and the
// ledger row that says who owns it.
type membershipFixture struct {
	svc      *InboundService
	rs       *ResellerService
	admin    *model.User
	reseller *model.User
	// home is the inbound the ledger row names; away is the one it does not.
	home *model.Inbound
	away *model.Inbound
}

// seedMembershipInbound writes an inbound holding the sold account plus an admin's,
// both DISABLED for the reason newInboundDB documents: the delete paths push to a
// live Xray over gRPC for an enabled client, and there is none here.
//
// Written here rather than through seedInboundWithClients because that helper names
// the tag after the protocol, and every inbound in this file is the same protocol on
// purpose: what is being tested is one account on TWO of them.
func seedMembershipInbound(t *testing.T, port int, protocol model.Protocol, clients []map[string]any) *model.Inbound {
	t.Helper()
	settings, err := json.Marshal(map[string]any{"clients": clients})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		UserId: 1, Tag: fmt.Sprintf("inbound-%d", port), Port: port,
		Protocol: protocol, Enable: false, Settings: string(settings),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound on port %d: %v", port, err)
	}
	return inbound
}

// soldAndHouse is the two-client shape every inbound here holds: the reseller's
// account and an admin's beside it, so no inbound is ever the last-client case
// unless a test sets that up deliberately.
func soldAndHouse(sold string, soldTotal int64) []map[string]any {
	return []map[string]any{
		{"id": "uuid-" + sold, "password": "pw-" + sold, "email": sold,
			"enable": false, "totalGB": soldTotal},
		{"id": "uuid-house", "password": "pw-house", "email": "admins-client",
			"enable": false, "totalGB": 1 * gb},
	}
}

// newMembershipFixture builds the two-inbound shape. soldTotals are the quota the
// account carries on the home and away inbound; passing different ones is how the
// divergent-projection cases are set up.
func newMembershipFixture(t *testing.T, profile model.ResellerProfile, charged int64, soldTotals ...int64) *membershipFixture {
	t.Helper()
	svc := newInboundDB(t)
	db := database.GetDB()

	admin := &model.User{Username: "ms-admin", Password: "x", Enable: true, Permissions: model.PermAccessInbounds}
	reseller := &model.User{Username: "ms-reseller", Password: "x", Enable: true, IsReseller: true}
	for _, u := range []*model.User{admin, reseller} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create user %s: %v", u.Username, err)
		}
	}
	profile.UserId = reseller.Id
	profile.CreatedBy = admin.Id
	if err := db.Create(&profile).Error; err != nil {
		t.Fatalf("create reseller profile: %v", err)
	}

	homeTotal, awayTotal := int64(5*gb), int64(5*gb)
	if len(soldTotals) > 0 {
		homeTotal = soldTotals[0]
		awayTotal = soldTotals[0]
	}
	if len(soldTotals) > 1 {
		awayTotal = soldTotals[1]
	}
	home := seedMembershipInbound(t, 43001, model.VMESS, soldAndHouse("sold-one", homeTotal))
	away := seedMembershipInbound(t, 43002, model.VMESS, soldAndHouse("sold-one", awayTotal))

	// ONE traffic row for the account, naming the home inbound: that is the whole
	// point of the accounts layer, and it is what every "which inbound is this on"
	// query used to answer from.
	if err := db.Create(&xray.ClientTraffic{
		InboundId: home.Id, Email: "sold-one", Enable: true, Total: homeTotal,
	}).Error; err != nil {
		t.Fatalf("create client traffic: %v", err)
	}
	if err := db.Create(&model.ResellerClient{
		Email: "sold-one", InboundId: home.Id, UserId: reseller.Id, ChargedBytes: charged,
	}).Error; err != nil {
		t.Fatalf("create ledger row: %v", err)
	}
	// Both admin and reseller hold both inbounds: the grant is shared, so it is
	// never what separates them.
	var adminService AdminService
	for _, u := range []*model.User{admin, reseller} {
		for _, in := range []*model.Inbound{home, away} {
			if err := adminService.GrantInbound(u.Id, in.Id); err != nil {
				t.Fatalf("grant: %v", err)
			}
		}
	}
	return &membershipFixture{svc: svc, rs: &ResellerService{}, admin: admin, reseller: reseller, home: home, away: away}
}

func (f *membershipFixture) spent(t *testing.T) int64 {
	t.Helper()
	p := model.ResellerProfile{}
	if err := database.GetDB().Model(&model.ResellerProfile{}).
		Where("user_id = ?", f.reseller.Id).First(&p).Error; err != nil {
		t.Fatalf("read profile: %v", err)
	}
	return p.SpentBytes
}

// ledgerRow is the ownership row, or nil once the account has been forgotten.
func (f *membershipFixture) ledgerRow(t *testing.T) *model.ResellerClient {
	t.Helper()
	rc := model.ResellerClient{}
	err := database.GetDB().Model(&model.ResellerClient{}).
		Where("email = ?", "sold-one").First(&rc).Error
	if err != nil {
		return nil
	}
	return &rc
}

// quotaOn reads an account's quota out of ONE inbound's stored settings, which is
// what the data plane is generated from and therefore what the customer gets.
func quotaOn(t *testing.T, inboundId int, email string) (int64, bool) {
	t.Helper()
	var inbound model.Inbound
	if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", inboundId).
		First(&inbound).Error; err != nil {
		t.Fatalf("read inbound %d: %v", inboundId, err)
	}
	var root struct {
		Clients []struct {
			Email   string `json:"email"`
			TotalGB int64  `json:"totalGB"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &root); err != nil {
		t.Fatalf("settings of inbound %d are not readable JSON: %v", inboundId, err)
	}
	for _, c := range root.Clients {
		if sameEmail(c.Email, email) {
			return c.TotalGB, true
		}
	}
	return 0, false
}

func expiryOn(t *testing.T, inboundId int, email string) int64 {
	t.Helper()
	var inbound model.Inbound
	if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", inboundId).
		First(&inbound).Error; err != nil {
		t.Fatalf("read inbound %d: %v", inboundId, err)
	}
	var root struct {
		Clients []struct {
			Email      string `json:"email"`
			ExpiryTime int64  `json:"expiryTime"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &root); err != nil {
		t.Fatalf("settings of inbound %d are not readable JSON: %v", inboundId, err)
	}
	for _, c := range root.Clients {
		if sameEmail(c.Email, email) {
			return c.ExpiryTime
		}
	}
	t.Fatalf("account %s is not on inbound %d any more", email, inboundId)
	return 0
}

func trafficRow(t *testing.T, email string) *xray.ClientTraffic {
	t.Helper()
	ct := xray.ClientTraffic{}
	if err := database.GetDB().Model(&xray.ClientTraffic{}).
		Where("email = ?", email).First(&ct).Error; err != nil {
		return nil
	}
	return &ct
}

// --- 1. the home inbound -----------------------------------------------------------

// ResellerClient.InboundId is the inbound the account was FIRST sold on and nothing
// else. An edit posted against another of its inbounds moves the charge and leaves
// the home alone, because that column describes one membership of N and no decision
// may be taken from it.
func TestEditingAnAwayMembershipMovesTheChargeNotTheHome(t *testing.T) {
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 5 * gb}, 5*gb)

	// The panel's own shape for an edit: the whole client posted back against the
	// inbound it is being edited on, keyed by its identity in the URL.
	data := &model.Inbound{
		Id:       f.away.Id,
		Protocol: model.VMESS,
		Settings: `{"clients":[{"id":"uuid-sold-one","email":"sold-one","enable":true,"totalGB":8589934592}]}`,
	}
	ticket, err := f.rs.PrepareClientUpdate(f.reseller, data, "uuid-sold-one")
	if err != nil {
		t.Fatalf("PrepareClientUpdate on the away inbound: %v", err)
	}
	if ticket.Quote.DeltaSpent != 3*gb {
		t.Errorf("DeltaSpent = %d; want %d, the 5 to 8 GB top-up", ticket.Quote.DeltaSpent, 3*gb)
	}

	rc := f.ledgerRow(t)
	if rc == nil {
		t.Fatal("the ledger row vanished during an edit")
	}
	if rc.ChargedBytes != 8*gb {
		t.Errorf("ChargedBytes = %d; want %d", rc.ChargedBytes, 8*gb)
	}
	if rc.InboundId != f.home.Id {
		t.Errorf("InboundId = %d; want the home inbound %d. It records where the account was sold, not where it was last edited: one account is on N inbounds and this column can only name one of them",
			rc.InboundId, f.home.Id)
	}
	if got := f.spent(t); got != 8*gb {
		t.Errorf("SpentBytes = %d; want %d", got, 8*gb)
	}
}

// --- 2. the reseller delete cascade -------------------------------------------------

// Deleting a reseller with cascade must take its accounts off EVERY inbound serving
// them. Removing only the one the ledger row names left the rest live with no
// ownership row, and absence of a row means the house owns it: a working account,
// still passing traffic, that nobody is billed for and no page attributes.
func TestCascadeRemovesTheAccountFromEveryInbound(t *testing.T) {
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 10 * gb}, 10*gb)

	res, err := f.rs.DeleteReseller(&model.User{IsSuperAdmin: true}, f.reseller.Id, DeleteModeCascade)
	if err != nil {
		t.Fatalf("cascade delete: %v", err)
	}
	if res.Deleted != 1 || res.Kept != 0 {
		t.Fatalf("want 1 account deleted and 0 kept, got %+v", res)
	}
	for _, in := range []*model.Inbound{f.home, f.away} {
		if _, ok := quotaOn(t, in.Id, "sold-one"); ok {
			t.Errorf("the account still serves on inbound %d after the cascade: it is live and nobody is billed for it", in.Id)
		}
		// The admin's client on the same inbound is not the reseller's to destroy.
		if _, ok := quotaOn(t, in.Id, "admins-client"); !ok {
			t.Errorf("the admin's own client was deleted from inbound %d", in.Id)
		}
	}
	if f.ledgerRow(t) != nil {
		t.Error("the ledger row survived the cascade")
	}
}

// The one membership a cascade may not remove is the last client on an admin's
// inbound. The account survives there, so it is handed to the house rather than
// counted as deleted, and the rest of its memberships still go.
func TestCascadeKeepsAnAccountItCannotFullyRemove(t *testing.T) {
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 10 * gb}, 10*gb)
	// Make the away inbound hold the sold account alone, which may not be emptied.
	solo := seedMembershipInbound(t, 43003, model.VMESS, []map[string]any{
		{"id": "uuid-sold-one", "email": "sold-one", "enable": false, "totalGB": 10 * gb},
	})

	res, err := f.rs.DeleteReseller(&model.User{IsSuperAdmin: true}, f.reseller.Id, DeleteModeCascade)
	if err != nil {
		t.Fatalf("cascade delete: %v", err)
	}
	if res.Deleted != 0 || res.Kept != 1 {
		t.Fatalf("an account that survives anywhere is kept, not deleted: %+v", res)
	}
	if _, ok := quotaOn(t, solo.Id, "sold-one"); !ok {
		t.Error("the inbound whose last client this was got emptied under the admin")
	}
	for _, in := range []*model.Inbound{f.home, f.away} {
		if _, ok := quotaOn(t, in.Id, "sold-one"); ok {
			t.Errorf("the memberships that COULD go should still have gone, inbound %d kept it", in.Id)
		}
	}
	if f.ledgerRow(t) != nil {
		t.Error("the ledger row must go with the reseller: a charge against a deleted user can never be settled")
	}
}

// --- 3. refund on delete ------------------------------------------------------------

// Removing one membership of two is not a delete. Refunding there hands back the
// unused part of a quota the other membership is still selling, and dropping the
// ledger row makes that live account house-owned.
func TestRefundWaitsForTheLastMembership(t *testing.T) {
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 40 * gb}, 10*gb)

	// Consumption is captured before the first delete, as every delete path does:
	// the traffic row goes with it.
	used, known, err := f.rs.UsageOf("sold-one")
	if err != nil {
		t.Fatalf("UsageOf: %v", err)
	}
	if !known {
		t.Fatal("the account has a traffic row, so its usage must be readable")
	}

	if _, err := f.svc.DelInboundClientByEmail(f.home.Id, "sold-one"); err != nil {
		t.Fatalf("delete the first membership: %v", err)
	}
	if err := f.rs.RefundDeleted("sold-one", used, known); err != nil {
		t.Fatalf("RefundDeleted after the first membership: %v", err)
	}
	if got := f.spent(t); got != 40*gb {
		t.Errorf("SpentBytes = %d; want it unmoved at %d: the account is still served on the second inbound and still selling", got, 40*gb)
	}
	rc := f.ledgerRow(t)
	if rc == nil {
		t.Fatal("the ledger row was dropped while the account was still running: absence of a row means the HOUSE owns it, so the reseller stopped paying for a live account")
	}
	if rc.ChargedBytes != 10*gb {
		t.Errorf("ChargedBytes = %d; want the charge untouched at %d", rc.ChargedBytes, 10*gb)
	}

	// The last one going is the delete.
	if _, err := f.svc.DelInboundClientByEmail(f.away.Id, "sold-one"); err != nil {
		t.Fatalf("delete the last membership: %v", err)
	}
	if err := f.rs.RefundDeleted("sold-one", used, known); err != nil {
		t.Fatalf("RefundDeleted after the last membership: %v", err)
	}
	if got := f.spent(t); got != 30*gb {
		t.Errorf("SpentBytes = %d; want %d, the whole unused charge back once the account is really gone", got, 30*gb)
	}
	if f.ledgerRow(t) != nil {
		t.Error("the ledger row outlived the account it belonged to")
	}
}

// --- 4. deleting an inbound ---------------------------------------------------------

// Deleting one inbound of two removes a MEMBERSHIP. Nothing is refunded, the ledger
// row stays, and the home pointer follows the account to an inbound it is really on
// rather than naming a row that no longer exists.
func TestDropInboundRefundsNothingWhileTheAccountLivesElsewhere(t *testing.T) {
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 40 * gb}, 10*gb)

	// The controller's order: the roster and the usage while the inbound still has
	// both, then the delete, then the settlement.
	owned, err := f.rs.OwnedEmailsOnInbound(f.home.Id)
	if err != nil {
		t.Fatalf("OwnedEmailsOnInbound: %v", err)
	}
	if len(owned) != 1 || !sameEmail(owned[0], "sold-one") {
		t.Fatalf("owned = %v; want the one reseller account this inbound serves", owned)
	}
	usage, err := f.rs.UsageSnapshot(owned)
	if err != nil {
		t.Fatalf("UsageSnapshot: %v", err)
	}
	if _, err := f.svc.DelInbound(f.home.Id); err != nil {
		t.Fatalf("DelInbound: %v", err)
	}
	if err := f.rs.DropInbound(f.home.Id, owned, usage); err != nil {
		t.Fatalf("DropInbound: %v", err)
	}

	if got := f.spent(t); got != 40*gb {
		t.Errorf("SpentBytes = %d; want it unmoved at %d: the account is still sold and still running on the second inbound", got, 40*gb)
	}
	rc := f.ledgerRow(t)
	if rc == nil {
		t.Fatal("the ledger row went with an inbound the account merely happened to be on")
	}
	if rc.InboundId != f.away.Id {
		t.Errorf("InboundId = %d; want it repointed at the surviving inbound %d rather than left naming a deleted row", rc.InboundId, f.away.Id)
	}
}

// The other half, and the one the old WHERE inbound_id = ? got backwards: deleting
// the inbound the ledger row does NOT name is still the last membership going when
// it is the last one, and it refunds.
func TestDropInboundRefundsWhenTheLastMembershipGoes(t *testing.T) {
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 40 * gb}, 10*gb)

	// Empty the home inbound first, so the away inbound (which the ledger row does
	// not name) is the account's only membership.
	if _, err := f.svc.DelInboundClientByEmail(f.home.Id, "sold-one"); err != nil {
		t.Fatalf("delete the home membership: %v", err)
	}

	owned, err := f.rs.OwnedEmailsOnInbound(f.away.Id)
	if err != nil {
		t.Fatalf("OwnedEmailsOnInbound: %v", err)
	}
	if len(owned) != 1 {
		t.Fatalf("owned = %v; an account whose HOME is elsewhere is still served here, so it must be listed", owned)
	}
	// Its traffic row went with the first delete, so consumption is unknown and the
	// refund is withheld rather than invented. Prove the ledger row still goes.
	usage, err := f.rs.UsageSnapshot(owned)
	if err != nil {
		t.Fatalf("UsageSnapshot: %v", err)
	}
	if _, err := f.svc.DelInbound(f.away.Id); err != nil {
		t.Fatalf("DelInbound: %v", err)
	}
	if err := f.rs.DropInbound(f.away.Id, owned, usage); err != nil {
		t.Fatalf("DropInbound: %v", err)
	}
	if f.ledgerRow(t) != nil {
		t.Error("the account is served by nothing at all now, so its ledger row must go: a recycled email would inherit the charge")
	}
}

// --- 5. bulk write-back --------------------------------------------------------------

// Under days-per-GB the deadline is derived from the traffic and written back after
// the applier runs. It has to land on EVERY inbound serving the account: written
// through the traffic row's inbound alone, the account expires on one date on one
// inbound and another date on the rest.
func TestApplyBulkChargesReachesEveryMembership(t *testing.T) {
	profile := model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 10 * gb, DaysPerGB: 3}
	f := newMembershipFixture(t, profile, 5*gb)

	req := &BulkClientUpdateRequest{
		Op: "addTraffic", AmountBytes: gb,
		Targets: []BulkClientTarget{
			{InboundId: f.home.Id, Email: "sold-one"},
			{InboundId: f.away.Id, Email: "sold-one"},
		},
	}
	ticket, err := f.rs.PrepareBulk(f.reseller, req)
	if err != nil {
		t.Fatalf("PrepareBulk: %v", err)
	}
	if len(ticket.Charges) != 1 || !ticket.Charges[0].ForceExpiry {
		t.Fatalf("charges = %+v; want one carrying the derived deadline", ticket.Charges)
	}
	want := ticket.Charges[0].ExpiryTime

	if _, _, err := f.svc.BulkUpdateClients(*req); err != nil {
		t.Fatalf("BulkUpdateClients: %v", err)
	}
	if err := f.rs.ApplyBulkCharges(ticket); err != nil {
		t.Fatalf("ApplyBulkCharges: %v", err)
	}

	for _, in := range []*model.Inbound{f.home, f.away} {
		if got := expiryOn(t, in.Id, "sold-one"); got != want {
			t.Errorf("inbound %d expiry = %d; want the derived %d. One account has one deadline, whichever inbound serves it", in.Id, got, want)
		}
	}
	ct := trafficRow(t, "sold-one")
	if ct == nil {
		t.Fatal("the traffic row vanished")
	}
	if ct.ExpiryTime != want {
		t.Errorf("client_traffics expiry = %d; want %d: the enforcement table decides when the account dies", ct.ExpiryTime, want)
	}
}

// --- 6. one charge, one applied change ----------------------------------------------

// The pricer charges an account ONCE however many of its inbounds a batch names;
// the applier ran over the targets and moved each membership's own quota from its
// own starting point. So a top-up bought one gigabyte and handed out two, and which
// figure the enforcement table ended up with depended on map iteration order.
func TestBulkTopUpAppliesThePricedQuotaToEveryMembership(t *testing.T) {
	// Deliberately divergent starting quotas: identical ones hide the bug, because
	// both memberships then land on the same number by accident.
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 5 * gb}, 5*gb, 5*gb, 100*gb)

	req := &BulkClientUpdateRequest{
		Op: "addTraffic", AmountBytes: gb,
		Targets: []BulkClientTarget{
			{InboundId: f.home.Id, Email: "sold-one"},
			{InboundId: f.away.Id, Email: "sold-one"},
		},
	}
	ticket, err := f.rs.PrepareBulk(f.reseller, req)
	if err != nil {
		t.Fatalf("PrepareBulk: %v", err)
	}
	if ticket.DeltaSpent != gb {
		t.Fatalf("DeltaSpent = %d; want %d charged once for one account", ticket.DeltaSpent, int64(gb))
	}
	if _, _, err := f.svc.BulkUpdateClients(*req); err != nil {
		t.Fatalf("BulkUpdateClients: %v", err)
	}
	if err := f.rs.ApplyBulkCharges(ticket); err != nil {
		t.Fatalf("ApplyBulkCharges: %v", err)
	}

	for _, in := range []*model.Inbound{f.home, f.away} {
		got, ok := quotaOn(t, in.Id, "sold-one")
		if !ok {
			t.Fatalf("the account left inbound %d", in.Id)
		}
		if got != 6*gb {
			t.Errorf("inbound %d quota = %d; want the priced %d. One account has one quota, and it is the one the balance paid for", in.Id, got, 6*gb)
		}
	}
	ct := trafficRow(t, "sold-one")
	if ct == nil {
		t.Fatal("the traffic row vanished")
	}
	if ct.Total != 6*gb {
		t.Errorf("client_traffics total = %d; want the priced %d: this is the number the account is enforced against", ct.Total, 6*gb)
	}
	if got := f.spent(t); got != 6*gb {
		t.Errorf("SpentBytes = %d; want %d", got, 6*gb)
	}
}

// The same mismatch from the other side: the skip toggles are evaluated per
// membership by the applier and per ACCOUNT by the pricer, so an account skipped on
// one of its inbounds and live on another is the case where the two can drift.
// It must still be charged exactly once, and it must still end with ONE quota,
// because that is what its balance paid for.
func TestBulkChargesOnceWhenOneMembershipIsSkipped(t *testing.T) {
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 5 * gb}, 5*gb)
	// Disabled on the home inbound (the one priced first, lowest id) and live on the
	// away one, which is exactly the state a per-membership filter disagrees over.
	db := database.GetDB()
	if err := db.Model(&model.Inbound{}).Where("id = ?", f.away.Id).
		Update("settings", `{"clients":[{"id":"uuid-sold-one","email":"sold-one","enable":true,"totalGB":5368709120},{"id":"uuid-house","email":"admins-client","enable":true,"totalGB":1073741824}]}`).
		Error; err != nil {
		t.Fatalf("seed the away inbound: %v", err)
	}

	req := &BulkClientUpdateRequest{
		Op: "addTraffic", AmountBytes: 3 * gb, SkipDisabled: true,
		Targets: []BulkClientTarget{
			{InboundId: f.home.Id, Email: "sold-one"},
			{InboundId: f.away.Id, Email: "sold-one"},
		},
	}
	ticket, err := f.rs.PrepareBulk(f.reseller, req)
	if err != nil {
		t.Fatalf("PrepareBulk: %v", err)
	}
	if len(ticket.Charges) != 1 || ticket.DeltaSpent != 3*gb {
		t.Fatalf("ticket = %+v; want one charge of %d: two memberships of one account are one sale", ticket, 3*gb)
	}
	if _, _, err := f.svc.BulkUpdateClients(*req); err != nil {
		t.Fatalf("BulkUpdateClients: %v", err)
	}
	if err := f.rs.ApplyBulkCharges(ticket); err != nil {
		t.Fatalf("ApplyBulkCharges: %v", err)
	}
	for _, in := range []*model.Inbound{f.home, f.away} {
		got, ok := quotaOn(t, in.Id, "sold-one")
		if !ok {
			t.Fatalf("the account left inbound %d", in.Id)
		}
		if got != 8*gb {
			t.Errorf("inbound %d quota = %d; want the one priced quota %d on every membership", in.Id, got, 8*gb)
		}
	}
	if got := f.spent(t); got != 8*gb {
		t.Errorf("SpentBytes = %d; want %d: charged once, not once per membership", got, 8*gb)
	}
}

// The canonical membership a batch is priced from must not depend on map iteration
// order, or the same request quotes different numbers on different runs and the
// preview a reseller confirmed is not the batch they get.
func TestBulkPricesFromTheLowestInboundEveryTime(t *testing.T) {
	for i := 0; i < 8; i++ {
		f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 5 * gb}, 5*gb, 5*gb, 100*gb)
		req := &BulkClientUpdateRequest{
			Op: "subTraffic", AmountBytes: gb,
			Targets: []BulkClientTarget{
				{InboundId: f.away.Id, Email: "sold-one"},
				{InboundId: f.home.Id, Email: "sold-one"},
			},
		}
		ticket, err := f.rs.PrepareBulk(f.reseller, req)
		if err != nil {
			t.Fatalf("PrepareBulk: %v", err)
		}
		if len(ticket.Charges) != 1 {
			t.Fatalf("charges = %+v; want exactly one for one account", ticket.Charges)
		}
		// Priced off the home inbound's 5 GB, never the away inbound's 100 GB,
		// whichever order the targets arrived in.
		if got := ticket.Charges[0].NewTotal; got != 4*gb {
			t.Fatalf("run %d: NewTotal = %d; want %d, priced from the lowest inbound id", i, got, 4*gb)
		}
	}
}
