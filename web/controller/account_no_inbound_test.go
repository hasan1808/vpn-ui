package controller

import (
	"encoding/json"
	"net/url"
	"strconv"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// An account on NO inbound, over the routes.
//
// The service can hold the state; these are about reaching it from outside, which is
// where the interesting problem was. Form encoding cannot distinguish an empty list
// from an absent one - Qs.stringify drops an empty array, so "I unticked everything"
// and "I said nothing about memberships" arrive as the same bytes - and those two
// mean opposite things: the second is every caller written before memberships
// existed, and reading its silence as "take this account off everything" would
// unprovision customers from requests that never mentioned the subject. Hence the
// separate noInbounds flag, and hence the first test here.
//
// The suite shares the bulk-membership harness (bulkMembershipPost, seedMembershipInbound,
// syncMembershipAccounts, inboundHolds): same package, same fixtures, one router.

// clientBody form-encodes a client write the way the Clients form posts it: the entry
// as a settings JSON string, the membership set as a repeated field, and the flag when
// the set is deliberately empty.
func clientBody(t *testing.T, inboundId int, entry map[string]any, inboundIds []int, noInbounds bool) string {
	t.Helper()
	settings, err := json.Marshal(map[string]any{"clients": []map[string]any{entry}})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	form := url.Values{}
	form.Set("id", strconv.Itoa(inboundId))
	form.Set("settings", string(settings))
	for _, id := range inboundIds {
		form.Add("inboundIds", strconv.Itoa(id))
	}
	if noInbounds {
		form.Set("noInbounds", "true")
	}
	return form.Encode()
}

func accountTraffic(t *testing.T, email string) *xray.ClientTraffic {
	t.Helper()
	row := &xray.ClientTraffic{}
	if err := database.GetDB().Where("email = ?", email).First(row).Error; err != nil {
		t.Fatalf("the client_traffics row for %s is gone: %v", email, err)
	}
	return row
}

func mustSucceed(t *testing.T, msg map[string]any, what string) {
	t.Helper()
	if ok, _ := msg["success"].(bool); !ok {
		t.Fatalf("%s was refused: %v", what, msg["msg"])
	}
}

// Unticking the last inbound on the ordinary edit route. The account is not deleted:
// it keeps its row, its credentials and the counter row carrying its usage history.
func TestUpdateClientCanUntickTheLastInbound(t *testing.T) {
	env := newBulkMembershipEnv(t)
	const email = "leaving@example.com"
	const uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	only := seedMembershipInbound(t, env.admin.Id, model.VLESS, 48801,
		`{"id":"`+uuid+`","email":"`+email+`","enable":true}`)
	syncMembershipAccounts(t)
	if err := database.GetDB().Create(&xray.ClientTraffic{
		InboundId: only.Id, Email: email, Enable: true, Up: 1024, Down: 2048, Total: 1 << 30,
	}).Error; err != nil {
		t.Fatalf("create client traffic: %v", err)
	}

	msg := bulkMembershipPost(t, env.admin, "/panel/api/inbounds/updateClient/"+uuid,
		clientBody(t, only.Id, map[string]any{
			"id": uuid, "email": email, "enable": true, "totalGB": float64(1 << 30),
			"comment": "parked until March",
		}, nil, true))
	mustSucceed(t, msg, "unticking the last inbound")

	if inboundHolds(t, only.Id, email) {
		t.Error("the account is still in the inbound's settings, so the data plane still serves it")
	}
	ids, err := accountService.InboundIdsForEmail(email)
	if err != nil || len(ids) != 0 {
		t.Errorf("memberships = %v (err %v), want none", ids, err)
	}
	account, err := accountService.GetAccountByEmail(email)
	if err != nil || account == nil {
		t.Fatalf("the account row was deleted (err %v)", err)
	}
	if account.UUID != uuid {
		t.Errorf("uuid = %q, want %q", account.UUID, uuid)
	}
	if account.Comment != "parked until March" {
		t.Errorf("comment = %q, want the one the same request set: the account-wide fields of "+
			"an edit have to reach the account row even when the edit empties it", account.Comment)
	}
	traffic := accountTraffic(t, email)
	if traffic.Up != 1024 || traffic.Down != 2048 {
		t.Errorf("usage = %d/%d, want 1024/2048", traffic.Up, traffic.Down)
	}
}

// The flag is the ONLY way to say it. An ordinary edit that names no memberships is
// the pre-existing single-inbound write and must keep behaving exactly as it did.
func TestAnAbsentMembershipListStillMeansLeaveThemAlone(t *testing.T) {
	env := newBulkMembershipEnv(t)
	const email = "quiet@example.com"
	const uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	first := seedMembershipInbound(t, env.admin.Id, model.VLESS, 48811,
		`{"id":"`+uuid+`","email":"`+email+`","enable":true}`)
	second := seedMembershipInbound(t, env.admin.Id, model.Trojan, 48812,
		`{"password":"pw-quiet","email":"`+email+`","enable":true}`)
	syncMembershipAccounts(t)

	msg := bulkMembershipPost(t, env.admin, "/panel/api/inbounds/updateClient/"+uuid,
		clientBody(t, first.Id, map[string]any{
			"id": uuid, "email": email, "enable": true, "comment": "edited",
		}, nil, false))
	mustSucceed(t, msg, "an edit that says nothing about memberships")

	for _, id := range []int{first.Id, second.Id} {
		if !inboundHolds(t, id, email) {
			t.Errorf("inbound %d lost the account: an edit that never mentioned memberships "+
				"unprovisioned it", id)
		}
	}

	// And the cleared-checkbox sentinel is not the flag either. A browser posts
	// inboundIds="" for a group with nothing ticked, and that has always meant "the
	// addressed inbound and no other" here; reading it as the deliberate empty set
	// would let a malformed or truncated request take an account off everything.
	form := url.Values{}
	form.Set("id", strconv.Itoa(first.Id))
	form.Set("settings", `{"clients":[{"id":"`+uuid+`","email":"`+email+`","enable":true}]}`)
	form.Add("inboundIds", "")
	msg = bulkMembershipPost(t, env.admin, "/panel/api/inbounds/updateClient/"+uuid, form.Encode())
	mustSucceed(t, msg, "an edit posting a cleared checkbox group")
	if !inboundHolds(t, first.Id, email) {
		t.Error("the empty sentinel emptied the account: it means the addressed inbound only")
	}
}

// Creating a client with no inbound at all. Nothing addresses the write, so it goes
// to the account route rather than /addClient, which has an inbound to splice into.
func TestSaveAccountCreatesAClientOnNoInbound(t *testing.T) {
	env := newBulkMembershipEnv(t)
	const email = "future@example.com"

	msg := bulkMembershipPost(t, env.admin, "/panel/api/inbounds/saveAccount",
		clientBody(t, 0, map[string]any{
			"email": email, "enable": true, "totalGB": float64(3 << 30),
			"uuid": "0e5cd5ff-4dd0-4e1a-9d94-0b0e1a1f2b3c", "password": "pw-future",
			"subId": "sub-future",
		}, nil, true))
	mustSucceed(t, msg, "creating a client on no inbound")

	account, err := accountService.GetAccountByEmail(email)
	if err != nil || account == nil {
		t.Fatalf("no account was created (err %v)", err)
	}
	if account.UUID != "0e5cd5ff-4dd0-4e1a-9d94-0b0e1a1f2b3c" || account.Password != "pw-future" {
		t.Errorf("credentials = %q / %q, want the posted pair", account.UUID, account.Password)
	}
	if traffic := accountTraffic(t, email); traffic.Total != 3<<30 {
		t.Errorf("quota = %d, want %d", traffic.Total, int64(3<<30))
	}

	// And it is on the page that lists accounts, which is the only place it can ever
	// be given an inbound.
	result, err := accountService.ListAccounts(env.admin, 1, 50, "", "")
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	found := false
	for _, row := range result.Rows {
		if row.Email == email {
			found = true
			if len(row.Memberships) != 0 {
				t.Errorf("memberships = %v, want none", row.Memberships)
			}
		}
	}
	if !found {
		t.Error("the account is not on the Clients list")
	}
}

// Attaching an inbound to an account that is already on nothing. It cannot go through
// /addClient - the email is taken, by the very account being attached - so the account
// route carries the membership set as well as the fields.
func TestSaveAccountAttachesAnInboundLater(t *testing.T) {
	env := newBulkMembershipEnv(t)
	const email = "returning@example.com"
	const uuid = "0e5cd5ff-4dd0-4e1a-9d94-0b0e1a1f2b3c"
	vless := seedMembershipInbound(t, env.admin.Id, model.VLESS, 48821, "")

	msg := bulkMembershipPost(t, env.admin, "/panel/api/inbounds/saveAccount",
		clientBody(t, 0, map[string]any{
			"email": email, "enable": true, "uuid": uuid,
		}, nil, true))
	mustSucceed(t, msg, "creating the parked account")

	msg = bulkMembershipPost(t, env.admin, "/panel/api/inbounds/saveAccount",
		clientBody(t, 0, map[string]any{
			"email": email, "enable": true, "uuid": uuid,
		}, []int{vless.Id}, false))
	mustSucceed(t, msg, "attaching an inbound")

	if !inboundHolds(t, vless.Id, email) {
		t.Fatal("the inbound does not carry the account after the attach")
	}
	var inbound model.Inbound
	if err := database.GetDB().Where("id = ?", vless.Id).First(&inbound).Error; err != nil {
		t.Fatalf("read inbound: %v", err)
	}
	var settings struct {
		Clients []map[string]any `json:"clients"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if len(settings.Clients) != 1 || settings.Clients[0]["id"] != uuid {
		t.Errorf("projected entry = %v, want the uuid the account was created with: a "+
			"re-minted one breaks every config the customer already installed", settings.Clients)
	}
}

// The Clients page has to be able to remove one of these again. Its per-inbound
// delete is addressed to an inbound, and this account has none.
func TestDelAccountRemovesAnAccountNothingServes(t *testing.T) {
	env := newBulkMembershipEnv(t)
	const email = "gone@example.com"
	msg := bulkMembershipPost(t, env.admin, "/panel/api/inbounds/saveAccount",
		clientBody(t, 0, map[string]any{"email": email, "enable": true}, nil, true))
	mustSucceed(t, msg, "creating the parked account")

	msg = bulkMembershipPost(t, env.admin,
		"/panel/api/inbounds/delAccount/"+url.PathEscape(email), "")
	mustSucceed(t, msg, "deleting an account nothing serves")

	if account, _ := accountService.GetAccountByEmail(email); account != nil {
		t.Error("the account row is still there")
	}
	var rows int64
	if err := database.GetDB().Model(&xray.ClientTraffic{}).
		Where("email = ?", email).Count(&rows).Error; err != nil {
		t.Fatalf("count client_traffics: %v", err)
	}
	if rows != 0 {
		t.Error("the counter row outlived the account it belonged to")
	}
}

// ...and refuses one that is still served, so a live account keeps exactly one
// destructive path: the inbound-addressed delete, which also takes the entry out of
// settings.clients, drops the IP bindings and pulls the user out of the core.
func TestDelAccountRefusesAServedAccount(t *testing.T) {
	env := newBulkMembershipEnv(t)
	const email = "served@example.com"
	only := seedMembershipInbound(t, env.admin.Id, model.VLESS, 48831,
		`{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"`+email+`","enable":true}`)
	syncMembershipAccounts(t)

	msg := bulkMembershipPost(t, env.admin,
		"/panel/api/inbounds/delAccount/"+url.PathEscape(email), "")
	if ok, _ := msg["success"].(bool); ok {
		t.Errorf("a served account was deleted through the account route: %v", msg)
	}
	if !inboundHolds(t, only.Id, email) {
		t.Error("the account left the inbound's settings anyway")
	}
	if account, _ := accountService.GetAccountByEmail(email); account == nil {
		t.Error("the account row was deleted anyway")
	}
}

// An ordinary admin cannot leave an account on nothing, because they would never see
// it again: their Clients list is the accounts with a membership on an inbound they
// hold, and this one has none. The refusal is what stops the save looking like a
// delete to the only person who could undo it.
func TestLeavingAnAccountUnservedIsSuperAdminOnly(t *testing.T) {
	f := newIdorFixture(t)
	syncMembershipAccounts(t)
	clients := readInboundClients(t, f.rezaInbound.Id)
	if len(clients) == 0 {
		t.Fatal("the fixture inbound has no client to edit")
	}
	identity, _ := clients[0]["id"].(string)

	msg := bulkMembershipPost(t, f.reza, "/panel/api/inbounds/updateClient/"+url.PathEscape(identity),
		clientBody(t, f.rezaInbound.Id, map[string]any{
			"id": identity, "email": "reza-client", "enable": true,
		}, nil, true))
	if ok, _ := msg["success"].(bool); ok {
		t.Errorf("an ordinary admin emptied an account: %v", msg)
	}
	if !inboundHolds(t, f.rezaInbound.Id, "reza-client") {
		t.Error("the account was taken off its last inbound anyway")
	}

	// The same rule on the account route, which is the create half.
	msg = bulkMembershipPost(t, f.reza, "/panel/api/inbounds/saveAccount",
		clientBody(t, 0, map[string]any{"email": "new-parked", "enable": true}, nil, true))
	if ok, _ := msg["success"].(bool); ok {
		t.Errorf("an ordinary admin created an account on no inbound: %v", msg)
	}
}

// readInboundClients returns an inbound's stored client entries as raw maps.
func readInboundClients(t *testing.T, inboundId int) []map[string]any {
	t.Helper()
	var inbound model.Inbound
	if err := database.GetDB().Where("id = ?", inboundId).First(&inbound).Error; err != nil {
		t.Fatalf("read inbound %d: %v", inboundId, err)
	}
	var settings struct {
		Clients []map[string]any `json:"clients"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		t.Fatalf("unmarshal settings of inbound %d: %v", inboundId, err)
	}
	return settings.Clients
}
