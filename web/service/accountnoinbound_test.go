package service

import (
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// An account may be served by NO inbound at all: created that way, or reduced to it
// by taking its last membership off.
//
// The state is deliberate and is not a delete, which is the whole reason it needed
// building rather than being left as a side effect. A delete takes the client_traffics
// row with it, and that row is the customer's quota, expiry and entire usage history;
// an account parked on nothing keeps all of it, plus the credentials already installed
// on the customer's devices, so putting them back on an inbound next month is one
// tick rather than a new account and a new profile to distribute.
//
// What these pin is therefore mostly survival: after the last membership goes, the
// accounts row, its credentials and its counter row are all still there, the account
// is still listed, and re-attaching reuses what it kept.

// noInboundAccount returns the account row, failing the test when it is gone. The
// prune is the thing most likely to eat it, and "not found" is the symptom.
func noInboundAccount(t *testing.T, svc *AccountService, email string) *model.Account {
	t.Helper()
	account, err := svc.GetAccountByEmail(email)
	if err != nil {
		t.Fatalf("GetAccountByEmail(%s): %v", email, err)
	}
	if account == nil {
		t.Fatalf("the account row for %s is gone", email)
	}
	return account
}

// listedEmails is what the Clients page would show a super admin.
func listedEmails(t *testing.T, svc *AccountService) []string {
	t.Helper()
	result, err := svc.ListAccounts(&model.User{Id: 1, IsSuperAdmin: true}, 1, 100, "", "", "", 0)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	out := make([]string, 0, len(result.Rows))
	for _, row := range result.Rows {
		out = append(out, row.Email)
	}
	return out
}

func listed(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// Removing the LAST membership. Everything a delete would have destroyed survives.
func TestRemovingTheLastMembershipKeepsTheAccount(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "parked@example.com"
	const uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	vless := seedInboundWithClients(t, model.VLESS, 47301, []map[string]any{
		{"id": uuid, "email": email, "enable": true, "totalGB": float64(5 << 30)},
	})
	svc.MigrationAccounts()
	seedAccountTraffic(t, email, vless.Id)
	if err := database.GetDB().Model(xray.ClientTraffic{}).Where("email = ?", email).
		Updates(map[string]any{"up": 4096, "down": 8192, "total": 5 << 30}).Error; err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	touched, err := svc.ApplyMemberships(email, nil, []int{vless.Id}, true)
	if err != nil {
		t.Fatalf("ApplyMemberships with an empty set: %v", err)
	}
	if len(touched) != 1 || touched[0] != vless.Id {
		t.Errorf("touched = %v, want just the inbound the account left: the reconcile "+
			"fan-out is what takes it out of the running config", touched)
	}

	// Off the inbound.
	if clients := readClients(t, vless.Id); len(clients) != 0 {
		t.Errorf("settings.clients = %v, want the account stripped from it", clients)
	}
	ids, err := svc.InboundIdsForEmail(email)
	if err != nil {
		t.Fatalf("InboundIdsForEmail: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("memberships = %v, want none", ids)
	}

	// And still an account.
	account := noInboundAccount(t, svc, email)
	if account.UUID != uuid {
		t.Errorf("uuid = %q, want %q: the credential the customer already has installed", account.UUID, uuid)
	}
	traffic := accountTrafficOf(t, email)
	if traffic.Up != 4096 || traffic.Down != 8192 || traffic.Total != 5<<30 {
		t.Errorf("client_traffics = up %d, down %d, quota %d; want 4096/8192 of %d: the row a "+
			"delete would have taken", traffic.Up, traffic.Down, traffic.Total, int64(5<<30))
	}
	if emails := listedEmails(t, svc); !listed(emails, email) {
		t.Errorf("the Clients list shows %v, want %s in it: an account nothing serves is "+
			"still an account, and it is the only place an inbound can be attached again", emails, email)
	}
}

// The protection the empty-set guard was actually giving. A caller that says nothing
// about memberships means "leave the set alone and re-project", never "take this
// account off everything" - that is the Telegram bot, any script posting one client,
// and every caller written before memberships existed.
func TestAnImplicitEmptySetLeavesTheMembershipsAlone(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "implicit@example.com"
	vless := seedInboundWithClients(t, model.VLESS, 47311, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": email, "enable": true},
	})
	svc.MigrationAccounts()

	if _, err := svc.ApplyMemberships(email, nil, []int{vless.Id}, false); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	ids, err := svc.InboundIdsForEmail(email)
	if err != nil {
		t.Fatalf("InboundIdsForEmail: %v", err)
	}
	if len(ids) != 1 || ids[0] != vless.Id {
		t.Errorf("memberships = %v, want the one it had: a request that never mentioned "+
			"memberships unprovisioned the customer", ids)
	}
	if !listed(listedEmails(t, svc), email) {
		t.Error("the account was pruned by a write that said nothing about memberships")
	}
}

// Created on nothing at all, with no inbound anywhere in the request. Both rows that
// make an account exist are written, or the first attach would have nothing to bill.
func TestAnAccountCanBeCreatedOnNoInbound(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "fresh@example.com"

	account, err := svc.SaveAccountWithoutInbound(map[string]any{
		"email": email, "enable": true, "totalGB": float64(2 << 30),
		"uuid": "0e5cd5ff-4dd0-4e1a-9d94-0b0e1a1f2b3c", "password": "pw-fresh",
		"subId": "sub-fresh", "comment": "kept for later",
	})
	if err != nil {
		t.Fatalf("SaveAccountWithoutInbound: %v", err)
	}
	if account.UUID != "0e5cd5ff-4dd0-4e1a-9d94-0b0e1a1f2b3c" || account.Password != "pw-fresh" {
		t.Errorf("credentials = %q / %q, want the posted ones: with no inbound addressed, "+
			"nothing else carries them", account.UUID, account.Password)
	}
	if account.SubID != "sub-fresh" || account.Comment != "kept for later" {
		t.Errorf("subId/comment = %q / %q, want the posted ones", account.SubID, account.Comment)
	}

	traffic := accountTrafficOf(t, email)
	if traffic.Total != 2<<30 || !traffic.Enable {
		t.Errorf("client_traffics = quota %d, enable %v; want %d and true: the quota lives in "+
			"this row, not on the account, for every path that enforces it",
			traffic.Total, traffic.Enable, int64(2<<30))
	}
	if traffic.InboundId != 0 {
		t.Errorf("client_traffics.inbound_id = %d, want 0: the column is the account's HOME "+
			"inbound and this one was created on none", traffic.InboundId)
	}
	if !listed(listedEmails(t, svc), email) {
		t.Error("an account created on no inbound is not on the Clients page, which is the " +
			"only place it could ever be given one")
	}
}

// The email is one panel-wide namespace, and a counter row with no account behind it
// means something outside this layer already holds it.
func TestCreatingOnNoInboundRefusesATakenEmail(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "taken@example.com"
	seedInboundWithClients(t, model.VLESS, 47321, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": email, "enable": true},
	})
	seedAccountTraffic(t, email, 1)

	if _, err := svc.SaveAccountWithoutInbound(map[string]any{"email": email, "enable": true}); err == nil {
		t.Error("an account was created over an email that already has a usage row")
	}
}

// Re-attaching. The point of keeping the account rather than deleting it: the
// customer's installed profile still works, because ensureCredentialsFor only ever
// FILLS a blank and the account is not blank.
func TestReattachingAnInboundKeepsTheCredentialsAndMintsOnlyWhatIsMissing(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "returning@example.com"
	const uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	vless := seedInboundWithClients(t, model.VLESS, 47331, []map[string]any{
		{"id": uuid, "email": email, "enable": true},
	})
	l2tp := seedInboundWithClients(t, model.L2TP, 47332, []map[string]any{})
	svc.MigrationAccounts()
	seedAccountTraffic(t, email, vless.Id)

	if _, err := svc.ApplyMemberships(email, nil, []int{vless.Id}, true); err != nil {
		t.Fatalf("emptying the account: %v", err)
	}

	// Back onto the inbound it came off, plus one of a protocol it has never been on.
	if _, err := svc.ApplyMembershipsFrom(email, 0, []int{vless.Id, l2tp.Id}, nil, true); err != nil {
		t.Fatalf("re-attaching: %v", err)
	}

	account := noInboundAccount(t, svc, email)
	if account.UUID != uuid {
		t.Errorf("uuid = %q, want the stored %q: a re-minted uuid stops every vless config "+
			"the customer already installed", account.UUID, uuid)
	}
	if account.VpnUsername == "" || account.Password == "" {
		t.Errorf("l2tp credentials = %q / %q, want both minted: a membership whose protocol "+
			"needs a login the account does not hold is one RADIUS can never authenticate",
			account.VpnUsername, account.Password)
	}

	// And the projection put it back where it belongs.
	vlessClients := readClients(t, vless.Id)
	if len(vlessClients) != 1 || vlessClients[0]["id"] != uuid {
		t.Errorf("vless settings = %v, want the account back with its own uuid", vlessClients)
	}
	l2tpClients := readClients(t, l2tp.Id)
	if len(l2tpClients) != 1 || l2tpClients[0]["id"] != account.VpnUsername {
		t.Errorf("l2tp settings = %v, want the account keyed on its login name", l2tpClients)
	}
	if traffic := accountTrafficOf(t, email); traffic.Email != email {
		t.Error("the counter row did not survive the round trip")
	}
}

// The IP slot is a column on the membership row, so deleting the row is what frees
// it - but the allocator reads the INBOUND's settings, not the membership table, so
// this is only true once the projection has taken the entry out of the blob too.
// Both halves happen inside ApplyMemberships; this checks the result rather than the
// mechanism, because the address another account is handed is what actually matters.
func TestEmptyingAnAccountReleasesItsIpSlot(t *testing.T) {
	svc := newAccountsDB(t)
	openvpn := seedInboundWithClients(t, model.OPENVPN, 47341, []map[string]any{
		{"id": "first-login", "password": "pw1", "email": "first@example.com", "enable": true, "slot": float64(0)},
		{"id": "second-login", "password": "pw2", "email": "second@example.com", "enable": true, "slot": float64(1)},
	})
	svc.MigrationAccounts()

	if slot := membershipUsageOf(t, "first@example.com", openvpn.Id).Slot; slot == nil || *slot != 0 {
		t.Fatalf("the first account starts on slot %v, want 0", slot)
	}

	if _, err := svc.ApplyMemberships("first@example.com", nil, []int{openvpn.Id}, true); err != nil {
		t.Fatalf("emptying the first account: %v", err)
	}
	var left int64
	if err := database.GetDB().Model(&model.AccountInbound{}).
		Where("inbound_id = ?", openvpn.Id).Count(&left).Error; err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if left != 1 {
		t.Errorf("memberships on the inbound = %d, want 1: the row holding the slot is still there", left)
	}

	// A third account joins and must be given the address the first one gave up,
	// rather than the next one after the highest ever used.
	third := &model.Account{Email: "third@example.com", Enable: true, VpnUsername: "third-login", Password: "pw3"}
	if err := database.GetDB().Create(third).Error; err != nil {
		t.Fatalf("create the third account: %v", err)
	}
	if _, err := svc.ApplyMembershipsFrom("third@example.com", 0, []int{openvpn.Id}, nil, true); err != nil {
		t.Fatalf("attaching the third account: %v", err)
	}
	slot := membershipUsageOf(t, "third@example.com", openvpn.Id).Slot
	if slot == nil || *slot != 0 {
		t.Errorf("the new account took slot %v, want 0: the freed slot was not reused, so the "+
			"pool leaks one address per account that is ever parked", slot)
	}
	if second := membershipUsageOf(t, "second@example.com", openvpn.Id).Slot; second == nil || *second != 1 {
		t.Errorf("the untouched account moved to slot %v, want 1: two accounts on one address", second)
	}
}

// The rule that survives all of this: two l2tp inbounds are still refused, and an
// empty set still passes it trivially, which is what lets an account be emptied
// without the check having an opinion about it.
func TestTheSameProtocolRuleIsUnchangedByTheEmptySet(t *testing.T) {
	svc := newAccountsDB(t)
	first := seedInboundWithClients(t, model.L2TP, 47351, []map[string]any{})
	// Not seedInboundWithClients: it names the tag after the protocol, and the tag is
	// unique, so a second l2tp inbound cannot be seeded through it.
	second := &model.Inbound{UserId: 1, Tag: "l2tp-second", Port: 47352,
		Protocol: model.L2TP, Enable: true, Settings: `{"clients":[]}`}
	if err := database.GetDB().Create(second).Error; err != nil {
		t.Fatalf("create the second l2tp inbound: %v", err)
	}
	vless := seedInboundWithClients(t, model.VLESS, 47353, []map[string]any{})

	if err := svc.ValidateMembershipSet(nil); err != nil {
		t.Errorf("an empty set was refused: %v", err)
	}
	if err := svc.ValidateMembershipSet([]*model.Inbound{first, vless}); err != nil {
		t.Errorf("one l2tp inbound was refused: %v", err)
	}
	if err := svc.ValidateMembershipSet([]*model.Inbound{first, second}); err == nil {
		t.Error("two l2tp inbounds were accepted: the account is served by whichever has the " +
			"lower id and the other half silently never runs")
	}
}

// A client DELETE still takes the account with it. The prune that used to fire on
// every sync is now scoped to the memberships the sync itself removed, and this is
// the population it was always meant to be about: an entry that vanished from
// settings.clients without anyone deciding the account should stay.
func TestASyncStillPrunesAnAccountWhoseEntryVanished(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "deleted@example.com"
	vless := seedInboundWithClients(t, model.VLESS, 47361, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": email, "enable": true},
	})
	const kept = "kept@example.com"
	trojan := seedInboundWithClients(t, model.Trojan, 47362, []map[string]any{
		{"password": "pw-kept", "email": kept, "enable": true},
	})
	svc.MigrationAccounts()

	// The delete paths rewrite settings and then re-sync; do exactly that.
	if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", vless.Id).
		Update("settings", `{"clients":[]}`).Error; err != nil {
		t.Fatalf("empty the inbound: %v", err)
	}
	if err := svc.SyncInboundAccounts(database.GetDB(), vless.Id); err != nil {
		t.Fatalf("SyncInboundAccounts: %v", err)
	}

	if account, _ := svc.GetAccountByEmail(email); account != nil {
		t.Error("an account whose only entry was deleted is still listed; nothing can reach it")
	}
	if account, _ := svc.GetAccountByEmail(kept); account == nil {
		t.Errorf("syncing inbound %d pruned an account on inbound %d", vless.Id, trojan.Id)
	}
}

// The other half of that scoping: an account deliberately left on nothing must
// survive every later sync of every OTHER inbound. The old sweep was panel-wide, so
// the next client write anywhere on the box would have deleted it.
func TestAnUnservedAccountSurvivesUnrelatedSyncs(t *testing.T) {
	svc := newAccountsDB(t)
	const parked = "parked@example.com"
	if _, err := svc.SaveAccountWithoutInbound(map[string]any{
		"email": parked, "enable": true, "uuid": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
	}); err != nil {
		t.Fatalf("SaveAccountWithoutInbound: %v", err)
	}
	other := seedInboundWithClients(t, model.VLESS, 47371, []map[string]any{
		{"id": "9c1e4b7a-2f3d-4c5e-8a6b-7d8e9f0a1b2c", "email": "busy@example.com", "enable": true},
	})

	for i := 0; i < 2; i++ {
		if err := svc.SyncInboundAccounts(database.GetDB(), other.Id); err != nil {
			t.Fatalf("SyncInboundAccounts: %v", err)
		}
	}

	if account, _ := svc.GetAccountByEmail(parked); account == nil {
		t.Error("a client write on an unrelated inbound deleted the parked account")
	}
	if _, err := database.GetDB().Model(xray.ClientTraffic{}).
		Where("email = ?", parked).Rows(); err != nil {
		t.Errorf("read the parked account's counter row: %v", err)
	}
}

// A parked account still OWNS its email.
//
// This is the hazard that parking creates. The duplicate-email check reads
// settings.clients, and a parked account has no entry in any of them, so without
// help the email reads as free. Creating a "new" client with it then walks into
// AddClientStat's orphan branch: it finds the parked account's client_traffics row,
// sees nothing serving the email, and zeroes up/down/all_time along with the quota
// and expiry - and upsertAccountFromEntry adopts the parked account itself. The
// customer's whole history disappears behind one Info log line.
//
// Reserving the email is the entire point of parking an account rather than deleting
// it, so this asserts the refusal AND that the refusal says where the email went:
// there is no inbound to name, and "already used by another client" with no holder
// sends the operator hunting through inbound lists for an entry that is not there.
func TestAParkedAccountKeepsItsEmailReserved(t *testing.T) {
	svc := newAccountsDB(t)
	openvpn := seedInboundWithClients(t, model.OPENVPN, 47391, []map[string]any{
		{"id": "parked-login", "password": "pw1", "email": "parked@example.com", "enable": true, "slot": float64(0)},
	})
	svc.MigrationAccounts()

	// Give it usage worth losing, so a regression here is unmistakable. Created
	// outright: seedInboundWithClients writes settings only, so there is no counter
	// row to update and an Updates() would silently match nothing.
	usage := &xray.ClientTraffic{
		InboundId: openvpn.Id, Email: "parked@example.com", Enable: true,
		Up: 111, Down: 222, AllTime: 333, Total: 4444,
	}
	if err := database.GetDB().Create(usage).Error; err != nil {
		t.Fatalf("seed usage: %v", err)
	}
	if _, err := svc.ApplyMemberships("parked@example.com", nil, []int{openvpn.Id}, true); err != nil {
		t.Fatalf("parking the account: %v", err)
	}

	var inboundSvc InboundService
	dupe, err := inboundSvc.checkEmailsExistForClients([]model.Client{{Email: "parked@example.com"}})
	if err != nil {
		t.Fatalf("duplicate check: %v", err)
	}
	if dupe != "parked@example.com" {
		t.Fatalf("the duplicate check let a parked account's email through (got %q): a new client "+
			"with it would reset that account's counters and adopt its row", dupe)
	}

	// The rejection has to be actionable. There is no inbound to point at, so the
	// generic "on inbound X" wording cannot apply.
	msg := duplicateEmailError("parked@example.com", inboundSvc.emailHolders("parked@example.com")...).Error()
	if !strings.Contains(msg, "not attached to any inbound") {
		t.Errorf("the rejection does not say where the email is:\n%s", msg)
	}
	if strings.Contains(msg, holderIsParkedAccount) {
		t.Errorf("the sentinel leaked into the message shown to the operator:\n%s", msg)
	}

	// And nothing was harmed by asking.
	var traffic xray.ClientTraffic
	if err := database.GetDB().Where("email = ?", "parked@example.com").First(&traffic).Error; err != nil {
		t.Fatalf("the counter row went missing: %v", err)
	}
	if traffic.Up != 111 || traffic.Down != 222 || traffic.Total != 4444 {
		t.Errorf("usage changed: up=%d down=%d total=%d", traffic.Up, traffic.Down, traffic.Total)
	}
}

// The other direction: an email nothing holds is still free, so the reservation above
// cannot be a blanket refusal that stops ordinary clients being created.
func TestAFreeEmailIsStillFreeAfterParkingSomeoneElse(t *testing.T) {
	svc := newAccountsDB(t)
	openvpn := seedInboundWithClients(t, model.OPENVPN, 47392, []map[string]any{
		{"id": "parked-login", "password": "pw1", "email": "parked@example.com", "enable": true, "slot": float64(0)},
	})
	svc.MigrationAccounts()
	if _, err := svc.ApplyMemberships("parked@example.com", nil, []int{openvpn.Id}, true); err != nil {
		t.Fatalf("parking the account: %v", err)
	}

	var inboundSvc InboundService
	dupe, err := inboundSvc.checkEmailsExistForClients([]model.Client{{Email: "somebody-else@example.com"}})
	if err != nil {
		t.Fatalf("duplicate check: %v", err)
	}
	if dupe != "" {
		t.Errorf("an unused email was refused as a duplicate: %q", dupe)
	}
}
