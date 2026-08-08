package service

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// One account, several inbounds, one quota. These pin the feature working, which
// is also what makes the IDOR cases in web/controller meaningful: if inboundIds
// were ignored outright those would pass vacuously.

// The headline: an account added on one inbound and given a membership on a
// second appears on BOTH, with the credential each protocol keys on.
func TestApplyMembershipsSpreadsAccountAcrossProtocols(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46101, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true, "totalGB": float64(100)},
	})
	l2tp := seedInboundWithClients(t, model.L2TP, 46102, []map[string]any{})
	svc.MigrationAccounts()

	// Give the account the l2tp credential fields it will need there.
	account, err := svc.GetAccountByEmail("bob@example.com")
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	account.VpnUsername = "bob-login"
	account.Password = "bob-pw"
	if err := database.GetDB().Save(account).Error; err != nil {
		t.Fatalf("save account: %v", err)
	}

	touched, err := svc.ApplyMemberships("bob@example.com", []int{vless.Id, l2tp.Id}, nil, true, 0)
	if err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}
	if len(touched) == 0 {
		t.Fatal("no inbound was reported as changed")
	}

	l2tpClients := readClients(t, l2tp.Id)
	if len(l2tpClients) != 1 {
		t.Fatalf("l2tp has %d clients, want 1", len(l2tpClients))
	}
	if got, _ := l2tpClients[0]["email"].(string); got != "bob@example.com" {
		t.Errorf("l2tp client email = %q", got)
	}
	if got, _ := l2tpClients[0]["id"].(string); got != "bob-login" {
		t.Errorf("l2tp id = %q, want the vpn username: without it RADIUS has nothing to authenticate", got)
	}
	if got, _ := l2tpClients[0]["password"].(string); got != "bob-pw" {
		t.Errorf("l2tp password = %q", got)
	}
	// The quota is the ACCOUNT's, carried onto the new membership.
	if got, _ := l2tpClients[0]["totalGB"].(float64); got != 100 {
		t.Errorf("l2tp totalGB = %v, want the account's 100", got)
	}
	// A pool protocol must get an explicit slot, or its tunnel address is decided
	// by list position.
	if _, ok := l2tpClients[0]["slot"]; !ok {
		t.Error("the new l2tp membership has no explicit slot")
	}

	// And the vless side keeps its own credential, untouched.
	vlessClients := readClients(t, vless.Id)
	if got, _ := vlessClients[0]["id"].(string); got != "3fa85f64-5717-4562-b3fc-2c963f66afa6" {
		t.Errorf("vless uuid changed to %q", got)
	}

	if got := len(accountsInDB(t)); got != 1 {
		t.Errorf("accounts = %d, want 1: this is ONE account on two inbounds", got)
	}
	if got := len(membershipsInDB(t)); got != 2 {
		t.Errorf("memberships = %d, want 2", got)
	}
}

// Unticking an inbound removes the account from it. A membership left behind is
// a working account nobody is billed for.
func TestApplyMembershipsRemovesDroppedInbound(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46201, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	trojan := seedInboundWithClients(t, model.Trojan, 46202, []map[string]any{
		{"password": "pw", "email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()
	if got := len(membershipsInDB(t)); got != 2 {
		t.Fatalf("setup: memberships = %d, want 2", got)
	}

	if _, err := svc.ApplyMemberships("bob@example.com", []int{vless.Id}, []int{trojan.Id}, true, 0); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	if got := len(readClients(t, trojan.Id)); got != 0 {
		t.Errorf("the dropped inbound still carries %d clients: a live account nobody is billed for", got)
	}
	if got := len(readClients(t, vless.Id)); got != 1 {
		t.Errorf("the kept inbound has %d clients, want 1", got)
	}
	if got := len(membershipsInDB(t)); got != 1 {
		t.Errorf("memberships = %d, want 1", got)
	}
}

// Removing is authorized by owning the inbound being removed FROM, which is a
// different set from the one being added to. An admin who edits a shared account
// without ticking an inbound they cannot even see must leave it alone: silently
// unprovisioning it would be an IDOR in the removal direction.
func TestApplyMembershipsKeepsMembershipsTheCallerCannotRemove(t *testing.T) {
	svc := newAccountsDB(t)
	mine := seedInboundWithClients(t, model.VLESS, 46601, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	theirs := seedInboundWithClients(t, model.Trojan, 46602, []map[string]any{
		{"password": "pw", "email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()

	// The caller asks for only their own inbound, and is allowed to remove nothing.
	if _, err := svc.ApplyMemberships("bob@example.com", []int{mine.Id}, nil, true, 0); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	if got := len(readClients(t, theirs.Id)); got != 1 {
		t.Errorf("the account was removed from an inbound the caller may not touch (%d clients left)", got)
	}
	if got := len(membershipsInDB(t)); got != 2 {
		t.Errorf("memberships = %d, want 2: the unowned one must survive", got)
	}
}

// mergeKeepSet is the rule itself, tested directly.
func TestMergeKeepSet(t *testing.T) {
	cases := []struct {
		name                       string
		wanted, current, removable []int
		want                       []int
	}{
		{"adds what was asked for", []int{1, 2}, []int{1}, []int{}, []int{1, 2}},
		{"drops only what may be dropped", []int{1}, []int{1, 2}, []int{2}, []int{1}},
		{"keeps what may not be dropped", []int{1}, []int{1, 2}, []int{}, []int{1, 2}},
		{"mixed", []int{1, 3}, []int{1, 2, 4}, []int{2}, []int{1, 3, 4}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeKeepSet(tc.wanted, tc.current, tc.removable)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// A single-inbound request must not change the membership SET. That is what
// protects every existing caller (the Telegram bot, bulk ops, external scripts) on
// upgrade: they name one inbound and mean one inbound, and an account they have
// never heard of must not be taken off the others.
//
// It does NOT mean the request is inert. See
// TestSingleInboundWriteReprojectsEveryMembership for the half that has to happen.
func TestApplyMembershipsSingleInboundKeepsTheMembershipSet(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46301, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	trojan := seedInboundWithClients(t, model.Trojan, 46302, []map[string]any{
		{"password": "pw-bob", "email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()
	before := len(membershipsInDB(t))

	if _, err := svc.ApplyMemberships("bob@example.com", []int{vless.Id}, nil, false, 0); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	after := membershipsInDB(t)
	if len(after) != before {
		t.Fatalf("a single-inbound write changed the membership count: %d -> %d", before, len(after))
	}
	on := map[int]bool{}
	for _, m := range after {
		on[m.InboundId] = true
	}
	if !on[vless.Id] || !on[trojan.Id] {
		t.Errorf("a single-inbound write dropped a membership: still on %v, want both %d and %d",
			on, vless.Id, trojan.Id)
	}
}

// The other half, and the bug this closes: a write naming ONE inbound already
// changes the SHARED account row (the mirror lifts the edited entry into it), so it
// has to be pushed back out to every membership. Returning before the projection
// left the account row saying one thing and 17 of an account's 18 inbounds saying
// another, with every enforcement path reading the stale per-inbound copies.
func TestSingleInboundWriteReprojectsEveryMembership(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46311, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com",
			"enable": true, "totalGB": 0},
	})
	trojan := seedInboundWithClients(t, model.Trojan, 46312, []map[string]any{
		{"password": "pw-bob", "email": "bob@example.com", "enable": true, "totalGB": 0},
	})
	svc.MigrationAccounts()

	// The legacy shape: rewrite ONE inbound's entry with a new quota and a disable,
	// then run the single-inbound path over it exactly as the controller does.
	writeClients(t, vless.Id, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com",
			"enable": false, "totalGB": 5368709120},
	})
	if _, err := svc.ApplyMemberships("bob@example.com", []int{vless.Id}, nil, false, 0); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	for _, id := range []int{vless.Id, trojan.Id} {
		entry := clientEntry(t, id, "bob@example.com")
		if entry == nil {
			t.Fatalf("inbound %d lost the account entirely", id)
		}
		if entry["enable"] != false {
			t.Errorf("inbound %d reads enable=%v, want false: the account row was "+
				"disabled and this membership was left serving", id, entry["enable"])
		}
		if got, _ := entry["totalGB"].(float64); int64(got) != 5368709120 {
			t.Errorf("inbound %d reads totalGB=%v, want the account's 5368709120", id, entry["totalGB"])
		}
	}
}

// The per-inbound switch has to be per-inbound. Its own flag, ANDed with the
// account's, so one membership goes dark and the rest keep serving.
func TestMembershipEnableIsPerInbound(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46321, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	trojan := seedInboundWithClients(t, model.Trojan, 46322, []map[string]any{
		{"password": "pw-bob", "email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()

	if _, err := svc.SetMembershipEnable("bob@example.com", vless.Id, false); err != nil {
		t.Fatalf("SetMembershipEnable: %v", err)
	}

	if got := clientEntry(t, vless.Id, "bob@example.com")["enable"]; got != false {
		t.Errorf("the switched-off membership reads enable=%v, want false", got)
	}
	if got := clientEntry(t, trojan.Id, "bob@example.com")["enable"]; got != true {
		t.Errorf("the OTHER membership reads enable=%v, want true: switching one inbound "+
			"off must leave the rest serving", got)
	}
	// And the account itself is untouched, which is what stops client_traffics (and
	// so RADIUS and the rbridge sweep) from cutting the customer off panel-wide.
	accounts := accountsInDB(t)
	if len(accounts) != 1 || !accounts[0].Enable {
		t.Errorf("account enable = %v, want true: a per-inbound switch must not "+
			"lower the account-wide flag", accounts)
	}

	// Switching it back on restores that membership and nothing else.
	if _, err := svc.SetMembershipEnable("bob@example.com", vless.Id, true); err != nil {
		t.Fatalf("SetMembershipEnable back on: %v", err)
	}
	if got := clientEntry(t, vless.Id, "bob@example.com")["enable"]; got != true {
		t.Errorf("re-enabled membership reads enable=%v, want true", got)
	}
}

// A disabled membership renders enable:false into that inbound's settings. The
// mirror must not read that back as an account-wide disable, or the next write
// touching that inbound would take every other membership down with it.
func TestDisabledMembershipDoesNotLowerTheAccount(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46331, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	trojan := seedInboundWithClients(t, model.Trojan, 46332, []map[string]any{
		{"password": "pw-bob", "email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()
	if _, err := svc.SetMembershipEnable("bob@example.com", vless.Id, false); err != nil {
		t.Fatalf("SetMembershipEnable: %v", err)
	}

	// Any later write that syncs the disabled inbound: the entry says false, and the
	// reason is the membership, not the account.
	if _, err := svc.ApplyMemberships("bob@example.com", []int{vless.Id}, nil, false, 0); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	accounts := accountsInDB(t)
	if len(accounts) != 1 || !accounts[0].Enable {
		t.Fatalf("the account was disabled by re-syncing an inbound it is switched off on: %+v", accounts)
	}
	if got := clientEntry(t, trojan.Id, "bob@example.com")["enable"]; got != true {
		t.Errorf("the other membership reads enable=%v, want true", got)
	}
}

// Two l2tp inbounds share one daemon that sends a bare "l2tp" NAS-Identifier, so
// RADIUS resolves the account to whichever inbound has the lower id. The account
// would be created, listed on both, log in fine, and always be served by one of
// them, taking ITS ranges and user limit. Refused rather than silently accepted.
func TestValidateMembershipSetRefusesAmbiguousSameProtocol(t *testing.T) {
	svc := newAccountsDB(t)
	for _, protocol := range []model.Protocol{model.L2TP, model.PPTP, model.IKEV2} {
		first := &model.Inbound{Protocol: protocol, Remark: "first", Id: 1}
		second := &model.Inbound{Protocol: protocol, Remark: "second", Id: 2}
		if err := svc.ValidateMembershipSet([]*model.Inbound{first, second}); err == nil {
			t.Errorf("%s: two memberships accepted, but the shared daemon cannot tell them apart", protocol)
		}
	}
}

// openvpn, openconnect and sstp already send "<proto>-<inboundId>", so RADIUS
// resolves them exactly and two memberships are safe.
func TestValidateMembershipSetAllowsPerInboundNasProtocols(t *testing.T) {
	svc := newAccountsDB(t)
	for _, protocol := range []model.Protocol{model.OPENVPN, model.OPENCONNECT, model.SSTP} {
		first := &model.Inbound{Protocol: protocol, Remark: "first", Id: 1}
		second := &model.Inbound{Protocol: protocol, Remark: "second", Id: 2}
		if err := svc.ValidateMembershipSet([]*model.Inbound{first, second}); err != nil {
			t.Errorf("%s: refused, but it sends a per-inbound NAS-Identifier and resolves exactly: %v", protocol, err)
		}
	}
}

// Different protocols are the whole point and must always be allowed.
func TestValidateMembershipSetAllowsDifferentProtocols(t *testing.T) {
	svc := newAccountsDB(t)
	err := svc.ValidateMembershipSet([]*model.Inbound{
		{Protocol: model.L2TP, Id: 1}, {Protocol: model.PPTP, Id: 2},
		{Protocol: model.VLESS, Id: 3}, {Protocol: model.WGC, Id: 4},
	})
	if err != nil {
		t.Errorf("one account across four different protocols was refused: %v", err)
	}
}

// An account whose last membership goes away must not linger: the email would
// read as taken and refuse a later re-create of the same customer.
func TestSyncInboundAccountsPrunesOrphans(t *testing.T) {
	svc := newAccountsDB(t)
	inbound := seedInboundWithClients(t, model.VLESS, 46401, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()
	if len(accountsInDB(t)) != 1 {
		t.Fatal("setup: expected one account")
	}

	// Emulate a plain client delete through the legacy path.
	if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", inbound.Id).
		Update("settings", `{"clients":[]}`).Error; err != nil {
		t.Fatalf("clear clients: %v", err)
	}
	if err := svc.SyncInboundAccounts(database.GetDB(), inbound.Id, 0); err != nil {
		t.Fatalf("SyncInboundAccounts: %v", err)
	}

	if got := len(membershipsInDB(t)); got != 0 {
		t.Errorf("memberships = %d, want 0", got)
	}
	if got := len(accountsInDB(t)); got != 0 {
		t.Errorf("accounts = %d, want 0: an account with no membership is addressable by nothing", got)
	}
}

// Deleting the inbound itself drops its memberships but must not delete accounts
// that are still served elsewhere.
func TestSyncInboundAccountsKeepsAccountAliveOnOtherInbounds(t *testing.T) {
	svc := newAccountsDB(t)
	keep := seedInboundWithClients(t, model.VLESS, 46501, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	gone := seedInboundWithClients(t, model.Trojan, 46502, []map[string]any{
		{"password": "pw", "email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()

	if err := database.GetDB().Where("id = ?", gone.Id).Delete(&model.Inbound{}).Error; err != nil {
		t.Fatalf("delete inbound: %v", err)
	}
	if err := svc.SyncInboundAccounts(database.GetDB(), gone.Id, 0); err != nil {
		t.Fatalf("SyncInboundAccounts: %v", err)
	}

	if got := len(accountsInDB(t)); got != 1 {
		t.Fatalf("accounts = %d, want 1: the account is still served on the other inbound", got)
	}
	ids, err := svc.InboundIdsForEmail("bob@example.com")
	if err != nil {
		t.Fatalf("InboundIdsForEmail: %v", err)
	}
	if len(ids) != 1 || ids[0] != keep.Id {
		t.Errorf("memberships = %v, want just [%d]", ids, keep.Id)
	}
}

// The projection renders the credential FROM the account, so an account whose
// credential columns were never filled projects an EMPTY credential over the real
// one. That both unaddressable-ifies the client (clientIdentity returns "", so
// edit and delete stop matching it) and, for a native protocol, leaves a client
// the core cannot authenticate. It corrupts the entry the request was not about.
func TestSyncInboundAccountsLiftsTheCredential(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46701, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	if err := svc.SyncInboundAccounts(database.GetDB(), vless.Id, 0); err != nil {
		t.Fatalf("SyncInboundAccounts: %v", err)
	}

	account, err := svc.GetAccountByEmail("bob@example.com")
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	if account.UUID != "3fa85f64-5717-4562-b3fc-2c963f66afa6" {
		t.Fatalf("UUID = %q, want the entry's uuid: an empty one projects over the real credential", account.UUID)
	}

	// And projecting must write it straight back, not blank it.
	if _, err := svc.ProjectAccount(database.GetDB(), account.Id); err != nil {
		t.Fatalf("ProjectAccount: %v", err)
	}
	clients := readClients(t, vless.Id)
	if got, _ := clients[0]["id"].(string); got != "3fa85f64-5717-4562-b3fc-2c963f66afa6" {
		t.Errorf("projected id = %q, want the uuid unchanged", got)
	}
}

// Joining a protocol whose credential the account does not hold must MINT one.
// An account that only ever existed on vless has a uuid and no VPN username, so
// without minting it would join an l2tp inbound with an empty id: listed, looks
// fine, and can never authenticate because RADIUS has nothing to check.
func TestApplyMembershipsMintsMissingCredentials(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46801, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	l2tp := seedInboundWithClients(t, model.L2TP, 46802, []map[string]any{})
	svc.MigrationAccounts()

	if _, err := svc.ApplyMemberships("bob@example.com", []int{vless.Id, l2tp.Id}, nil, true, 0); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	clients := readClients(t, l2tp.Id)
	if len(clients) != 1 {
		t.Fatalf("l2tp has %d clients, want 1", len(clients))
	}
	login, _ := clients[0]["id"].(string)
	password, _ := clients[0]["password"].(string)
	if login == "" {
		t.Error("l2tp id is empty: RADIUS has no username to authenticate")
	}
	if password == "" {
		t.Error("l2tp password is empty: RADIUS has nothing to check against")
	}
	// The vless side must keep the credential the customer already installed.
	vlessClients := readClients(t, vless.Id)
	if got, _ := vlessClients[0]["id"].(string); got != "3fa85f64-5717-4562-b3fc-2c963f66afa6" {
		t.Errorf("vless uuid changed to %q: every installed client config would break", got)
	}
}

// A membership created by the projection must be indistinguishable in the client
// table from one added directly: the panel renders a creation date from these, and
// a projected entry used to carry none.
func TestNewMembershipGetsTimestamps(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46901, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	l2tp := seedInboundWithClients(t, model.L2TP, 46902, []map[string]any{})
	svc.MigrationAccounts()

	if _, err := svc.ApplyMemberships("bob@example.com", []int{vless.Id, l2tp.Id}, nil, true, 0); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}
	clients := readClients(t, l2tp.Id)
	if len(clients) != 1 {
		t.Fatalf("clients = %d, want 1", len(clients))
	}
	for _, key := range []string{"created_at", "updated_at"} {
		v, ok := clients[0][key].(float64)
		if !ok || v <= 0 {
			t.Errorf("%s = %v, want a real timestamp", key, clients[0][key])
		}
	}
}

// One account on several inbounds is the feature, so the cross-inbound duplicate
// check must not treat its own membership as a stranger. It used to: saving an
// inbound that held ANY multi-inbound account failed with "Duplicate email ...
// must be unique across all inbounds", and the operator could not edit that
// inbound at all. Found on a live panel.
func TestUpdateInboundAllowsAnAccountThatIsAlsoElsewhere(t *testing.T) {
	svc := newAccountsDB(t)
	a := seedInboundWithClients(t, model.VLESS, 47101, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "shared@example.com", "enable": false},
	})
	seedInboundWithClients(t, model.Trojan, 47102, []map[string]any{
		{"password": "pw", "email": "shared@example.com", "enable": false},
	})
	svc.MigrationAccounts()

	inboundSvc := &InboundService{}
	stored, err := inboundSvc.GetInbound(a.Id)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	stored.Remark = "renamed"
	if _, _, err := inboundSvc.UpdateInbound(stored); err != nil {
		t.Fatalf("could not edit an inbound holding a multi-inbound account: %v", err)
	}

	// A genuinely NEW email that collides with another inbound's account is still
	// refused: joining an account to an inbound goes through inboundIds.
	stored2, _ := inboundSvc.GetInbound(a.Id)
	stored2.Settings = `{"clients":[
		{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"shared@example.com","enable":false},
		{"id":"11111111-2222-3333-4444-555555555555","email":"stranger@example.com","enable":false}
	]}`
	seedInboundWithClients(t, model.Shadowsocks, 47103, []map[string]any{
		{"password": "pw2", "email": "stranger@example.com", "enable": false},
	})
	if _, _, err := inboundSvc.UpdateInbound(stored2); err == nil {
		t.Error("typing another account's email into the client list was accepted")
	}
}

// Deleting the INBOUND must not leave an account behind that is now served by
// nothing: it stays listed on the Clients page forever and blocks
// revert-accounts. The gone-inbound path used to return before pruning.
func TestDeletingAnInboundPrunesAccountsLeftWithNothing(t *testing.T) {
	svc := newAccountsDB(t)
	solo := seedInboundWithClients(t, model.VLESS, 47201, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "solo@example.com", "enable": false},
	})
	keep := seedInboundWithClients(t, model.Trojan, 47202, []map[string]any{
		{"password": "pw", "email": "both@example.com", "enable": false},
	})
	seedInboundWithClients(t, model.Shadowsocks, 47203, []map[string]any{
		{"password": "pw2", "email": "both@example.com", "enable": false},
	})
	svc.MigrationAccounts()

	if err := database.GetDB().Where("id = ?", solo.Id).Delete(&model.Inbound{}).Error; err != nil {
		t.Fatalf("delete inbound: %v", err)
	}
	if err := svc.SyncInboundAccounts(database.GetDB(), solo.Id, 0); err != nil {
		t.Fatalf("SyncInboundAccounts: %v", err)
	}

	if acct, _ := svc.GetAccountByEmail("solo@example.com"); acct != nil {
		t.Error("an account whose only inbound was deleted survived with no membership")
	}
	if acct, _ := svc.GetAccountByEmail("both@example.com"); acct == nil {
		t.Error("an account still served on another inbound was pruned")
	}
	_ = keep
}

// An account holds ONE password, shared with trojan, anytls, naive and every
// credential VPN. shadowsocks-2022 is the one protocol that cannot take it: its PSK
// must be base64 of exactly the cipher's key length. So an account that already had
// a password and then joined a 2022 inbound was projected with a key that cipher
// refuses, and could never connect there.
func TestShadowsocks2022MembershipGetsAUsableKey(t *testing.T) {
	svc := newAccountsDB(t)
	// openvpn first, so the account's password is a dashless uuid: 32 characters
	// that happen to be legal base64 and decode to 24 bytes, not the 32 this cipher
	// needs. Exactly the shape that made the failure invisible.
	ovpn := seedInboundWithClients(t, model.OPENVPN, 46341, []map[string]any{
		{"id": "bob-login", "password": "0123456789abcdef0123456789abcdef",
			"email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()

	ss := seedShadowsocksInbound(t, 46342, "2022-blake3-aes-256-gcm")
	if _, err := svc.ApplyMemberships("bob@example.com", []int{ovpn.Id, ss.Id}, nil, true, 0); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	entry := clientEntry(t, ss.Id, "bob@example.com")
	if entry == nil {
		t.Fatal("the account was not projected onto the shadowsocks inbound")
	}
	psk, _ := entry["password"].(string)
	raw, err := base64.StdEncoding.DecodeString(psk)
	if err != nil || len(raw) != 32 {
		t.Fatalf("projected PSK %q is not base64 of 32 bytes (err=%v, len=%d): that "+
			"account cannot connect on a 2022-blake3-aes-256-gcm inbound", psk, err, len(raw))
	}
	// And the shared account password is untouched, so openvpn still authenticates.
	accounts := accountsInDB(t)
	if len(accounts) != 1 || accounts[0].Password != "0123456789abcdef0123456789abcdef" {
		t.Errorf("the account password was rotated to the shadowsocks PSK: %+v", accounts)
	}
	if got, _ := clientEntry(t, ovpn.Id, "bob@example.com")["password"].(string); got != "0123456789abcdef0123456789abcdef" {
		t.Errorf("openvpn password = %q, want the account's own", got)
	}

	// Re-projecting must not churn the PSK: a rotating credential would break the
	// client config the customer already installed.
	if _, err := svc.ApplyMemberships("bob@example.com", []int{ovpn.Id, ss.Id}, nil, true, 0); err != nil {
		t.Fatalf("second ApplyMemberships: %v", err)
	}
	if got, _ := clientEntry(t, ss.Id, "bob@example.com")["password"].(string); got != psk {
		t.Errorf("the PSK changed on re-projection: %q -> %q", psk, got)
	}
}

// A non-2022 cipher takes any string, so it keeps sharing the account password.
func TestShadowsocksLegacyMethodKeepsTheSharedPassword(t *testing.T) {
	svc := newAccountsDB(t)
	ovpn := seedInboundWithClients(t, model.OPENVPN, 46351, []map[string]any{
		{"id": "bob-login", "password": "0123456789abcdef0123456789abcdef",
			"email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()
	ss := seedShadowsocksInbound(t, 46352, "aes-256-gcm")
	if _, err := svc.ApplyMemberships("bob@example.com", []int{ovpn.Id, ss.Id}, nil, true, 0); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}
	if got, _ := clientEntry(t, ss.Id, "bob@example.com")["password"].(string); got != "0123456789abcdef0123456789abcdef" {
		t.Errorf("legacy-cipher shadowsocks password = %q, want the shared account password", got)
	}
}

// MTProto's three transports are per-CLIENT booleans the accounts layer does not
// model. A membership created by ticking an inbound has no entry to inherit them
// from, so all three arrived false: an account that exists, is listed, and cannot
// connect in any transport.
func TestMtprotoMembershipGetsItsModes(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46361, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()
	mt := seedInboundWithClients(t, model.MTPROTO, 46362, []map[string]any{})

	if _, err := svc.ApplyMemberships("bob@example.com", []int{vless.Id, mt.Id}, nil, true, 0); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	entry := clientEntry(t, mt.Id, "bob@example.com")
	if entry == nil {
		t.Fatal("the account was not projected onto the mtproto inbound")
	}
	for _, mode := range []string{"modeClassic", "modeSecure", "modeTls"} {
		if entry[mode] != true {
			t.Errorf("%s = %v, want true: a new mtproto membership with every mode off "+
				"cannot connect in any transport", mode, entry[mode])
		}
	}
	if entry["secret"] == nil || entry["secret"] == "" {
		t.Errorf("no secret minted for the mtproto membership: %v", entry["secret"])
	}
	// An operator turning a mode off must stick: the defaults are for a BRAND NEW
	// membership, never re-applied over a stored choice.
	entry["modeTls"] = false
	writeClients(t, mt.Id, []map[string]any{entry})
	if _, err := svc.ApplyMemberships("bob@example.com", []int{vless.Id, mt.Id}, nil, true, 0); err != nil {
		t.Fatalf("second ApplyMemberships: %v", err)
	}
	if got := clientEntry(t, mt.Id, "bob@example.com")["modeTls"]; got != false {
		t.Errorf("modeTls = %v after re-projection, want the operator's false to stick", got)
	}
}

// writeClients replaces an inbound's stored clients array, which is how a legacy
// caller that bypasses the accounts layer leaves the settings JSON.
func writeClients(t *testing.T, inboundId int, clients []map[string]any) {
	t.Helper()
	settings, err := json.Marshal(map[string]any{"clients": clients})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", inboundId).
		Update("settings", string(settings)).Error; err != nil {
		t.Fatalf("write settings: %v", err)
	}
}

// clientEntry reads one account's stored entry on one inbound, as the raw JSON the
// enforcement paths parse rather than as a struct with defaults filled in.
func clientEntry(t *testing.T, inboundId int, email string) map[string]any {
	t.Helper()
	for _, entry := range readClients(t, inboundId) {
		if got, _ := entry["email"].(string); got == email {
			return entry
		}
	}
	return nil
}

// seedShadowsocksInbound makes an empty shadowsocks inbound with a chosen cipher,
// which is the field that decides whether its per-user password is free text.
func seedShadowsocksInbound(t *testing.T, port int, method string) *model.Inbound {
	t.Helper()
	settings, err := json.Marshal(map[string]any{
		"clients": []map[string]any{}, "method": method, "network": "tcp,udp",
	})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		UserId: 1, Tag: "ss-inbound", Port: port,
		Protocol: model.Shadowsocks, Enable: true, Settings: string(settings),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	return inbound
}

// A login name is unique PANEL-WIDE, like an email. The check used to be scoped to
// one protocol, which is all the RADIUS demux strictly needs (l2tp/pptp/ikev2 share a
// daemon that sends a bare NAS-Identifier, so findClientInbound resolves by username
// across a protocol and takes the first match) but is not a rule anyone can hold in
// their head: an operator does not think of a customer's login as belonging to l2tp.
func TestLoginNameIsUniqueAcrossProtocols(t *testing.T) {
	svc := &InboundService{}
	newAccountsDB(t)
	seedInboundWithClients(t, model.L2TP, 47101, []map[string]any{
		{"id": "shareduser", "password": "pw1", "email": "a@example.com", "enable": true},
	})
	pptp := seedInboundWithClients(t, model.PPTP, 47102, []map[string]any{})

	dup, err := svc.findNewDuplicateLogin([]model.Client{
		{ID: "shareduser", Password: "pw2", Email: "b@example.com", Enable: true},
	})
	if err != nil {
		t.Fatalf("findNewDuplicateLogin: %v", err)
	}
	if dup != "shareduser" {
		t.Errorf("a login already used on another PROTOCOL was accepted (got %q)", dup)
	}
	_ = pptp

	// Case differences do not make it a different name.
	dup, _ = svc.findNewDuplicateLogin([]model.Client{
		{ID: "SharedUser", Email: "c@example.com", Enable: true},
	})
	if dup == "" {
		t.Error("a login differing only in case was accepted")
	}
	// A name nobody holds is fine.
	dup, _ = svc.findNewDuplicateLogin([]model.Client{
		{ID: "brandnew", Email: "d@example.com", Enable: true},
	})
	if dup != "" {
		t.Errorf("a free login was refused: %q", dup)
	}
}

// RADIUS matches `client.ID == username || client.Email == username`
// (radius.go:764), so a login that equals somebody else's email authenticates as
// them. The two are one namespace and the check has to treat them as one.
func TestLoginNameCannotBeAnotherAccountsEmail(t *testing.T) {
	svc := &InboundService{}
	newAccountsDB(t)
	seedInboundWithClients(t, model.VLESS, 47201, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "victim@example.com",
			"enable": true},
	})
	seedInboundWithClients(t, model.L2TP, 47202, []map[string]any{})

	dup, err := svc.findNewDuplicateLogin([]model.Client{
		{ID: "victim@example.com", Password: "pw", Email: "attacker@example.com",
			Enable: true},
	})
	if err != nil {
		t.Fatalf("findNewDuplicateLogin: %v", err)
	}
	if dup == "" {
		t.Error("a login equal to ANOTHER account's email was accepted: RADIUS would "+
			"authenticate it as that account")
	}
	// An account may of course use its OWN email as its login.
	dup, _ = svc.findNewDuplicateLogin([]model.Client{
		{ID: "victim@example.com", Email: "victim@example.com", Enable: true},
	})
	if dup != "" {
		t.Errorf("an account was refused its own email as a login: %q", dup)
	}
}

// Migrated data can already hold a collision, from a panel that predates this rule
// or an import. Those accounts must stay editable: only a name the posting account
// does NOT already hold is a new collision.
func TestExistingDuplicateLoginStaysEditable(t *testing.T) {
	svc := &InboundService{}
	newAccountsDB(t)
	// The shape a migration leaves: one login on two accounts, on two protocols.
	seedInboundWithClients(t, model.L2TP, 47301, []map[string]any{
		{"id": "legacydup", "password": "pw1", "email": "old1@example.com", "enable": true},
	})
	seedInboundWithClients(t, model.PPTP, 47302, []map[string]any{
		{"id": "legacydup", "password": "pw2", "email": "old2@example.com", "enable": true},
	})

	for _, email := range []string{"old1@example.com", "old2@example.com"} {
		dup, err := svc.findNewDuplicateLogin([]model.Client{
			{ID: "legacydup", Password: "pw", Email: email, Enable: true},
		})
		if err != nil {
			t.Fatalf("findNewDuplicateLogin: %v", err)
		}
		if dup != "" {
			t.Errorf("%s can no longer be edited: re-posting the login it already "+
				"holds was refused as a duplicate", email)
		}
	}
	// But a THIRD account still cannot take that name.
	dup, _ := svc.findNewDuplicateLogin([]model.Client{
		{ID: "legacydup", Email: "new@example.com", Enable: true},
	})
	if dup == "" {
		t.Error("a new account was allowed to join an existing login collision")
	}
}

// Two clients in ONE posted batch cannot share a login either.
func TestDuplicateLoginWithinOneBatchIsRefused(t *testing.T) {
	svc := &InboundService{}
	newAccountsDB(t)
	seedInboundWithClients(t, model.OPENCONNECT, 47401, []map[string]any{})
	dup, err := svc.findNewDuplicateLogin([]model.Client{
		{ID: "samename", Email: "one@example.com", Enable: true},
		{ID: "samename", Email: "two@example.com", Enable: true},
	})
	if err != nil {
		t.Fatalf("findNewDuplicateLogin: %v", err)
	}
	if dup != "samename" {
		t.Errorf("two clients in one batch shared a login and it was accepted (got %q)", dup)
	}
}

// openconnect was missing from the old guard list entirely, so its logins were never
// checked at all. It is a login protocol like the rest.
func TestOpenconnectIsALoginProtocol(t *testing.T) {
	if !isVpnLoginProtocol(model.OPENCONNECT) {
		t.Error("openconnect is not treated as a login protocol, so its usernames go unchecked")
	}
	for _, p := range []model.Protocol{model.WGC, model.AWG, model.GRE, model.MTPROTO} {
		if isVpnLoginProtocol(p) {
			t.Errorf("%s stores id=email and authenticates by neither; it must not join "+
				"the login namespace", p)
		}
	}
}

// The exact sequence the E2E runs: disable the account through a single-inbound
// write, then re-enable it through a write that DOES name the membership set. The
// second write must actually re-enable it.
func TestReEnableAfterSingleInboundDisable(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 47501, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	trojan := seedInboundWithClients(t, model.Trojan, 47502, []map[string]any{
		{"password": "pw-bob", "email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()
	ids := []int{vless.Id, trojan.Id}

	// 1. disable through a single-inbound write (no membership set named).
	writeClients(t, vless.Id, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": false},
	})
	if _, err := svc.ApplyMemberships("bob@example.com", []int{vless.Id}, nil, false, 0); err != nil {
		t.Fatalf("disable: %v", err)
	}
	for _, id := range ids {
		if got := clientEntry(t, id, "bob@example.com")["enable"]; got != false {
			t.Fatalf("setup: inbound %d reads enable=%v, want false", id, got)
		}
	}

	// 2. re-enable, naming the whole membership set.
	writeClients(t, vless.Id, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	if _, err := svc.ApplyMemberships("bob@example.com", ids, nil, true, 0); err != nil {
		t.Fatalf("re-enable: %v", err)
	}

	accounts := accountsInDB(t)
	if len(accounts) != 1 || !accounts[0].Enable {
		t.Errorf("the account is still disabled after a re-enable naming every membership: %+v", accounts)
	}
	for _, id := range ids {
		if got := clientEntry(t, id, "bob@example.com")["enable"]; got != true {
			t.Errorf("inbound %d still reads enable=%v after the re-enable", id, got)
		}
	}
}

// The E2E shape, reproduced: an account on MANY inbounds, put through a
// disable/re-enable cycle, and only then switched off on ONE membership. The
// two-inbound version of this passes, so whatever breaks needs the fuller sequence.
func TestMembershipEnableAfterAnEnableCycle(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 47601, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	ids := []int{vless.Id}
	for i, proto := range []model.Protocol{model.Trojan, model.ANYTLS, model.VMESS,
		model.L2TP, model.PPTP} {
		ib := seedInboundWithClients(t, proto, 47602+i, []map[string]any{})
		ids = append(ids, ib.Id)
	}
	svc.MigrationAccounts()
	if _, err := svc.ApplyMemberships("bob@example.com", ids, nil, true, 0); err != nil {
		t.Fatalf("spread: %v", err)
	}

	// disable through a single-inbound write, then re-enable naming the whole set
	writeClients(t, vless.Id, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": false},
	})
	if _, err := svc.ApplyMemberships("bob@example.com", []int{vless.Id}, nil, false, 0); err != nil {
		t.Fatalf("disable: %v", err)
	}
	writeClients(t, vless.Id, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	if _, err := svc.ApplyMemberships("bob@example.com", ids, nil, true, 0); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	for _, id := range ids {
		if got := clientEntry(t, id, "bob@example.com")["enable"]; got != true {
			t.Fatalf("precondition: inbound %d reads enable=%v after the re-enable", id, got)
		}
	}

	// now the per-membership switch on ONE of them
	if _, err := svc.SetMembershipEnable("bob@example.com", vless.Id, false); err != nil {
		t.Fatalf("SetMembershipEnable: %v", err)
	}
	off := []int{}
	for _, id := range ids {
		if clientEntry(t, id, "bob@example.com")["enable"] != true {
			off = append(off, id)
		}
	}
	if len(off) != 1 || off[0] != vless.Id {
		t.Errorf("switching inbound %d off disabled %v, want exactly [%d]", vless.Id, off, vless.Id)
	}
	if a := accountsInDB(t); len(a) != 1 || !a[0].Enable {
		t.Errorf("the account flag was lowered by a per-membership switch: %+v", a)
	}
}

// The per-inbound switch on a WIDE account: switching one membership off must leave
// the other sixteen serving and must not lower the account flag.
//
// The two-inbound versions above cover the same rule, but nothing exercised it at
// the width the panel actually reaches. Width is what stresses membershipEnabledFor:
// it runs inside a transaction that has already issued a Where, an Update and one
// query per member inbound, so the more memberships an account has, the more
// statement state exists for that lookup to trip over. A lookup that stops matching
// reads as "no membership" -> enabled, the guard never fires, and one entry's
// enable:false is mirrored onto the ACCOUNT, whose next projection switches every
// membership off. This passes both with and without the fresh-session lookup, so it
// is a guard on the invariant at scale, not a reproduction of a known failure.
func TestMembershipEnableOnAWideAccount(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 47701, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	ids := []int{vless.Id}
	// One inbound per protocol, as wide as the E2E account, avoiding a second
	// membership of any protocol ValidateMembershipSet refuses.
	for i, proto := range []model.Protocol{
		model.VMESS, model.Trojan, model.ANYTLS, model.TUIC, model.NAIVE,
		model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT, model.SSTP,
		model.IKEV2, model.SSH, model.WGC, model.AWG, model.GRE, model.MTPROTO,
	} {
		ib := seedInboundWithClients(t, proto, 47702+i, []map[string]any{})
		ids = append(ids, ib.Id)
	}
	svc.MigrationAccounts()
	if _, err := svc.ApplyMemberships("bob@example.com", ids, nil, true, 0); err != nil {
		t.Fatalf("spread across %d inbounds: %v", len(ids), err)
	}
	for _, id := range ids {
		if got := clientEntry(t, id, "bob@example.com")["enable"]; got != true {
			t.Fatalf("precondition: inbound %d reads enable=%v", id, got)
		}
	}

	if _, err := svc.SetMembershipEnable("bob@example.com", vless.Id, false); err != nil {
		t.Fatalf("SetMembershipEnable: %v", err)
	}

	off := []int{}
	for _, id := range ids {
		if clientEntry(t, id, "bob@example.com")["enable"] != true {
			off = append(off, id)
		}
	}
	if len(off) != 1 || off[0] != vless.Id {
		t.Errorf("switching inbound %d off disabled %d of %d memberships (%v), want exactly [%d]",
			vless.Id, len(off), len(ids), off, vless.Id)
	}
	if a := accountsInDB(t); len(a) != 1 || !a[0].Enable {
		t.Errorf("the ACCOUNT flag was lowered by a per-inbound switch: %+v", a)
	}
}
