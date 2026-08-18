package service

import (
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"

	"gorm.io/gorm"
)

// D3 and D5: what the accounts layer must do when a client entry is renamed or
// removed. Both defects have the same shape, an accounts row left describing a
// customer the settings no longer agree with, and both end in a live account nobody
// meant to still exist.

// A rename carries the ONE account onto the new email rather than minting a second.
//
// The old behaviour left the previous email as a live, working account on every
// inbound but the one the edit was posted against, with its own quota and its own
// credentials, listed under a customer who had been renamed away.
func TestRenameAccountCarriesTheAccountAndEveryEntry(t *testing.T) {
	svc := newAccountsDB(t)
	first := seedInboundWithClients(t, model.VLESS, 49101, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "old@example.com", "enable": true, "totalGB": float64(100)},
	})
	second := seedInboundWithClients(t, model.VMESS, 49102, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "old@example.com", "enable": true, "totalGB": float64(100)},
	})
	svc.MigrationAccounts()

	before, err := svc.GetAccountByEmail("old@example.com")
	if err != nil || before == nil {
		t.Fatalf("setup: no account for the old email: %v", err)
	}

	touched, err := svc.RenameAccount("old@example.com", "new@example.com")
	if err != nil {
		t.Fatalf("RenameAccount: %v", err)
	}
	if len(touched) != 2 {
		t.Errorf("touched = %v, want both inbounds: a daemon left holding the old login still authenticates it", touched)
	}

	// ONE account, the same row, under the new key.
	accounts := accountsInDB(t)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %d, want 1: a rename must not mint a second customer", len(accounts))
	}
	if accounts[0].Id != before.Id {
		t.Errorf("account id changed from %d to %d; the row was replaced, not renamed", before.Id, accounts[0].Id)
	}
	if accounts[0].Email != "new@example.com" {
		t.Errorf("account email = %q", accounts[0].Email)
	}
	// The memberships key on account_id, so they must have followed untouched.
	ids, err := svc.InboundIdsForEmail("new@example.com")
	if err != nil {
		t.Fatalf("InboundIdsForEmail: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("memberships = %v, want both", ids)
	}

	// And no inbound is left carrying the old spelling.
	for _, in := range []*model.Inbound{first, second} {
		for _, c := range readClients(t, in.Id) {
			if got, _ := c["email"].(string); got != "new@example.com" {
				t.Errorf("inbound %d still serves %q: a live account under an email nobody is billed for", in.Id, got)
			}
		}
	}
	if got := len(readClients(t, second.Id)); got != 1 {
		t.Errorf("inbound %d has %d clients, want 1: the rename appended instead of replacing", second.Id, got)
	}
}

// The rename leaves the rest of each entry alone. Only the email moves.
func TestRenameAccountKeepsTheCredentials(t *testing.T) {
	svc := newAccountsDB(t)
	inbound := seedInboundWithClients(t, model.VLESS, 49103, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "old@example.com", "enable": true, "totalGB": float64(100), "slot": float64(3)},
	})
	svc.MigrationAccounts()

	if _, err := svc.RenameAccount("old@example.com", "new@example.com"); err != nil {
		t.Fatalf("RenameAccount: %v", err)
	}
	clients := readClients(t, inbound.Id)
	if len(clients) != 1 {
		t.Fatalf("clients = %d", len(clients))
	}
	if got, _ := clients[0]["id"].(string); got != "3fa85f64-5717-4562-b3fc-2c963f66afa6" {
		t.Errorf("the uuid changed to %q: every installed client config would stop working", got)
	}
	if got, _ := clients[0]["totalGB"].(float64); got != 100 {
		t.Errorf("totalGB = %v", got)
	}
	if got, _ := clients[0]["slot"].(float64); got != 3 {
		t.Errorf("slot = %v: the account's tunnel address moved because its label changed", got)
	}
}

// An email that already belongs to somebody else is NOT merged into and NOT
// deleted. Both rows are live customers with their own quota and credentials, and
// the duplicate check is what is supposed to stop this reaching the rename at all.
func TestRenameAccountRefusesToMergeTwoLiveAccounts(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.VLESS, 49104, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "old@example.com", "enable": true, "totalGB": float64(100)},
		{"id": "aaaaaaaa-5717-4562-b3fc-2c963f66afa6", "email": "taken@example.com", "enable": true, "totalGB": float64(200)},
	})
	svc.MigrationAccounts()

	if _, err := svc.RenameAccount("old@example.com", "taken@example.com"); err != nil {
		t.Fatalf("RenameAccount: %v", err)
	}
	if got := len(accountsInDB(t)); got != 2 {
		t.Fatalf("accounts = %d, want both left standing", got)
	}
	if a, _ := svc.GetAccountByEmail("old@example.com"); a == nil {
		t.Error("the account being renamed was destroyed by a collision it should have refused")
	}
	if a, _ := svc.GetAccountByEmail("taken@example.com"); a == nil || a.TotalGB != 200 {
		t.Error("the account that already held the email lost its quota to a merge")
	}
}

// A case-only change is not a change of identity, so the account row is already
// correct, but the SETTINGS still have to move: the stored spelling is what the core
// and RADIUS carry.
func TestRenameAccountIgnoresACaseOnlyChange(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.VLESS, 49105, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()

	touched, err := svc.RenameAccount("bob@example.com", "Bob@Example.com")
	if err != nil {
		t.Fatalf("RenameAccount: %v", err)
	}
	if len(touched) != 0 {
		t.Errorf("touched = %v, want none: the identity did not change", touched)
	}
	if got := len(accountsInDB(t)); got != 1 {
		t.Errorf("accounts = %d, want 1", got)
	}
}

// D5: the membership goes with the settings entry, in the delete itself.
//
// Left behind, it is not inert. ProjectAccount treats memberships as the source and
// appends the account to any member inbound whose blob lacks it, so the next
// projection puts the deleted customer back, live and serving.
func TestDeletingAClientDropsItsMembership(t *testing.T) {
	svc := newInboundDB(t)
	accounts := AccountService{}
	shared := testClient("multi@example.com")
	first := seedTaggedInbound(t, model.VLESS, 49106, []map[string]any{shared})
	second := seedTaggedInbound(t, model.VLESS, 49107, []map[string]any{shared})
	if err := accounts.SyncInboundAccounts(database.GetDB(), first.Id); err != nil {
		t.Fatalf("seed the mirror: %v", err)
	}
	if err := accounts.SyncInboundAccounts(database.GetDB(), second.Id); err != nil {
		t.Fatalf("seed the mirror: %v", err)
	}
	if ids, _ := accounts.InboundIdsForEmail("multi@example.com"); len(ids) != 2 {
		t.Fatalf("setup: memberships = %v, want 2", ids)
	}

	if _, err := svc.DelInboundClientByEmail(first.Id, "multi@example.com"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	ids, err := accounts.InboundIdsForEmail("multi@example.com")
	if err != nil {
		t.Fatalf("InboundIdsForEmail: %v", err)
	}
	if len(ids) != 1 || ids[0] != second.Id {
		t.Fatalf("memberships = %v, want only the inbound still serving it", ids)
	}
	// The account itself stays: it is still served on the second inbound.
	if a, _ := accounts.GetAccountByEmail("multi@example.com"); a == nil {
		t.Error("the account was pruned while a membership still served it")
	}

	// Removing the last one takes the account with it, or the email stays held
	// against a re-create.
	if _, err := svc.DelInboundClientByEmail(second.Id, "multi@example.com"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if ids, _ := accounts.InboundIdsForEmail("multi@example.com"); len(ids) != 0 {
		t.Errorf("memberships = %v, want none", ids)
	}
	if a, _ := accounts.GetAccountByEmail("multi@example.com"); a != nil {
		t.Error("the account outlived every client entry that described it")
	}
}

// The same through the id-keyed delete, which is the one the LDAP sync job calls
// and which reconciles nothing of its own.
func TestDeletingAClientByIdDropsItsMembership(t *testing.T) {
	svc := newInboundDB(t)
	accounts := AccountService{}
	client := testClient("solo@example.com")
	inbound := seedTaggedInbound(t, model.VLESS, 49108, []map[string]any{client})
	if err := accounts.SyncInboundAccounts(database.GetDB(), inbound.Id); err != nil {
		t.Fatalf("seed the mirror: %v", err)
	}

	if _, err := svc.DelInboundClient(inbound.Id, client["id"].(string)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if ids, _ := accounts.InboundIdsForEmail("solo@example.com"); len(ids) != 0 {
		t.Errorf("memberships = %v, want none", ids)
	}
	if a, _ := accounts.GetAccountByEmail("solo@example.com"); a != nil {
		t.Error("the account survived the delete and still holds the email")
	}
}

// The resurrection itself, end to end: delete a client, then project the account
// again from any cause. It must stay deleted.
func TestADeletedClientIsNotResurrectedByTheNextProjection(t *testing.T) {
	svc := newInboundDB(t)
	accounts := AccountService{}
	shared := testClient("ghost@example.com")
	first := seedTaggedInbound(t, model.VLESS, 49109, []map[string]any{shared, testClient("keep@example.com")})
	second := seedTaggedInbound(t, model.VLESS, 49110, []map[string]any{shared})
	for _, in := range []*model.Inbound{first, second} {
		if err := accounts.SyncInboundAccounts(database.GetDB(), in.Id); err != nil {
			t.Fatalf("seed the mirror: %v", err)
		}
	}

	if _, err := svc.DelInboundClientByEmail(first.Id, "ghost@example.com"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Any later write to the account re-projects it onto every inbound it is a
	// member of. Before the membership was dropped, that put it straight back.
	account, err := accounts.GetAccountByEmail("ghost@example.com")
	if err != nil || account == nil {
		t.Fatalf("the account should still exist, it is served on the second inbound: %v", err)
	}
	if err := database.GetDB().Transaction(func(tx *gorm.DB) error {
		_, perr := accounts.ProjectAccount(tx, account.Id)
		return perr
	}); err != nil {
		t.Fatalf("ProjectAccount: %v", err)
	}

	for _, c := range readClients(t, first.Id) {
		if got, _ := c["email"].(string); got == "ghost@example.com" {
			t.Fatal("the deleted client came back on the next projection")
		}
	}
	if got := len(readClients(t, second.Id)); got != 1 {
		t.Errorf("the inbound that should still serve it has %d clients", got)
	}
}
