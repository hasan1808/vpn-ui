package service

import (
	"encoding/json"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// Enforcement is decided per ACCOUNT (per email), never per inbound.
//
// client_traffics.Email is UNIQUE panel-wide, so one account has exactly ONE row
// naming exactly ONE inbound. Every path that scoped itself with
// `WHERE inbound_id = ?` or read through the ClientStats has-many was therefore
// acting on one arbitrary membership of N. For a depleted account that meant it
// kept passing traffic on the other N-1 inbounds while still billing into the
// same row, so up+down climbed past total forever with enable already false.
//
// These pin the fixes.

func seedTraffic(t *testing.T, inboundId int, email string, up, down, total, expiry int64, enable bool) {
	t.Helper()
	row := &xray.ClientTraffic{
		InboundId: inboundId, Email: email, Up: up, Down: down,
		Total: total, ExpiryTime: expiry, Enable: enable,
	}
	if err := database.GetDB().Create(row).Error; err != nil {
		t.Fatalf("seed traffic for %s: %v", email, err)
	}
}

// The headline leak: an account on two inbounds, whose single traffic row names
// the first, must be removed from BOTH when its quota runs out.
func TestInboundsServingEmailsFindsEveryMembership(t *testing.T) {
	svc := newInboundDB(t)
	a := seedInboundWithClients(t, model.VLESS, 44101, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	b := seedInboundWithClients(t, model.Trojan, 44102, []map[string]any{
		{"password": "pw", "email": "bob@example.com", "enable": true},
	})

	rows, err := svc.inboundsServingEmails(database.GetDB(), []string{"bob@example.com"})
	if err != nil {
		t.Fatalf("inboundsServingEmails: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("found %d memberships, want 2: %+v", len(rows), rows)
	}
	gotIds := map[int]bool{rows[0].Id: true, rows[1].Id: true}
	if !gotIds[a.Id] || !gotIds[b.Id] {
		t.Errorf("found inbounds %v, want both %d and %d", gotIds, a.Id, b.Id)
	}
	for _, row := range rows {
		if row.Email != "bob@example.com" {
			t.Errorf("email = %q, want the original casing preserved for RemoveUser", row.Email)
		}
	}
}

// Identity is compared case- and whitespace-insensitively everywhere else, so
// enforcement must not miss a membership over a stray space.
func TestInboundsServingEmailsFoldsIdentity(t *testing.T) {
	svc := newInboundDB(t)
	seedInboundWithClients(t, model.VLESS, 44201, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "  Bob@Example.com ", "enable": true},
	})

	rows, err := svc.inboundsServingEmails(database.GetDB(), []string{"bob@example.com"})
	if err != nil {
		t.Fatalf("inboundsServingEmails: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("found %d memberships, want 1", len(rows))
	}
}

// EnableStateByEmail is what GetXrayConfig now filters on. It must be panel-wide:
// keyed only on the email, with no inbound component at all.
func TestEnableStateByEmailIsPanelWide(t *testing.T) {
	svc := newInboundDB(t)
	a := seedInboundWithClients(t, model.VLESS, 44301, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	seedInboundWithClients(t, model.Trojan, 44302, []map[string]any{
		{"password": "pw", "email": "bob@example.com", "enable": true},
	})
	// One row, naming only the FIRST inbound, already depleted.
	seedTraffic(t, a.Id, "bob@example.com", 60, 50, 100, 0, false)

	states, err := svc.EnableStateByEmail()
	if err != nil {
		t.Fatalf("EnableStateByEmail: %v", err)
	}
	enable, exists := states[accountKey("bob@example.com")]
	if !exists {
		t.Fatal("the account is missing from the map, so the config filter would render it ENABLED on every inbound")
	}
	if enable {
		t.Error("enable = true for a depleted account")
	}
}

// The delayed-start conversion has to reach every membership, or the inbounds
// that did not get it keep the negative value forever and render as "delayed
// start" on an account whose clock is already running.
func TestAdjustTrafficsConvertsExpiryOnEveryMembership(t *testing.T) {
	svc := newInboundDB(t)
	a := seedInboundWithClients(t, model.VLESS, 44401, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true, "expiryTime": float64(-86400000)},
	})
	b := seedInboundWithClients(t, model.Trojan, 44402, []map[string]any{
		{"password": "pw", "email": "bob@example.com", "enable": true, "expiryTime": float64(-86400000)},
	})

	traffics := []*xray.ClientTraffic{
		{InboundId: a.Id, Email: "bob@example.com", ExpiryTime: -86400000, Enable: true},
	}
	if _, err := svc.adjustTraffics(database.GetDB(), traffics); err != nil {
		t.Fatalf("adjustTraffics: %v", err)
	}

	for _, inboundId := range []int{a.Id, b.Id} {
		clients := readClients(t, inboundId)
		if len(clients) != 1 {
			t.Fatalf("inbound %d has %d clients", inboundId, len(clients))
		}
		expiry, _ := clients[0]["expiryTime"].(float64)
		if expiry <= 0 {
			t.Errorf("inbound %d still holds a negative expiry (%v): the account reads as 'delayed start' while its clock runs", inboundId, expiry)
		}
	}

	// And both memberships must land on the SAME deadline, or one account has two
	// expiry dates.
	first, _ := readClients(t, a.Id)[0]["expiryTime"].(float64)
	second, _ := readClients(t, b.Id)[0]["expiryTime"].(float64)
	if first != second {
		t.Errorf("memberships got different deadlines: %v vs %v", first, second)
	}
	if traffics[0].ExpiryTime <= 0 {
		t.Errorf("the traffic row kept its negative expiry (%d)", traffics[0].ExpiryTime)
	}
}

// An account on vless AND l2tp must keep BOTH its native "user" routing match and
// its tunnel source-IP match. Choosing one silently broke the vless half: the
// source rule only covers tunnel addresses.
func TestXrayNativeEmailSetSeparatesNativeFromTunnelOnly(t *testing.T) {
	newInboundDB(t)
	seedInboundWithClients(t, model.VLESS, 44501, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "both@example.com", "enable": true},
	})
	seedInboundWithClients(t, model.L2TP, 44502, []map[string]any{
		{"id": "login", "password": "pw", "email": "both@example.com", "enable": true, "slot": float64(0)},
		{"id": "login2", "password": "pw2", "email": "tunnelonly@example.com", "enable": true, "slot": float64(1)},
	})

	native := buildXrayNativeEmailSet()

	if !native[accountKey("both@example.com")] {
		t.Error("an account on vless is not in the native set, so its user routing rule would be dropped")
	}
	if native[accountKey("tunnelonly@example.com")] {
		t.Error("an l2tp-only account is in the native set; Xray never authenticates it, so the user match is meaningless")
	}
}

// mtproto and ssh are relays: Xray gets no user list for them either, so they
// must not count as native.
func TestXrayNativeEmailSetExcludesRelays(t *testing.T) {
	newInboundDB(t)
	seedInboundWithClients(t, model.MTPROTO, 44601, []map[string]any{
		{"id": "relay@example.com", "email": "relay@example.com", "secret": "0123456789abcdef0123456789abcdef", "enable": true},
	})
	seedInboundWithClients(t, model.SSH, 44602, []map[string]any{
		{"id": "login", "password": "pw", "email": "sshuser@example.com", "enable": true},
	})

	native := buildXrayNativeEmailSet()
	if native[accountKey("relay@example.com")] {
		t.Error("mtproto counted as an Xray-native inbound")
	}
	if native[accountKey("sshuser@example.com")] {
		t.Error("ssh counted as an Xray-native inbound")
	}
}

// A disabled inbound serves nobody, so its clients must not keep a native match.
func TestXrayNativeEmailSetSkipsDisabledInbounds(t *testing.T) {
	newInboundDB(t)
	inbound := seedInboundWithClients(t, model.VLESS, 44701, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "off@example.com", "enable": true},
	})
	if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", inbound.Id).
		Update("enable", false).Error; err != nil {
		t.Fatalf("disable inbound: %v", err)
	}

	if buildXrayNativeEmailSet()[accountKey("off@example.com")] {
		t.Error("a disabled inbound's client counted as native")
	}
}

// The projection is the only writer of settings.clients once accounts are
// authoritative. It must splice IN PLACE: position is the slot fallback, so
// reordering moves live sessions onto other accounts' tunnel addresses.
func TestProjectAccountSplicesInPlace(t *testing.T) {
	svc := newAccountsDB(t)
	inbound := seedInboundWithClients(t, model.L2TP, 44801, []map[string]any{
		{"id": "first", "password": "pw1", "email": "first@example.com", "enable": true, "slot": float64(0)},
		{"id": "second", "password": "pw2", "email": "second@example.com", "enable": true, "slot": float64(1)},
		{"id": "third", "password": "pw3", "email": "third@example.com", "enable": true, "slot": float64(2)},
	})
	svc.MigrationAccounts()

	account, err := svc.GetAccountByEmail("second@example.com")
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail: %v (account=%v)", err, account)
	}
	account.TotalGB = 5000
	if err := database.GetDB().Save(account).Error; err != nil {
		t.Fatalf("save account: %v", err)
	}
	if _, err := svc.ProjectAccount(database.GetDB(), account.Id); err != nil {
		t.Fatalf("ProjectAccount: %v", err)
	}

	clients := readClients(t, inbound.Id)
	if len(clients) != 3 {
		t.Fatalf("clients = %d, want 3", len(clients))
	}
	wantOrder := []string{"first@example.com", "second@example.com", "third@example.com"}
	for i, want := range wantOrder {
		if got, _ := clients[i]["email"].(string); got != want {
			t.Errorf("position %d = %q, want %q: the projection reordered the array", i, got, want)
		}
	}
	if got, _ := clients[1]["totalGB"].(float64); got != 5000 {
		t.Errorf("totalGB = %v, want 5000", got)
	}
	// The untouched neighbours must keep their credentials and slots exactly.
	if got, _ := clients[0]["password"].(string); got != "pw1" {
		t.Errorf("neighbour credential changed: %q", got)
	}
	if got, _ := clients[2]["slot"].(float64); got != 2 {
		t.Errorf("neighbour slot moved to %v", got)
	}
}

// Removing a membership must not renumber anybody: every remaining pool client
// keeps an EXPLICIT slot, so nothing falls back to its list index.
func TestProjectAccountRemovalKeepsSlotsStable(t *testing.T) {
	svc := newAccountsDB(t)
	inbound := seedInboundWithClients(t, model.L2TP, 44901, []map[string]any{
		{"id": "first", "password": "pw1", "email": "first@example.com", "enable": true, "slot": float64(0)},
		{"id": "second", "password": "pw2", "email": "second@example.com", "enable": true, "slot": float64(1)},
		{"id": "third", "password": "pw3", "email": "third@example.com", "enable": true, "slot": float64(2)},
	})
	svc.MigrationAccounts()

	account, err := svc.GetAccountByEmail("first@example.com")
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	// Drop the membership, then re-project: the account should leave the inbound.
	if err := database.GetDB().Where("account_id = ?", account.Id).
		Delete(&model.AccountInbound{}).Error; err != nil {
		t.Fatalf("delete membership: %v", err)
	}
	if _, err := svc.ProjectAccount(database.GetDB(), account.Id); err != nil {
		t.Fatalf("ProjectAccount: %v", err)
	}

	clients := readClients(t, inbound.Id)
	if len(clients) != 2 {
		t.Fatalf("clients = %d, want 2 after removing one", len(clients))
	}
	wantSlots := map[string]float64{"second@example.com": 1, "third@example.com": 2}
	for _, c := range clients {
		email, _ := c["email"].(string)
		slot, ok := c["slot"].(float64)
		if !ok {
			t.Errorf("%s lost its explicit slot: it would fall back to its list index and move address", email)
			continue
		}
		if slot != wantSlots[email] {
			t.Errorf("%s moved from slot %v to %v", email, wantSlots[email], slot)
		}
	}
}

// The overlay rule, end to end: a protocol field the account layer does not model
// survives a projection untouched.
func TestProjectAccountPreservesUnmodelledFields(t *testing.T) {
	svc := newAccountsDB(t)
	inbound := seedInboundWithClients(t, model.WGC, 45001, []map[string]any{
		{
			"id": "dave@example.com", "email": "dave@example.com", "enable": true, "slot": float64(0),
			"devices": []any{map[string]any{"name": "phone", "privateKey": "PRIV", "publicKey": "PUB"}},
		},
	})
	svc.MigrationAccounts()

	account, err := svc.GetAccountByEmail("dave@example.com")
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	account.TotalGB = 42
	if err := database.GetDB().Save(account).Error; err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := svc.ProjectAccount(database.GetDB(), account.Id); err != nil {
		t.Fatalf("ProjectAccount: %v", err)
	}

	clients := readClients(t, inbound.Id)
	raw, _ := json.Marshal(clients[0]["devices"])
	var devices []map[string]any
	if err := json.Unmarshal(raw, &devices); err != nil || len(devices) != 1 {
		t.Fatalf("devices were destroyed by the projection: %s", raw)
	}
	if devices[0]["privateKey"] != "PRIV" {
		t.Errorf("keypair changed: %+v", devices[0])
	}
	if got, _ := clients[0]["totalGB"].(float64); got != 42 {
		t.Errorf("totalGB = %v, want 42", got)
	}
}
