package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"

	"github.com/op/go-logging"
)

// MigrationAccounts runs unattended, on every start, on other people's live
// panels holding accounts real users have already paid for. Its contract is that
// it is ADDITIVE ONLY: it inserts into accounts and account_inbounds and writes
// nothing else, so a failure leaves the database exactly as it was.
//
// These tests exist to make that contract fail loudly if anyone breaks it.

// newAccountsDB points config.GetDBPath at the test database, so the pre-flight
// backup has a real file to copy instead of silently skipping the migration.
func newAccountsDB(t *testing.T) *AccountService {
	t.Helper()
	emailTestLoggerOnce.Do(func() { logger.InitLogger(logging.ERROR) })
	dir := t.TempDir()
	t.Setenv("VPNUI_DB_FOLDER", dir)
	if err := database.InitDB(config.GetDBPath()); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	orig := p
	p = xray.NewProcess(&xray.Config{})
	t.Cleanup(func() { p = orig })
	return &AccountService{}
}

// dbSnapshot captures every table the migration promises not to touch.
type dbSnapshot struct {
	Inbounds       map[int]string
	ClientTraffics []xray.ClientTraffic
	ResellerRows   []model.ResellerClient
	ClientIps      []model.InboundClientIps
}

func snapshotUntouchedTables(t *testing.T) dbSnapshot {
	t.Helper()
	db := database.GetDB()
	snap := dbSnapshot{Inbounds: map[int]string{}}

	var inbounds []model.Inbound
	if err := db.Find(&inbounds).Error; err != nil {
		t.Fatalf("snapshot inbounds: %v", err)
	}
	for _, in := range inbounds {
		snap.Inbounds[in.Id] = in.Settings
	}
	if err := db.Find(&snap.ClientTraffics).Error; err != nil {
		t.Fatalf("snapshot client_traffics: %v", err)
	}
	if err := db.Find(&snap.ResellerRows).Error; err != nil {
		t.Fatalf("snapshot reseller_clients: %v", err)
	}
	if err := db.Find(&snap.ClientIps).Error; err != nil {
		t.Fatalf("snapshot inbound_client_ips: %v", err)
	}
	return snap
}

// assertAdditiveOnly is the Part 6.0 property, as a test that fails loudly.
func assertAdditiveOnly(t *testing.T, before dbSnapshot) {
	t.Helper()
	after := snapshotUntouchedTables(t)

	if len(before.Inbounds) != len(after.Inbounds) {
		t.Fatalf("migration changed the inbound count: %d -> %d", len(before.Inbounds), len(after.Inbounds))
	}
	for id, settings := range before.Inbounds {
		if after.Inbounds[id] != settings {
			t.Errorf("MIGRATION WROTE TO inbounds.settings for inbound %d.\n  before: %s\n  after:  %s",
				id, settings, after.Inbounds[id])
		}
	}
	if !reflect.DeepEqual(before.ClientTraffics, after.ClientTraffics) {
		t.Errorf("MIGRATION WROTE TO client_traffics.\n  before: %+v\n  after:  %+v", before.ClientTraffics, after.ClientTraffics)
	}
	if !reflect.DeepEqual(before.ResellerRows, after.ResellerRows) {
		t.Errorf("MIGRATION WROTE TO reseller_clients.\n  before: %+v\n  after:  %+v", before.ResellerRows, after.ResellerRows)
	}
	if !reflect.DeepEqual(before.ClientIps, after.ClientIps) {
		t.Errorf("MIGRATION WROTE TO inbound_client_ips.\n  before: %+v\n  after:  %+v", before.ClientIps, after.ClientIps)
	}
}

func accountsInDB(t *testing.T) []model.Account {
	t.Helper()
	var out []model.Account
	if err := database.GetDB().Order("id ASC").Find(&out).Error; err != nil {
		t.Fatalf("read accounts: %v", err)
	}
	return out
}

func membershipsInDB(t *testing.T) []model.AccountInbound {
	t.Helper()
	var out []model.AccountInbound
	if err := database.GetDB().Order("account_id ASC, inbound_id ASC").Find(&out).Error; err != nil {
		t.Fatalf("read memberships: %v", err)
	}
	return out
}

// The headline property: a full pass writes the two new tables and NOTHING else.
func TestMigrationAccountsIsAdditiveOnly(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.L2TP, 42101, []map[string]any{
		{"id": "bob", "password": "pw1", "email": "bob@example.com", "enable": true, "totalGB": float64(100), "slot": float64(0)},
		{"id": "eve", "password": "pw2", "email": "eve@example.com", "enable": true, "totalGB": float64(200), "slot": float64(1)},
	})
	seedInboundWithClients(t, model.VLESS, 42102, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "carol@example.com", "enable": true},
	})

	before := snapshotUntouchedTables(t)
	svc.MigrationAccounts()
	assertAdditiveOnly(t, before)

	if got := len(accountsInDB(t)); got != 3 {
		t.Errorf("accounts created = %d, want 3", got)
	}
	if got := len(membershipsInDB(t)); got != 3 {
		t.Errorf("memberships created = %d, want 3", got)
	}
	if !svc.AccountsMigrated() {
		t.Error("AccountsMigrated() is false after a successful pass")
	}
}

// Runs on every start, so a second pass must converge rather than duplicate.
func TestMigrationAccountsIsIdempotent(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.PPTP, 42201, []map[string]any{
		{"id": "bob", "password": "pw1", "email": "bob@example.com", "enable": true, "slot": float64(0)},
	})

	svc.MigrationAccounts()
	firstAccounts := accountsInDB(t)
	firstMemberships := membershipsInDB(t)

	before := snapshotUntouchedTables(t)
	svc.MigrationAccounts()
	assertAdditiveOnly(t, before)

	if !reflect.DeepEqual(firstAccounts, accountsInDB(t)) {
		t.Error("second pass changed the accounts table")
	}
	if !reflect.DeepEqual(firstMemberships, membershipsInDB(t)) {
		t.Error("second pass changed the memberships table")
	}
}

// One email on two inbounds of different protocols is the whole point of the
// feature: ONE account, TWO memberships, and the per-FIELD credential split means
// the vless uuid and the l2tp username land in different columns with no conflict.
func TestMigrationAccountsFoldsOneEmailAcrossProtocols(t *testing.T) {
	svc := newAccountsDB(t)
	l2tp := seedInboundWithClients(t, model.L2TP, 42301, []map[string]any{
		{"id": "bob-login", "password": "pw1", "email": "bob@example.com", "enable": true, "totalGB": float64(100), "slot": float64(0)},
	})
	vless := seedInboundWithClients(t, model.VLESS, 42302, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true, "totalGB": float64(100)},
	})

	before := snapshotUntouchedTables(t)
	svc.MigrationAccounts()
	assertAdditiveOnly(t, before)

	accounts := accountsInDB(t)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %d, want 1 (one email is one account)", len(accounts))
	}
	acct := accounts[0]
	if acct.VpnUsername != "bob-login" {
		t.Errorf("VpnUsername = %q, want %q (from the l2tp membership)", acct.VpnUsername, "bob-login")
	}
	if acct.UUID != "3fa85f64-5717-4562-b3fc-2c963f66afa6" {
		t.Errorf("UUID = %q, want the vless uuid", acct.UUID)
	}
	if acct.Password != "pw1" {
		t.Errorf("Password = %q, want %q", acct.Password, "pw1")
	}

	memberships := membershipsInDB(t)
	if len(memberships) != 2 {
		t.Fatalf("memberships = %d, want 2", len(memberships))
	}
	gotInbounds := []int{memberships[0].InboundId, memberships[1].InboundId}
	wantInbounds := []int{l2tp.Id, vless.Id}
	if !reflect.DeepEqual(gotInbounds, wantInbounds) {
		t.Errorf("membership inbounds = %v, want %v", gotInbounds, wantInbounds)
	}

	report := svc.GetAccountsMigrationReport()
	if report == nil {
		t.Fatal("no report stored")
	}
	if len(report.Conflicts) != 0 {
		t.Errorf("conflicts = %+v, want none: different protocols fill different credential fields", report.Conflicts)
	}
}

// The same email on two inbounds with DIFFERENT quotas is reachable only through
// ImportDB or a hand-edited DB (the service layer refuses it), and the documented
// outcome is first-wins plus a recorded conflict. Critically it must NOT roll the
// migration back: that would leave every operator who ever imported a DB stuck on
// the legacy path forever with no explanation.
func TestMigrationAccountsRecordsConflictWithoutAborting(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.L2TP, 42401, []map[string]any{
		{"id": "bob", "password": "pw1", "email": "bob@example.com", "enable": true, "totalGB": float64(100), "slot": float64(0)},
	})
	seedInboundWithClients(t, model.PPTP, 42402, []map[string]any{
		{"id": "bob", "password": "pw1", "email": "bob@example.com", "enable": true, "totalGB": float64(999), "slot": float64(0)},
	})

	before := snapshotUntouchedTables(t)
	svc.MigrationAccounts()
	assertAdditiveOnly(t, before)

	if !svc.AccountsMigrated() {
		t.Fatal("a recorded conflict must not abort the migration")
	}
	accounts := accountsInDB(t)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(accounts))
	}
	if accounts[0].TotalGB != 100 {
		t.Errorf("TotalGB = %d, want 100 (the FIRST inbound wins)", accounts[0].TotalGB)
	}
	if len(membershipsInDB(t)) != 2 {
		t.Error("both memberships must still be created")
	}
	report := svc.GetAccountsMigrationReport()
	if report == nil || len(report.Conflicts) == 0 {
		t.Fatal("the divergence must be recorded in the report")
	}
	var found bool
	for _, c := range report.Conflicts {
		if c.Field == "totalGB" && c.Kept == "100" && c.New == "999" {
			found = true
		}
	}
	if !found {
		t.Errorf("conflicts = %+v, want a totalGB 100-vs-999 entry", report.Conflicts)
	}
}

// A hand-edited or corrupt settings blob must skip THAT inbound and migrate the
// rest. The broken one stays legacy-only, which is safe and keeps working.
func TestMigrationAccountsSkipsUnparseableInbound(t *testing.T) {
	svc := newAccountsDB(t)
	broken := &model.Inbound{
		UserId: 1, Tag: "broken-inbound", Port: 42501,
		Protocol: model.L2TP, Enable: true, Settings: `{"clients": [ THIS IS NOT JSON`,
	}
	if err := database.GetDB().Create(broken).Error; err != nil {
		t.Fatalf("create broken inbound: %v", err)
	}
	seedInboundWithClients(t, model.VLESS, 42502, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "carol@example.com", "enable": true},
	})

	before := snapshotUntouchedTables(t)
	svc.MigrationAccounts()
	assertAdditiveOnly(t, before)

	if !svc.AccountsMigrated() {
		t.Fatal("one broken inbound must not abort the whole migration")
	}
	accounts := accountsInDB(t)
	if len(accounts) != 1 || accounts[0].Email != "carol@example.com" {
		t.Fatalf("accounts = %+v, want only carol", accounts)
	}
	report := svc.GetAccountsMigrationReport()
	if report == nil || len(report.InboundsSkipped) != 1 || report.InboundsSkipped[0] != broken.Id {
		t.Errorf("InboundsSkipped = %+v, want [%d]", report, broken.Id)
	}
}

// An empty email carries no account identity. Allowed today, so counted rather
// than treated as an error.
func TestMigrationAccountsSkipsEmptyEmail(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.L2TP, 42601, []map[string]any{
		{"id": "nobody", "password": "pw", "email": "", "enable": true, "slot": float64(0)},
		{"id": "bob", "password": "pw2", "email": "bob@example.com", "enable": true, "slot": float64(1)},
	})

	svc.MigrationAccounts()

	accounts := accountsInDB(t)
	if len(accounts) != 1 || accounts[0].Email != "bob@example.com" {
		t.Fatalf("accounts = %+v, want only bob", accounts)
	}
	report := svc.GetAccountsMigrationReport()
	if report == nil || report.ClientsSkipped != 1 {
		t.Errorf("ClientsSkipped = %v, want 1", report)
	}
}

// Rows predating normalizeClientEmails can carry untrimmed emails. They are the
// same account and must fold, or the person ends up billed twice.
func TestMigrationAccountsFoldsUntrimmedEmail(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.L2TP, 42701, []map[string]any{
		{"id": "bob", "password": "pw1", "email": "bob@example.com", "enable": true, "slot": float64(0)},
	})
	seedInboundWithClients(t, model.PPTP, 42702, []map[string]any{
		{"id": "bob", "password": "pw1", "email": "  bob@example.com  ", "enable": true, "slot": float64(0)},
	})

	svc.MigrationAccounts()

	if got := len(accountsInDB(t)); got != 1 {
		t.Errorf("accounts = %d, want 1: %q and %q are the same identity", got, "bob@example.com", "  bob@example.com  ")
	}
	if got := len(membershipsInDB(t)); got != 2 {
		t.Errorf("memberships = %d, want 2", got)
	}
}

// nextAvailableCopiedEmail mints "<email>_<inboundId>". Those are SEPARATE
// accounts with separate quotas, which is exactly what they are. Guessing a merge
// from the suffix would silently halve someone's paid traffic.
func TestMigrationAccountsKeepsCopiedAccountsSeparate(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.L2TP, 42801, []map[string]any{
		{"id": "bob", "password": "pw1", "email": "bob@example.com", "enable": true, "slot": float64(0)},
	})
	seedInboundWithClients(t, model.PPTP, 42802, []map[string]any{
		{"id": "bob2", "password": "pw2", "email": "bob@example.com_5", "enable": true, "slot": float64(0)},
	})

	svc.MigrationAccounts()

	if got := len(accountsInDB(t)); got != 2 {
		t.Errorf("accounts = %d, want 2: a copied account is a separate account", got)
	}
}

// The slot is the account's tunnel address. A row written before slots existed
// carries none and effectively holds its LIST INDEX; stamping that is what keeps
// the address exactly where it already is.
func TestMigrationAccountsStampsSlotFromListIndex(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.L2TP, 42901, []map[string]any{
		{"id": "first", "password": "pw1", "email": "first@example.com", "enable": true},
		{"id": "second", "password": "pw2", "email": "second@example.com", "enable": true},
		{"id": "third", "password": "pw3", "email": "third@example.com", "enable": true, "slot": float64(7)},
	})

	before := snapshotUntouchedTables(t)
	svc.MigrationAccounts()
	assertAdditiveOnly(t, before)

	byEmail := map[string]*model.AccountInbound{}
	for _, acct := range accountsInDB(t) {
		for i, m := range membershipsInDB(t) {
			if m.AccountId == acct.Id {
				byEmail[acct.Email] = &membershipsInDB(t)[i]
			}
		}
	}
	want := map[string]int{"first@example.com": 0, "second@example.com": 1, "third@example.com": 7}
	for email, wantSlot := range want {
		m, ok := byEmail[email]
		if !ok {
			t.Errorf("%s has no membership", email)
			continue
		}
		if m.Slot == nil {
			t.Errorf("%s got a nil slot, want %d", email, wantSlot)
			continue
		}
		if *m.Slot != wantSlot {
			t.Errorf("%s slot = %d, want %d", email, *m.Slot, wantSlot)
		}
	}
}

// mtproto and ssh relay and the Xray protocols have no address pool, so a slot
// would be meaningless on them.
func TestMigrationAccountsLeavesSlotNilForPoollessProtocols(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.VLESS, 43001, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "carol@example.com", "enable": true},
	})

	svc.MigrationAccounts()

	memberships := membershipsInDB(t)
	if len(memberships) != 1 {
		t.Fatalf("memberships = %d, want 1", len(memberships))
	}
	if memberships[0].Slot != nil {
		t.Errorf("Slot = %v, want nil for a protocol with no address pool", *memberships[0].Slot)
	}
}

// The load-bearing one for wg-c and awg: model.Client does not model devices[]
// at all, so a projection that rebuilt entries from modelled fields would destroy
// every per-device keypair, invalidating client configs already installed on
// users' devices. The membership keeps the entry verbatim so that cannot happen.
func TestMigrationAccountsPreservesUnmodelledProtocolFields(t *testing.T) {
	svc := newAccountsDB(t)
	devices := []any{
		map[string]any{"name": "phone", "privateKey": "PRIV-1", "publicKey": "PUB-1", "ip": "10.9.0.2"},
		map[string]any{"name": "laptop", "privateKey": "PRIV-2", "publicKey": "PUB-2", "ip": "10.9.0.3"},
	}
	seedInboundWithClients(t, model.WGC, 43101, []map[string]any{
		{"id": "dave@example.com", "email": "dave@example.com", "enable": true, "slot": float64(0), "devices": devices},
	})

	svc.MigrationAccounts()

	memberships := membershipsInDB(t)
	if len(memberships) != 1 {
		t.Fatalf("memberships = %d, want 1", len(memberships))
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(memberships[0].Extra), &extra); err != nil {
		t.Fatalf("membership Extra is not valid JSON: %v", err)
	}
	gotDevices, ok := extra["devices"].([]any)
	if !ok || len(gotDevices) != 2 {
		t.Fatalf("devices = %#v, want the 2 seeded keypairs preserved verbatim", extra["devices"])
	}

	// And the projection must render them straight back out.
	account := accountsInDB(t)[0]
	rendered := renderClientEntry(&account, &memberships[0], &model.Inbound{Protocol: model.WGC}, nil)
	renderedDevices, ok := rendered["devices"].([]any)
	if !ok || len(renderedDevices) != 2 {
		t.Fatalf("projection dropped devices: %#v", rendered["devices"])
	}
	if !reflect.DeepEqual(renderedDevices, devices) {
		t.Errorf("projection altered the keypairs.\n  want: %#v\n  got:  %#v", devices, renderedDevices)
	}
}

// SSH's "id" is a real login username compared directly against what the client
// offers (ssh.go:371), NOT the email, despite two in-tree comments saying so.
// Rendering the email would change the login name of every existing SSH account.
func TestMigrationAccountsKeepsSshLoginUsername(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.SSH, 43201, []map[string]any{
		{"id": "dave-login", "password": "pw", "email": "dave@example.com", "enable": true},
	})

	svc.MigrationAccounts()

	accounts := accountsInDB(t)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(accounts))
	}
	if accounts[0].VpnUsername != "dave-login" {
		t.Fatalf("VpnUsername = %q, want %q", accounts[0].VpnUsername, "dave-login")
	}
	rendered := renderClientEntry(&accounts[0], &membershipsInDB(t)[0], &model.Inbound{Protocol: model.SSH}, nil)
	if rendered["id"] != "dave-login" {
		t.Errorf("projected ssh id = %v, want %q (the email here would break the login)", rendered["id"], "dave-login")
	}
}

// The projection must round-trip for every protocol, or the migration's own
// verification would roll back on a real panel.
func TestMigrationAccountsProjectionRoundTripsPerProtocol(t *testing.T) {
	cases := []struct {
		protocol model.Protocol
		client   map[string]any
	}{
		{model.VMESS, map[string]any{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "security": "auto", "email": "a@x.com", "enable": true}},
		{model.VLESS, map[string]any{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "flow": "xtls-rprx-vision", "email": "b@x.com", "enable": true}},
		{model.Trojan, map[string]any{"password": "pw", "email": "c@x.com", "enable": true}},
		{model.Shadowsocks, map[string]any{"password": "pw", "email": "d@x.com", "enable": true}},
		{model.ANYTLS, map[string]any{"password": "pw", "email": "e@x.com", "enable": true}},
		{model.NAIVE, map[string]any{"password": "pw", "username": "naive-user", "email": "f@x.com", "enable": true}},
		{model.TUIC, map[string]any{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "password": "pw", "email": "g@x.com", "enable": true}},
		{model.Hysteria, map[string]any{"auth": "authpw", "email": "h@x.com", "enable": true}},
		{model.L2TP, map[string]any{"id": "login", "password": "pw", "email": "i@x.com", "enable": true, "slot": float64(0)}},
		{model.PPTP, map[string]any{"id": "login", "password": "pw", "email": "j@x.com", "enable": true, "slot": float64(0)}},
		{model.OPENVPN, map[string]any{"id": "login", "password": "pw", "email": "k@x.com", "enable": true, "slot": float64(0)}},
		{model.OPENCONNECT, map[string]any{"id": "login", "password": "pw", "email": "l@x.com", "enable": true, "slot": float64(0)}},
		{model.SSTP, map[string]any{"id": "login", "password": "pw", "email": "m@x.com", "enable": true, "slot": float64(0)}},
		{model.IKEV2, map[string]any{"id": "login", "password": "pw", "email": "n@x.com", "enable": true, "slot": float64(0)}},
		{model.SSH, map[string]any{"id": "login", "password": "pw", "email": "o@x.com", "enable": true}},
		{model.MTPROTO, map[string]any{"id": "p@x.com", "secret": "0123456789abcdef0123456789abcdef", "email": "p@x.com", "enable": true}},
		{model.WGC, map[string]any{"id": "q@x.com", "email": "q@x.com", "enable": true, "slot": float64(0)}},
		{model.AWG, map[string]any{"id": "r@x.com", "email": "r@x.com", "enable": true, "slot": float64(0)}},
		{model.GRE, map[string]any{"id": "s@x.com", "email": "s@x.com", "enable": true, "slot": float64(0)}},
	}

	svc := newAccountsDB(t)
	port := 43300
	for _, tc := range cases {
		port++
		seedInboundWithClients(t, tc.protocol, port, []map[string]any{tc.client})
	}

	before := snapshotUntouchedTables(t)
	svc.MigrationAccounts()
	assertAdditiveOnly(t, before)

	if !svc.AccountsMigrated() {
		t.Fatal("the pass rolled back: its own round-trip verification failed for at least one protocol")
	}
	if got, want := len(accountsInDB(t)), len(cases); got != want {
		t.Errorf("accounts = %d, want %d (one per protocol)", got, want)
	}
}

// A depleted-looking pass must leave the flag unset if verification fails, so the
// panel keeps running on the legacy path rather than half-enabling.
func TestMigrationAccountsLeavesFlagUnsetWhenNothingRan(t *testing.T) {
	svc := newAccountsDB(t)
	if svc.AccountsMigrated() {
		t.Fatal("AccountsMigrated() is true on a fresh database")
	}
}

// A panel with no clients at all must still come up cleanly.
func TestMigrationAccountsHandlesEmptyPanel(t *testing.T) {
	svc := newAccountsDB(t)
	before := snapshotUntouchedTables(t)
	svc.MigrationAccounts()
	assertAdditiveOnly(t, before)
	if len(accountsInDB(t)) != 0 {
		t.Error("accounts created on a panel with no clients")
	}
}

// The escape hatch. On a panel where every account is on ONE inbound, reverting
// is a no-op for the data plane: settings.clients is still the truth, so every
// account keeps its entry, its credentials and its address.
func TestRevertAccountsIsANoOpForSingleMembership(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.L2TP, 43601, []map[string]any{
		{"id": "bob", "password": "pw", "email": "bob@example.com", "enable": true, "slot": float64(0)},
	})
	seedInboundWithClients(t, model.VLESS, 43602, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "carol@example.com", "enable": true},
	})
	svc.MigrationAccounts()

	before := snapshotUntouchedTables(t)
	accounts, memberships, err := svc.RevertAccounts()
	if err != nil {
		t.Fatalf("RevertAccounts: %v", err)
	}
	assertAdditiveOnly(t, before)

	if accounts != 2 || memberships != 2 {
		t.Errorf("removed %d accounts / %d memberships, want 2 / 2", accounts, memberships)
	}
	if len(accountsInDB(t)) != 0 || len(membershipsInDB(t)) != 0 {
		t.Error("the tables were not cleared")
	}
	if svc.AccountsMigrated() {
		t.Error("the migrated flag survived the revert, so the next start would not re-run the pass")
	}
}

// It must REFUSE while any account is on several inbounds. Dropping the tables
// there would leave several settings entries sharing one email and one traffic
// row, which is exactly the shape that leaks quota between inbounds. Naming the
// accounts and stopping is the only honest answer.
func TestRevertAccountsRefusesMultiMembership(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.VLESS, 43701, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	seedInboundWithClients(t, model.Trojan, 43702, []map[string]any{
		{"password": "pw", "email": "bob@example.com", "enable": true},
	})
	svc.MigrationAccounts()
	if len(membershipsInDB(t)) != 2 {
		t.Fatal("setup: expected two memberships")
	}

	_, _, err := svc.RevertAccounts()
	if err == nil {
		t.Fatal("reverted a multi-membership panel: that silently creates duplicate settings entries sharing one traffic row")
	}
	if !strings.Contains(err.Error(), "bob@example.com") {
		t.Errorf("the refusal must NAME the offending accounts so the operator can fix them; got: %v", err)
	}
	if len(accountsInDB(t)) != 1 || len(membershipsInDB(t)) != 2 {
		t.Error("a refused revert must change nothing")
	}
	if !svc.AccountsMigrated() {
		t.Error("a refused revert cleared the migrated flag")
	}
}

// The pre-flight backup is the operator's last resort. It must actually exist.
func TestMigrationAccountsTakesPreFlightBackup(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.L2TP, 43501, []map[string]any{
		{"id": "bob", "password": "pw", "email": "bob@example.com", "enable": true, "slot": float64(0)},
	})

	svc.MigrationAccounts()

	report := svc.GetAccountsMigrationReport()
	if report == nil || report.BackupPath == "" {
		t.Fatal("no backup path recorded")
	}
	if filepath.Base(filepath.Dir(report.BackupPath)) != "backups" {
		t.Errorf("backup went to %q, want a backups/ directory", report.BackupPath)
	}
	if _, err := os.Stat(report.BackupPath); err != nil {
		t.Errorf("recorded backup %q does not exist: %v", report.BackupPath, err)
	}
}

// The four email-identity protocols (wg-c, awg, gre, mtproto) store an "id" that
// NOTHING reads, so nothing has ever forced it to equal the email. On a real
// panel it does not: a live GRE account was found with id "grelive" against email
// "grelive@t". The projection used to overwrite it with the email, which is a
// gratuitous rewrite of stored data, and it rolled the entire migration back on
// the first live panel it met.
func TestMigrationAccountsPreservesEmailIdentityProtocolIds(t *testing.T) {
	svc := newAccountsDB(t)
	port := 43800
	for _, protocol := range []model.Protocol{model.GRE, model.WGC, model.AWG, model.MTPROTO} {
		port++
		entry := map[string]any{
			// id deliberately DIFFERENT from email, as the live box had it.
			"id": "shortname", "email": "shortname@t", "enable": true,
		}
		if protocol == model.MTPROTO {
			entry["secret"] = "0123456789abcdef0123456789abcdef"
		} else {
			entry["slot"] = float64(0)
		}
		if protocol == model.GRE {
			entry["peers"] = []any{map[string]any{}, map[string]any{}}
		}
		seedInboundWithClients(t, protocol, port, []map[string]any{entry})
	}

	before := snapshotUntouchedTables(t)
	svc.MigrationAccounts()
	assertAdditiveOnly(t, before)

	if !svc.AccountsMigrated() {
		t.Fatal("the pass rolled back: an id that differs from the email must not fail the round-trip")
	}

	// And re-projecting must leave that id alone rather than rewriting it.
	account, err := svc.GetAccountByEmail("shortname@t")
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	for _, m := range membershipsInDB(t) {
		if m.AccountId != account.Id {
			continue
		}
		var inbound model.Inbound
		if err := database.GetDB().Where("id = ?", m.InboundId).First(&inbound).Error; err != nil {
			t.Fatalf("read inbound: %v", err)
		}
		rendered := renderClientEntry(account, &m, &inbound, nil)
		if got, _ := rendered["id"].(string); got != "shortname" {
			t.Errorf("%s: projected id = %q, want the stored %q left untouched",
				inbound.Protocol, got, "shortname")
		}
	}
}

// A brand new membership has no entry to preserve, so the email is the fallback.
func TestRenderClientEntryDefaultsIdToEmailWhenAbsent(t *testing.T) {
	account := &model.Account{Email: "fresh@example.com"}
	m := &model.AccountInbound{}
	for _, protocol := range []model.Protocol{model.GRE, model.WGC, model.AWG, model.MTPROTO} {
		rendered := renderClientEntry(account, m, &model.Inbound{Protocol: protocol}, nil)
		if got, _ := rendered["id"].(string); got != "fresh@example.com" {
			t.Errorf("%s: new membership id = %q, want the email as the fallback", protocol, got)
		}
	}
}

// A DISABLED client must migrate. This is not an edge case: exceeding a quota
// disables an account automatically, so most real panels have several.
//
// Account.Enable used to carry gorm:"default:1", which makes GORM treat Go's
// false as "unset" and write 1. The account came back ENABLED, the projection
// rendered enable:true over the stored false, the round-trip check caught the
// difference, and the ENTIRE migration rolled back. Every panel holding one
// disabled client would have stayed on the legacy model forever.
func TestMigrationAccountsMigratesDisabledClients(t *testing.T) {
	svc := newAccountsDB(t)
	seedInboundWithClients(t, model.VLESS, 43901, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "off@example.com", "enable": false},
		{"id": "11111111-2222-3333-4444-555555555555", "email": "on@example.com", "enable": true},
	})

	before := snapshotUntouchedTables(t)
	svc.MigrationAccounts()
	assertAdditiveOnly(t, before)

	if !svc.AccountsMigrated() {
		t.Fatal("the pass rolled back on a disabled client")
	}
	off, err := svc.GetAccountByEmail("off@example.com")
	if err != nil || off == nil {
		t.Fatalf("disabled account not migrated: %v", err)
	}
	if off.Enable {
		t.Error("a DISABLED client migrated to an ENABLED account: it would start serving again")
	}
	on, _ := svc.GetAccountByEmail("on@example.com")
	if on == nil || !on.Enable {
		t.Error("the enabled account did not survive as enabled")
	}

	// And the projection must render the stored false straight back.
	m, err := svc.GetMemberships(off.Id)
	if err != nil || len(m) != 1 {
		t.Fatalf("memberships: %v", err)
	}
	if got := renderClientEntry(off, &m[0], &model.Inbound{Protocol: model.VLESS}, nil)["enable"]; got != false {
		t.Errorf("projected enable = %v, want false", got)
	}
}
