package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// The single property the whole reseller role turns on: an admin and a reseller can
// hold the SAME grant on the SAME inbound and must not see the same accounts on it.
// Everything below is a way of failing that property.

// One shared inbound holding one account each, plus the non-client keys a settings
// blob really carries. The reseller's account is stored lower-cased in the ledger and
// mixed-case in the settings on purpose: emails are the panel's case-insensitive
// account identity, and a filter that compared them exactly would silently strip a
// reseller's own accounts from their own page.
const sharedInboundSettings = `{"clients":[{"id":"admin-uuid","email":"admins-client","enable":false,"totalGB":123,"subId":"sub-admin"},{"id":"reseller-uuid","email":"Resellers-Client","enable":false,"totalGB":456,"subId":"sub-reseller","externalProxy":[{"dest":"cdn.example","port":443,"remark":"edge"}]}],"decryption":"none","fallbacks":[{"dest":8080,"xver":1}],"unknownFutureKey":{"nested":[1,2,3]}}`

type resellerFixture struct {
	svc      *InboundService
	admin    *model.User
	reseller *model.User
	inbound  *model.Inbound
}

// newResellerFixture builds the shared-inbound shape. ownedEmails are the accounts
// the reseller has sold; passing none is the brand-new reseller.
func newResellerFixture(t *testing.T, ownedEmails ...string) *resellerFixture {
	t.Helper()
	svc := newInboundDB(t)
	db := database.GetDB()

	var adminService AdminService
	admin := &model.User{Username: "an-admin", Password: "x", Enable: true, Permissions: model.PermAccessInbounds}
	reseller := &model.User{Username: "a-reseller", Password: "x", Enable: true, IsReseller: true}
	for _, u := range []*model.User{admin, reseller} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create user %s: %v", u.Username, err)
		}
	}

	inbound := &model.Inbound{
		UserId: admin.Id, Tag: "inbound-41001", Port: 41001,
		Protocol: model.VMESS, Enable: true, Settings: sharedInboundSettings,
	}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	// The same grant for both. This is the point: the grant cannot be what separates
	// them, because they legitimately share the inbound.
	for _, u := range []*model.User{admin, reseller} {
		if err := adminService.GrantInbound(u.Id, inbound.Id); err != nil {
			t.Fatalf("grant to %s: %v", u.Username, err)
		}
	}

	for _, email := range []string{"admins-client", "resellers-client"} {
		if err := db.Create(&xray.ClientTraffic{
			InboundId: inbound.Id, Email: email, Enable: true, Up: 1, Down: 2,
		}).Error; err != nil {
			t.Fatalf("create client traffic %s: %v", email, err)
		}
	}
	for _, email := range ownedEmails {
		if err := db.Create(&model.ResellerClient{
			Email: email, InboundId: inbound.Id, UserId: reseller.Id, ChargedBytes: 456,
		}).Error; err != nil {
			t.Fatalf("create ownership row %s: %v", email, err)
		}
	}
	return &resellerFixture{svc: svc, admin: admin, reseller: reseller, inbound: inbound}
}

// clientEmailsIn lists the emails left in a settings blob, in order.
func clientEmailsIn(t *testing.T, settings string) []string {
	t.Helper()
	var root struct {
		Clients []struct {
			Email string `json:"email"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(settings), &root); err != nil {
		t.Fatalf("settings are not readable JSON: %v\n%s", err, settings)
	}
	out := make([]string, 0, len(root.Clients))
	for _, c := range root.Clients {
		out = append(out, c.Email)
	}
	return out
}

func statEmailsIn(stats []xray.ClientTraffic) []string {
	out := make([]string, 0, len(stats))
	for _, s := range stats {
		out = append(out, s.Email)
	}
	return out
}

func TestGetInboundsForResellerHidesOtherPeoplesClients(t *testing.T) {
	f := newResellerFixture(t, "resellers-client")

	inbounds, err := f.svc.GetInboundsFor(f.reseller)
	if err != nil {
		t.Fatalf("GetInboundsFor: %v", err)
	}
	if len(inbounds) != 1 {
		t.Fatalf("got %d inbounds; the grant is real, so the inbound itself must still be visible", len(inbounds))
	}

	// Settings is what the page parses to build its table, so a client left here is
	// visible down to its credentials.
	if got := clientEmailsIn(t, inbounds[0].Settings); len(got) != 1 || !sameEmail(got[0], "resellers-client") {
		t.Errorf("settings clients = %v; want only the reseller's own", got)
	}
	// ClientStats is the traffic the same table joins on. Either half alone leaks.
	if got := statEmailsIn(inbounds[0].ClientStats); len(got) != 1 || !sameEmail(got[0], "resellers-client") {
		t.Errorf("clientStats = %v; want only the reseller's own", got)
	}
	// The account credentials must not survive anywhere in the payload either.
	if strings.Contains(inbounds[0].Settings, "admin-uuid") {
		t.Errorf("the admin's client id is still in the blob:\n%s", inbounds[0].Settings)
	}
}

// The Inbounds page sums the INBOUND's own up/down/allTime into the "Total usage" and
// "All-time total usage" band above the table. Those columns are panel-wide, so
// filtering the client rows alone left a reseller reading the admin's traffic as
// their own.
func TestGetInboundsForResellerScopesTheInboundTotals(t *testing.T) {
	f := newResellerFixture(t, "resellers-client")
	db := database.GetDB()

	// What the counters really look like: the inbound row carries both accounts, and
	// all_time is ahead of up+down because a reset rewinds one and not the other.
	if err := db.Model(&xray.ClientTraffic{}).Where("email = ?", "admins-client").
		Updates(map[string]any{"up": 700, "down": 300, "all_time": 4000}).Error; err != nil {
		t.Fatalf("seed the admin's usage: %v", err)
	}
	if err := db.Model(&xray.ClientTraffic{}).Where("email = ?", "resellers-client").
		Updates(map[string]any{"up": 20, "down": 5, "all_time": 90}).Error; err != nil {
		t.Fatalf("seed the reseller's usage: %v", err)
	}
	if err := db.Model(&model.Inbound{}).Where("id = ?", f.inbound.Id).
		Updates(map[string]any{"up": 720, "down": 305, "all_time": 4090}).Error; err != nil {
		t.Fatalf("seed the inbound totals: %v", err)
	}

	inbounds, err := f.svc.GetInboundsFor(f.reseller)
	if err != nil {
		t.Fatalf("GetInboundsFor: %v", err)
	}
	if len(inbounds) != 1 {
		t.Fatalf("got %d inbounds; want the granted one", len(inbounds))
	}
	got := inbounds[0]
	if got.Up != 20 || got.Down != 5 || got.AllTime != 90 {
		t.Errorf("up/down/allTime = %d/%d/%d; want 20/5/90, the reseller's own accounts and nobody else's",
			got.Up, got.Down, got.AllTime)
	}

	// The admin sharing the same inbound still sees the whole thing.
	inbounds, err = f.svc.GetInboundsFor(f.admin)
	if err != nil {
		t.Fatalf("GetInboundsFor(admin): %v", err)
	}
	if got := inbounds[0]; got.Up != 720 || got.Down != 305 || got.AllTime != 4090 {
		t.Errorf("the admin's totals were rescoped too: up/down/allTime = %d/%d/%d; want 720/305/4090",
			got.Up, got.Down, got.AllTime)
	}
}

// A reseller with nothing on an inbound has used nothing on it, however busy the
// inbound is. This is the case that used to show the panel's entire traffic.
func TestGetInboundsForResellerWithNoAccountsHasNoUsage(t *testing.T) {
	f := newResellerFixture(t)
	if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", f.inbound.Id).
		Updates(map[string]any{"up": 720, "down": 305, "all_time": 4090}).Error; err != nil {
		t.Fatalf("seed the inbound totals: %v", err)
	}

	inbounds, err := f.svc.GetInboundsFor(f.reseller)
	if err != nil {
		t.Fatalf("GetInboundsFor: %v", err)
	}
	if got := inbounds[0]; got.Up != 0 || got.Down != 0 || got.AllTime != 0 {
		t.Errorf("up/down/allTime = %d/%d/%d; want all zero", got.Up, got.Down, got.AllTime)
	}
}

// all_time is only backfilled for rows the panel has written since the column existed.
// The page falls back to up+down for the rest, and the scoped total has to fall back
// the same way or a reseller's band reads lower than the rows it is summing.
func TestRescopedAllTimeFallsBackToUpPlusDown(t *testing.T) {
	s := &InboundService{}
	inbound := &model.Inbound{
		Id:       7,
		Settings: sharedInboundSettings,
		ClientStats: []xray.ClientTraffic{
			{Email: "admins-client", Up: 700, Down: 300, AllTime: 4000},
			{Email: "resellers-client", Up: 20, Down: 5}, // pre-dates all_time
			{Email: "Resellers-Client-2", Up: 1, Down: 2, AllTime: 30},
		},
	}
	s.FilterInboundForReseller(inbound, map[string]bool{
		"resellers-client": true, "resellers-client-2": true,
	})

	if inbound.Up != 21 || inbound.Down != 7 {
		t.Errorf("up/down = %d/%d; want 21/7", inbound.Up, inbound.Down)
	}
	if inbound.AllTime != 55 { // (20+5) + 30
		t.Errorf("allTime = %d; want 55, the legacy row counted as up+down", inbound.AllTime)
	}
}

// The filtering rewrites the blob, so everything that is NOT a client has to come
// back out of it unchanged: protocol settings, external proxies, and keys this panel
// has never heard of.
func TestResellerFilterKeepsNonClientSettings(t *testing.T) {
	f := newResellerFixture(t, "resellers-client")

	inbounds, err := f.svc.GetInboundsFor(f.reseller)
	if err != nil {
		t.Fatalf("GetInboundsFor: %v", err)
	}

	var want, got map[string]any
	if err := json.Unmarshal([]byte(sharedInboundSettings), &want); err != nil {
		t.Fatalf("fixture settings: %v", err)
	}
	if err := json.Unmarshal([]byte(inbounds[0].Settings), &got); err != nil {
		t.Fatalf("filtered settings: %v", err)
	}
	delete(want, "clients")
	delete(got, "clients")

	wantJSON, _ := json.Marshal(want)
	gotJSON, _ := json.Marshal(got)
	if string(wantJSON) != string(gotJSON) {
		t.Errorf("non-client settings changed\n want %s\n  got %s", wantJSON, gotJSON)
	}

	// And the surviving client keeps its own sub-objects: the filter copies clients
	// verbatim rather than re-encoding them through a model the panel may not fully
	// describe.
	if !strings.Contains(inbounds[0].Settings, "cdn.example") {
		t.Errorf("the reseller's own externalProxy was dropped:\n%s", inbounds[0].Settings)
	}
}

// A reseller who has sold nothing is a normal state, not an error, and must not fall
// back to the unfiltered list.
func TestGetInboundsForResellerWithNoAccounts(t *testing.T) {
	f := newResellerFixture(t)

	inbounds, err := f.svc.GetInboundsFor(f.reseller)
	if err != nil {
		t.Fatalf("GetInboundsFor: %v", err)
	}
	if len(inbounds) != 1 {
		t.Fatalf("got %d inbounds; want the granted one, empty", len(inbounds))
	}
	if got := clientEmailsIn(t, inbounds[0].Settings); len(got) != 0 {
		t.Errorf("settings clients = %v; want none", got)
	}
	if got := statEmailsIn(inbounds[0].ClientStats); len(got) != 0 {
		t.Errorf("clientStats = %v; want none", got)
	}
	// [] and not null: the page iterates this array.
	if !strings.Contains(inbounds[0].Settings, `"clients": []`) {
		t.Errorf("empty client list must marshal as [], got:\n%s", inbounds[0].Settings)
	}
	if inbounds[0].ClientStats == nil {
		t.Error("ClientStats must be an empty slice, not nil")
	}
}

// The regression guard for every panel that has no resellers at all: the feature has
// to be completely inert on the admin path.
func TestGetInboundsForAdminIsUnaffected(t *testing.T) {
	f := newResellerFixture(t, "resellers-client")

	inbounds, err := f.svc.GetInboundsFor(f.admin)
	if err != nil {
		t.Fatalf("GetInboundsFor: %v", err)
	}
	if len(inbounds) != 1 {
		t.Fatalf("got %d inbounds; want 1", len(inbounds))
	}
	if inbounds[0].Settings != sharedInboundSettings {
		t.Errorf("an admin's settings were rewritten\n want %s\n  got %s", sharedInboundSettings, inbounds[0].Settings)
	}
	if got := statEmailsIn(inbounds[0].ClientStats); len(got) != 2 {
		t.Errorf("clientStats = %v; an admin must still see every account on the inbound", got)
	}
}

// Settings that will not parse cannot be proven safe to hand over, so they are not
// handed over. The inbound stays, because the grant is real.
func TestFilterInboundForResellerFailsClosedOnBadSettings(t *testing.T) {
	s := &InboundService{}
	inbound := &model.Inbound{
		Id:       7,
		Settings: `{"clients": [ this is not JSON`,
		ClientStats: []xray.ClientTraffic{
			{Email: "admins-client"}, {Email: "resellers-client"},
		},
	}
	s.FilterInboundForReseller(inbound, map[string]bool{"resellers-client": true})

	if got := clientEmailsIn(t, inbound.Settings); len(got) != 0 {
		t.Errorf("settings clients = %v; want none", got)
	}
	// The stats half is keyed on email and never depended on the blob, so it stays
	// correct on its own: the reseller keeps their own row, the admin's still goes.
	if got := statEmailsIn(inbound.ClientStats); len(got) != 1 || !sameEmail(got[0], "resellers-client") {
		t.Errorf("clientStats = %v; want only the reseller's own", got)
	}
}

// A nil ownership set is not "unrestricted". Every caller here is a reseller, so the
// absence of a set means the absence of accounts.
func TestFilterInboundForResellerNilSetOwnsNothing(t *testing.T) {
	s := &InboundService{}
	inbound := &model.Inbound{Id: 7, Settings: sharedInboundSettings}
	s.FilterInboundForReseller(inbound, nil)

	if got := clientEmailsIn(t, inbound.Settings); len(got) != 0 {
		t.Errorf("settings clients = %v; a nil set must own nothing", got)
	}
	// And a nil inbound is a no-op rather than a panicked request.
	s.FilterInboundForReseller(nil, nil)
	s.FilterInboundsForReseller(nil, nil)
}

// A protocol with no client list at all (dokodemo-door, the relay inbounds) has
// nothing to strip, and its blob must not be churned on the way through.
func TestFilterSettingsClientsLeavesClientlessBlobAlone(t *testing.T) {
	const settings = `{"address":"127.0.0.1","port":62789,"network":"tcp,udp"}`
	got, err := filterSettingsClients(settings, map[string]bool{})
	if err != nil {
		t.Fatalf("filterSettingsClients: %v", err)
	}
	if got != settings {
		t.Errorf("clientless settings were rewritten\n want %s\n  got %s", settings, got)
	}
}

// seedPlainInbound is the ordinary shape, for the sweeps that match settings against
// client_traffics: the settings email and the traffic email are the SAME string, which
// is what the panel writes. (The fixture above deliberately differs in case, which is
// the right shape for testing ownership and the wrong one for testing these.)
func seedPlainInbound(t *testing.T, port int, emails ...string) *model.Inbound {
	t.Helper()
	db := database.GetDB()

	clients := make([]map[string]any, 0, len(emails))
	for _, email := range emails {
		clients = append(clients, map[string]any{
			"id": "uuid-" + email, "email": email, "enable": false, "subId": "sub-" + email,
		})
	}
	settings, err := json.Marshal(map[string]any{"clients": clients})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	// Seeded disabled for the reason newInboundDB documents: DelInbound pushes to the
	// live Xray over gRPC for an ENABLED row, and there is no Xray here to push to.
	inbound := &model.Inbound{
		UserId: 1, Tag: fmt.Sprintf("inbound-%d", port), Port: port,
		Protocol: model.VMESS, Enable: false, Settings: string(settings),
	}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	for _, email := range emails {
		if err := db.Create(&xray.ClientTraffic{
			InboundId: inbound.Id, Email: email, Enable: true,
		}).Error; err != nil {
			t.Fatalf("create client traffic %s: %v", email, err)
		}
	}
	return inbound
}

// deplete exhausts every account's quota on an inbound, which is what the sweep looks
// for.
func deplete(t *testing.T, inboundId int) {
	t.Helper()
	if err := database.GetDB().Model(&xray.ClientTraffic{}).Where("inbound_id = ?", inboundId).
		Updates(map[string]any{"total": 100, "up": 60, "down": 60}).Error; err != nil {
		t.Fatalf("deplete: %v", err)
	}
}

// The depleted sweep is gated on PermDeleteClient plus access to the INBOUND, and a
// reseller holds both on an inbound it shares. Unscoped, one click deletes the
// admin's depleted accounts too.
func TestDelDepletedClientsScopedSparesOtherPeoplesAccounts(t *testing.T) {
	svc := newInboundDB(t)
	db := database.GetDB()
	inbound := seedPlainInbound(t, 41003, "admins-client", "resellers-client")
	deplete(t, inbound.Id)

	deleted, err := svc.DelDepletedClientsScoped(inbound.Id, map[string]bool{"resellers-client": true})
	if err != nil {
		t.Fatalf("DelDepletedClientsScoped: %v", err)
	}
	if len(deleted) != 1 || !sameEmail(deleted[0], "resellers-client") {
		t.Fatalf("deleted = %v; want only the reseller's own (it is what gets refunded)", deleted)
	}

	reloaded, err := svc.GetInbound(inbound.Id)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	if got := clientEmailsIn(t, reloaded.Settings); len(got) != 1 || !sameEmail(got[0], "admins-client") {
		t.Errorf("settings clients = %v; the admin's depleted account must survive", got)
	}
	var remaining []xray.ClientTraffic
	if err := db.Model(&xray.ClientTraffic{}).Find(&remaining).Error; err != nil {
		t.Fatalf("read traffics: %v", err)
	}
	if got := statEmailsIn(remaining); len(got) != 1 || !sameEmail(got[0], "admins-client") {
		t.Errorf("client_traffics = %v; only the reseller's row may go", got)
	}
}

// Emptying a reseller's last account must not take the inbound with it: they own
// accounts, the admin owns the inbound.
func TestDelDepletedClientsScopedNeverDeletesTheInbound(t *testing.T) {
	svc := newInboundDB(t)
	inbound := seedPlainInbound(t, 41004, "resellers-client")
	deplete(t, inbound.Id)

	if _, err := svc.DelDepletedClientsScoped(inbound.Id, map[string]bool{"resellers-client": true}); err != nil {
		t.Fatalf("DelDepletedClientsScoped: %v", err)
	}

	reloaded, err := svc.GetInbound(inbound.Id)
	if err != nil {
		t.Fatalf("the inbound was deleted along with its last account: %v", err)
	}
	if got := clientEmailsIn(t, reloaded.Settings); len(got) != 0 {
		t.Errorf("settings clients = %v; want none left", got)
	}
}

// The unscoped sweep is the admin path and must behave exactly as it always has,
// including deleting an inbound whose last client is gone.
func TestDelDepletedClientsUnscopedStillClearsEverything(t *testing.T) {
	svc := newInboundDB(t)
	db := database.GetDB()
	inbound := seedPlainInbound(t, 41005, "admins-client", "resellers-client")
	deplete(t, inbound.Id)

	if err := svc.DelDepletedClients(inbound.Id); err != nil {
		t.Fatalf("DelDepletedClients: %v", err)
	}
	if _, err := svc.GetInbound(inbound.Id); err == nil {
		t.Error("an inbound whose every client was depleted must still be deleted")
	}
	var remaining int64
	if err := db.Model(&xray.ClientTraffic{}).Count(&remaining).Error; err != nil {
		t.Fatalf("count traffics: %v", err)
	}
	if remaining != 0 {
		t.Errorf("%d traffic rows survived an unscoped sweep", remaining)
	}
}

// copyClients takes an OPTIONAL email list, and an empty one means "everything on the
// source inbound". That is the whole hole: a reseller reaches this route on an
// inbound it shares.
func TestCopyInboundClientsScopedRestrictsTheSource(t *testing.T) {
	f := newResellerFixture(t, "resellers-client")
	db := database.GetDB()

	target := &model.Inbound{
		UserId: f.admin.Id, Tag: "inbound-41002", Port: 41002,
		Protocol: model.VMESS, Enable: true, Settings: `{"clients":[]}`,
	}
	if err := db.Create(target).Error; err != nil {
		t.Fatalf("create target: %v", err)
	}

	result, _, err := f.svc.CopyInboundClientsScoped(target.Id, f.inbound.Id, nil, "",
		map[string]bool{"resellers-client": true})
	if err != nil {
		t.Fatalf("CopyInboundClientsScoped: %v", err)
	}
	if len(result.Added) != 1 || !strings.HasPrefix(strings.ToLower(result.Added[0]), "resellers-client") {
		t.Fatalf("added = %v; an empty email list must not sweep up the admin's accounts", result.Added)
	}

	reloaded, err := f.svc.GetInbound(target.Id)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	for _, email := range clientEmailsIn(t, reloaded.Settings) {
		if strings.HasPrefix(strings.ToLower(email), "admins-client") {
			t.Errorf("the admin's account was copied across: %s", email)
		}
	}
}
