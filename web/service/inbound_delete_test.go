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

// These pin the delete paths. Every one of them describes a state an operator
// reached by deleting a client and being told, on the re-create, that the email is
// already used by another client: the rejection was truthful and the delete was the
// thing that had failed.

// seedTaggedInbound is seedInboundWithClients with a tag derived from the port.
// The shared helper names every inbound of a protocol the same, and inbounds.tag is
// unique, so these tests could not stand up the two same-protocol inbounds that are
// the whole multi-inbound case.
func seedTaggedInbound(t *testing.T, protocol model.Protocol, port int, clients []map[string]any) *model.Inbound {
	t.Helper()
	settings, err := json.Marshal(map[string]any{"clients": clients})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		UserId: 1, Tag: fmt.Sprintf("%s-%d", protocol, port), Port: port,
		Protocol: protocol, Enable: true, Settings: string(settings),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	return inbound
}

func seedTrafficRow(t *testing.T, row xray.ClientTraffic) {
	t.Helper()
	if err := database.GetDB().Create(&row).Error; err != nil {
		t.Fatalf("seed client_traffics for %q: %v", row.Email, err)
	}
}

// addClientPayload is what the add route posts: the inbound id plus a settings blob
// holding only the new client.
func addClientPayload(t *testing.T, inboundId int, client map[string]any) *model.Inbound {
	t.Helper()
	settings, err := json.Marshal(map[string]any{"clients": []map[string]any{client}})
	if err != nil {
		t.Fatalf("marshal client: %v", err)
	}
	return &model.Inbound{Id: inboundId, Settings: string(settings)}
}

// D1: the last client of an inbound is deletable, and deleting it frees the email.
//
// The panel used to refuse with "no client remained in Inbound", so the customer
// stayed live and their email stayed taken - which is exactly the report, seen from
// the operator's side, of a delete that succeeded and a re-create that would not.
func TestDelInboundClientRemovesTheLastClient(t *testing.T) {
	svc := newInboundDB(t)
	client := testClient("solo@example.com")
	inbound := seedTaggedInbound(t, model.VLESS, 47101, []map[string]any{client})

	if _, err := svc.DelInboundClient(inbound.Id, client["id"].(string)); err != nil {
		t.Fatalf("deleting the only client: %v", err)
	}

	if got := readClients(t, inbound.Id); len(got) != 0 {
		t.Fatalf("clients = %d after deleting the only one, want 0", len(got))
	}
	// Not null: everything downstream reads settings.clients as an array.
	var stored model.Inbound
	if err := database.GetDB().Where("id = ?", inbound.Id).First(&stored).Error; err != nil {
		t.Fatalf("reload inbound: %v", err)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(stored.Settings), &settings); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if list, ok := settings["clients"].([]any); !ok || list == nil {
		t.Errorf("settings.clients = %#v, want an empty array", settings["clients"])
	}

	// The email is free again, which is the whole point.
	taken, err := svc.checkEmailsExistForClients([]model.Client{{Email: "solo@example.com"}})
	if err != nil {
		t.Fatalf("duplicate check: %v", err)
	}
	if taken != "" {
		t.Errorf("the email is still held by %q after the delete", taken)
	}
	if row := trafficRow(t, "solo@example.com"); row != nil {
		t.Error("the traffic row outlived the client it belonged to")
	}
}

// The same for the by-email path, which the Clients page and the reseller cascade
// both go through.
func TestDelInboundClientByEmailRemovesTheLastClient(t *testing.T) {
	svc := newInboundDB(t)
	inbound := seedTaggedInbound(t, model.VLESS, 47102, []map[string]any{testClient("solo@example.com")})

	if _, err := svc.DelInboundClientByEmail(inbound.Id, "solo@example.com"); err != nil {
		t.Fatalf("deleting the only client by email: %v", err)
	}
	if got := readClients(t, inbound.Id); len(got) != 0 {
		t.Fatalf("clients = %d, want 0", len(got))
	}
}

// D2: an account on two inbounds has ONE traffic row. The first delete takes it, and
// the second membership must still be deletable with no row left to read.
func TestDelInboundClientSecondMembershipHasNoTrafficRow(t *testing.T) {
	svc := newInboundDB(t)
	shared := testClient("multi@example.com")
	first := seedTaggedInbound(t, model.VLESS, 47103, []map[string]any{shared})
	second := seedTaggedInbound(t, model.VLESS, 47104, []map[string]any{shared})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: first.Id, Email: "multi@example.com", Enable: true, Total: 10 * gb})

	if _, err := svc.DelInboundClient(first.Id, shared["id"].(string)); err != nil {
		t.Fatalf("deleting the first membership: %v", err)
	}
	if row := trafficRow(t, "multi@example.com"); row != nil {
		t.Fatal("the first delete left the traffic row behind, so the rest of this test proves nothing")
	}
	if _, err := svc.DelInboundClient(second.Id, shared["id"].(string)); err != nil {
		t.Fatalf("deleting the second membership with no traffic row: %v", err)
	}
	if got := readClients(t, second.Id); len(got) != 0 {
		t.Errorf("the second inbound still serves %d client(s)", len(got))
	}
}

// Same trap, reached through the by-email path.
func TestDelInboundClientByEmailSecondMembershipHasNoTrafficRow(t *testing.T) {
	svc := newInboundDB(t)
	shared := testClient("multi@example.com")
	first := seedTaggedInbound(t, model.VLESS, 47105, []map[string]any{shared})
	second := seedTaggedInbound(t, model.VLESS, 47106, []map[string]any{shared})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: first.Id, Email: "multi@example.com", Enable: true})

	if _, err := svc.DelInboundClientByEmail(first.Id, "multi@example.com"); err != nil {
		t.Fatalf("first membership: %v", err)
	}
	if _, err := svc.DelInboundClientByEmail(second.Id, "multi@example.com"); err != nil {
		t.Fatalf("second membership with no traffic row: %v", err)
	}
}

// D4: identity is case-insensitive everywhere else, so an account stored "Bob" has
// to be deletable by a caller holding "bob". It used to report "not found" and the
// client stayed live while its ledger row went.
func TestDelInboundClientByEmailMatchesCaseInsensitively(t *testing.T) {
	svc := newInboundDB(t)
	stored := testClient("Bob@Example.com")
	other := testClient("carol@example.com")
	inbound := seedTaggedInbound(t, model.VLESS, 47107, []map[string]any{stored, other})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: inbound.Id, Email: "Bob@Example.com", Enable: true})

	if _, err := svc.DelInboundClientByEmail(inbound.Id, "bob@example.com"); err != nil {
		t.Fatalf("deleting a case-differing email: %v", err)
	}
	clients := readClients(t, inbound.Id)
	if len(clients) != 1 {
		t.Fatalf("clients = %d, want 1", len(clients))
	}
	if got, _ := clients[0]["email"].(string); got != "carol@example.com" {
		t.Errorf("the surviving client is %q, want carol@example.com", got)
	}
	// The row was written with the settings' spelling, so a delete keyed on the
	// caller's spelling had to resolve it or leave an orphan behind.
	if row := trafficRow(t, "Bob@Example.com"); row != nil {
		t.Error("the traffic row survived as an orphan holding the email")
	}
}

// A member of the clients array that is not an object is KEPT. Dropping it deleted
// data the caller never asked about.
func TestDelInboundClientByEmailKeepsNonObjectEntries(t *testing.T) {
	svc := newInboundDB(t)
	inbound := seedTaggedInbound(t, model.VLESS, 47108, []map[string]any{testClient("gone@example.com")})
	// Splice a non-object member in, which no UI writes but a hand-edited or
	// imported settings blob can carry.
	var settings map[string]any
	var stored model.Inbound
	if err := database.GetDB().Where("id = ?", inbound.Id).First(&stored).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := json.Unmarshal([]byte(stored.Settings), &settings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	settings["clients"] = append(settings["clients"].([]any), "not-an-object")
	blob, _ := json.Marshal(settings)
	stored.Settings = string(blob)
	if err := database.GetDB().Save(&stored).Error; err != nil {
		t.Fatalf("save: %v", err)
	}

	if _, err := svc.DelInboundClientByEmail(inbound.Id, "gone@example.com"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var after model.Inbound
	if err := database.GetDB().Where("id = ?", inbound.Id).First(&after).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	var afterSettings map[string]any
	if err := json.Unmarshal([]byte(after.Settings), &afterSettings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	list, _ := afterSettings["clients"].([]any)
	if len(list) != 1 {
		t.Fatalf("clients = %d, want the one non-object entry to survive", len(list))
	}
	if list[0] != "not-an-object" {
		t.Errorf("the surviving entry is %#v", list[0])
	}
}

// Phase 2, the headline: a client re-created after a full delete must not inherit
// the dead predecessor's counters. The orphan below is over a 1 GB quota by 12 GB,
// disabled and expired, and a customer born into it cannot connect and nothing in
// the UI says why.
func TestAddClientStatDoesNotInheritAnOrphanRow(t *testing.T) {
	svc := newInboundDB(t)
	inbound := seedTaggedInbound(t, model.VLESS, 47109, []map[string]any{})
	seedTrafficRow(t, xray.ClientTraffic{
		InboundId: inbound.Id, Email: "recycled@example.com",
		Up: 5 * gb, Down: 7 * gb, AllTime: 12 * gb,
		Total: 1 * gb, ExpiryTime: 1, Enable: false, LastOnline: 999,
	})

	fresh := testClient("recycled@example.com")
	fresh["totalGB"] = float64(50 * gb)
	fresh["expiryTime"] = float64(0)
	// Enabled, because "born disabled" is the half of the report an operator can
	// actually see. The xray API is not connected in these tests, so the AddUser this
	// unlocks returns "xray api is not connected" without dialing anything.
	fresh["enable"] = true
	if _, err := svc.AddInboundClient(addClientPayload(t, inbound.Id, fresh)); err != nil {
		t.Fatalf("re-creating the client: %v", err)
	}

	row := trafficRow(t, "recycled@example.com")
	if row == nil {
		t.Fatal("no traffic row after the re-create")
	}
	if row.Up != 0 || row.Down != 0 || row.AllTime != 0 {
		t.Errorf("counters = up %d, down %d, allTime %d; the new customer inherited the deleted one's usage", row.Up, row.Down, row.AllTime)
	}
	if row.Total != 50*gb {
		t.Errorf("total = %d, want the 50 GB just bought and not the dead 1 GB", row.Total)
	}
	if row.ExpiryTime != 0 {
		t.Errorf("expiryTime = %d, want 0: the account was born expired", row.ExpiryTime)
	}
	if !row.Enable {
		t.Error("the re-created account is disabled, inherited from the row it reused")
	}
	if row.LastOnline != 0 {
		t.Errorf("lastOnline = %d, want 0", row.LastOnline)
	}
	// Only ever ONE row per account, whatever the reset did.
	var count int64
	if err := database.GetDB().Model(xray.ClientTraffic{}).Where("email = ?", "recycled@example.com").Count(&count).Error; err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Errorf("rows = %d, want exactly 1", count)
	}
}

// The other half of the same rule, and the one that must NOT change: a genuine
// second membership of a live account reuses the existing row untouched. Resetting
// here would zero a paying customer's usage and overwrite their quota every time
// they were added to another inbound.
func TestAddClientStatReusesALiveAccountsRow(t *testing.T) {
	svc := newInboundDB(t)
	home := seedTaggedInbound(t, model.VLESS, 47110, []map[string]any{testClient("live@example.com")})
	joined := seedTaggedInbound(t, model.VLESS, 47111, []map[string]any{})
	seedTrafficRow(t, xray.ClientTraffic{
		InboundId: home.Id, Email: "live@example.com",
		Up: 3 * gb, Down: 2 * gb, AllTime: 9 * gb,
		Total: 50 * gb, ExpiryTime: 12345, Enable: true,
	})

	// What a second membership looks like from here: the same email, a different
	// inbound, and whatever the caller happened to be holding for the other fields.
	err := svc.AddClientStat(database.GetDB(), joined.Id, &model.Client{
		Email: "live@example.com", TotalGB: 1, ExpiryTime: 1, Enable: false,
	})
	if err != nil {
		t.Fatalf("AddClientStat for a second membership: %v", err)
	}

	row := trafficRow(t, "live@example.com")
	if row == nil {
		t.Fatal("the row went away")
	}
	if row.Up != 3*gb || row.Down != 2*gb || row.AllTime != 9*gb {
		t.Errorf("usage was reset to up %d, down %d, allTime %d on a LIVE account", row.Up, row.Down, row.AllTime)
	}
	if row.Total != 50*gb || row.ExpiryTime != 12345 || !row.Enable {
		t.Errorf("quota/expiry/enable were overwritten: total %d, expiry %d, enable %v", row.Total, row.ExpiryTime, row.Enable)
	}
	if row.InboundId != home.Id {
		t.Errorf("inboundId moved to %d; the home inbound is %d", row.InboundId, home.Id)
	}
}

// A membership recorded before the projection spliced its entry into settings is
// still a live account, and its row must survive the same way.
func TestAddClientStatReusesTheRowOfAnAccountKnownOnlyByMembership(t *testing.T) {
	svc := newInboundDB(t)
	home := seedTaggedInbound(t, model.VLESS, 47112, []map[string]any{})
	joined := seedTaggedInbound(t, model.VLESS, 47113, []map[string]any{})
	seedTrafficRow(t, xray.ClientTraffic{
		InboundId: home.Id, Email: "pending@example.com", Up: 4 * gb, Total: 20 * gb, Enable: true,
	})
	account := model.Account{Email: "pending@example.com", Enable: true}
	if err := database.GetDB().Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := database.GetDB().Create(&model.AccountInbound{AccountId: account.Id, InboundId: home.Id}).Error; err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	if err := svc.AddClientStat(database.GetDB(), joined.Id, &model.Client{Email: "pending@example.com", TotalGB: 1}); err != nil {
		t.Fatalf("AddClientStat: %v", err)
	}
	row := trafficRow(t, "pending@example.com")
	if row == nil || row.Up != 4*gb || row.Total != 20*gb {
		t.Errorf("a membership-only account was treated as an orphan: %#v", row)
	}
}

// D6: the depleted sweep resolves the inbounds that really serve an account rather
// than the one its counter row happens to name, or it takes the account off one
// inbound, deletes its only quota row, and leaves it live and unmetered on the rest.
func TestDelDepletedClientsSweepsEveryMembership(t *testing.T) {
	svc := newInboundDB(t)
	shared := testClient("spent@example.com")
	first := seedTaggedInbound(t, model.VLESS, 47114, []map[string]any{shared})
	second := seedTaggedInbound(t, model.VLESS, 47115, []map[string]any{shared, testClient("keep@example.com")})
	seedTrafficRow(t, xray.ClientTraffic{
		InboundId: first.Id, Email: "spent@example.com",
		Up: 2 * gb, Down: 0, Total: 1 * gb, Enable: false,
	})
	seedTrafficRow(t, xray.ClientTraffic{InboundId: second.Id, Email: "keep@example.com", Total: 100 * gb, Enable: true})

	if err := svc.DelDepletedClients(first.Id); err != nil {
		t.Fatalf("DelDepletedClients: %v", err)
	}

	if got := readClients(t, second.Id); len(got) != 1 {
		t.Fatalf("the second inbound serves %d client(s), want only keep@example.com", len(got))
	} else if email, _ := got[0]["email"].(string); email != "keep@example.com" {
		t.Errorf("the surviving client is %q", email)
	}
	if row := trafficRow(t, "spent@example.com"); row != nil {
		t.Error("the depleted account kept its traffic row")
	}
	if row := trafficRow(t, "keep@example.com"); row == nil {
		t.Error("the sweep took an account that was not depleted")
	}
}

// Phase 3: the rejection names WHERE the email is. Without it, a truthful refusal
// reads as the panel remembering a customer that is gone, and there is nowhere for
// the operator to go and look.
func TestDuplicateEmailErrorNamesTheInboundHoldingIt(t *testing.T) {
	svc := newInboundDB(t)
	holder := seedTaggedInbound(t, model.VLESS, 47116, []map[string]any{testClient("taken@example.com")})
	holder.Remark = "Germany VLESS"
	if err := database.GetDB().Save(holder).Error; err != nil {
		t.Fatalf("set remark: %v", err)
	}
	target := seedTaggedInbound(t, model.VLESS, 47117, []map[string]any{})

	_, err := svc.AddInboundClient(addClientPayload(t, target.Id, testClient("taken@example.com")))
	if err == nil {
		t.Fatal("a duplicate email was accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, "Germany VLESS") {
		t.Errorf("the rejection does not name the inbound holding the email: %q", msg)
	}
	if !strings.Contains(msg, fmt.Sprintf("#%d", holder.Id)) {
		t.Errorf("the rejection does not carry the inbound id: %q", msg)
	}
}

// No DB handle, no detail, but still a rejection. The message must never be traded
// for a database error.
func TestDuplicateEmailErrorWithoutHoldersIsStillTheSameSentence(t *testing.T) {
	err := duplicateEmailError("someone@example.com")
	if !strings.Contains(err.Error(), "Emails must be unique across all inbounds") {
		t.Errorf("wording changed: %q", err.Error())
	}
}
