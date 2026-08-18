package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/web/locale"
	"github.com/hasan1808/pro-ui/xray"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"
)

// Bulk membership: adding the selected accounts to, or removing them from, a set
// of inbounds.
//
// Driven through the real route, because the whole operation is a controller: the
// service call underneath (ApplyMemberships) is one line, and everything that can
// actually go wrong lives around it. The target list arrives as (inbound, email)
// PAIRS and has to be reduced to accounts; an account cannot be left on nothing,
// which ApplyMemberships will not say so this has to; the same-protocol refusal
// and the two capacity guards are checked here; and the ownership assertion is
// over two different id sets that no route middleware can see.

// bulkMembershipEnv is a panel with one super admin, so the ownership machinery is
// out of the way for the cases that are not about it. The scoping case builds its
// own two-admin world from the IDOR fixture.
type bulkMembershipEnv struct {
	admin *model.User
}

func newBulkMembershipEnv(t *testing.T) *bulkMembershipEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	// The handlers log; a nil package logger panics on the first warning instead of
	// reporting the finding under test.
	logger.InitLogger(logging.CRITICAL)
	if err := database.InitDB(filepath.Join(t.TempDir(), "membership.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	admin := &model.User{Username: "root", Password: "x", Enable: true, IsSuperAdmin: true}
	if err := database.GetDB().Create(admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}
	return &bulkMembershipEnv{admin: admin}
}

// post runs one request through a real router as the given admin, the same way
// the IDOR suite does: the login user is seeded into the per-request cache that
// session.GetLoginUser reads, so no cookie or session store is needed.
func bulkMembershipPost(t *testing.T, user *model.User, path, body string) map[string]any {
	t.Helper()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("LOGIN_USER_ROW", user)
		c.Set("base_path", "/")
		c.Set("I18n", func(i18nType locale.I18nType, key string, keyParams ...string) string { return key })
		c.Next()
	})
	NewInboundController(r.Group("/panel/api/inbounds"))

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var msg map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("response is not JSON (%d): %s", w.Code, w.Body.String())
	}
	return msg
}

// bulkMembershipBody form-encodes the payload the way the panel posts it: one
// field named "data" holding the whole request as a JSON string.
func bulkMembershipBody(t *testing.T, op string, inboundIds []int, targets []map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"op": op, "inboundIds": inboundIds, "targets": targets,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return url.Values{"data": {string(payload)}}.Encode()
}

// seedMembershipInbound creates an inbound holding the given clients and returns it.
func seedMembershipInbound(t *testing.T, userId int, protocol model.Protocol, port int, clients string) *model.Inbound {
	t.Helper()
	inbound := &model.Inbound{
		UserId: userId, Tag: string(protocol) + "-" + strconv.Itoa(port), Port: port,
		Protocol: protocol, Enable: true,
		Settings: `{"clients":[` + clients + `]}`,
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	return inbound
}

// syncMembershipAccounts builds the accounts layer from what the seeded inbounds
// already hold, which is exactly what the panel does after any write that changes
// an inbound's client list. Preferred over MigrationAccounts here because that one
// takes a pre-flight backup of config.GetDBPath and skips itself when there is no
// file there to copy, which a controller test would not notice.
func syncMembershipAccounts(t *testing.T) {
	t.Helper()
	var inbounds []model.Inbound
	if err := database.GetDB().Find(&inbounds).Error; err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	for _, inbound := range inbounds {
		if err := accountService.SyncInboundAccounts(database.GetDB(), inbound.Id); err != nil {
			t.Fatalf("sync accounts for inbound %d: %v", inbound.Id, err)
		}
	}
}

// inboundHolds reports whether an inbound's stored settings carry this email.
func inboundHolds(t *testing.T, inboundId int, email string) bool {
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
	for _, c := range settings.Clients {
		if got, _ := c["email"].(string); strings.EqualFold(strings.TrimSpace(got), email) {
			return true
		}
	}
	return false
}

// counts pulls applied/skipped/reasons out of the response object.
func membershipCounts(t *testing.T, msg map[string]any) (int, int, string) {
	t.Helper()
	if ok, _ := msg["success"].(bool); !ok {
		t.Fatalf("the request was refused: %v", msg["msg"])
	}
	obj, _ := msg["obj"].(map[string]any)
	applied, _ := obj["applied"].(float64)
	skipped, _ := obj["skipped"].(float64)
	reasons := ""
	if list, ok := obj["reasons"].([]any); ok {
		parts := make([]string, 0, len(list))
		for _, r := range list {
			parts = append(parts, r.(string))
		}
		reasons = strings.Join(parts, " | ")
	}
	return int(applied), int(skipped), reasons
}

// The Clients page expands one ticked account into one (inbound, email) pair per
// membership it already has, so a customer on two inbounds arrives TWICE in the
// same batch. Membership is an account-level act, so without reducing the list to
// accounts the operation runs once per pair: the second pass finds the inbound
// already added and counts a skip, and the run reports one applied and one skipped
// for what the operator saw as one customer.
func TestBulkMembershipAddCountsEachAccountOnce(t *testing.T) {
	env := newBulkMembershipEnv(t)
	vless := seedMembershipInbound(t, env.admin.Id, model.VLESS, 48101,
		`{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"bob@example.com","enable":true}`)
	trojan := seedMembershipInbound(t, env.admin.Id, model.Trojan, 48102,
		`{"password":"pw-bob","email":"bob@example.com","enable":true}`)
	vmess := seedMembershipInbound(t, env.admin.Id, model.VMESS, 48103, "")
	syncMembershipAccounts(t)

	// Both of bob's memberships, exactly as the page posts them.
	msg := bulkMembershipPost(t, env.admin, "/panel/api/inbounds/bulkMembership",
		bulkMembershipBody(t, "addInbounds", []int{vmess.Id}, []map[string]any{
			{"inboundId": vless.Id, "email": "bob@example.com"},
			{"inboundId": trojan.Id, "email": "bob@example.com"},
		}))

	applied, skipped, reasons := membershipCounts(t, msg)
	if applied != 1 || skipped != 0 {
		t.Errorf("applied=%d skipped=%d (%s), want 1 and 0: one account arrived as two "+
			"targets and the operation ran twice for it", applied, skipped, reasons)
	}
	if !inboundHolds(t, vmess.Id, "bob@example.com") {
		t.Error("the account was not added to the chosen inbound")
	}
	for _, id := range []int{vless.Id, trojan.Id} {
		if !inboundHolds(t, id, "bob@example.com") {
			t.Errorf("adding a membership dropped the account from inbound %d", id)
		}
	}
	ids, err := accountService.InboundIdsForEmail("bob@example.com")
	if err != nil {
		t.Fatalf("InboundIdsForEmail: %v", err)
	}
	if len(ids) != 3 {
		t.Errorf("memberships = %v, want three", ids)
	}
}

// Taking an account off its LAST inbound is allowed, and it is not a delete.
//
// This test used to assert the opposite, and the rule it pinned was a limitation of
// the writer rather than a decision: ApplyMemberships returned early on an empty
// wanted set, so "off every inbound" could not be expressed there at all, and the
// only path that could express it (the per-inbound delete) destroys the shared
// client_traffics row. An account may now deliberately sit on nothing, so what this
// checks is the thing that made the refusal worth having in the first place - that
// everything the customer would need to be put back survives the removal.
func TestBulkMembershipCanEmptyAnAccount(t *testing.T) {
	env := newBulkMembershipEnv(t)
	only := seedMembershipInbound(t, env.admin.Id, model.VLESS, 48201,
		`{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"solo@example.com","enable":true}`)
	syncMembershipAccounts(t)
	if err := database.GetDB().Create(&xray.ClientTraffic{
		InboundId: only.Id, Email: "solo@example.com", Enable: true, Up: 4096, Down: 8192,
	}).Error; err != nil {
		t.Fatalf("create client traffic: %v", err)
	}

	msg := bulkMembershipPost(t, env.admin, "/panel/api/inbounds/bulkMembership",
		bulkMembershipBody(t, "removeInbounds", []int{only.Id}, []map[string]any{
			{"inboundId": only.Id, "email": "solo@example.com"},
		}))

	applied, skipped, reasons := membershipCounts(t, msg)
	if applied != 1 || skipped != 0 {
		t.Errorf("applied=%d skipped=%d (%s), want 1 and 0", applied, skipped, reasons)
	}
	if inboundHolds(t, only.Id, "solo@example.com") {
		t.Error("the account is still on the inbound it was taken off")
	}
	if ids, err := accountService.InboundIdsForEmail("solo@example.com"); err != nil || len(ids) != 0 {
		t.Errorf("memberships = %v (err %v), want none", ids, err)
	}
	// The account itself, which is the difference between this and a delete.
	account, err := accountService.GetAccountByEmail("solo@example.com")
	if err != nil || account == nil {
		t.Fatalf("the account row was pruned (err %v)", err)
	}
	if account.UUID != "3fa85f64-5717-4562-b3fc-2c963f66afa6" {
		t.Errorf("uuid = %q, want the one the customer already has installed", account.UUID)
	}
	// The one that would be unrecoverable: client_traffics is one row per email
	// panel-wide, and dropping it takes the customer's whole usage history with it.
	ct := &xray.ClientTraffic{}
	if err := database.GetDB().Where("email = ?", "solo@example.com").First(ct).Error; err != nil {
		t.Fatalf("the client_traffics row is gone: %v", err)
	}
	if ct.Up != 4096 || ct.Down != 8192 {
		t.Errorf("usage = %d/%d, want 4096/8192", ct.Up, ct.Down)
	}
}

// ...but only for a super admin. An account on no inbound is outside every inbound
// grant, so it is outside the Clients list of the admin who made it: allowing this
// would look to them exactly like the operation deleted their customer. Skipped with
// a reason rather than refused whole, so the rest of a batch still runs.
func TestBulkMembershipEmptyingIsSuperAdminOnly(t *testing.T) {
	f := newIdorFixture(t)
	syncMembershipAccounts(t)

	msg := bulkMembershipPost(t, f.reza, "/panel/api/inbounds/bulkMembership",
		bulkMembershipBody(t, "removeInbounds", []int{f.rezaInbound.Id}, []map[string]any{
			{"inboundId": f.rezaInbound.Id, "email": "reza-client"},
		}))

	applied, skipped, reasons := membershipCounts(t, msg)
	if applied != 0 || skipped != 1 {
		t.Errorf("applied=%d skipped=%d, want 0 and 1", applied, skipped)
	}
	if !strings.Contains(reasons, "super admin") {
		t.Errorf("reasons = %q, want one naming the rule", reasons)
	}
	if !inboundHolds(t, f.rezaInbound.Id, "reza-client") {
		t.Error("the account was taken off its last inbound anyway")
	}
}

// l2tp, pptp and ikev2 authenticate through a shared daemon that sends a bare
// NAS-Identifier, so an account on two inbounds of one of those is always served
// by whichever has the lower id. The account looks provisioned on both and half of
// it silently never runs.
//
// The half the browser cannot catch is this one: ONE inbound is being added, and
// it clashes with a membership the account already has. Only the server knows each
// account's current set, so the refusal has to be per account, and it has to
// happen before anything is written.
func TestBulkMembershipRefusesASecondSameProtocolInbound(t *testing.T) {
	env := newBulkMembershipEnv(t)
	vless := seedMembershipInbound(t, env.admin.Id, model.VLESS, 48301,
		`{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"bob@example.com","enable":true}`)
	firstL2tp := seedMembershipInbound(t, env.admin.Id, model.L2TP, 48302,
		`{"id":"bob-login","password":"pw","email":"bob@example.com","enable":true}`)
	secondL2tp := seedMembershipInbound(t, env.admin.Id, model.L2TP, 48303, "")
	syncMembershipAccounts(t)

	msg := bulkMembershipPost(t, env.admin, "/panel/api/inbounds/bulkMembership",
		bulkMembershipBody(t, "addInbounds", []int{secondL2tp.Id}, []map[string]any{
			{"inboundId": vless.Id, "email": "bob@example.com"},
			{"inboundId": firstL2tp.Id, "email": "bob@example.com"},
		}))

	applied, skipped, reasons := membershipCounts(t, msg)
	if applied != 0 || skipped != 1 {
		t.Errorf("applied=%d skipped=%d, want 0 and 1", applied, skipped)
	}
	if !strings.Contains(reasons, "l2tp") {
		t.Errorf("reasons = %q, want one naming the protocol", reasons)
	}
	if inboundHolds(t, secondL2tp.Id, "bob@example.com") {
		t.Error("the account was written onto a second l2tp inbound, where it can never be served")
	}
	if !inboundHolds(t, firstL2tp.Id, "bob@example.com") {
		t.Error("a refused add disturbed the membership the account already had")
	}
}

// psk and eap-tls IKEv2 inbounds share one key or one client certificate across
// the whole inbound, so a second account there is a second name for the same
// credential. AddInboundClient refuses it; ApplyMemberships has never heard of an
// auth mode, so the membership path has to run the same guard (AdmitAccount).
func TestBulkMembershipHonoursTheIkev2AdmissionRule(t *testing.T) {
	env := newBulkMembershipEnv(t)
	vless := seedMembershipInbound(t, env.admin.Id, model.VLESS, 48401,
		`{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"bob@example.com","enable":true}`)
	psk := &model.Inbound{
		UserId: env.admin.Id, Tag: "ikev2-48402", Port: 48402, Protocol: model.IKEV2, Enable: true,
		Settings: `{"authMode":"psk","clients":[{"email":"first@example.com","enable":true}]}`,
	}
	if err := database.GetDB().Create(psk).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	syncMembershipAccounts(t)

	msg := bulkMembershipPost(t, env.admin, "/panel/api/inbounds/bulkMembership",
		bulkMembershipBody(t, "addInbounds", []int{psk.Id}, []map[string]any{
			{"inboundId": vless.Id, "email": "bob@example.com"},
		}))

	applied, skipped, reasons := membershipCounts(t, msg)
	if applied != 0 || skipped != 1 {
		t.Errorf("applied=%d skipped=%d, want 0 and 1", applied, skipped)
	}
	if !strings.Contains(strings.ToLower(reasons), "psk") {
		t.Errorf("reasons = %q, want one naming the auth mode", reasons)
	}
	if inboundHolds(t, psk.Id, "bob@example.com") {
		t.Error("a second account was added to a PSK IKEv2 inbound")
	}
}

// Removing a membership must leave client_traffics alone. That row is keyed on
// email and is panel-wide, not per inbound: it carries the quota, the counters and
// the enable bit every enforcement path reads. Deleting the account (the other way
// to take it off an inbound) destroys it, which is precisely why this path does
// not fall back to a delete.
func TestBulkMembershipRemovalKeepsTheUsageRow(t *testing.T) {
	env := newBulkMembershipEnv(t)
	keep := seedMembershipInbound(t, env.admin.Id, model.VLESS, 48501,
		`{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"bob@example.com","enable":true}`)
	drop := seedMembershipInbound(t, env.admin.Id, model.Trojan, 48502,
		`{"password":"pw-bob","email":"bob@example.com","enable":true}`)
	syncMembershipAccounts(t)
	if err := database.GetDB().Create(&xray.ClientTraffic{
		InboundId: keep.Id, Email: "bob@example.com", Enable: true,
		Up: 111, Down: 222, Total: 999,
	}).Error; err != nil {
		t.Fatalf("create client traffic: %v", err)
	}

	msg := bulkMembershipPost(t, env.admin, "/panel/api/inbounds/bulkMembership",
		bulkMembershipBody(t, "removeInbounds", []int{drop.Id}, []map[string]any{
			{"inboundId": keep.Id, "email": "bob@example.com"},
			{"inboundId": drop.Id, "email": "bob@example.com"},
		}))

	applied, skipped, reasons := membershipCounts(t, msg)
	if applied != 1 || skipped != 0 {
		t.Errorf("applied=%d skipped=%d (%s), want 1 and 0", applied, skipped, reasons)
	}
	if inboundHolds(t, drop.Id, "bob@example.com") {
		t.Error("the account is still on the inbound it was removed from")
	}
	if !inboundHolds(t, keep.Id, "bob@example.com") {
		t.Error("removing one membership took the account off the other inbound too")
	}
	ct := &xray.ClientTraffic{}
	if err := database.GetDB().Where("email = ?", "bob@example.com").First(ct).Error; err != nil {
		t.Fatalf("the client_traffics row was destroyed by a membership removal: %v", err)
	}
	if ct.Up != 111 || ct.Down != 222 || ct.Total != 999 {
		t.Errorf("usage/quota = %d/%d of %d, want 111/222 of 999", ct.Up, ct.Down, ct.Total)
	}
}

// Ownership, over the two id sets that decide this operation. Neither is visible
// to a route middleware: both arrive in the body.
//
// Run as an ordinary admin on purpose. A super admin bypasses every check, so the
// same suite run as one passes with every hole open.
func TestBulkMembershipOwnership(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Adding is authorised by owning the inbound added TO. Ali's inbound is named
	// in inboundIds, where the route table cannot see it.
	t.Run("cannot add an account onto another admin's inbound", func(t *testing.T) {
		f := newIdorFixture(t)
		syncMembershipAccounts(t)
		msg := bulkMembershipPost(t, f.reza, "/panel/api/inbounds/bulkMembership",
			bulkMembershipBody(t, "addInbounds", []int{f.aliInbound.Id}, []map[string]any{
				{"inboundId": f.rezaInbound.Id, "email": "reza-client"},
			}))
		if ok, _ := msg["success"].(bool); ok {
			t.Errorf("the request was accepted: %v", msg)
		}
		if inboundHolds(t, f.aliInbound.Id, "reza-client") {
			t.Error("Reza put his account on Ali's inbound: a live account eating the " +
				"victim's IP pool and user-limit capacity")
		}
	})

	// Removing is authorised by owning the inbound removed FROM, which is a
	// different set. Here BOTH lists name Ali's inbound.
	t.Run("cannot remove another admin's account from their inbound", func(t *testing.T) {
		f := newIdorFixture(t)
		syncMembershipAccounts(t)
		msg := bulkMembershipPost(t, f.reza, "/panel/api/inbounds/bulkMembership",
			bulkMembershipBody(t, "removeInbounds", []int{f.aliInbound.Id}, []map[string]any{
				{"inboundId": f.aliInbound.Id, "email": f.aliEmail},
			}))
		if ok, _ := msg["success"].(bool); ok {
			t.Errorf("the request was accepted: %v", msg)
		}
		if !inboundHolds(t, f.aliInbound.Id, f.aliEmail) {
			t.Error("Reza unprovisioned Ali's customer")
		}
	})

	// The batch is refused WHOLE rather than applied to the part the caller owns,
	// matching bulkUpdateClients: a partial apply on a set the operator believes
	// they selected is worse than a refusal.
	t.Run("one foreign target refuses the whole batch", func(t *testing.T) {
		f := newIdorFixture(t)
		second := &model.Inbound{
			UserId: f.reza.Id, Tag: "inbound-41004", Port: 41004, Protocol: model.VMESS,
			Enable: true, Settings: `{"clients":[]}`,
		}
		if err := database.GetDB().Create(second).Error; err != nil {
			t.Fatalf("create inbound: %v", err)
		}
		if err := database.GetDB().Create(&model.InboundAccess{UserId: f.reza.Id, InboundId: second.Id}).Error; err != nil {
			t.Fatalf("grant access: %v", err)
		}
		syncMembershipAccounts(t)

		msg := bulkMembershipPost(t, f.reza, "/panel/api/inbounds/bulkMembership",
			bulkMembershipBody(t, "addInbounds", []int{second.Id}, []map[string]any{
				{"inboundId": f.rezaInbound.Id, "email": "reza-client"},
				{"inboundId": f.aliInbound.Id, "email": f.aliEmail}, // the poisoned one
			}))
		if ok, _ := msg["success"].(bool); ok {
			t.Errorf("a batch naming one foreign inbound was accepted: %v", msg)
		}
		if inboundHolds(t, second.Id, f.aliEmail) {
			t.Error("Ali's account was re-homed onto Reza's inbound")
		}
		if inboundHolds(t, second.Id, "reza-client") {
			t.Error("the batch was applied in part; it must be refused whole")
		}
	})

	// And the refusals above are not vacuous: the same request over inbounds Reza
	// really owns goes through.
	t.Run("an admin can re-home their own account", func(t *testing.T) {
		f := newIdorFixture(t)
		second := &model.Inbound{
			UserId: f.reza.Id, Tag: "inbound-41005", Port: 41005, Protocol: model.VMESS,
			Enable: true, Settings: `{"clients":[]}`,
		}
		if err := database.GetDB().Create(second).Error; err != nil {
			t.Fatalf("create inbound: %v", err)
		}
		if err := database.GetDB().Create(&model.InboundAccess{UserId: f.reza.Id, InboundId: second.Id}).Error; err != nil {
			t.Fatalf("grant access: %v", err)
		}
		syncMembershipAccounts(t)

		msg := bulkMembershipPost(t, f.reza, "/panel/api/inbounds/bulkMembership",
			bulkMembershipBody(t, "addInbounds", []int{second.Id}, []map[string]any{
				{"inboundId": f.rezaInbound.Id, "email": "reza-client"},
			}))
		applied, skipped, reasons := membershipCounts(t, msg)
		if applied != 1 || skipped != 0 {
			t.Errorf("applied=%d skipped=%d (%s), want 1 and 0", applied, skipped, reasons)
		}
		if !inboundHolds(t, second.Id, "reza-client") {
			t.Error("an admin could not add their own account to their own inbound")
		}
	})
}

// A reseller holds the bulk-operation bit, so the route gate lets them in. The
// refusal is deliberate and explicit: their grant says which inbounds they may
// sell FROM, not that they may move a customer between them, and re-homing spends
// another admin's IP pool and user-limit capacity on a shared inbound. Nothing
// about it is priced in bytes, so the ledger has no opinion to fall back on.
func TestBulkMembershipIsRefusedForResellers(t *testing.T) {
	env := newBulkMembershipEnv(t)
	first := seedMembershipInbound(t, env.admin.Id, model.VLESS, 48601,
		`{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"bob@example.com","enable":true}`)
	second := seedMembershipInbound(t, env.admin.Id, model.VMESS, 48602, "")
	syncMembershipAccounts(t)

	all := model.Permission(0)
	for _, d := range model.AllPermissions {
		all |= d.Bit
	}
	sara := &model.User{Username: "sara", Password: "x", Enable: true,
		IsReseller: true, Permissions: all}
	if err := database.GetDB().Create(sara).Error; err != nil {
		t.Fatalf("create reseller: %v", err)
	}
	for _, id := range []int{first.Id, second.Id} {
		if err := database.GetDB().Create(&model.InboundAccess{UserId: sara.Id, InboundId: id}).Error; err != nil {
			t.Fatalf("grant access: %v", err)
		}
	}

	msg := bulkMembershipPost(t, sara, "/panel/api/inbounds/bulkMembership",
		bulkMembershipBody(t, "addInbounds", []int{second.Id}, []map[string]any{
			{"inboundId": first.Id, "email": "bob@example.com"},
		}))
	if ok, _ := msg["success"].(bool); ok {
		t.Errorf("a reseller re-homed an account: %v", msg)
	}
	if inboundHolds(t, second.Id, "bob@example.com") {
		t.Error("the account was moved despite the refusal")
	}
}

// An op the handler does not know must be refused rather than fall through to
// something. The two membership ops are also not ops of bulkUpdateClients, and
// posting one there hits that applier's own whitelist.
func TestBulkMembershipRejectsUnknownOps(t *testing.T) {
	env := newBulkMembershipEnv(t)
	inbound := seedMembershipInbound(t, env.admin.Id, model.VLESS, 48701,
		`{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"bob@example.com","enable":true}`)
	syncMembershipAccounts(t)

	msg := bulkMembershipPost(t, env.admin, "/panel/api/inbounds/bulkMembership",
		bulkMembershipBody(t, "enable", []int{inbound.Id}, []map[string]any{
			{"inboundId": inbound.Id, "email": "bob@example.com"},
		}))
	if ok, _ := msg["success"].(bool); ok {
		t.Errorf("a client op was accepted by the membership route: %v", msg)
	}

	// No inbound named is not "every inbound", and not a silent success either.
	msg = bulkMembershipPost(t, env.admin, "/panel/api/inbounds/bulkMembership",
		bulkMembershipBody(t, "addInbounds", nil, []map[string]any{
			{"inboundId": inbound.Id, "email": "bob@example.com"},
		}))
	if ok, _ := msg["success"].(bool); ok {
		t.Errorf("an empty inbound set was accepted: %v", msg)
	}

	msg = bulkMembershipPost(t, env.admin, "/panel/api/inbounds/bulkUpdateClients",
		bulkMembershipBody(t, "addInbounds", []int{inbound.Id}, []map[string]any{
			{"inboundId": inbound.Id, "email": "bob@example.com"},
		}))
	if ok, _ := msg["success"].(bool); ok {
		t.Errorf("the client applier accepted a membership op: %v", msg)
	}
}
