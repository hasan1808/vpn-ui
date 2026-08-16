package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/crypto"
	"github.com/hasan1808/pro-ui/web/locale"
	"github.com/hasan1808/pro-ui/xray"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"
	"github.com/xlzd/gotp"
)

// Cross-admin isolation, driven end to end.
//
// This exists because the unit tests could not have caught the bugs it pins. They
// exercise the middleware in isolation (a seeded context, no DB) and the services
// in isolation (no routes), and every real IDOR lived in the seam between the two:
// a route whose actual target is resolved somewhere the route table cannot see,
// either a body field or a service that re-resolves by email and ignores the path
// id. `owns` on a path :id proves nothing until you read the service it fronts.
//
// It also runs as a NON-super admin on purpose. Super admins bypass every ownership
// check, so the same suite run as a super admin passes while every hole is open.
//
// Each case is a real HTTP request through a real router against a real SQLite,
// asking: can Reza touch Ali's inbound?

type idorFixture struct {
	router *gin.Engine
	ali    *model.User
	reza   *model.User
	// Ali's, the victim's.
	aliInbound  *model.Inbound
	aliEmail    string
	rezaInbound *model.Inbound
}

// as builds a request authenticated as the given admin, bypassing the cookie by
// seeding the same per-request cache session.GetLoginUser reads.
func (f *idorFixture) as(t *testing.T, user *model.User, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("LOGIN_USER_ROW", user)
		c.Set("base_path", "/")
		c.Set("I18n", func(i18nType locale.I18nType, key string, keyParams ...string) string { return key })
		c.Next()
	})
	NewInboundController(r.Group("/panel/api/inbounds"))

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func newIdorFixture(t *testing.T) *idorFixture {
	t.Helper()
	// The controllers log; without this the package-level logger is nil and any
	// warning panics rather than reporting the finding under test.
	logger.InitLogger(logging.CRITICAL)
	if err := database.InitDB(filepath.Join(t.TempDir(), "idor.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	// Two ordinary admins. Reza deliberately holds EVERY capability bit: this suite
	// is about ownership, not permissions, so Reza must fail purely because the
	// objects are not his.
	all := model.Permission(0)
	for _, d := range model.AllPermissions {
		all |= d.Bit
	}
	ali := &model.User{Username: "ali", Password: "x", Enable: true, Permissions: all}
	reza := &model.User{Username: "reza", Password: "x", Enable: true, Permissions: all}
	for _, u := range []*model.User{ali, reza} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create admin: %v", err)
		}
	}

	aliInbound := &model.Inbound{
		UserId: ali.Id, Tag: "inbound-41001", Port: 41001, Protocol: model.VMESS, Enable: true,
		Settings: `{"clients":[{"id":"ali-uuid","email":"ali-client","enable":true}]}`,
	}
	rezaInbound := &model.Inbound{
		UserId: reza.Id, Tag: "inbound-41002", Port: 41002, Protocol: model.VMESS, Enable: true,
		Settings: `{"clients":[{"id":"reza-uuid","email":"reza-client","enable":true}]}`,
	}
	for _, ib := range []*model.Inbound{aliInbound, rezaInbound} {
		if err := db.Create(ib).Error; err != nil {
			t.Fatalf("create inbound: %v", err)
		}
	}
	// Access is ASSIGNED, so creating a row grants nothing. Give each admin exactly
	// their own, which is what a super admin ticking the checklist does.
	for _, g := range []*model.InboundAccess{
		{UserId: ali.Id, InboundId: aliInbound.Id},
		{UserId: reza.Id, InboundId: rezaInbound.Id},
	} {
		if err := db.Create(g).Error; err != nil {
			t.Fatalf("grant access: %v", err)
		}
	}

	// Ali's client is DISABLED and has usage, so a cross-admin reset is observable:
	// it would both zero the counter and force-enable it.
	if err := db.Create(&xray.ClientTraffic{
		InboundId: aliInbound.Id, Email: "ali-client", Enable: false, Up: 5000, Down: 5000,
	}).Error; err != nil {
		t.Fatalf("create client traffic: %v", err)
	}

	return &idorFixture{ali: ali, reza: reza, aliInbound: aliInbound, aliEmail: "ali-client", rezaInbound: rezaInbound}
}

func (f *idorFixture) aliSettings(t *testing.T) string {
	t.Helper()
	ib := &model.Inbound{}
	if err := database.GetDB().Where("id = ?", f.aliInbound.Id).First(ib).Error; err != nil {
		t.Fatalf("reload Ali's inbound: %v", err)
	}
	return ib.Settings
}

// TestCrossAdminIsolation is the regression suite for every cross-admin hole.
// Each subtest is a concrete exploit: Reza, fully permissioned but not the owner,
// reaching for Ali's data.
func TestCrossAdminIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("addClient onto another admin's inbound", func(t *testing.T) {
		f := newIdorFixture(t)
		// The target inbound is a BODY field, invisible to the route table.
		body := url.Values{
			"id":       {fmt.Sprint(f.aliInbound.Id)},
			"settings": {`{"clients":[{"id":"reza-backdoor","email":"reza-backdoor","enable":true}]}`},
		}.Encode()
		f.as(t, f.reza, http.MethodPost, "/panel/api/inbounds/addClient", body)

		if strings.Contains(f.aliSettings(t), "reza-backdoor") {
			t.Error("Reza provisioned a live account on Ali's inbound: it eats Ali's IP pool " +
				"and quota and never shows in Reza's own list")
		}
	})

	// One account can now be asked for on SEVERAL inbounds, and every one of them
	// arrives in the body. Checking only the target id would reopen the exact hole
	// the addClient case above pins, one field to the left.
	t.Run("addClient with a membership on another admin's inbound", func(t *testing.T) {
		f := newIdorFixture(t)
		body := url.Values{
			"id":         {fmt.Sprint(f.rezaInbound.Id)}, // his own, so the target check passes
			"inboundIds": {fmt.Sprint(f.rezaInbound.Id), fmt.Sprint(f.aliInbound.Id)},
			"settings":   {`{"clients":[{"id":"reza-spread","email":"reza-spread","enable":true}]}`},
		}.Encode()
		f.as(t, f.reza, http.MethodPost, "/panel/api/inbounds/addClient", body)

		if strings.Contains(f.aliSettings(t), "reza-spread") {
			t.Error("Reza put a membership on Ali's inbound by listing it in inboundIds: " +
				"a live account on the victim's inbound, eating their IP pool and quota")
		}
	})

	t.Run("updateClient adding a membership on another admin's inbound", func(t *testing.T) {
		f := newIdorFixture(t)
		body := url.Values{
			"id":         {fmt.Sprint(f.rezaInbound.Id)},
			"inboundIds": {fmt.Sprint(f.rezaInbound.Id), fmt.Sprint(f.aliInbound.Id)},
			"settings":   {`{"clients":[{"id":"reza-uuid","email":"reza-client","enable":true}]}`},
		}.Encode()
		f.as(t, f.reza, http.MethodPost, "/panel/api/inbounds/updateClient/reza-uuid", body)

		if strings.Contains(f.aliSettings(t), "reza-client") {
			t.Error("Reza spread his account onto Ali's inbound through an edit")
		}
	})

	t.Run("copyClients from another admin's inbound", func(t *testing.T) {
		f := newIdorFixture(t)
		// Destination is Reza's own (so `owns` on :id passes); the SOURCE is Ali's and
		// arrives in the body. An empty clientEmails copies everything.
		body := url.Values{"sourceInboundId": {fmt.Sprint(f.aliInbound.Id)}}.Encode()
		w := f.as(t, f.reza, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/%d/copyClients", f.rezaInbound.Id), body)

		ib := &model.Inbound{}
		database.GetDB().Where("id = ?", f.rezaInbound.Id).First(ib)
		if strings.Contains(ib.Settings, "ali-client") || strings.Contains(w.Body.String(), "ali-client") {
			t.Error("Reza copied Ali's client credentials (uuid/password/email) into his own " +
				"inbound and can read them straight back out")
		}
	})

	t.Run("resetClientTraffic on another admin's client", func(t *testing.T) {
		f := newIdorFixture(t)
		// Reza's OWN inbound id (so `owns` passes) plus Ali's client email. The service
		// resolves by email and ignores the id.
		f.as(t, f.reza, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/%d/resetClientTraffic/%s", f.rezaInbound.Id, f.aliEmail), "")

		ct := &xray.ClientTraffic{}
		database.GetDB().Where("email = ?", f.aliEmail).First(ct)
		if ct.Up == 0 && ct.Down == 0 {
			t.Error("Reza zeroed Ali's client usage")
		}
		if ct.Enable {
			t.Error("Reza force-enabled a client Ali had disabled, defeating quota enforcement")
		}
	})

	t.Run("read another admin's inbound", func(t *testing.T) {
		f := newIdorFixture(t)
		w := f.as(t, f.reza, http.MethodGet,
			fmt.Sprintf("/panel/api/inbounds/get/%d", f.aliInbound.Id), "")
		if strings.Contains(w.Body.String(), "ali-uuid") {
			t.Errorf("Reza read Ali's inbound config: %s", w.Body.String())
		}
	})

	t.Run("delete another admin's inbound", func(t *testing.T) {
		f := newIdorFixture(t)
		f.as(t, f.reza, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/del/%d", f.aliInbound.Id), "")
		var n int64
		database.GetDB().Model(model.Inbound{}).Where("id = ?", f.aliInbound.Id).Count(&n)
		if n == 0 {
			t.Error("Reza deleted Ali's inbound")
		}
	})

	t.Run("list is scoped to the caller", func(t *testing.T) {
		f := newIdorFixture(t)
		w := f.as(t, f.reza, http.MethodGet, "/panel/api/inbounds/list", "")
		if strings.Contains(w.Body.String(), "41001") {
			t.Error("Ali's inbound appears in Reza's list")
		}
		if !strings.Contains(w.Body.String(), "41002") {
			t.Error("Reza's OWN inbound is missing from his list; scoping is too aggressive")
		}
	})

	t.Run("onlines and lastOnline do not leak other admins' clients", func(t *testing.T) {
		f := newIdorFixture(t)
		for _, path := range []string{"/panel/api/inbounds/onlines", "/panel/api/inbounds/lastOnline"} {
			w := f.as(t, f.reza, http.MethodPost, path, "")
			if strings.Contains(w.Body.String(), f.aliEmail) {
				t.Errorf("%s leaked Ali's client roster to Reza: %s", path, w.Body.String())
			}
		}
	})

	t.Run("bulk ops cannot target another admin's inbound", func(t *testing.T) {
		f := newIdorFixture(t)
		payload, _ := json.Marshal(map[string]any{
			"op": "resetTraffic",
			"targets": []map[string]any{
				{"inboundId": f.rezaInbound.Id, "email": "reza-client"},
				{"inboundId": f.aliInbound.Id, "email": f.aliEmail}, // the poisoned one
			},
		})
		f.as(t, f.reza, http.MethodPost, "/panel/api/inbounds/bulkUpdateClients",
			url.Values{"data": {string(payload)}}.Encode())

		ct := &xray.ClientTraffic{}
		database.GetDB().Where("email = ?", f.aliEmail).First(ct)
		if ct.Up == 0 && ct.Down == 0 {
			t.Error("a bulk batch containing one foreign inbound reached Ali's client; " +
				"the batch must be refused whole, not applied partially")
		}
	})

	// The list's display order is stored panel-wide and shared by every admin, so a
	// reorder naming someone else's inbound would move a row in THEIR table. The ids
	// arrive in the body, where no route middleware can see them.
	t.Run("reorder cannot name another admin's inbound", func(t *testing.T) {
		f := newIdorFixture(t)
		db := database.GetDB()
		// A second inbound for Reza, so he has a list of his own to rearrange.
		rezaSecond := &model.Inbound{
			UserId: f.reza.Id, Tag: "inbound-41003", Port: 41003, Protocol: model.VMESS,
			Enable: true, Settings: `{"clients":[]}`,
		}
		if err := db.Create(rezaSecond).Error; err != nil {
			t.Fatalf("create inbound: %v", err)
		}
		if err := db.Create(&model.InboundAccess{UserId: f.reza.Id, InboundId: rezaSecond.Id}).Error; err != nil {
			t.Fatalf("grant access: %v", err)
		}

		order := func(id int) int {
			ib := &model.Inbound{}
			if err := db.Where("id = ?", id).First(ib).Error; err != nil {
				t.Fatalf("reload inbound %d: %v", id, err)
			}
			return ib.SortOrder
		}

		// Ali's inbound in the list: refused whole, and nothing is written.
		payload, _ := json.Marshal([]int{f.aliInbound.Id, rezaSecond.Id, f.rezaInbound.Id})
		f.as(t, f.reza, http.MethodPost, "/panel/api/inbounds/reorder",
			url.Values{"data": {string(payload)}}.Encode())
		if order(f.aliInbound.Id) != 0 || order(f.rezaInbound.Id) != 0 {
			t.Error("a reorder naming another admin's inbound was applied; it must be " +
				"refused whole, since the order it writes is the one Ali sees too")
		}

		// His own two, on the other hand, swap. And Ali's inbound, which sits between
		// them in the panel-wide order, must not be dragged along.
		payload, _ = json.Marshal([]int{rezaSecond.Id, f.rezaInbound.Id})
		w := f.as(t, f.reza, http.MethodPost, "/panel/api/inbounds/reorder",
			url.Values{"data": {string(payload)}}.Encode())
		if !strings.Contains(w.Body.String(), `"success":true`) {
			t.Fatalf("an admin cannot reorder their own inbounds: %s", w.Body.String())
		}
		if got := order(rezaSecond.Id); got != 2 {
			t.Errorf("reza's second inbound is at %d; want slot 2, the one his first held", got)
		}
		if got := order(f.rezaInbound.Id); got != 3 {
			t.Errorf("reza's first inbound is at %d; want slot 3", got)
		}
		if got := order(f.aliInbound.Id); got != 1 {
			t.Errorf("Ali's inbound moved to %d; a reorder must pin every row the caller "+
				"cannot see where it already was", got)
		}
	})

	// The property that distinguishes ASSIGNED access from created-by ownership: a
	// grant can be given and taken away for an inbound the admin never created.
	t.Run("a granted inbound becomes visible, a revoked one disappears", func(t *testing.T) {
		f := newIdorFixture(t)
		db := database.GetDB()

		// Reza did not create Ali's inbound and cannot see it.
		w := f.as(t, f.reza, http.MethodGet, "/panel/api/inbounds/list", "")
		if strings.Contains(w.Body.String(), "41001") {
			t.Fatal("Ali's inbound is visible to Reza before any grant")
		}

		// The super admin ticks it for Reza.
		if err := db.Create(&model.InboundAccess{UserId: f.reza.Id, InboundId: f.aliInbound.Id}).Error; err != nil {
			t.Fatalf("grant: %v", err)
		}
		w = f.as(t, f.reza, http.MethodGet, "/panel/api/inbounds/list", "")
		if !strings.Contains(w.Body.String(), "41001") {
			t.Error("a granted inbound must appear in the admin's list")
		}
		w = f.as(t, f.reza, http.MethodGet, fmt.Sprintf("/panel/api/inbounds/get/%d", f.aliInbound.Id), "")
		if !strings.Contains(w.Body.String(), "ali-uuid") {
			t.Error("a granted inbound must be reachable, not just listed")
		}

		// And untick it.
		if err := db.Where("user_id = ? AND inbound_id = ?", f.reza.Id, f.aliInbound.Id).
			Delete(&model.InboundAccess{}).Error; err != nil {
			t.Fatalf("revoke: %v", err)
		}
		w = f.as(t, f.reza, http.MethodGet, fmt.Sprintf("/panel/api/inbounds/get/%d", f.aliInbound.Id), "")
		if strings.Contains(w.Body.String(), "ali-uuid") {
			t.Error("a revoked inbound must stop being reachable immediately")
		}
	})

	// The counterpart: a super admin SHOULD reach everything. Without this the suite
	// would pass just as well if ownership refused everyone.
	t.Run("super admin bypasses ownership", func(t *testing.T) {
		f := newIdorFixture(t)
		// A real super admin, holding NO grants: they must reach everything by role.
		super := &model.User{}
		if err := database.GetDB().Model(model.User{}).Where("is_super_admin = ?", true).
			First(super).Error; err != nil {
			t.Fatalf("no seeded super admin: %v", err)
		}
		w := f.as(t, super, http.MethodGet,
			fmt.Sprintf("/panel/api/inbounds/get/%d", f.aliInbound.Id), "")
		if !strings.Contains(w.Body.String(), "ali-uuid") {
			t.Errorf("a super admin must be able to read any inbound; got %s", w.Body.String())
		}
	})
}

// Reseller isolation, on the case the admin-vs-admin suite above cannot reach.
//
// Every check in that suite keys, one way or another, on the inbound grant, and for
// two admins the grant IS the answer: if Reza does not hold Ali's inbound he cannot
// touch anything on it. A reseller breaks that equivalence. Sara is assigned Ali's
// inbound (that is the whole point of the role: she sells on inbounds an admin gave
// her), so every grant check passes for her on every account there, Ali's included.
// The only question that separates them is who created the account, and these tests
// are the ones that fail if any route asks the grant question instead.
type resellerFixture struct {
	*idorFixture
	sara *model.User
	// Sara's own account, on ALI's inbound, alongside Ali's.
	saraEmail string
}

const testGB = int64(1024 * 1024 * 1024)

func newResellerFixture(t *testing.T) *resellerFixture {
	t.Helper()
	f := newIdorFixture(t)
	db := database.GetDB()

	// A non-zero stored mask on purpose: Can() must derive a reseller's rights from
	// the role, so this column has to be inert. If it were read, Sara would hold
	// manageResellers and the panel settings bits the role deliberately withholds.
	all := model.Permission(0)
	for _, d := range model.AllPermissions {
		all |= d.Bit
	}
	sara := &model.User{Username: "sara", Password: "x", Enable: true, IsReseller: true, Permissions: all}
	if err := db.Create(sara).Error; err != nil {
		t.Fatalf("create reseller: %v", err)
	}
	if err := db.Create(&model.ResellerProfile{
		UserId: sara.Id, AllowanceBytes: 100 * testGB, CreatedBy: f.ali.Id,
	}).Error; err != nil {
		t.Fatalf("create reseller profile: %v", err)
	}
	// The shared inbound. Sara sells on Ali's.
	if err := db.Create(&model.InboundAccess{UserId: sara.Id, InboundId: f.aliInbound.Id}).Error; err != nil {
		t.Fatalf("assign inbound: %v", err)
	}

	// Sara's account lives beside Ali's in the same settings blob, which is exactly
	// how it looks in production and why a per-inbound filter is not enough.
	// Sara's account is stored DISABLED, like Ali's above. Both the delete and the
	// reset path dial the Xray API for an account Xray currently holds, and this
	// harness has no Xray process; nothing else about either path changes.
	saraEmail := "sara-client"
	if err := db.Model(model.Inbound{}).Where("id = ?", f.aliInbound.Id).
		Update("settings", `{"clients":[`+
			`{"id":"ali-uuid","email":"ali-client","enable":true,"totalGB":0},`+
			`{"id":"sara-uuid","email":"sara-client","enable":false,"totalGB":10737418240}]}`).
		Error; err != nil {
		t.Fatalf("seed shared inbound: %v", err)
	}
	// 2000 bytes on the counters: what a reset would clear, and so what it costs.
	if err := db.Create(&xray.ClientTraffic{
		InboundId: f.aliInbound.Id, Email: saraEmail, Enable: false,
		Up: 1000, Down: 1000, AllTime: 2000, Total: 10 * testGB,
	}).Error; err != nil {
		t.Fatalf("create reseller client traffic: %v", err)
	}
	if err := db.Create(&model.ResellerClient{
		Email: saraEmail, InboundId: f.aliInbound.Id, UserId: sara.Id,
		ChargedBytes: 10 * testGB,
	}).Error; err != nil {
		t.Fatalf("create ownership row: %v", err)
	}
	// 10 GB already committed to that account, out of 100.
	if err := db.Model(&model.ResellerProfile{}).Where("user_id = ?", sara.Id).
		Update("spent_bytes", 10*testGB).Error; err != nil {
		t.Fatalf("seed spent: %v", err)
	}

	return &resellerFixture{idorFixture: f, sara: sara, saraEmail: saraEmail}
}

// zeroUsage makes an account one that has never carried traffic.
func zeroUsage(t *testing.T, email string) {
	t.Helper()
	if err := database.GetDB().Model(&xray.ClientTraffic{}).Where("email = ?", email).
		Updates(map[string]any{"up": 0, "down": 0, "all_time": 0}).Error; err != nil {
		t.Fatalf("zero usage: %v", err)
	}
}

func (f *resellerFixture) spent(t *testing.T) int64 {
	t.Helper()
	p := &model.ResellerProfile{}
	if err := database.GetDB().Model(&model.ResellerProfile{}).
		Where("user_id = ?", f.sara.Id).First(p).Error; err != nil {
		t.Fatalf("read profile: %v", err)
	}
	return p.SpentBytes
}

func TestResellerIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("cannot read an admin's client on a shared inbound", func(t *testing.T) {
		f := newResellerFixture(t)

		// The grant check would pass here: Sara holds this inbound.
		w := f.as(t, f.sara, http.MethodGet,
			"/panel/api/inbounds/getClientTraffics/"+f.aliEmail, "")
		if strings.Contains(w.Body.String(), f.aliEmail) {
			t.Errorf("a reseller read Ali's account off a shared inbound: %s", w.Body.String())
		}
		w = f.as(t, f.sara, http.MethodPost, "/panel/api/inbounds/clientIps/"+f.aliEmail, "")
		if !strings.Contains(w.Body.String(), `"success":false`) {
			t.Errorf("a reseller reached Ali's client IP log: %s", w.Body.String())
		}

		// Her OWN account still resolves, or the scoping is simply refusing everyone.
		w = f.as(t, f.sara, http.MethodGet,
			"/panel/api/inbounds/getClientTraffics/"+f.saraEmail, "")
		if !strings.Contains(w.Body.String(), f.saraEmail) {
			t.Errorf("a reseller cannot read their OWN account: %s", w.Body.String())
		}
	})

	// /list is scoped by GetInboundsFor, and this route hands back the SAME row
	// without going through it. The middleware cannot stand in: `owns` passes because
	// the reseller genuinely holds this inbound, which is the whole premise of the
	// role. So one GET returned every account on it, credentials included.
	t.Run("get by id returns only the caller's own clients", func(t *testing.T) {
		f := newResellerFixture(t)
		// The inbound's own counters, which cover both accounts on it. They are what
		// the Inbounds page sums into its usage band, and they are not derived from
		// the client rows the filter strips.
		if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", f.aliInbound.Id).
			Updates(map[string]any{"up": 6000, "down": 6000, "all_time": 12000}).Error; err != nil {
			t.Fatalf("seed the inbound totals: %v", err)
		}
		w := f.as(t, f.sara, http.MethodGet,
			fmt.Sprintf("/panel/api/inbounds/get/%d", f.aliInbound.Id), "")
		body := w.Body.String()

		// On the RAW body, not a parsed struct: the settings blob crosses the wire as
		// an opaque string that the Inbounds page parses client-side, so a filter that
		// only cleaned the modelled fields would still ship the credentials here.
		for _, secret := range []string{f.aliEmail, "ali-uuid"} {
			if strings.Contains(body, secret) {
				t.Errorf("a reseller read %q off an inbound they merely share: %s", secret, body)
			}
		}
		// Positive control: the route must still work and still show her own account,
		// or this passes just as well when the whole request is refused.
		if !strings.Contains(body, f.saraEmail) {
			t.Fatalf("the reseller's OWN account is missing from their own inbound: %s", body)
		}

		var resp struct {
			Obj struct {
				Settings    string               `json:"settings"`
				ClientStats []xray.ClientTraffic `json:"clientStats"`
				Up          int64                `json:"up"`
				Down        int64                `json:"down"`
				AllTime     int64                `json:"allTime"`
			} `json:"obj"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		var settings struct {
			Clients []struct {
				Email string `json:"email"`
			} `json:"clients"`
		}
		if err := json.Unmarshal([]byte(resp.Obj.Settings), &settings); err != nil {
			t.Fatalf("decode settings blob: %v", err)
		}
		if len(settings.Clients) != 1 || settings.Clients[0].Email != f.saraEmail {
			t.Errorf("settings carried %d clients (%+v); want exactly the reseller's own",
				len(settings.Clients), settings.Clients)
		}
		// The other half of the filter. GetInbound does not preload ClientStats, so the
		// route loads them itself before filtering (the inbound's own counters are
		// rescoped from these rows, and unloaded rows would read as zero usage).
		for _, stat := range resp.Obj.ClientStats {
			if stat.Email != f.saraEmail {
				t.Errorf("clientStats leaked %q", stat.Email)
			}
		}
		// And the inbound's own counters, which the Inbounds page sums into its usage
		// band: Sara's 1000/1000/2000, not the whole inbound's.
		if resp.Obj.Up != 1000 || resp.Obj.Down != 1000 || resp.Obj.AllTime != 2000 {
			t.Errorf("up/down/allTime = %d/%d/%d; want the reseller's own 1000/1000/2000",
				resp.Obj.Up, resp.Obj.Down, resp.Obj.AllTime)
		}

		// And the filter must be a no-op for an admin: Ali still sees his own client
		// on his own inbound.
		w = f.as(t, f.ali, http.MethodGet,
			fmt.Sprintf("/panel/api/inbounds/get/%d", f.aliInbound.Id), "")
		if !strings.Contains(w.Body.String(), f.aliEmail) {
			t.Errorf("the reseller filter reached an admin's own view: %s", w.Body.String())
		}
	})

	t.Run("cannot edit an admin's client on a shared inbound", func(t *testing.T) {
		f := newResellerFixture(t)
		body := url.Values{
			"id": {fmt.Sprint(f.aliInbound.Id)},
			"settings": {`{"clients":[{"id":"ali-uuid","email":"ali-client",` +
				`"enable":true,"totalGB":1073741824000}]}`},
		}.Encode()
		f.as(t, f.sara, http.MethodPost, "/panel/api/inbounds/updateClient/ali-uuid", body)

		if strings.Contains(f.aliSettings(t), "1073741824000") {
			t.Error("a reseller rewrote Ali's account quota on an inbound they merely share")
		}
		// And nothing was charged for the attempt.
		if got := f.spent(t); got != 10*testGB {
			t.Errorf("spent = %d; the refused edit moved the balance (want %d)", got, 10*testGB)
		}
	})

	t.Run("cannot delete an admin's client on a shared inbound", func(t *testing.T) {
		f := newResellerFixture(t)
		f.as(t, f.sara, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/%d/delClient/ali-uuid", f.aliInbound.Id), "")
		if !strings.Contains(f.aliSettings(t), "ali-client") {
			t.Error("a reseller deleted Ali's account off a shared inbound")
		}

		f.as(t, f.sara, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/%d/delClientByEmail/%s", f.aliInbound.Id, f.aliEmail), "")
		if !strings.Contains(f.aliSettings(t), "ali-client") {
			t.Error("a reseller deleted Ali's account by email off a shared inbound")
		}
	})

	// A reset is ALLOWED for a reseller and is a purchase, not an adjustment: the
	// cleared bytes are bytes the account gets to move a second time against the same
	// quota, so the balance buys them again. Unpriced, this route is an
	// unlimited-traffic button (sell 1 GB, reset, repeat), which is why asserting the
	// balance actually moved matters more than asserting the request succeeded.
	t.Run("resets their own account and is charged the cleared bytes", func(t *testing.T) {
		f := newResellerFixture(t)

		w := f.as(t, f.sara, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/%d/resetClientTraffic/%s", f.aliInbound.Id, f.saraEmail), "")
		if !strings.Contains(w.Body.String(), `"success":true`) {
			t.Fatalf("a reseller could not reset their OWN account: %s", w.Body.String())
		}
		ct := &xray.ClientTraffic{}
		database.GetDB().Where("email = ?", f.saraEmail).First(ct)
		if ct.Up != 0 || ct.Down != 0 {
			t.Errorf("the reset reported success and cleared nothing: up=%d down=%d", ct.Up, ct.Down)
		}
		// 1000 up + 1000 down cleared, on top of the 10 GB already committed.
		if want, got := 10*testGB+2000, f.spent(t); got != want {
			t.Errorf("spent = %d after a reset that handed the account 2000 bytes back; "+
				"want %d. An uncharged reset is an unlimited-traffic button", got, want)
		}
	})

	t.Run("cannot reset an admin's account on a shared inbound", func(t *testing.T) {
		f := newResellerFixture(t)

		f.as(t, f.sara, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/%d/resetClientTraffic/%s", f.aliInbound.Id, f.aliEmail), "")
		ct := &xray.ClientTraffic{}
		database.GetDB().Where("email = ?", f.aliEmail).First(ct)
		if ct.Up == 0 && ct.Down == 0 {
			t.Error("a reseller zeroed Ali's usage on an inbound they merely share")
		}
		if ct.Enable {
			t.Error("a reseller force-enabled a client Ali had disabled, defeating quota enforcement")
		}
		if got := f.spent(t); got != 10*testGB {
			t.Errorf("spent = %d; the refused reset moved the balance (want %d)", got, 10*testGB)
		}
	})

	// The refusal has to name the gap. "Not enough traffic" leaves a reseller guessing
	// how much to ask an admin for; what they cannot see is the shortfall.
	t.Run("a reset they cannot afford is refused, and the error names the shortfall", func(t *testing.T) {
		f := newResellerFixture(t)
		// 500 bytes of headroom against a 2000 byte reset.
		if err := database.GetDB().Model(&model.ResellerProfile{}).Where("user_id = ?", f.sara.Id).
			Update("allowance_bytes", 10*testGB+500).Error; err != nil {
			t.Fatalf("tighten allowance: %v", err)
		}

		w := f.as(t, f.sara, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/%d/resetClientTraffic/%s", f.aliInbound.Id, f.saraEmail), "")
		body := w.Body.String()
		if strings.Contains(body, `"success":true`) {
			t.Fatalf("a reset was granted on a balance that cannot pay for it: %s", body)
		}
		if !strings.Contains(body, "short") {
			t.Errorf("the refusal does not name the shortfall, so the reseller cannot tell "+
				"how much to ask for: %s", body)
		}
		ct := &xray.ClientTraffic{}
		database.GetDB().Where("email = ?", f.saraEmail).First(ct)
		if ct.Up == 0 && ct.Down == 0 {
			t.Error("the reset was refused and cleared the counters anyway")
		}
		if got := f.spent(t); got != 10*testGB {
			t.Errorf("spent = %d; a refused reset must not move the balance (want %d)",
				got, 10*testGB)
		}
	})

	// Still refused: setting counters to arbitrary values is an admin accounting tool,
	// and unlike a reset there is no quantity for the ledger to charge.
	t.Run("cannot write traffic counters by hand", func(t *testing.T) {
		f := newResellerFixture(t)
		f.as(t, f.sara, http.MethodPost,
			"/panel/api/inbounds/updateClientTraffic/"+f.saraEmail, `{"upload":0,"download":0}`)
		ct := &xray.ClientTraffic{}
		database.GetDB().Where("email = ?", f.saraEmail).First(ct)
		if ct.Up == 0 && ct.Down == 0 {
			t.Error("a reseller wrote their own account's counters down to zero, off the house")
		}
	})

	// These four are defined over a whole inbound, which is shared, and none of them
	// has a per-owner form to narrow to.
	t.Run("cannot run inbound-wide client operations", func(t *testing.T) {
		f := newResellerFixture(t)
		db := database.GetDB()

		// Ali's account, depleted: the sweep would take it.
		db.Model(&xray.ClientTraffic{}).Where("email = ?", f.aliEmail).
			Updates(map[string]any{"up": 20, "down": 20, "total": 10})
		f.as(t, f.sara, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/delDepletedClients/%d", f.aliInbound.Id), "")
		if !strings.Contains(f.aliSettings(t), "ali-client") {
			t.Error("a reseller swept Ali's depleted account off a shared inbound")
		}

		w := f.as(t, f.sara, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/%d/copyClients", f.aliInbound.Id),
			url.Values{"sourceInboundId": {fmt.Sprint(f.aliInbound.Id)}}.Encode())
		if strings.Contains(w.Body.String(), "ali-client") {
			t.Errorf("a reseller copied Ali's account credentials: %s", w.Body.String())
		}

		// The bulk resets. A reseller now HOLDS bulkOperation, so the permission bit no
		// longer closes these and the controller has to. Neither can be scoped to one
		// reseller's accounts, and a free reset is the unlimited-traffic button again.
		for _, path := range []string{
			"/panel/api/inbounds/resetAllTraffics",
			fmt.Sprintf("/panel/api/inbounds/resetAllClientTraffics/%d", f.aliInbound.Id),
		} {
			w = f.as(t, f.sara, http.MethodPost, path, "")
			if strings.Contains(w.Body.String(), `"success":true`) {
				t.Errorf("%s ran for a reseller: %s", path, w.Body.String())
			}
		}
		ct := &xray.ClientTraffic{}
		db.Where("email = ?", f.saraEmail).First(ct)
		if ct.Up == 0 && ct.Down == 0 {
			t.Error("a bulk reset cleared the counters for free")
		}
		if got := f.spent(t); got != 10*testGB {
			t.Errorf("spent = %d; a refused bulk reset must not move the balance (want %d)",
				got, 10*testGB)
		}

		// The list's order is the panel's, shared by every admin who sees the inbound.
		// A reseller sells accounts on inbounds an admin lent them and holds no
		// *Inbound bit at all, so rearranging that admin's table is not theirs to do.
		payload, _ := json.Marshal([]int{f.aliInbound.Id})
		w = f.as(t, f.sara, http.MethodPost, "/panel/api/inbounds/reorder",
			url.Values{"data": {string(payload)}}.Encode())
		if strings.Contains(w.Body.String(), `"success":true`) {
			t.Errorf("a reseller reordered an admin's inbound list: %s", w.Body.String())
		}
	})

	// Bulk is the one client path where the CALLER names the targets, so the inbound
	// grant and the permission bit between them authorize nothing about whose accounts
	// are in the list. Foreign targets are dropped rather than refusing the batch: the
	// reseller's own half is a legitimate request.
	t.Run("bulk targets naming an admin's account are dropped, not applied", func(t *testing.T) {
		f := newResellerFixture(t)
		db := database.GetDB()

		payload, _ := json.Marshal(map[string]any{
			"op":          "addTraffic",
			"amountBytes": testGB,
			"targets": []map[string]any{
				{"inboundId": f.aliInbound.Id, "email": f.saraEmail},
				{"inboundId": f.aliInbound.Id, "email": f.aliEmail}, // the poisoned one
			},
		})
		w := f.as(t, f.sara, http.MethodPost, "/panel/api/inbounds/bulkUpdateClients",
			url.Values{"data": {string(payload)}}.Encode())
		if !strings.Contains(w.Body.String(), `"success":true`) {
			t.Fatalf("a reseller could not run a bulk op on their own account: %s", w.Body.String())
		}

		settings := f.aliSettings(t)
		var parsed struct {
			Clients []struct {
				Email   string `json:"email"`
				TotalGB int64  `json:"totalGB"`
			} `json:"clients"`
		}
		if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
			t.Fatalf("decode settings: %v", err)
		}
		seen := 0
		for _, cl := range parsed.Clients {
			switch cl.Email {
			case f.aliEmail:
				seen++
				if cl.TotalGB != 0 {
					t.Errorf("the batch reached Ali's account: totalGB = %d, want the "+
						"unlimited 0 it started with", cl.TotalGB)
				}
			case f.saraEmail:
				seen++
				if want := 11 * testGB; cl.TotalGB != want {
					t.Errorf("the reseller's OWN target got totalGB = %d; want %d. "+
						"Scoping must drop foreign targets, not the whole batch", cl.TotalGB, want)
				}
			}
		}
		// Or the loop above matched nothing and asserted nothing.
		if seen != 2 {
			t.Fatalf("matched %d of the 2 seeded clients in %s", seen, settings)
		}
		// Charged for ONE account's gigabyte, not two: the dropped target must not be
		// billed either.
		if want, got := 11*testGB, f.spent(t); got != want {
			t.Errorf("spent = %d after adding 1 GB to one owned account; want %d", got, want)
		}
		// And the dropped target left no ledger row behind.
		var n int64
		db.Model(&model.ResellerClient{}).Where("email = ?", f.aliEmail).Count(&n)
		if n != 0 {
			t.Error("the batch created an ownership row for an account the reseller does not own")
		}

		// The control that proves SCOPING is what dropped the target, rather than the
		// batch having failed for some unrelated reason: the identical request, run by
		// the admin who owns the inbound, reaches both accounts.
		g := newResellerFixture(t)
		w = g.as(t, g.ali, http.MethodPost, "/panel/api/inbounds/bulkUpdateClients",
			url.Values{"data": {string(payload)}}.Encode())
		if !strings.Contains(w.Body.String(), `"success":true`) {
			t.Fatalf("an admin could not run the same batch: %s", w.Body.String())
		}
		after := g.aliSettings(t)
		parsed.Clients = nil
		if err := json.Unmarshal([]byte(after), &parsed); err != nil {
			t.Fatalf("decode settings: %v", err)
		}
		// Exact, not a substring: 1073741824 is a prefix of the 10737418240 the other
		// client was seeded with, so Contains would pass without the batch doing a thing.
		for _, cl := range parsed.Clients {
			if cl.Email == g.aliEmail && cl.TotalGB != testGB {
				t.Errorf("the admin's identical batch left Ali's account at totalGB = %d; "+
					"want %d, so the reseller case above proves nothing", cl.TotalGB, testGB)
			}
		}
	})

	// Days are not a currency this balance holds, so a bulk day cut moves no bytes and
	// leaves no trace any ledger check could read. Refused rather than priced.
	t.Run("subDays is refused for a reseller and still works for an admin", func(t *testing.T) {
		f := newResellerFixture(t)
		db := database.GetDB()
		deadline := time.Now().Add(30 * 24 * time.Hour).UnixMilli()
		db.Model(&xray.ClientTraffic{}).Where("email = ?", f.saraEmail).
			Update("expiry_time", deadline)
		if err := db.Model(model.Inbound{}).Where("id = ?", f.aliInbound.Id).
			Update("settings", fmt.Sprintf(`{"clients":[`+
				`{"id":"ali-uuid","email":"ali-client","enable":true,"totalGB":0,"expiryTime":%d},`+
				`{"id":"sara-uuid","email":"sara-client","enable":false,"totalGB":10737418240,`+
				`"expiryTime":%d}]}`, deadline, deadline)).Error; err != nil {
			t.Fatalf("seed expiries: %v", err)
		}

		payload, _ := json.Marshal(map[string]any{
			"op": "subDays", "days": 5,
			"targets": []map[string]any{{"inboundId": f.aliInbound.Id, "email": f.saraEmail}},
		})
		form := url.Values{"data": {string(payload)}}.Encode()

		w := f.as(t, f.sara, http.MethodPost, "/panel/api/inbounds/bulkUpdateClients", form)
		if strings.Contains(w.Body.String(), `"success":true`) {
			t.Errorf("a reseller took days off an account in bulk: %s", w.Body.String())
		}
		if strings.Contains(f.aliSettings(t), fmt.Sprint(deadline-5*24*60*60*1000)) {
			t.Error("subDays was refused and shortened the account anyway")
		}

		// The counterpart: the op itself is fine, it is the ROLE that cannot run it.
		// Without this the test would pass just as well if subDays were broken outright.
		w = f.as(t, f.ali, http.MethodPost, "/panel/api/inbounds/bulkUpdateClients", form)
		if !strings.Contains(w.Body.String(), `"success":true`) {
			t.Fatalf("an admin could not run subDays on their own inbound: %s", w.Body.String())
		}
		if !strings.Contains(f.aliSettings(t), fmt.Sprint(deadline-5*24*60*60*1000)) {
			t.Errorf("an admin's subDays did not shorten the account: %s", f.aliSettings(t))
		}
	})

	t.Run("panel-wide client rosters are scoped to owned accounts", func(t *testing.T) {
		f := newResellerFixture(t)
		for _, path := range []string{"/panel/api/inbounds/onlines", "/panel/api/inbounds/lastOnline"} {
			w := f.as(t, f.sara, http.MethodPost, path, "")
			if strings.Contains(w.Body.String(), f.aliEmail) {
				t.Errorf("%s handed a reseller Ali's roster off a shared inbound: %s",
					path, w.Body.String())
			}
		}
		// lastOnline lists every account, so the positive control is real: Sara's own
		// must survive the filter.
		w := f.as(t, f.sara, http.MethodPost, "/panel/api/inbounds/lastOnline", "")
		if !strings.Contains(w.Body.String(), f.saraEmail) {
			t.Errorf("lastOnline dropped the reseller's OWN account: %s", w.Body.String())
		}

		w = f.as(t, f.sara, http.MethodGet, "/panel/api/inbounds/getClientTrafficsById/ali-uuid", "")
		if strings.Contains(w.Body.String(), f.aliEmail) {
			t.Errorf("getClientTrafficsById handed a reseller Ali's account: %s", w.Body.String())
		}
	})

	// The counterpart: a reseller must actually be able to work, and the ledger must
	// follow. Without this the suite would pass just as well if resellers were
	// refused everything.
	//
	// Delete is the only ledger-moving route this harness can drive end to end.
	// AddInboundClient and UpdateInboundClient dereference the package-level Xray
	// process unconditionally, which is nil with no Xray running, so the create and
	// rename halves of the ledger are proven at the service layer instead.
	t.Run("can delete their own account, and the refund lands", func(t *testing.T) {
		f := newResellerFixture(t)
		db := database.GetDB()

		// An account that never moved a byte, so the whole charge is refundable on
		// either side of the delete. How much of a USED account comes back is the
		// service's arithmetic and is proven there; it is not observable from here,
		// because the delete drops the client_traffics row the consumption is
		// measured from before any refund can read it.
		zeroUsage(t, f.saraEmail)

		w := f.as(t, f.sara, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/%d/delClient/sara-uuid", f.aliInbound.Id), "")
		if !strings.Contains(w.Body.String(), `"success":true`) {
			t.Fatalf("a reseller could not delete their OWN account: %s", w.Body.String())
		}
		if strings.Contains(f.aliSettings(t), f.saraEmail) {
			t.Error("the delete reported success and removed nothing")
		}
		if got := f.spent(t); got != 0 {
			t.Errorf("spent = %d after deleting the unused 10 GB account it was all "+
				"committed to; want 0, the whole charge back", got)
		}
		var n int64
		db.Model(&model.ResellerClient{}).Where("email = ?", f.saraEmail).Count(&n)
		if n != 0 {
			t.Error("the ownership row outlived the account it tracked, so the reseller " +
				"still holds a charge for an account that no longer exists")
		}
	})

	// Deleting the inbound is an admin action, and it takes the reseller's accounts
	// with it. The rows must not outlive it: ids are not reissued, but a stale row
	// keeps a reseller's balance committed to an account nobody can find any more.
	t.Run("deleting an inbound drops and refunds its reseller rows", func(t *testing.T) {
		f := newResellerFixture(t)
		db := database.GetDB()
		// Disabled first: DelInbound dials the Xray API for a live inbound, and this
		// harness has no Xray process. Nothing else about the delete changes.
		db.Model(model.Inbound{}).Where("id = ?", f.aliInbound.Id).Update("enable", false)
		zeroUsage(t, f.saraEmail)

		w := f.as(t, f.ali, http.MethodPost,
			fmt.Sprintf("/panel/api/inbounds/del/%d", f.aliInbound.Id), "")
		if !strings.Contains(w.Body.String(), `"success":true`) {
			t.Fatalf("the owner could not delete their own inbound: %s", w.Body.String())
		}

		var n int64
		db.Model(&model.ResellerClient{}).Where("inbound_id = ?", f.aliInbound.Id).Count(&n)
		if n != 0 {
			t.Errorf("%d reseller ownership rows outlived the deleted inbound", n)
		}
		if got := f.spent(t); got != 0 {
			t.Errorf("spent = %d; an admin deleting the inbound out from under a reseller "+
				"must credit back what those accounts had left (want 0)", got)
		}
	})
}

// The login flow must never ask an admin for a code they do not have.
//
// This regressed once already: with 2FA per-admin, the pre-auth "does this account
// have 2FA?" endpoint becomes a username oracle, and the first fix for that was to
// always claim yes, which showed a Code box to every admin who had never enabled it.
// The real answer is two-step, and these are the two properties that matter.
func TestLoginTwoFactorPrompt(t *testing.T) {
	gin.SetMode(gin.TestMode)

	post := func(t *testing.T, form string) *httptest.ResponseRecorder {
		t.Helper()
		r := gin.New()
		// login writes a session, so the store has to be there or it panics.
		r.Use(sessions.Sessions("vpn-ui", cookie.NewStore([]byte("test-secret"))))
		r.Use(func(c *gin.Context) {
			c.Set("base_path", "/")
			c.Set("I18n", func(i18nType locale.I18nType, key string, keyParams ...string) string { return key })
			c.Next()
		})
		NewIndexController(r.Group("/"))
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	t.Run("the preflight never claims an account has 2FA", func(t *testing.T) {
		newIdorFixture(t)
		r := gin.New()
		r.Use(sessions.Sessions("vpn-ui", cookie.NewStore([]byte("test-secret"))))
		r.Use(func(c *gin.Context) {
			c.Set("base_path", "/")
			c.Set("I18n", func(i18nType locale.I18nType, key string, keyParams ...string) string { return key })
			c.Next()
		})
		NewIndexController(r.Group("/"))
		req := httptest.NewRequest(http.MethodPost, "/getTwoFactorEnable", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		// It must not report true: pre-auth it cannot know WHICH account is logging
		// in, and answering per-username would leak which usernames exist.
		if strings.Contains(w.Body.String(), `"obj":true`) {
			t.Errorf("the login page would show a Code field to every admin: %s", w.Body.String())
		}
	})

	t.Run("an admin without 2FA is never asked for a code", func(t *testing.T) {
		f := newIdorFixture(t)
		hash, _ := crypto.HashPasswordAsBcrypt("pw")
		database.GetDB().Model(model.User{}).Where("id = ?", f.reza.Id).
			Updates(map[string]any{"password": hash, "two_factor_enable": false})

		w := post(t, url.Values{"username": {"reza"}, "password": {"pw"}}.Encode())
		if strings.Contains(w.Body.String(), "twoFactorRequired") {
			t.Errorf("an admin who never enabled 2FA was asked for a code: %s", w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"success":true`) {
			t.Errorf("a correct password without 2FA should just log in: %s", w.Body.String())
		}
	})

	t.Run("an admin WITH 2FA is asked, only after the password checks out", func(t *testing.T) {
		f := newIdorFixture(t)
		hash, _ := crypto.HashPasswordAsBcrypt("pw")
		database.GetDB().Model(model.User{}).Where("id = ?", f.reza.Id).
			Updates(map[string]any{
				"password": hash, "two_factor_enable": true, "two_factor_token": "JBSWY3DPEHPK3PXP",
			})

		// Right password, no code: asked for the code.
		w := post(t, url.Values{"username": {"reza"}, "password": {"pw"}}.Encode())
		if !strings.Contains(w.Body.String(), "twoFactorRequired") {
			t.Errorf("an admin with 2FA was not asked for a code: %s", w.Body.String())
		}

		// WRONG password: must NOT reveal that the account has 2FA, or the login form
		// becomes the very oracle the pre-auth endpoint was closed to prevent.
		w = post(t, url.Values{"username": {"reza"}, "password": {"wrong"}}.Encode())
		if strings.Contains(w.Body.String(), "twoFactorRequired") {
			t.Errorf("a WRONG password revealed that the account has 2FA: %s", w.Body.String())
		}

		// A correct code completes the login.
		w = post(t, url.Values{
			"username": {"reza"}, "password": {"pw"},
			"twoFactorCode": {gotp.NewDefaultTOTP("JBSWY3DPEHPK3PXP").Now()},
		}.Encode())
		if !strings.Contains(w.Body.String(), `"success":true`) {
			t.Errorf("a correct code should complete the login: %s", w.Body.String())
		}
	})
}

// The Admins form must actually carry every field to the service.
//
// This exists because a real bug slipped through: spec() silently omitted
// InboundIds, so the form parsed the ticked inbounds and threw them away. Creating
// an admin reported success and granted nothing. No unit test caught it: the
// service tests call AddAdmin directly with a hand-built spec, and the middleware
// tests never reach a handler. The gap was the form-to-spec mapping itself.
func TestAdminFormCarriesEveryField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newIdorFixture(t)

	super := &model.User{}
	if err := database.GetDB().Model(model.User{}).Where("is_super_admin = ?", true).
		First(super).Error; err != nil {
		t.Fatalf("no super admin: %v", err)
	}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("LOGIN_USER_ROW", super)
		c.Set("base_path", "/")
		c.Set("I18n", func(i18nType locale.I18nType, key string, keyParams ...string) string { return key })
		c.Next()
	})
	NewAdminController(r.Group("/panel"))

	form := url.Values{
		"username":     {"formtest"},
		"password":     {"pw"},
		"nickname":     {"Form Test"},
		"enable":       {"true"},
		"isSuperAdmin": {"false"},
		"permissions":  {"accessInbounds", "createClient"},
		// Exactly how the modal sends a multi-select: repeated keys.
		"inboundIds": {fmt.Sprint(f.aliInbound.Id), fmt.Sprint(f.rezaInbound.Id)},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/panel/admins/add", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("add admin: %s", w.Body.String())
	}

	created := &model.User{}
	if err := database.GetDB().Model(model.User{}).Where("username = ?", "formtest").
		First(created).Error; err != nil {
		t.Fatalf("created admin missing: %v", err)
	}
	if created.Nickname != "Form Test" {
		t.Errorf("nickname = %q; want %q", created.Nickname, "Form Test")
	}
	if !created.Permissions.Has(model.PermAccessInbounds) || !created.Permissions.Has(model.PermCreateClient) {
		t.Errorf("permissions = %v; want accessInbounds + createClient", created.Permissions.Slugs())
	}

	// The bit that was silently dropped.
	var granted []int
	if err := database.GetDB().Model(&model.InboundAccess{}).
		Where("user_id = ?", created.Id).Pluck("inbound_id", &granted).Error; err != nil {
		t.Fatalf("read grants: %v", err)
	}
	if len(granted) != 2 {
		t.Errorf("ticked 2 inbounds, %d were granted (%v): the form's inbound "+
			"selection never reached the database", len(granted), granted)
	}

	// And an edit must REPLACE the set, not merge into it: unticking has to revoke.
	edit := url.Values{
		"username": {"formtest"}, "nickname": {"Form Test"}, "enable": {"true"},
		"isSuperAdmin": {"false"}, "permissions": {"accessInbounds"},
		"inboundIds": {fmt.Sprint(f.aliInbound.Id)},
	}.Encode()
	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/panel/admins/update/%d", created.Id),
		strings.NewReader(edit))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("update admin: %s", w.Body.String())
	}
	granted = nil
	database.GetDB().Model(&model.InboundAccess{}).Where("user_id = ?", created.Id).Pluck("inbound_id", &granted)
	if len(granted) != 1 || granted[0] != f.aliInbound.Id {
		t.Errorf("after unticking one, grants = %v; want exactly [%d]", granted, f.aliInbound.Id)
	}
}
