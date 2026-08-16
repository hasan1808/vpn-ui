package controller

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/web/locale"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"
)

// The overview is gated by TWO bits that must not collapse into one another.
//
// PermOverviewManage is an AND on top of each action's own permission, never a
// substitute for it and never satisfied by it. Both halves are pinned here because
// each is a different way to get the gate wrong: drop the new bit and the overview
// goes back to offering management to anyone who can log in, drop the old one and a
// single new checkbox silently hands out Xray and panel-settings rights.
//
// PermAccessOverview gates the page itself, which is only possible because a denial
// now resolves a reachable landing page instead of redirecting to the overview. Its
// cases pin both ends of that: who is refused, and that the refusal never points
// back at the page that just refused them.
//
// A real request through a real router, for the reason idor_test.go gives: the
// middleware in isolation proves nothing about what the route table actually wired.

// forbiddenKey is what a refusal says. Asserting on the BODY rather than the status
// is not a shortcut: deny() answers XHR with HTTP 200 and success:false on purpose,
// because axios rejects any non-2xx and the frontend would show its own "Request
// failed with status code 403" instead of the reason (see the comment on deny). A
// test that looked for 403 here would be pinning a shape this panel deliberately
// does not use.
const forbiddenKey = "pages.admins.forbidden"

// overviewCall issues one authenticated request against the server + custom-geo
// routes, seeding the same per-request cache session.GetLoginUser reads.
func overviewCall(t *testing.T, user *model.User, method, path, body string) string {
	t.Helper()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("LOGIN_USER_ROW", user)
		c.Set("base_path", "/")
		c.Set("I18n", func(i18nType locale.I18nType, key string, keyParams ...string) string { return key })
		c.Next()
	})
	// initRouter rather than NewServerController: the constructor also starts the
	// background status poller, which this has no use for and which would outlive
	// the test.
	(&ServerController{}).initRouter(r.Group("/panel/api/server"))
	// A nil service is safe for the denial cases, which never reach a handler. The
	// group carries the same either-claim gate api.go mounts it with.
	customGeo := r.Group("/panel/api/custom-geo")
	customGeo.Use(requireXrayOrOverviewManage())
	NewCustomGeoController(customGeo, nil)

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Body.String()
}

// overviewNav issues a page NAVIGATION against the panel's real route table: a GET
// whose Accept asks for HTML, which is what deny() keys its redirect on. The XHR
// helper above cannot stand in for it, because the two branches of deny() are
// exactly what differs between them.
func overviewNav(t *testing.T, user *model.User, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	// A stand-in for the real index.html, which is not parsed here: c.HTML with no
	// template set panics before any assertion runs. Only "the handler was reached"
	// is being measured.
	r.SetHTMLTemplate(template.Must(template.New("index.html").Parse(overviewBody)))
	r.Use(func(c *gin.Context) {
		c.Set("LOGIN_USER_ROW", user)
		c.Set("base_path", "/")
		c.Set("I18n", func(i18nType locale.I18nType, key string, keyParams ...string) string { return key })
		c.Next()
	})
	// The whole panel route table, for the reason the file header gives: a middleware
	// tested in isolation says nothing about which routes it was actually mounted on,
	// and "the overview is gated" is a claim about the route table.
	(&XUIController{}).initRouter(r.Group("/"))

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// overviewBody is what the stand-in template renders, so a test can tell "the page
// was served" from "the request was refused" without parsing anything.
const overviewBody = "overview page"

// permCtx is a bare context carrying just what landingPath reads, for the cases that
// are about the resolver itself rather than about a route.
func permCtx(user *model.User) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("LOGIN_USER_ROW", user)
	c.Set("base_path", "/")
	return c
}

// newReseller inserts the profile row that decides a reseller's overview grants.
// The USER row is not needed: session.GetLoginUser is seeded from the context, and
// the profile is looked up by user id.
func newReseller(t *testing.T, id int, allowOverview, allowManage bool) *model.User {
	t.Helper()
	err := database.GetDB().Create(&model.ResellerProfile{
		UserId:              id,
		AllowOverview:       allowOverview,
		AllowOverviewManage: allowManage,
	}).Error
	if err != nil {
		t.Fatalf("seeding the reseller profile: %v", err)
	}
	return &model.User{Id: id, Username: "seller", Enable: true, IsReseller: true}
}

func newPermTestDB(t *testing.T) {
	t.Helper()
	// The controllers log; without this the package-level logger is nil and any
	// warning panics rather than reporting the finding under test.
	logger.InitLogger(logging.CRITICAL)
	if err := database.InitDB(filepath.Join(t.TempDir(), "overviewperm.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
}

func TestOverviewManageGatesTheOverviewOnlyActions(t *testing.T) {
	newPermTestDB(t)

	withBoth := &model.User{
		Username: "both", Enable: true,
		Permissions: model.PermPanelSettings | model.PermXraySettings | model.PermOverviewManage,
	}
	// Holds the underlying rights but not the one that says this page may act.
	withoutManage := &model.User{
		Username: "nomanage", Enable: true,
		Permissions: model.PermPanelSettings | model.PermXraySettings,
	}
	// Holds only the manage bit. Since 2026-07-31 that is SUFFICIENT on its own for
	// every action the overview offers: the operator chose to make this permission
	// self-sufficient rather than an AND on top of each action's own bit, because the
	// AND made it unreachable for a reseller (whose derived mask carries no settings
	// bit) and therefore made their AllowOverviewManage column inert.
	onlyManage := &model.User{
		Username: "onlymanage", Enable: true,
		Permissions: model.PermOverviewManage,
	}
	superAdmin := &model.User{Username: "root", Enable: true, IsSuperAdmin: true}

	for _, tc := range []struct {
		name         string
		user         *model.User
		method, path string
		body         string
		wantForbid   bool
	}{
		{"rename is refused without the manage bit", withoutManage,
			http.MethodPost, "/panel/api/server/serverName", "serverName=x", true},
		{"rename is allowed with only the manage bit", onlyManage,
			http.MethodPost, "/panel/api/server/serverName", "serverName=x", false},
		{"rename is allowed with both", withBoth,
			http.MethodPost, "/panel/api/server/serverName", "serverName=x", false},
		{"rename is allowed for a super admin", superAdmin,
			http.MethodPost, "/panel/api/server/serverName", "serverName=x", false},

		{"geofile update is refused without the manage bit", withoutManage,
			http.MethodPost, "/panel/api/server/updateGeofile/geoip.dat", "", true},
		{"geofile update is allowed with only the manage bit", onlyManage,
			http.MethodPost, "/panel/api/server/updateGeofile/geoip.dat", "", false},

		{"custom geo write is refused without the manage bit", withoutManage,
			http.MethodPost, "/panel/api/custom-geo/delete/1", "", true},
		{"custom geo write is allowed with only the manage bit", onlyManage,
			http.MethodPost, "/panel/api/custom-geo/delete/1", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := overviewCall(t, tc.user, tc.method, tc.path, tc.body)
			refused := strings.Contains(body, forbiddenKey)
			if tc.wantForbid && !refused {
				t.Errorf("the request was allowed through; body was %s", body)
			}
			if !tc.wantForbid && refused {
				t.Errorf("the request was refused by the permission gate; body was %s", body)
			}
		})
	}
}

// The Xray buttons on the overview are ALSO offered on the Xray settings page, so
// they stay on the Xray bit alone. Requiring the overview bit here would take them
// away from an admin who never opens the overview, which is a different page's
// permission reaching into this one.
func TestXrayControlsAreNotGatedOnOverviewManage(t *testing.T) {
	newPermTestDB(t)

	xrayOnly := &model.User{
		Username: "xrayonly", Enable: true,
		Permissions: model.PermXraySettings,
	}
	for _, path := range []string{
		"/panel/api/server/stopXrayService",
		"/panel/api/server/restartXrayService",
	} {
		if body := overviewCall(t, xrayOnly, http.MethodPost, path, ""); strings.Contains(body, forbiddenKey) {
			t.Errorf("%s: refused, but the Xray permission alone should reach it", path)
		}
	}
}

// The slug is wire format: the Admins UI fetches the list from the server and posts
// the same strings back, so a rename here silently drops the permission from every
// admin who had it on the next save.
func TestOverviewManageSlugIsStable(t *testing.T) {
	var found bool
	for _, d := range model.AllPermissions {
		if d.Bit == model.PermOverviewManage {
			found = true
			if d.Slug != "manageOverview" {
				t.Errorf("slug is %q, want manageOverview", d.Slug)
			}
		}
	}
	if !found {
		t.Fatal("PermOverviewManage is missing from AllPermissions, so the Admins UI cannot offer it")
	}
	// Round trip, which is how a save actually applies it.
	if got := model.PermissionsFromSlugs([]string{"manageOverview"}); got != model.PermOverviewManage {
		t.Errorf("PermissionsFromSlugs round trip gave %d, want %d", got, model.PermOverviewManage)
	}
}

// A reseller's stored mask is ignored by design, so neither overview bit can reach
// them and both grants have to come from the profile instead. Pinned because the two
// roles answering one question from two columns is exactly the kind of thing a later
// refactor "simplifies" into a single lookup that silently denies every reseller.
func TestResellerCannotHoldTheOverviewBits(t *testing.T) {
	reseller := &model.User{
		Username: "seller", Enable: true, IsReseller: true,
		// Even with them stored, which an imported or hand-edited DB can produce.
		Permissions: model.PermOverviewManage | model.PermAccessOverview,
	}
	if reseller.Can(model.PermOverviewManage) {
		t.Error("a reseller's stored mask granted PermOverviewManage; the role must derive its own")
	}
	if reseller.Can(model.PermAccessOverview) {
		t.Error("a reseller's stored mask granted PermAccessOverview; the profile is the source of truth")
	}
}

// PermAccessOverview gates the overview PAGE, which nothing gated before it: the
// page was the target every denial redirected to, so gating it would have looped.
// That is why these cases are all really one case, checked from both ends: the page
// refuses whoever may not open it, AND the refusal goes somewhere they can.
func TestAccessOverviewGatesTheOverviewPage(t *testing.T) {
	newPermTestDB(t)

	superAdmin := &model.User{Id: 1, Username: "root", Enable: true, IsSuperAdmin: true}
	withAccess := &model.User{Id: 2, Username: "reader", Enable: true,
		Permissions: model.PermAccessOverview | model.PermAccessInbounds}
	// The pre-upgrade shape of a delegated admin: inbounds and nothing else. Before
	// the backfill in AdminService.MigrationOverviewAccess this is also what an
	// existing admin looks like on the first restart after the bit is added.
	withoutAccess := &model.User{Id: 3, Username: "seller-ish", Enable: true,
		Permissions: model.PermAccessInbounds}
	// Holds the manage bit alone, which opens no page at all: the state where any
	// redirect loops.
	noPageAtAll := &model.User{Id: 4, Username: "stranded", Enable: true,
		Permissions: model.PermOverviewManage}

	for _, tc := range []struct {
		name       string
		user       *model.User
		wantCode   int
		wantTarget string // Location, or "" for a response that is not a redirect
	}{
		{"a super admin sees it", superAdmin, http.StatusOK, ""},
		{"the access bit opens it", withAccess, http.StatusOK, ""},
		{"without the bit it redirects to a page they can open", withoutAccess,
			http.StatusTemporaryRedirect, "/panel/inbounds"},
		{"with no reachable page it refuses instead of redirecting", noPageAtAll,
			http.StatusForbidden, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := overviewNav(t, tc.user, "/panel/")
			if w.Code != tc.wantCode {
				t.Errorf("status %d, want %d (body %q, location %q)",
					w.Code, tc.wantCode, w.Body.String(), w.Header().Get("Location"))
			}
			if got := w.Header().Get("Location"); got != tc.wantTarget {
				t.Errorf("redirected to %q, want %q", got, tc.wantTarget)
			}
			// The one target that can never be right for a refusal: it is the page
			// that just refused, so a browser would follow it straight back here.
			if w.Code != http.StatusOK && w.Header().Get("Location") == "/panel/" {
				t.Error("the refusal redirects to the overview itself, which loops")
			}
			if tc.wantCode == http.StatusOK && !strings.Contains(w.Body.String(), overviewBody) {
				t.Errorf("the page was not served; body was %q", w.Body.String())
			}
			if tc.wantCode == http.StatusForbidden && !strings.Contains(w.Body.String(), forbiddenKey) {
				t.Errorf("the refusal does not say why; body was %q", w.Body.String())
			}
		})
	}
}

// A reseller's grant comes from their profile and not from the mask, so the route
// has to read the other column for them. Both directions are pinned: a reseller who
// was given the overview must still get it (the easy half to break by gating the
// route on the bit alone, since resellerPerms can never contain it), and one who was
// not must land on the accounts page rather than on a refusal.
func TestResellerOverviewAccessComesFromTheProfile(t *testing.T) {
	newPermTestDB(t)

	granted := newReseller(t, 11, true, false)
	withheld := newReseller(t, 12, false, false)

	if w := overviewNav(t, granted, "/panel/"); w.Code != http.StatusOK {
		t.Errorf("a reseller with allowOverview was refused: status %d, location %q",
			w.Code, w.Header().Get("Location"))
	}
	w := overviewNav(t, withheld, "/panel/")
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status %d, want a redirect for a reseller without allowOverview", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/panel/inbounds" {
		t.Errorf("redirected to %q, want /panel/inbounds", got)
	}
}

// The reseller half of the acting bit, which is the case that was actually broken.
//
// Every management control used to be gated `and <someSettingsBit> manageOverview`,
// server side and in the template. A reseller's mask is DERIVED from resellerPerms,
// which carries only inbound and client bits, so the left half of every one of those
// ANDs was permanently false and AllowOverviewManage did literally nothing: the
// operator ticked it, saw no change, and reported the permission as broken. Routes now
// ask requireOverviewManage(), which resolves the profile columns for this role.
//
// Both columns are required. Manage scopes a page, so manage without access is a
// half-saved form rather than a grant, and the modal already refuses to produce it.
func TestResellerOverviewManageReachesTheOverviewActions(t *testing.T) {
	newPermTestDB(t)

	for _, tc := range []struct {
		name                   string
		allowOverview, allowMg bool
		wantForbid             bool
	}{
		{"both granted can act", true, true, false},
		{"page without manage cannot act", true, false, true},
		{"manage without the page grants nothing", false, true, true},
		{"neither", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := newReseller(t, 200+len(tc.name), tc.allowOverview, tc.allowMg)
			body := overviewCall(t, user, http.MethodPost,
				"/panel/api/server/serverName", "serverName=x")
			refused := strings.Contains(body, forbiddenKey)
			if tc.wantForbid && !refused {
				t.Errorf("the reseller was allowed through; body was %s", body)
			}
			if !tc.wantForbid && refused {
				t.Errorf("the reseller was refused despite holding both columns; body was %s", body)
			}
		})
	}
}

// The templates read ONE map for both roles, so a reseller's two profile booleans
// have to arrive under the same slugs an admin's bits do. Without this the sidebar
// entry and the overview's controls disappear for every reseller who was granted
// them, since Can() answers false for both bits by design.
func TestTemplatePermsResolvesTheResellerOverviewColumns(t *testing.T) {
	newPermTestDB(t)

	for _, tc := range []struct {
		name                   string
		allowOverview, allowMg bool
		wantAccess, wantManage bool
	}{
		{"both granted", true, true, true, true},
		{"page only", true, false, true, false},
		// Manage scopes a page they cannot reach, so it grants nothing on its own.
		// A profile in this shape is a half-saved form, not a grant.
		{"manage without the page", false, true, false, false},
		{"neither", false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := newReseller(t, 100+len(tc.name), tc.allowOverview, tc.allowMg)
			perms := templatePerms(permCtx(user))
			if perms["accessOverview"] != tc.wantAccess {
				t.Errorf("accessOverview = %v, want %v", perms["accessOverview"], tc.wantAccess)
			}
			if perms["manageOverview"] != tc.wantManage {
				t.Errorf("manageOverview = %v, want %v", perms["manageOverview"], tc.wantManage)
			}
		})
	}
}

// landingPath is what makes gating the overview possible at all, so it is pinned
// per role. The rule it must never break: it may only ever name a page the caller
// can actually open, and "" (no page) is a real answer that callers must handle by
// refusing rather than by substituting a default.
func TestLandingPathOnlyNamesReachablePages(t *testing.T) {
	newPermTestDB(t)

	for _, tc := range []struct {
		name string
		user *model.User
		want string
	}{
		{"a super admin lands on the overview",
			&model.User{Id: 1, Enable: true, IsSuperAdmin: true}, "/panel/"},
		{"the access bit lands on the overview",
			&model.User{Id: 2, Enable: true, Permissions: model.PermAccessOverview}, "/panel/"},
		{"without it, inbounds",
			&model.User{Id: 3, Enable: true, Permissions: model.PermAccessInbounds}, "/panel/inbounds"},
		{"resellers page when that is all they have",
			&model.User{Id: 4, Enable: true, Permissions: model.PermManageResellers}, "/panel/resellers"},
		{"panel settings when that is all they have",
			&model.User{Id: 5, Enable: true, Permissions: model.PermPanelSettings}, "/panel/settings"},
		{"xray when that is all they have",
			&model.User{Id: 6, Enable: true, Permissions: model.PermXraySettings}, "/panel/xray"},
		{"core when that is all they have",
			&model.User{Id: 7, Enable: true, Permissions: model.PermCoreSettings}, "/panel/core"},
		// Action bits without a page bit: legal to save from the Admins modal, and
		// the state every redirect target would bounce out of.
		{"nothing but the manage bit reaches no page",
			&model.User{Id: 8, Enable: true, Permissions: model.PermOverviewManage}, ""},
		{"client bits alone reach no page",
			&model.User{Id: 9, Enable: true,
				Permissions: model.PermCreateClient | model.PermEditClient}, ""},
		// A disabled account keeps its mask, and Can() refuses on it, so nothing is
		// reachable. It cannot get this far in practice (GetLoginUser returns nil for
		// a disabled row) but the resolver must not be the thing that assumes so.
		{"a disabled admin reaches no page",
			&model.User{Id: 10, Enable: false, Permissions: model.PermAccessInbounds}, ""},
		{"logged out reaches no page", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := landingPath(permCtx(tc.user)); got != tc.want {
				t.Errorf("landingPath = %q, want %q", got, tc.want)
			}
		})
	}

	// Resellers, whose overview answer is a profile row rather than a bit. They
	// always hold PermAccessInbounds by role, so there is always somewhere to send
	// them, and the granted one must not be sent past a page they were given.
	if got := landingPath(permCtx(newReseller(t, 21, true, false))); got != "/panel/" {
		t.Errorf("a reseller with allowOverview landed on %q, want /panel/", got)
	}
	if got := landingPath(permCtx(newReseller(t, 22, false, false))); got != "/panel/inbounds" {
		t.Errorf("a reseller without allowOverview landed on %q, want /panel/inbounds", got)
	}
	// No profile row at all is a broken account, not a privileged one: it must not
	// resolve to the overview.
	broken := &model.User{Id: 23, Enable: true, IsReseller: true}
	if got := landingPath(permCtx(broken)); got != "/panel/inbounds" {
		t.Errorf("a reseller with no profile landed on %q, want /panel/inbounds", got)
	}
}

// Every OTHER page's denial goes through the same resolver, so the loop cannot come
// back through a route that was left on the old unconditional target.
func TestDenialsOnOtherPagesUseTheLandingPage(t *testing.T) {
	newPermTestDB(t)

	inboundsOnly := &model.User{Id: 31, Username: "inbounds", Enable: true,
		Permissions: model.PermAccessInbounds}
	noPageAtAll := &model.User{Id: 32, Username: "stranded", Enable: true,
		Permissions: model.PermOverviewManage}

	for _, path := range []string{"/panel/settings", "/panel/xray", "/panel/core", "/panel/resellers"} {
		w := overviewNav(t, inboundsOnly, path)
		if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != "/panel/inbounds" {
			t.Errorf("%s: status %d location %q, want a 307 to /panel/inbounds",
				path, w.Code, w.Header().Get("Location"))
		}
		w = overviewNav(t, noPageAtAll, path)
		if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" {
			t.Errorf("%s: status %d location %q, want a plain 403 with no redirect",
				path, w.Code, w.Header().Get("Location"))
		}
	}

	// requireSuperAdmin denies on its own path and must resolve the same way.
	w := overviewNav(t, inboundsOnly, "/panel/admins")
	if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != "/panel/inbounds" {
		t.Errorf("/panel/admins: status %d location %q, want a 307 to /panel/inbounds",
			w.Code, w.Header().Get("Location"))
	}
}

// A refusal that is NOT a page navigation keeps this panel's shape: HTTP 200 with
// success:false. Pinned here because the new gate is the first one whose HTML branch
// can answer 403, and copying that status onto the XHR branch would hand axios a
// rejection it turns into "Request failed with status code 403".
func TestOverviewDenialToXhrIsNotAStatusCode(t *testing.T) {
	newPermTestDB(t)

	body := overviewCall(t, &model.User{Id: 41, Enable: true, Permissions: model.PermAccessInbounds},
		http.MethodPost, "/panel/api/server/serverName", "serverName=x")
	if !strings.Contains(body, forbiddenKey) {
		t.Errorf("the refusal does not carry the reason; body was %s", body)
	}
}

// The slug is wire format, like manageOverview's: the Admins UI fetches the list
// from the server and posts the same strings back, so a rename here silently drops
// the permission from every admin who had it on the next save.
func TestAccessOverviewSlugIsStable(t *testing.T) {
	var found bool
	for _, d := range model.AllPermissions {
		if d.Bit == model.PermAccessOverview {
			found = true
			if d.Slug != "accessOverview" {
				t.Errorf("slug is %q, want accessOverview", d.Slug)
			}
		}
	}
	if !found {
		t.Fatal("PermAccessOverview is missing from AllPermissions, so the Admins UI cannot offer it")
	}
	if got := model.PermissionsFromSlugs([]string{"accessOverview"}); got != model.PermAccessOverview {
		t.Errorf("PermissionsFromSlugs round trip gave %d, want %d", got, model.PermAccessOverview)
	}
	// The two are one pair in the checkbox column, and the slice order is what the
	// Admins UI renders in.
	access, manage := -1, -1
	for i, d := range model.AllPermissions {
		switch d.Bit {
		case model.PermAccessOverview:
			access = i
		case model.PermOverviewManage:
			manage = i
		}
	}
	if access != manage-1 {
		t.Errorf("accessOverview is at %d and manageOverview at %d; the access bit must render immediately before it",
			access, manage)
	}
}

// The bits are positional and stored as an integer column, so a bit INSERTED rather
// than appended rewrites what every mask already in the database means: an admin
// holding "manage resellers" would come back holding whatever now sits on that bit.
// Pinning the values makes that a failing test rather than a support ticket.
func TestOverviewBitsWereAppendedNotInserted(t *testing.T) {
	for _, tc := range []struct {
		name string
		bit  model.Permission
		want model.Permission
	}{
		{"accessInbounds", model.PermAccessInbounds, 1},
		{"manageResellers", model.PermManageResellers, 1 << 11},
		{"manageOverview", model.PermOverviewManage, 1 << 12},
		{"accessOverview", model.PermAccessOverview, 1 << 13},
	} {
		if tc.bit != tc.want {
			t.Errorf("%s is %d, want %d: a bit was inserted instead of appended, which "+
				"shifts every mask already stored", tc.name, tc.bit, tc.want)
		}
	}
}
