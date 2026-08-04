package controller

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"

	"github.com/gin-gonic/gin"
)

// Self-inflicted lockouts the Admins UI refuses. The service enforces that a panel
// always retains a super admin; these catch the narrower case of the caller doing
// it to themselves, where the service cannot tell who is asking.
var (
	errSelfDemote = errors.New("you cannot remove your own super admin role or disable your own account")
	errSelfDelete = errors.New("you cannot delete your own account")
	// errNotOwned is reported as a not-found so it cannot confirm that an object with
	// that id exists under another admin.
	errNotOwned = errors.New("not found")
)

// Permission gating. This is the ONLY enforcement: hiding a nav item or a page
// section in the UI is cosmetic, since the routes stay reachable by direct request.
//
// Note that /panel and /panel/api are SIBLING Gin groups despite the URL nesting,
// so middleware on /panel does not cover /panel/api. Both must be gated.

// deny aborts the request, matching the shape each caller expects: a JSON error
// for XHR, a redirect for a page navigation.
//
// The XHR case answers HTTP 200 with success:false, which is this panel's
// convention everywhere (see jsonMsg). It matters: axios REJECTS any non-2xx, so a
// real 403 never reaches the success/msg handling and the user is shown axios's own
// "Request failed with status code 403" instead of what actually went wrong. The
// status argument is kept for the 401 case, which the frontend does treat specially.
//
// An EMPTY redirectTo means the caller can open no page at all (see landingPath).
// That case must not redirect: every target would deny them in turn and the browser
// would spin through the redirect chain until it gave up.
func deny(c *gin.Context, status int, msgKey string, redirectTo string) {
	if !wantsHTML(c) {
		// Anything that is not a page navigation gets JSON, even without the ajax
		// header. Keying purely on X-Requested-With was wrong: a request that missed
		// the header got a 307 with an empty body, and the frontend surfaced that as
		// "No response data" instead of the reason. A redirect is only ever a
		// sensible answer to a browser asking for a page.
		if status == http.StatusUnauthorized {
			// Session expired: the frontend keys off the 401 to send them to login.
			pureJsonMsg(c, status, false, I18nWeb(c, msgKey))
			c.Abort()
			return
		}
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, msgKey))
		c.Abort()
		return
	}
	if redirectTo == "" {
		denyPlainPage(c, msgKey)
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, redirectTo)
	c.Abort()
}

// denyPlainPage refuses a page navigation that has nowhere to be sent, i.e. an
// account holding no permission that opens any page. It is the one place in the
// panel that answers a browser with a real 403: nothing here reaches axios (that is
// the !wantsHTML branch above), so the 200 + success:false convention does not apply
// and a status the browser understands is the honest answer.
func denyPlainPage(c *gin.Context, msgKey string) {
	c.String(http.StatusForbidden, I18nWeb(c, msgKey))
	c.Abort()
}

// landingPages is where a denied page navigation is sent, first entry the caller can
// actually open wins. Order is the panel's own nav order, so the fallback lands
// somewhere the caller recognises rather than on whichever page happens to be first
// in the route table.
//
// The overview leads because it is every ordinary admin's home. It is no longer a
// safe unconditional target though, which is the whole reason this table exists:
// PermAccessOverview can be withheld, and deny() used to redirect there blindly.
//
// /panel/admins is absent on purpose: it is super-admin-only, and a super admin
// passes every gate, so it can never be someone's only reachable page.
var landingPages = []struct {
	perm model.Permission
	path string
}{
	{model.PermAccessOverview, "panel/"},
	{model.PermAccessInbounds, "panel/inbounds"},
	{model.PermManageResellers, "panel/resellers"},
	{model.PermPanelSettings, "panel/settings"},
	{model.PermXraySettings, "panel/xray"},
	{model.PermCoreSettings, "panel/core"},
}

// landingPath is the first page this caller may actually open, base-path prefixed,
// or "" when there is none.
//
// Empty is a real answer and callers must handle it rather than substituting a
// default: an admin can legitimately hold only action bits (say createClient) with
// no page bit at all, and any redirect issued from that state loops.
func landingPath(c *gin.Context) string {
	user := session.GetLoginUser(c)
	if user == nil {
		return ""
	}
	for _, p := range landingPages {
		// The overview is asked through overviewAccess rather than Can, so a reseller
		// whose profile opens it lands there and one whose profile does not never gets
		// sent to a page that would only bounce them onward.
		if p.perm == model.PermAccessOverview {
			if overviewAccess(user) {
				return c.GetString("base_path") + p.path
			}
			continue
		}
		if user.Can(p.perm) {
			return c.GetString("base_path") + p.path
		}
	}
	return ""
}

// overviewAccess answers "may this caller open the overview", which the two roles
// answer from different columns: an admin from PermAccessOverview, a reseller from
// their profile, whose stored mask Can() ignores by design. Everything that gates
// the overview goes through here (the route, the landing resolver, the nav entry),
// so the two columns cannot drift into disagreeing about the same page.
func overviewAccess(user *model.User) bool {
	if user == nil {
		return false
	}
	if user.IsReseller {
		access, _ := resellerOverviewGrants(user)
		return access
	}
	return user.Can(model.PermAccessOverview)
}

// overviewManage answers "may this caller ACT from the overview", the counterpart to
// overviewAccess and resolved the same way: an admin from PermOverviewManage, a
// reseller from their profile.
//
// A reseller is asked for BOTH grants. Manage without access is a state the reseller
// modal already refuses to produce (turning Access off clears Manage), but the columns
// are two independent booleans in the database, and an import or a hand-edited row can
// carry the pair the modal will not.
//
// READ THIS BEFORE WIDENING ANYTHING ONTO THIS BIT. The operator deliberately chose,
// 2026-07-31 and with the consequence spelled out, that this permission reaches the
// escalation-class overview actions: the panel update (which replaces the running
// binary as root), config.json (every inbound's secrets across all admins), the logs
// (other admins' clients and IPs), and backup / restore / DB import-export (the whole
// SQLite file, users table and bcrypt hashes included). So a delegated admin or a
// reseller holding this bit can take the panel. That is the operator's call, not an
// oversight, and it is why what stayed behind requireSuperAdmin stayed: admin
// management (it mints super admins), the host reboot, core uninstall, and the systemd
// unit. None of those are on the overview, so none of them are what this bit is for.
func overviewManage(user *model.User) bool {
	if user == nil {
		return false
	}
	if user.IsReseller {
		access, manage := resellerOverviewGrants(user)
		return access && manage
	}
	return user.Can(model.PermOverviewManage)
}

// requireOverviewManage gates the acting half for both roles. Needed as its own
// middleware because requirePerm asks Can(), and Can() ignores a reseller's stored
// mask by design, so a reseller can never satisfy it no matter what their profile
// says. Gating these routes on requirePerm alone would render the reseller's
// AllowOverviewManage toggle permanently inert.
func requireOverviewManage() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			deny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if !overviewManage(user) {
			deny(c, http.StatusForbidden, "pages.admins.forbidden", landingPath(c))
			return
		}
		c.Next()
	}
}

// requireXrayOrOverviewManage admits a caller who holds EITHER the Xray permission or
// the overview's acting bit.
//
// It exists for the custom geo group, which two different pages read: the Xray routing
// editor (which has nothing to do with the overview) and the overview's geofiles
// dialog. Gating the group on the Xray bit alone made the dialog unreachable for
// anyone whose only claim on it is the overview, which is every reseller, since a
// reseller's derived mask never carries a settings bit. The WRITES inside the group
// still ask for the overview bit specifically, so this widens what can be READ, not
// what can be changed.
func requireXrayOrOverviewManage() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			deny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if user.Can(model.PermXraySettings) || overviewManage(user) {
			c.Next()
			return
		}
		deny(c, http.StatusForbidden, "pages.admins.forbidden", landingPath(c))
	}
}

// requireOverviewAccess gates the overview page for both roles.
//
// A reseller used to be turned away inside the handler instead. Same outcome, but
// as one gate rather than two: with the admin half added, two handlers answering
// the same question from two columns is how one of them ends up wrong.
func requireOverviewAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			deny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if !overviewAccess(user) {
			deny(c, http.StatusForbidden, "pages.admins.forbidden", landingPath(c))
			return
		}
		c.Next()
	}
}

// wantsHTML reports whether this is a browser navigating to a page, as opposed to
// a call expecting data. Only the former should ever be redirected.
//
// A page navigation is a GET whose Accept asks for HTML. Every API call fails at
// least one of those: a POST is never a navigation, and axios sends Accept:
// application/json, */*. The ajax header is treated as a definitive "not a
// navigation" but is no longer required, so a call that omits it still gets a
// readable error rather than an empty redirect body.
func wantsHTML(c *gin.Context) bool {
	if isAjax(c) {
		return false
	}
	if c.Request.Method != http.MethodGet {
		return false
	}
	return strings.Contains(c.GetHeader("Accept"), "text/html")
}

// requirePerm gates a route on a single permission. Super admins always pass.
func requirePerm(perm model.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			// Logged out, deleted mid-session, or disabled.
			deny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if !user.Can(perm) {
			// Authenticated but not allowed: send a page navigation to a page this
			// caller can actually open rather than to a dead end. It used to be the
			// overview unconditionally, which only worked while the overview was
			// ungated.
			deny(c, http.StatusForbidden, "pages.admins.forbidden", landingPath(c))
			return
		}
		c.Next()
	}
}

// requireSuperAdmin gates the escalation-class routes that no permission bit can
// safely stand in for, because reaching any of them yields the whole panel:
// exporting or importing the SQLite DB (every admin's bcrypt hash), mailing it to
// Telegram, replacing the panel binary, writing the systemd unit as root, and
// rebooting the host. It also gates admin management itself.
func requireSuperAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			deny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if !user.IsSuperAdmin {
			deny(c, http.StatusForbidden, "pages.admins.forbidden", landingPath(c))
			return
		}
		c.Next()
	}
}

// accessService backs the access middleware below. AdminService is stateless.
var accessService service.AdminService

// resellerService answers the question an inbound grant cannot: WHICH accounts on a
// shared inbound belong to the caller. Stateless, like accessService.
var resellerService service.ResellerService

// accountService owns the accounts layer: one identity, N inbound memberships,
// one quota. Stateless, like the two above.
var accountService service.AccountService

// denyNotFound refuses a cross-owner reference. It reports "not found" rather than
// "forbidden" on purpose: a distinguishable 403 would confirm that an inbound with
// that id exists and belongs to someone else, turning the middleware into an
// enumeration oracle over the small integer id space.
func denyNotFound(c *gin.Context) {
	if !wantsHTML(c) {
		// 200 + success:false, like every other error this panel returns: axios
		// rejects a non-2xx before the msg is ever read.
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.inbounds.notFound"))
		c.Abort()
		return
	}
	// Same landing rule as deny(), including the no-page case: a caller with nothing
	// to open cannot be redirected anywhere without looping.
	if to := landingPath(c); to != "" {
		c.Redirect(http.StatusTemporaryRedirect, to)
		c.Abort()
		return
	}
	denyPlainPage(c, "pages.inbounds.notFound")
}

// requireInboundAccess asserts the caller has been GRANTED the inbound named by the
// :id path param. Routes registered in both an :id-ful and an :id-less form (the cert
// generators, which also serve not-yet-saved inbounds) pass through when :id is
// absent; there is no object to authorize against yet.
func requireInboundAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			deny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if user.IsSuperAdmin {
			c.Next()
			return
		}
		raw := c.Param("id")
		if raw == "" {
			c.Next()
			return
		}
		id, err := strconv.Atoi(raw)
		if err != nil {
			denyNotFound(c)
			return
		}
		ok, err := accessService.CanAccessInbound(id, user.Id)
		if err != nil || !ok {
			denyNotFound(c)
			return
		}
		c.Next()
	}
}

// requireClientAccess asserts the caller may act on the client named by the :email
// path param. Client emails are a single panel-wide namespace, so without this an
// :email route reaches straight across admins.
//
// Two different questions, depending on who is asking. For an admin it is the
// inbound grant: every client on an inbound they hold is theirs to touch. For a
// reseller it is account ownership, and that check REPLACES the grant check rather
// than joining it. A reseller holds the grant for their assigned inbounds (that is
// how they see them at all), so CanAccessClientEmail answers true for every account
// on those inbounds, including the admin's, and supplementing would wave them
// straight through to exactly the accounts this role exists to keep them out of.
func requireClientAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			deny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if user.IsSuperAdmin {
			c.Next()
			return
		}
		email := c.Param("email")
		if email == "" {
			denyNotFound(c)
			return
		}
		if user.IsReseller {
			owns, err := resellerService.OwnsClientEmail(email, user.Id)
			if err != nil || !owns {
				denyNotFound(c)
				return
			}
			c.Next()
			return
		}
		ok, err := accessService.CanAccessClientEmail(email, user.Id)
		if err != nil || !ok {
			denyNotFound(c)
			return
		}
		c.Next()
	}
}

// Refusal text for the routes a reseller can reach with the bits the role derives
// but must not use. Plain English rather than an i18n key: these are reasons, not
// labels, and the reseller has to read why a control they can see does nothing.
const (
	// Both traffic-writing routes hand an account bytes past the quota the
	// reseller's balance was debited for, and the giveaway comes off the house
	// rather than off them. Refused outright rather than priced: there is no
	// charge that makes "your counter is now zero" cost the seller anything.
	msgResellerNoTrafficWrite = "Resellers cannot change an account's traffic counters. Change the account's traffic limit instead."
	// Both inbound-wide routes are defined over every client on an inbound, which
	// a reseller shares with admins and with other resellers, so they reach
	// accounts that are not theirs.
	msgResellerNoInboundWide = "Resellers cannot run this across a whole inbound: it would reach accounts you do not own."
)

// denyForReseller refuses an operation outright when the caller is a reseller, and
// reports whether it answered the request so call sites read as a guard.
//
// Unlike denyNotFound this says forbidden, plainly. Hiding the reason behind a
// not-found would be pointless here: the route is not about some object that may or
// may not exist under another owner, and the reseller can already see the button.
func denyForReseller(c *gin.Context, msg string) bool {
	user := session.GetLoginUser(c)
	if user == nil || !user.IsReseller {
		return false
	}
	pureJsonMsg(c, http.StatusOK, false, msg)
	return true
}
