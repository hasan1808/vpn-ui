package controller

import (
	"net"
	"net/http"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/entity"
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/session"
)

// getRemoteIp extracts the real IP address from the request headers or remote address.
func getRemoteIp(c *gin.Context) string {
	value := c.GetHeader("X-Real-IP")
	if value != "" {
		return value
	}
	value = c.GetHeader("X-Forwarded-For")
	if value != "" {
		ips := strings.Split(value, ",")
		return ips[0]
	}
	addr := c.Request.RemoteAddr
	ip, _, _ := net.SplitHostPort(addr)
	return ip
}

// jsonMsg sends a JSON response with a message and error status.
func jsonMsg(c *gin.Context, msg string, err error) {
	jsonMsgObj(c, msg, nil, err)
}

// jsonObj sends a JSON response with an object and error status.
func jsonObj(c *gin.Context, obj any, err error) {
	jsonMsgObj(c, "", obj, err)
}

// jsonMsgObj sends a JSON response with a message, object, and error status.
func jsonMsgObj(c *gin.Context, msg string, obj any, err error) {
	m := entity.Msg{
		Obj: obj,
	}
	if err == nil {
		m.Success = true
		if msg != "" {
			m.Msg = msg
		}
	} else {
		m.Success = false
		errStr := err.Error()
		if errStr != "" {
			m.Msg = msg + " (" + errStr + ")"
			logger.Warning(msg+" "+I18nWeb(c, "fail")+": ", err)
		} else if msg != "" {
			m.Msg = msg
			logger.Warning(msg + " " + I18nWeb(c, "fail"))
		} else {
			m.Msg = I18nWeb(c, "somethingWentWrong")
			logger.Warning(I18nWeb(c, "somethingWentWrong") + " " + I18nWeb(c, "fail"))
		}
	}
	c.JSON(http.StatusOK, m)
}

// pureJsonMsg sends a pure JSON message response with custom status code.
func pureJsonMsg(c *gin.Context, statusCode int, success bool, msg string) {
	c.JSON(statusCode, entity.Msg{
		Success: success,
		Msg:     msg,
	})
}

// browserHost returns the host the client used to reach the panel (the browser
// address-bar host, with the port stripped): the X-Forwarded-Host set by a reverse
// proxy, otherwise the request Host. This is the server-side equivalent of the
// location.hostname that xray share-links use, so server-generated configs (e.g. .ovpn,
// the WireGuard Endpoint, the SSH server) can point at whatever address the operator is
// actually using.
//
// It deliberately does NOT consult X-Real-IP: by convention (nginx
// `proxy_set_header X-Real-IP $remote_addr`) that header carries the CLIENT's IP, not
// the panel host, so using it made every generated endpoint resolve to the admin's own
// address behind a standard reverse proxy — visible as "the config ignores the panel
// URL unless an external proxy is set".
func browserHost(c *gin.Context) string {
	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		h, _, err := net.SplitHostPort(c.Request.Host)
		if err != nil {
			h = c.Request.Host
		}
		host = h
	}
	// A comma-separated X-Forwarded-Host (proxy chain) lists the original host first.
	if i := strings.IndexByte(host, ','); i >= 0 {
		host = strings.TrimSpace(host[:i])
	}
	return host
}

// html renders an HTML template with the provided data and title.
func html(c *gin.Context, name string, title string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	data["title"] = title
	data["host"] = browserHost(c)
	data["request_uri"] = c.Request.RequestURI
	data["base_path"] = c.GetString("base_path")
	data["cur_ver"] = config.GetVersion()
	// Every page funnels through here and includes the sidebar with the dot, so
	// putting the caller's permissions in once makes them available panel-wide with
	// no round trip and no nav flicker on first paint.
	//
	// This drives what the UI SHOWS, never what it ALLOWS: the routes stay reachable
	// by direct request, so the middleware is the enforcement. Hiding a tab is a
	// courtesy, not a control.
	data["perms"] = templatePerms(c)
	data["me"] = currentUserId(c)
	// A reseller's own limits, for the pages they actually use. Delivered with the
	// page rather than over XHR because the client modal has to know BEFORE first
	// paint whether to render an expiry field at all: fetching it would flash a
	// control the reseller is not allowed to have. Empty map for everyone else, so
	// a template reads {{ if .reseller.isReseller }} without a nil check.
	data["reseller"] = templateReseller(c)
	// The caller's own 2FA state, for the security panel's switch. The SECRET is
	// never shipped: the settings blob used to carry it, which handed every
	// logged-in admin the shared factor.
	data["two_factor"] = currentTwoFactorEnabled(c)
	c.HTML(http.StatusOK, name, getContext(data))
}

// currentUserId is the logged-in admin's id, 0 when logged out. The Admins page
// uses it to stop an admin deleting or demoting themselves.
func currentUserId(c *gin.Context) int {
	if user := session.GetLoginUser(c); user != nil {
		return user.Id
	}
	return 0
}

// currentTwoFactorEnabled reports whether the caller has their own TOTP on.
func currentTwoFactorEnabled(c *gin.Context) bool {
	if user := session.GetLoginUser(c); user != nil {
		return user.TwoFactorEnable
	}
	return false
}

// templatePerms is the logged-in admin's capability set, shaped for templates.
// A map keyed by slug so a template reads {{ if .perms.accessInbounds }}.
func templatePerms(c *gin.Context) map[string]bool {
	perms := make(map[string]bool, len(model.AllPermissions)+1)
	user := session.GetLoginUser(c)
	if user == nil {
		return perms
	}
	for _, d := range model.AllPermissions {
		perms[d.Slug] = user.Can(d.Bit)
	}
	perms["superAdmin"] = user.IsSuperAdmin
	// The overview asks two questions -- "may this page be opened?" and "may it
	// act?" -- and the two roles answer them from different columns: an admin from
	// the permission bits, a reseller from their profile, whose stored mask Can()
	// ignores by design. Resolving that here keeps it out of the templates, which
	// would otherwise have to spell the disjunction at every control and at the nav
	// entry, and would get it wrong once.
	if user.IsReseller {
		perms["accessOverview"], perms["manageOverview"] = resellerOverviewGrants(user)
	}
	return perms
}

// resellerOverviewGrants reports whether this reseller's profile opens the overview
// and, separately, its management controls. Both come out of ONE profile read: the
// two answers are always wanted together (page plus controls), and a second lookup
// per render only creates the chance of answering them from two different rows.
//
// Manage requires AllowOverview too: it scopes a page they have to be able to reach
// first, and a profile carrying only the second is a half-saved form, not a grant.
func resellerOverviewGrants(user *model.User) (access, manage bool) {
	var svc service.ResellerService
	p, err := svc.ProfileFor(user.Id)
	if err != nil {
		// Same reading as templateReseller: a reseller with no profile row is a
		// broken account, not a privileged one.
		return false, false
	}
	return p.AllowOverview, p.AllowOverview && p.AllowOverviewManage
}

// templateReseller is the caller's own reseller limits and balance, shaped for
// templates. Empty (isReseller false) for an admin.
//
// Like templatePerms this drives what the UI SHOWS, never what it ALLOWS. Every
// number here is re-derived server-side before a single byte is charged, so a
// browser that lies about its own minimums buys nothing.
func templateReseller(c *gin.Context) map[string]any {
	out := map[string]any{"isReseller": false}
	user := session.GetLoginUser(c)
	if user == nil || !user.IsReseller {
		return out
	}
	var svc service.ResellerService
	p, err := svc.ProfileFor(user.Id)
	if err != nil {
		// A reseller with no profile row is a broken account, not a privileged
		// one. Report the role with zeroed levers rather than failing the page:
		// the server-side checks still refuse every write.
		out["isReseller"] = true
		return out
	}
	available := p.AllowanceBytes - p.SpentBytes
	if available < 0 {
		available = 0
	}
	out["isReseller"] = true
	out["unlimited"] = p.Unlimited
	out["allowanceBytes"] = p.AllowanceBytes
	out["spentBytes"] = p.SpentBytes
	out["availableBytes"] = available
	out["daysPerGb"] = p.DaysPerGB
	out["minCreateGb"] = p.MinCreateGB
	out["minAddGb"] = p.MinAddGB
	out["allowExternalProxy"] = p.AllowExternalProxy
	out["allowOverview"] = p.AllowOverview
	out["allowOverviewManage"] = p.AllowOverviewManage
	return out
}

// getContext adds version and other context data to the provided gin.H.
func getContext(h gin.H) gin.H {
	a := gin.H{
		"cur_ver": config.GetVersion(),
	}
	for key, value := range h {
		a[key] = value
	}
	return a
}

// isAjax checks if the request is an AJAX request.
func isAjax(c *gin.Context) bool {
	return c.GetHeader("X-Requested-With") == "XMLHttpRequest"
}
