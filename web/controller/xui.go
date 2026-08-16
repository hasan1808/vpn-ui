package controller

import (
	"net/http"

	"github.com/hasan1808/pro-ui/database/model"

	"github.com/gin-gonic/gin"
)

// XUIController is the main controller for the vpn-ui panel, managing sub-controllers.
type XUIController struct {
	BaseController

	settingController     *SettingController
	xraySettingController *XraySettingController
	coreController        *CoreController
	adminController       *AdminController
	resellerController    *ResellerController
}

// NewXUIController creates a new XUIController and initializes its routes.
func NewXUIController(g *gin.RouterGroup) *XUIController {
	a := &XUIController{}
	a.initRouter(g)
	return a
}

// initRouter sets up the main panel routes and initializes sub-controllers.
func (a *XUIController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/panel")
	g.Use(a.checkLogin)

	// Not requirePerm: the overview is the one page whose grant lives in two columns
	// (an admin's PermAccessOverview, a reseller's AllowOverview), and
	// requireOverviewAccess reads both. A denial here goes to landingPath, never
	// blindly back to this route, which is what used to make gating it impossible.
	g.GET("/", requireOverviewAccess(), a.index)
	g.GET("/inbounds", requirePerm(model.PermAccessInbounds), a.inbounds)
	// A protocol-scoped view of the same page, reached from the protocol tabs:
	// /inbounds/:proto keeps the same permission and renders the same template
	// with the scope preset. Unknown slugs are redirected to the unfiltered
	// page rather than rendered as a filter that matches nothing.
	g.GET("/inbounds/:proto", requirePerm(model.PermAccessInbounds), a.inbounds)
	// The account-centric view of the same data the Inbounds page shows, so it
	// takes the same claim.
	g.GET("/clients", requirePerm(model.PermAccessInbounds), a.clients)
	g.GET("/settings", requirePerm(model.PermPanelSettings), a.settings)
	g.GET("/xray", requirePerm(model.PermXraySettings), a.xraySettings)
	g.GET("/core", requirePerm(model.PermCoreSettings), a.coreSettings)
	g.GET("/admins", requireSuperAdmin(), a.admins)
	// Resellers is a permission and not requireSuperAdmin(), so a delegated admin can
	// run their own resellers. The escalation that opens (assigning someone else's
	// inbound to a reseller you then log in as) is closed in the service.
	g.GET("/resellers", requirePerm(model.PermManageResellers), a.resellers)

	a.settingController = NewSettingController(g)
	a.xraySettingController = NewXraySettingController(g)
	a.coreController = NewCoreController(g)
	a.adminController = NewAdminController(g)
	a.resellerController = NewResellerController(g)
}

// index renders the main panel index page.
//
// Who may be here at all is decided by requireOverviewAccess above, for both roles.
// A reseller used to be turned away by a redirect written out here, and the outcome
// is unchanged: their profile's allowOverview still decides, and without it
// landingPath sends them to the accounts page the role exists for. The check moved
// so that one function answers "may this caller open the overview" for the route,
// the landing resolver and the nav entry alike.
func (a *XUIController) index(c *gin.Context) {
	html(c, "index.html", "pages.index.title", nil)
}

// inbounds renders the inbounds management page. When the URL carries the
// /inbounds/:proto segment, the page is scoped to that protocol: the template
// receives it as .Protocol and the protocol tabs highlight the matching tab.
// The slug is validated before the template runs — model.IsInboundProtocol
// holds the accepted set, kept in step with the frontend's Protocols list in
// web/assets/js/model/inbound.js — so a stray slug is redirected to the
// unfiltered page instead of silently showing an empty filter.
func (a *XUIController) inbounds(c *gin.Context) {
	proto := c.Param("proto")
	if proto != "" && !model.IsInboundProtocol(proto) {
		c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path")+"panel/inbounds")
		return
	}
	html(c, "inbounds.html", "pages.inbounds.title", gin.H{"Protocol": proto})
}

// clients renders the account-centric Clients page.
func (a *XUIController) clients(c *gin.Context) {
	html(c, "clients.html", "pages.clients.title", nil)
}

// settings renders the settings management page.
func (a *XUIController) settings(c *gin.Context) {
	html(c, "settings.html", "pages.settings.title", nil)
}

// xraySettings renders the Xray settings page.
func (a *XUIController) xraySettings(c *gin.Context) {
	html(c, "xray.html", "pages.xray.title", nil)
}

// coreSettings renders the Core Settings page (per-core status + provisioning).
func (a *XUIController) coreSettings(c *gin.Context) {
	html(c, "core.html", "pages.core.title", nil)
}

// admins renders the Admins management page (super admin only).
func (a *XUIController) admins(c *gin.Context) {
	html(c, "admins.html", "pages.admins.title", nil)
}

// resellers renders the Resellers management page.
func (a *XUIController) resellers(c *gin.Context) {
	html(c, "resellers.html", "pages.resellers.title", nil)
}
