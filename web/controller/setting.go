package controller

import (
	"errors"
	"time"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/util/crypto"
	"github.com/hasan1808/pro-ui/web/entity"
	"github.com/hasan1808/pro-ui/web/service"
	"github.com/hasan1808/pro-ui/web/session"

	"github.com/gin-gonic/gin"
)

// updateUserForm represents the form for updating user credentials.
type updateUserForm struct {
	OldUsername string `json:"oldUsername" form:"oldUsername"`
	OldPassword string `json:"oldPassword" form:"oldPassword"`
	NewUsername string `json:"newUsername" form:"newUsername"`
	NewPassword string `json:"newPassword" form:"newPassword"`
}

// SettingController handles settings and user management operations.
type SettingController struct {
	settingService service.SettingService
	userService    service.UserService
	panelService   service.PanelService
	systemdService service.SystemdService
	sslService     service.SSLService
}

// NewSettingController creates a new SettingController and initializes its routes.
func NewSettingController(g *gin.RouterGroup) *SettingController {
	a := &SettingController{}
	a.initRouter(g)
	return a
}

// initRouter sets up the routes for settings management.
func (a *SettingController) initRouter(g *gin.RouterGroup) {
	// defaultSettings is deliberately OUTSIDE the permission gate below, on its own
	// group so the exemption cannot be undone by moving a line.
	//
	// It serves the read-only defaults every page that renders clients needs
	// (expiry/traffic warning thresholds, subscription URIs, date picker, page
	// size), and the inbounds page is reachable by resellers and by delegated
	// admins who hold no PermPanelSettings. Gating it meant their page load always
	// fired one request they could never pass: the panel toasted "you do not have
	// permission" on every visit, and - worse than the noise - the reply never
	// landed, so subSettings stayed disabled and their accounts showed no
	// subscription link or QR at all.
	//
	// Login is still required: this group descends from /panel, which carries
	// checkLogin. The response is trimmed for callers without PermPanelSettings.
	g.Group("/setting").POST("/defaultSettings", a.getDefaultSettings)

	g = g.Group("/setting")
	g.Use(requirePerm(model.PermPanelSettings))

	g.POST("/all", a.getAllSetting)
	g.POST("/update", a.updateSetting)
	g.POST("/updateUser", a.updateUser)
	g.POST("/twoFactor", a.updateTwoFactor)
	g.POST("/restartPanel", a.restartPanel)
	// Its own route rather than a field in AllSetting: the switch is on the
	// inbounds page, which never loads the settings blob, so posting through
	// /update would mean fetching every setting just to send them all back -
	// and any field that round trip got wrong would be saved along with it.
	g.POST("/inboundForm", a.setLegacyInboundForm)
	g.GET("/getDefaultJsonConfig", a.getDefaultXrayConfig)
	g.GET("/service", a.serviceStatus)
	g.GET("/service/log", a.serviceLog)
	// Writes a systemd unit as root: escalation-class, so no permission bit stands
	// in for it.
	g.POST("/service", requireSuperAdmin(), a.saveService)

	// The SSL certificate manager. Reading rides the PermPanelSettings gate above;
	// every route that ACTS carries requireSuperAdmin() inline, for the same reason
	// saveService does and the reason spelled out at core.go:44-49. Driving acme.sh
	// as a subprocess and then writing the files this webserver loads as its own TLS
	// identity is running code as root on the host, and no permission bit stands in
	// for that. Handlers are in ssl.go; the gating stays here, where the group is.
	g.GET("/ssl/status", a.sslStatus)
	g.GET("/ssl/run-status", a.sslRunStatus)
	// A POST only because it carries the identifier list. It contacts no CA and
	// changes nothing, so it is a read.
	g.POST("/ssl/preflight", a.sslPreflight)
	// Also a read: it probes this host and reports which validation method it
	// would use for a set of names, without contacting anything.
	g.POST("/ssl/suggest", a.sslSuggest)
	g.GET("/ssl/consumers", a.sslConsumers)
	g.POST("/ssl/start", requireSuperAdmin(), a.sslStart)
	g.POST("/ssl/use-managed", requireSuperAdmin(), a.sslUseManaged)
	// The other half of the switch: clearing a listener's setting so it stops
	// serving TLS at all. Same gate, because it decides the panel's own identity.
	g.POST("/ssl/unassign", requireSuperAdmin(), a.sslUnassign)
	g.POST("/ssl/rollback", requireSuperAdmin(), a.sslRollback)
	// Deleting a certificate takes private keys off disk and can strand a listener,
	// so it sits on the same super-admin gate as everything else that mutates here.
	g.POST("/ssl/delete-profile", requireSuperAdmin(), a.sslDeleteProfile)
	g.POST("/ssl/adopt", requireSuperAdmin(), a.sslAdopt)
	// Taking over what deploy.sh and vpn-ui.sh installed. Writes certificate
	// material and can re-point a listener, so it takes the same gate as issuing.
	g.POST("/ssl/sync", requireSuperAdmin(), a.sslSync)
	g.POST("/ssl/auto-renew", requireSuperAdmin(), a.sslAutoRenew)
	g.POST("/ssl/nickname", requireSuperAdmin(), a.sslNickname)
}

// serviceStatus returns the current systemd unit state for the panel.
func (a *SettingController) serviceStatus(c *gin.Context) {
	jsonObj(c, a.systemdService.ServiceState(), nil)
}

// serviceLog returns the live systemd status + journal tail for the panel's unit.
func (a *SettingController) serviceLog(c *gin.Context) {
	jsonObj(c, a.systemdService.ServiceLog(), nil)
}

// saveService writes/updates the panel's systemd unit and applies the enable
// (start-on-boot) and start (run-now) toggles.
func (a *SettingController) saveService(c *gin.Context) {
	var req service.SaveServiceRequest
	if err := c.ShouldBind(&req); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	err := a.systemdService.SaveService(req)
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
}

// getAllSetting retrieves all current settings.
func (a *SettingController) getAllSetting(c *gin.Context) {
	allSetting, err := a.settingService.GetAllSetting()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, allSetting, nil)
}

// getDefaultSettings retrieves the default settings based on the host.
func (a *SettingController) getDefaultSettings(c *gin.Context) {
	// Panel-settings holders get the whole map; everyone else gets it minus the
	// inbound-authoring cert/key paths they have no route to use.
	full := session.GetLoginUser(c).Can(model.PermPanelSettings)
	result, err := a.settingService.GetDefaultSettings(c.Request.Host, full)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, result, nil)
}

// updateSetting updates all settings with the provided data.
func (a *SettingController) updateSetting(c *gin.Context) {
	allSetting := &entity.AllSetting{}
	err := c.ShouldBind(allSetting)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	err = a.settingService.UpdateAllSetting(allSetting)
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
}

// setLegacyInboundForm switches the panel between the old inbound dialog and the
// current one, for everyone. Form-encoded like every other POST the panel makes
// (assets/js/util/index.js stringifies each body), so the flag arrives as a
// string and "true" is the only value that turns it on.
func (a *SettingController) setLegacyInboundForm(c *gin.Context) {
	enabled := c.PostForm("enabled") == "true"
	err := a.settingService.SetLegacyInboundForm(enabled)
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
}

// updateUser updates the current user's username and password.
func (a *SettingController) updateUser(c *gin.Context) {
	form := &updateUserForm{}
	err := c.ShouldBind(form)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	user := session.GetLoginUser(c)
	if user.Username != form.OldUsername || !crypto.CheckPasswordHash(user.Password, form.OldPassword) {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifyUserError"), errors.New(I18nWeb(c, "pages.settings.toasts.originalUserPassIncorrect")))
		return
	}
	if form.NewUsername == "" || form.NewPassword == "" {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifyUserError"), errors.New(I18nWeb(c, "pages.settings.toasts.userPassMustBeNotEmpty")))
		return
	}
	err = a.userService.UpdateUser(user.Id, form.NewUsername, form.NewPassword)
	if err == nil {
		user.Username = form.NewUsername
		user.Password, _ = crypto.HashPasswordAsBcrypt(form.NewPassword)
		session.SetLoginUser(c, user)
	}
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifyUser"), err)
}

// restartPanel restarts the panel service after a delay.
func (a *SettingController) restartPanel(c *gin.Context) {
	err := a.panelService.RestartPanel(time.Second * 3)
	jsonMsg(c, I18nWeb(c, "pages.settings.restartPanelSuccess"), err)
}

// getDefaultXrayConfig retrieves the default Xray configuration.
func (a *SettingController) getDefaultXrayConfig(c *gin.Context) {
	defaultJsonConfig, err := a.settingService.GetDefaultXrayConfig()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, defaultJsonConfig, nil)
}

// twoFactorForm enrols or clears the CALLER's own TOTP. There is deliberately no
// user id: an admin may only ever change their own second factor, so it comes from
// the session and can never be aimed at someone else.
type twoFactorForm struct {
	Enable bool   `json:"enable" form:"enable"`
	Token  string `json:"token" form:"token"`
	Code   string `json:"code" form:"code"`
}

// updateTwoFactor turns the caller's own TOTP on or off.
func (a *SettingController) updateTwoFactor(c *gin.Context) {
	user := session.GetLoginUser(c)
	if user == nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.security.twoFactor"), errors.New("not logged in"))
		return
	}
	form := &twoFactorForm{}
	if err := c.ShouldBind(form); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.security.twoFactor"), err)
		return
	}
	if form.Enable {
		// Verify against the SUBMITTED secret before storing it. Enrolment used to be
		// checked in the browser only, so a mistyped code, a clock-skewed phone, or a
		// tampered request could enable 2FA with a secret the admin cannot produce
		// codes for, locking them out of their own account permanently.
		if !service.VerifyTOTPCode(form.Token, form.Code) {
			jsonMsg(c, I18nWeb(c, "pages.settings.security.twoFactor"),
				errors.New("that code does not match the secret; check your authenticator and try again"))
			return
		}
	} else if user.TwoFactorEnable {
		// Turning it off needs the authenticator, not just a live session. The secret
		// is never sent to the browser, so only the server can check this.
		if !service.VerifyTOTPCode(user.TwoFactorToken, form.Code) {
			jsonMsg(c, I18nWeb(c, "pages.settings.security.twoFactor"),
				errors.New("that code does not match; use your authenticator, or change your password to clear two-factor"))
			return
		}
	}
	if err := a.userService.SetTwoFactor(user.Id, form.Enable, form.Token); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.security.twoFactor"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.settings.security.twoFactor"), nil)
}
