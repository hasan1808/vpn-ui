package controller

import (
	"errors"
	"fmt"
	"net/http"
	"text/template"
	"time"

	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/web/entity"
	"github.com/hasan1808/pro-ui/web/service"
	"github.com/hasan1808/pro-ui/web/session"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// LoginForm represents the login request structure.
type LoginForm struct {
	Username      string `json:"username" form:"username"`
	Password      string `json:"password" form:"password"`
	TwoFactorCode string `json:"twoFactorCode" form:"twoFactorCode"`
}

// IndexController handles the main index and login-related routes.
type IndexController struct {
	BaseController

	settingService service.SettingService
	userService    service.UserService
	tgbot          service.Tgbot
}

// NewIndexController creates a new IndexController and initializes its routes.
func NewIndexController(g *gin.RouterGroup) *IndexController {
	a := &IndexController{}
	a.initRouter(g)
	return a
}

// initRouter sets up the routes for index, login, logout, and two-factor authentication.
func (a *IndexController) initRouter(g *gin.RouterGroup) {
	g.GET("/", a.index)
	g.GET("/logout", a.logout)

	g.POST("/login", a.login)
	g.POST("/getTwoFactorEnable", a.getTwoFactorEnable)
}

// index handles the root route, redirecting logged-in users to the panel or showing the login page.
func (a *IndexController) index(c *gin.Context) {
	if session.IsLogin(c) {
		c.Redirect(http.StatusTemporaryRedirect, "panel/")
		return
	}
	html(c, "login.html", "pages.login.title", nil)
}

// login handles user authentication and session creation.
func (a *IndexController) login(c *gin.Context) {
	var form LoginForm

	if err := c.ShouldBind(&form); err != nil {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.invalidFormData"))
		return
	}
	if form.Username == "" {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.emptyUsername"))
		return
	}
	if form.Password == "" {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.emptyPassword"))
		return
	}

	user, checkErr := a.userService.CheckUser(form.Username, form.Password, form.TwoFactorCode)
	timeStr := time.Now().Format("2006-01-02 15:04:05")
	safeUser := template.HTMLEscapeString(form.Username)
	safePass := template.HTMLEscapeString(form.Password)

	if user == nil {
		// The password was right and this account simply has a second factor: ask for
		// the code rather than reporting a failure. This is NOT a wrong login, so it
		// must not be logged as one or reported to Telegram as one.
		//
		// Safe to disclose here precisely because it is post-password: only someone
		// who already authenticated learns that the account has 2FA. Answering the
		// same question BEFORE the password (which is what the old pre-auth
		// getTwoFactorEnable did once 2FA became per-admin) would hand an
		// unauthenticated caller an oracle for which usernames exist.
		if errors.Is(checkErr, service.ErrInvalidTwoFactorCode) && form.TwoFactorCode == "" {
			c.JSON(http.StatusOK, entity.Msg{
				Success: false,
				Msg:     I18nWeb(c, "pages.login.toasts.twoFactorRequired"),
				Obj:     gin.H{"twoFactorRequired": true},
			})
			return
		}

		logger.Warningf("wrong username: \"%s\", password: \"%s\", IP: \"%s\"", safeUser, safePass, getRemoteIp(c))

		notifyPass := safePass

		if errors.Is(checkErr, service.ErrInvalidTwoFactorCode) {
			translatedError := a.tgbot.I18nBot("tgbot.messages.2faFailed")
			notifyPass = fmt.Sprintf("*** (%s)", translatedError)
		}

		a.tgbot.UserLoginNotify(safeUser, notifyPass, getRemoteIp(c), timeStr, 0)
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.wrongUsernameOrPassword"))
		return
	}

	logger.Infof("%s logged in successfully, Ip Address: %s\n", safeUser, getRemoteIp(c))
	a.tgbot.UserLoginNotify(safeUser, ``, getRemoteIp(c), timeStr, 1)

	session.SetLoginUser(c, user)
	if err := sessions.Default(c).Save(); err != nil {
		logger.Warning("Unable to save session: ", err)
		return
	}

	logger.Infof("%s logged in successfully", safeUser)
	jsonMsg(c, I18nWeb(c, "pages.login.toasts.successLogin"), nil)
}

// logout handles user logout by clearing the session and redirecting to the login page.
func (a *IndexController) logout(c *gin.Context) {
	user := session.GetLoginUser(c)
	if user != nil {
		logger.Infof("%s logged out successfully", user.Username)
	}
	session.ClearSession(c)
	if err := sessions.Default(c).Save(); err != nil {
		logger.Warning("Unable to save session after clearing:", err)
	}
	c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path"))
}

// getTwoFactorEnable tells the login page whether to render the code field up front.
//
// It always says NO, and the field is revealed only after a correct password on an
// account that has 2FA (see login, which answers twoFactorRequired).
//
// This endpoint is PRE-AUTH and 2FA is now per-admin, so an honest answer would need
// the username, which would turn it into an oracle for unauthenticated callers:
// whether an account exists, and whether it has a second factor. Always saying YES
// closes that too, but shows a Code box to every admin who does not use 2FA, which
// reads as "you need something you do not have".
//
// Kept rather than removed so an older cached login page still renders.
func (a *IndexController) getTwoFactorEnable(c *gin.Context) {
	jsonObj(c, false, nil)
}
