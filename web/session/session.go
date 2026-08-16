// Package session provides session management utilities for the vpn-ui web panel.
// It handles user authentication state, login sessions, and session storage using Gin sessions.
package session

import (
	"net/http"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	loginUserKey = "LOGIN_USER"
	// loginUserCtxKey caches the loaded user for the life of one request, so the
	// several handlers that ask for it don't each re-query.
	loginUserCtxKey = "LOGIN_USER_ROW"
)

// The session cookie holds ONLY the user's id, never the user row.
//
// The store is signed but not encrypted (cookie.NewStore -> securecookie with a
// nil blockKey), so its gob body is readable in the browser with base64 -d. It
// used to carry the whole model.User, which put the admin's bcrypt hash in every
// browser and would have put their TOTP secret there too.
//
// Loading the row per request also means permission changes and account disables
// take effect immediately instead of lingering until the cookie's 6h expiry, and
// it sidesteps securecookie's 4096-byte cap.
//
// Upgrade note: a pre-upgrade cookie holds a gob'd model.User, so the int type
// assertion below fails and the session soft-logs-out. That is the intended
// migration: one forced re-login, rather than a stale snapshot decoding with
// zero permissions into a panel where every action silently 403s.

// SetLoginUser stores the authenticated user's id in the session.
func SetLoginUser(c *gin.Context, user *model.User) {
	if user == nil {
		return
	}
	s := sessions.Default(c)
	s.Set(loginUserKey, user.Id)
	c.Set(loginUserCtxKey, user)
}

// loginUserId returns the session's user id, or 0 when absent or unreadable.
func loginUserId(c *gin.Context) int {
	s := sessions.Default(c)
	obj := s.Get(loginUserKey)
	if obj == nil {
		return 0
	}
	id, ok := obj.(int)
	if !ok || id <= 0 {
		// Garbage, or a pre-upgrade cookie holding a gob'd model.User.
		s.Delete(loginUserKey)
		return 0
	}
	return id
}

// GetLoginUser returns the CURRENT row for the logged-in admin, read fresh from
// the database rather than trusted from the cookie. Returns nil when logged out,
// when the account has been deleted, or when it has been disabled.
func GetLoginUser(c *gin.Context) *model.User {
	if cached, exists := c.Get(loginUserCtxKey); exists {
		user, _ := cached.(*model.User)
		return user
	}
	user := loadLoginUser(c)
	c.Set(loginUserCtxKey, user)
	return user
}

func loadLoginUser(c *gin.Context) *model.User {
	id := loginUserId(c)
	if id == 0 {
		return nil
	}
	db := database.GetDB()
	if db == nil {
		return nil
	}
	user := &model.User{}
	if err := db.Model(model.User{}).Where("id = ?", id).First(user).Error; err != nil {
		return nil // deleted mid-session, or the DB is unavailable
	}
	if !user.Enable {
		return nil // disabled admins are logged out on their next request
	}
	return user
}

// IsLogin checks if a user is currently authenticated in the session.
// Returns true if a valid user session exists, false otherwise.
func IsLogin(c *gin.Context) bool {
	return GetLoginUser(c) != nil
}

// ClearSession removes all session data and invalidates the session.
// This effectively logs out the user and clears any stored session information.
func ClearSession(c *gin.Context) {
	s := sessions.Default(c)
	s.Clear()
	cookiePath := c.GetString("base_path")
	if cookiePath == "" {
		cookiePath = "/"
	}
	s.Options(sessions.Options{
		Path:     cookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
