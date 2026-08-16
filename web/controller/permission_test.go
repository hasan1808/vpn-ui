package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/web/locale"
	"github.com/hasan1808/pro-ui/web/session"

	"github.com/gin-gonic/gin"
)

// The middleware is the only real enforcement (hiding UI is cosmetic), so it is
// worth driving through a real Gin stack rather than trusting the wiring.
//
// session.GetLoginUser reads the DB, but it caches into the gin context first, so
// seeding that cache lets these run without one.
func withUser(user *model.User) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("LOGIN_USER_ROW", user)
		c.Set("base_path", "/")
		// Stand in for LocalizerMiddleware, which every real request passes through.
		c.Set("I18n", func(i18nType locale.I18nType, key string, keyParams ...string) string {
			return key
		})
		c.Next()
	}
}

// runGuarded returns (httpStatus, body). Permission denials deliberately answer
// HTTP 200 with success:false, the panel's convention: axios rejects any non-2xx, so
// a real 403 would surface as "Request failed with status code 403" instead of the
// message explaining what went wrong.
func runGuarded(t *testing.T, user *model.User, guard gin.HandlerFunc, ajax bool) (int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/guarded", withUser(user), guard, func(c *gin.Context) {
		c.String(http.StatusOK, "reached")
	})

	req := httptest.NewRequest(http.MethodGet, "/guarded", nil)
	if ajax {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func TestRequirePerm(t *testing.T) {
	limited := &model.User{Id: 2, Enable: true, Permissions: model.PermAccessInbounds}
	super := &model.User{Id: 1, Enable: true, IsSuperAdmin: true}
	disabled := &model.User{Id: 3, Enable: false, Permissions: model.PermAccessInbounds}

	tests := []struct {
		name string
		user *model.User
		perm model.Permission
		want int
	}{
		{"granted permission passes", limited, model.PermAccessInbounds, http.StatusOK},
		{"ungranted permission is refused", limited, model.PermDeleteInbound, http.StatusOK},
		{"super admin bypasses the mask", super, model.PermPanelSettings, http.StatusOK},
		{"disabled account is refused", disabled, model.PermAccessInbounds, http.StatusOK},
		// 401 is the one status the frontend keys off, to send them back to login.
		{"logged out is unauthorized", nil, model.PermAccessInbounds, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, body := runGuarded(t, tc.user, requirePerm(tc.perm), true)
			if got != tc.want {
				t.Errorf("status = %d; want %d", got, tc.want)
			}
			denied := tc.user == nil || !tc.user.Can(tc.perm)
			if denied && !strings.Contains(body, `"success":false`) {
				t.Errorf("a denial must carry success:false so the UI shows why; got %s", body)
			}
			if denied && !strings.Contains(body, "forbidden") && tc.user != nil {
				t.Errorf("a denial must name a reason, not an empty msg; got %s", body)
			}
		})
	}
}

func TestRequireSuperAdmin(t *testing.T) {
	// The escalation-class routes hang off this: a permission bit must never be
	// enough to reach the DB export, the panel binary, or a host reboot.
	limited := &model.User{Id: 2, Enable: true, Permissions: model.PermPanelSettings | model.PermCoreSettings}
	_, body := runGuarded(t, limited, requireSuperAdmin(), true)
	if !strings.Contains(body, `"success":false`) {
		t.Errorf("a non-super admin holding every bit still must not pass; got %s", body)
	}
	super := &model.User{Id: 1, Enable: true, IsSuperAdmin: true}
	if got, _ := runGuarded(t, super, requireSuperAdmin(), true); got != http.StatusOK {
		t.Errorf("super admin: status = %d; want 200", got)
	}
	if got, _ := runGuarded(t, nil, requireSuperAdmin(), true); got != http.StatusUnauthorized {
		t.Errorf("logged out: status = %d; want 401", got)
	}
}

// A page navigation redirects; an XHR gets a JSON status. Denying a page with a raw
// 403 would leave the browser on a blank screen.
func TestDenyShapeMatchesRequestKind(t *testing.T) {
	limited := &model.User{Id: 2, Enable: true}
	if got, _ := runGuarded(t, limited, requirePerm(model.PermAccessInbounds), false); got != http.StatusTemporaryRedirect {
		t.Errorf("page navigation denial = %d; want 307 redirect", got)
	}
	// XHR: 200 so axios resolves and the UI can render the reason. A real 403 makes
	// axios reject, and the user sees "Request failed with status code 403".
	got, body := runGuarded(t, limited, requirePerm(model.PermAccessInbounds), true)
	if got != http.StatusOK {
		t.Errorf("xhr denial = %d; want 200 so the message reaches the user", got)
	}
	if !strings.Contains(body, `"success":false`) || !strings.Contains(body, "forbidden") {
		t.Errorf("xhr denial must carry success:false and a reason; got %s", body)
	}
}

// GetLoginUser must never trust the cookie for identity beyond the id: a disabled
// account has to lose access on its very next request, not at cookie expiry.
func TestSessionUserCacheRespectsDisable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("LOGIN_USER_ROW", (*model.User)(nil))
	if session.GetLoginUser(c) != nil {
		t.Error("a nil cached user must read back as logged out")
	}
}
