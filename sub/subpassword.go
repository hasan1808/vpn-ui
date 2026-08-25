package sub

// Subscriber self-service password change. The route hangs off the raw sub
// path so the subId stays the only credential involved in reaching the page,
// and the CURRENT password is required to set a new one, so possessing the
// link alone is not enough to rotate someone's credential.

import (
	"net/http"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/controller"
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/gin-gonic/gin"
)

// pwAttempts bounds password-guessing on the public endpoint: maxAttempts per
// window per (IP, subId) pair. Entries older than the window are pruned lazily.
const (
	pwMaxAttempts = 5
	pwWindow      = 10 * time.Minute
)

type pwLimiter struct {
	mu sync.Mutex
	m  map[string][]time.Time
}

var subPwLimiter = &pwLimiter{m: map[string][]time.Time{}}

func (l *pwLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	live := l.m[key][:0]
	for _, t := range l.m[key] {
		if now.Sub(t) < pwWindow {
			live = append(live, t)
		}
	}
	if len(live) >= pwMaxAttempts {
		l.m[key] = live
		return false
	}
	l.m[key] = append(live, now)
	return true
}

// registerPasswordRoute wires POST {subPath}:subid/password.
func (a *SUBController) registerPasswordRoute(gLink *gin.RouterGroup) {
	gLink.POST(":subid/password", a.changePassword)
}

// changePassword rotates the account credential from the subscriber page.
//
// Response codes are stable strings the page localizes itself: "ok", "wrong",
// "weak", "notfound", "rate", "error".
func (a *SUBController) changePassword(c *gin.Context) {
	subId := c.Param("subid")

	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Current == "" || req.New == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "code": "error"})
		return
	}
	if !subPwLimiter.allow(c.ClientIP() + "|" + subId) {
		c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "code": "rate"})
		return
	}

	touched, err := a.accountService.ChangeSubscriberPassword(subId, req.Current, req.New)
	switch {
	case err == nil:
	case err == service.ErrSubWrongPassword:
		c.JSON(http.StatusOK, gin.H{"success": false, "code": "wrong"})
		return
	case err == service.ErrSubWeakPassword:
		c.JSON(http.StatusOK, gin.H{"success": false, "code": "weak"})
		return
	case err == service.ErrSubAccountNotFound:
		c.JSON(http.StatusOK, gin.H{"success": false, "code": "notfound"})
		return
	default:
		logger.Warning("sub: password change for ", subId, ": ", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "code": "error"})
		return
	}

	// Same reconciliation a panel client edit gets: VPN daemon config regen,
	// Xray restart. A password the core never learned would strand the account.
	if len(touched) > 0 {
		controller.BareInboundController().ReconcileClientChange(touched, true)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "code": "ok"})
}
