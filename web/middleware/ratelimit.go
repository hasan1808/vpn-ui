package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type loginRateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	window   time.Duration
	maxRetry int
}

var loginLimiter = &loginRateLimiter{
	attempts: make(map[string][]time.Time),
	window:   5 * time.Minute,
	maxRetry: 10,
}

func (l *loginRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	// Remove old entries
	attempts := l.attempts[key]
	valid := attempts[:0]
	for _, t := range attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	l.attempts[key] = valid

	if len(valid) >= l.maxRetry {
		return false
	}
	l.attempts[key] = append(l.attempts[key], now)
	return true
}

// LoginRateLimit returns a gin middleware that rate-limits login attempts per IP.
func LoginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/login" && c.Request.Method == http.MethodPost {
			ip := c.ClientIP()
			if !loginLimiter.allow(ip) {
				c.JSON(http.StatusTooManyRequests, gin.H{
					"success": false,
					"msg":     "Too many login attempts. Please try again later.",
				})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}
