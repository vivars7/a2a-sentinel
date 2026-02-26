package security

import (
	"net/http"

	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
	"golang.org/x/time/rate"
)

// GlobalRateLimiter enforces a gateway-wide request rate limit using a token bucket.
type GlobalRateLimiter struct {
	limiter *rate.Limiter
}

// NewGlobalRateLimiter creates a global rate limiter.
// rps is requests per minute; internally converted to per-second.
func NewGlobalRateLimiter(rpm int) *GlobalRateLimiter {
	perSecond := float64(rpm) / 60.0
	burst := rpm / 60
	if burst < 1 {
		burst = 1
	}
	return &GlobalRateLimiter{
		limiter: rate.NewLimiter(rate.Limit(perSecond), burst),
	}
}

// Process returns an http.Handler that enforces the global rate limit.
func (g *GlobalRateLimiter) Process(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.limiter.Allow() {
			sentinelerrors.WriteHTTPError(w, sentinelerrors.ErrGlobalLimitReached)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Name returns the middleware name for logging and debugging.
func (g *GlobalRateLimiter) Name() string {
	return "global_rate_limiter"
}
