package security

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
	"golang.org/x/time/rate"
)

// userEntry holds a rate limiter and its last-used timestamp for cleanup.
type userEntry struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64 // UnixNano
}

// UserRateLimiter enforces per-user rate limiting using individual token buckets.
// Users are identified by the Subject field from AuthInfo in the request context.
type UserRateLimiter struct {
	limiters        sync.Map // subject string → *userEntry
	perUser         int
	burst           int
	cleanupInterval time.Duration
	cancel          context.CancelFunc
}

// NewUserRateLimiter creates a per-user rate limiter.
// perUser is requests per minute per user; burst is the token bucket burst size.
func NewUserRateLimiter(perUser, burst int, cleanupInterval time.Duration) *UserRateLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	rl := &UserRateLimiter{
		perUser:         perUser,
		burst:           burst,
		cleanupInterval: cleanupInterval,
		cancel:          cancel,
	}
	go rl.cleanup(ctx)
	return rl
}

// Process returns an http.Handler that enforces per-user rate limiting.
func (rl *UserRateLimiter) Process(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authInfo, ok := ctxkeys.AuthInfoFrom(r.Context())
		if !ok || authInfo.Subject == "" {
			// Unauthenticated — skip user rate limiting
			next.ServeHTTP(w, r)
			return
		}

		limiter := rl.getLimiter(authInfo.Subject)
		if !limiter.Allow() {
			sentinelerrors.WriteHTTPError(w, sentinelerrors.ErrRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Name returns the middleware name.
func (rl *UserRateLimiter) Name() string {
	return "user_rate_limiter"
}

// Stop stops the cleanup goroutine.
func (rl *UserRateLimiter) Stop() {
	rl.cancel()
}

// getLimiter returns the rate limiter for the given subject, creating one if needed.
func (rl *UserRateLimiter) getLimiter(subject string) *rate.Limiter {
	now := time.Now().UnixNano()

	if v, ok := rl.limiters.Load(subject); ok {
		entry := v.(*userEntry)
		entry.lastSeen.Store(now)
		return entry.limiter
	}

	perSecond := float64(rl.perUser) / 60.0
	limiter := rate.NewLimiter(rate.Limit(perSecond), rl.burst)
	entry := &userEntry{limiter: limiter}
	entry.lastSeen.Store(now)

	actual, loaded := rl.limiters.LoadOrStore(subject, entry)
	if loaded {
		existing := actual.(*userEntry)
		existing.lastSeen.Store(now)
		return existing.limiter
	}
	return limiter
}

// cleanup periodically removes inactive user entries.
func (rl *UserRateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-rl.cleanupInterval).UnixNano()
			rl.limiters.Range(func(key, value interface{}) bool {
				entry := value.(*userEntry)
				if entry.lastSeen.Load() < cutoff {
					rl.limiters.Delete(key)
				}
				return true
			})
		}
	}
}
