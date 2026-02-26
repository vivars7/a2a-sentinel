package security

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
	"golang.org/x/time/rate"
)

// ipEntry holds a rate limiter and its last-used timestamp for cleanup.
type ipEntry struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64 // UnixNano
}

// IPRateLimiter enforces per-IP rate limiting using individual token buckets.
type IPRateLimiter struct {
	limiters        sync.Map // IP string → *ipEntry
	perIP           int
	burst           int
	cleanupInterval time.Duration
	trustedProxies  []string
	cancel          context.CancelFunc
}

// NewIPRateLimiter creates a per-IP rate limiter.
// perIP is requests per minute per IP; burst is the token bucket burst size.
// cleanupInterval controls how often inactive entries are removed.
func NewIPRateLimiter(perIP, burst int, cleanupInterval time.Duration, trustedProxies []string) *IPRateLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	rl := &IPRateLimiter{
		perIP:           perIP,
		burst:           burst,
		cleanupInterval: cleanupInterval,
		trustedProxies:  trustedProxies,
		cancel:          cancel,
	}
	go rl.cleanup(ctx)
	return rl
}

// Process returns an http.Handler that enforces per-IP rate limiting.
func (rl *IPRateLimiter) Process(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := TrustedClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), rl.trustedProxies)
		limiter := rl.getLimiter(ip)

		if !limiter.Allow() {
			sentinelerrors.WriteHTTPError(w, sentinelerrors.ErrRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Name returns the middleware name.
func (rl *IPRateLimiter) Name() string {
	return "ip_rate_limiter"
}

// Stop stops the cleanup goroutine.
func (rl *IPRateLimiter) Stop() {
	rl.cancel()
}

// getLimiter returns the rate limiter for the given IP, creating one if needed.
func (rl *IPRateLimiter) getLimiter(ip string) *rate.Limiter {
	now := time.Now().UnixNano()

	if v, ok := rl.limiters.Load(ip); ok {
		entry := v.(*ipEntry)
		entry.lastSeen.Store(now)
		return entry.limiter
	}

	perSecond := float64(rl.perIP) / 60.0
	limiter := rate.NewLimiter(rate.Limit(perSecond), rl.burst)
	entry := &ipEntry{limiter: limiter}
	entry.lastSeen.Store(now)

	actual, loaded := rl.limiters.LoadOrStore(ip, entry)
	if loaded {
		existing := actual.(*ipEntry)
		existing.lastSeen.Store(now)
		return existing.limiter
	}
	return limiter
}

// cleanup periodically removes inactive IP entries.
func (rl *IPRateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-rl.cleanupInterval).UnixNano()
			rl.limiters.Range(func(key, value interface{}) bool {
				entry := value.(*ipEntry)
				if entry.lastSeen.Load() < cutoff {
					rl.limiters.Delete(key)
				}
				return true
			})
		}
	}
}
