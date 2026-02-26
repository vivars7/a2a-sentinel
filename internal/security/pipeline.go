// Package security implements the two-layer security middleware pipeline.
//
// Layer 1 (Pre-Auth): GlobalRateLimiter, IPRateLimiter
// Layer 2 (Post-Auth): AuthMiddleware, UserRateLimiter
// Post-Auth: SSRFChecker (push notification URL validation)
// Stubs (v0.2): JWSVerifier
package security

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/config"
)

// Middleware is a security processing step in the pipeline.
type Middleware interface {
	Process(next http.Handler) http.Handler
	Name() string
}

// SecurityPipelineConfig holds config needed for the pipeline.
type SecurityPipelineConfig struct {
	Auth            AuthPipelineConfig
	RateLimit       RateLimitPipelineConfig
	Replay          ReplayDetectorConfig
	GlobalRateLimit int
	TrustedProxies  []string
	Push            config.PushConfig
	Logger          *slog.Logger
}

// AuthPipelineConfig holds authentication configuration.
type AuthPipelineConfig struct {
	Mode                 string // "passthrough", "passthrough-strict", "terminate"
	AllowUnauthenticated bool
	// JWT fields for terminate mode
	Issuer   string
	Audience string
	JWKSURL  string
}

// RateLimitPipelineConfig holds rate limiting configuration.
type RateLimitPipelineConfig struct {
	Enabled             bool
	IPPerIP             int
	IPBurst             int
	IPCleanupInterval   time.Duration
	UserPerUser         int
	UserBurst           int
	UserCleanupInterval time.Duration
}

// BuildPipeline constructs the ordered security middleware chain.
// Layer 1 (Pre-Auth): GlobalRateLimiter, IPRateLimiter
// Layer 2 (Post-Auth): AuthMiddleware, UserRateLimiter, ReplayDetector, SSRFChecker
// Stubs (v0.2): JWSVerifier
func BuildPipeline(cfg SecurityPipelineConfig) []Middleware {
	var mws []Middleware

	// Layer 1: Pre-Auth
	if cfg.GlobalRateLimit > 0 {
		mws = append(mws, NewGlobalRateLimiter(cfg.GlobalRateLimit))
	}

	if cfg.RateLimit.Enabled && cfg.RateLimit.IPPerIP > 0 {
		mws = append(mws, NewIPRateLimiter(
			cfg.RateLimit.IPPerIP,
			cfg.RateLimit.IPBurst,
			cfg.RateLimit.IPCleanupInterval,
			cfg.TrustedProxies,
		))
	}

	// Layer 2: Post-Auth
	mws = append(mws, NewAuthMiddleware(cfg.Auth))

	if cfg.RateLimit.Enabled && cfg.RateLimit.UserPerUser > 0 {
		mws = append(mws, NewUserRateLimiter(
			cfg.RateLimit.UserPerUser,
			cfg.RateLimit.UserBurst,
			cfg.RateLimit.UserCleanupInterval,
		))
	}

	// JWS verification (v0.2 stub)
	mws = append(mws, NewJWSVerifier())

	// Replay detection
	mws = append(mws, NewReplayDetector(cfg.Replay, cfg.Logger))

	// SSRF protection for push notification URLs
	mws = append(mws, NewSSRFChecker(cfg.Push, cfg.Logger))

	return mws
}

// ApplyPipeline wraps a handler with all middleware in order.
// Apply in reverse order so first middleware executes first.
func ApplyPipeline(handler http.Handler, middlewares []Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i].Process(handler)
	}
	return handler
}
