package security

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
)

// backendHandler returns 200 and writes AuthInfo for verification.
var backendHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	info, ok := ctxkeys.AuthInfoFrom(r.Context())
	if !ok {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "no-auth")
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "ok mode=%s subject=%s", info.Mode, info.Subject)
})

func TestPipelineUnauthenticated401(t *testing.T) {
	cfg := SecurityPipelineConfig{
		Auth: AuthPipelineConfig{
			Mode:                 "passthrough-strict",
			AllowUnauthenticated: false,
		},
		RateLimit: RateLimitPipelineConfig{
			Enabled:             true,
			IPPerIP:             200,
			IPBurst:             50,
			IPCleanupInterval:   5 * time.Minute,
			UserPerUser:         100,
			UserBurst:           20,
			UserCleanupInterval: 5 * time.Minute,
		},
		GlobalRateLimit: 5000,
	}

	mws := BuildPipeline(cfg)
	handler := ApplyPipeline(backendHandler, mws)

	// Stop IP/User rate limiters after test
	defer stopRateLimiters(mws)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated request, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestPipelineAuthenticatedOK(t *testing.T) {
	cfg := SecurityPipelineConfig{
		Auth: AuthPipelineConfig{
			Mode: "passthrough-strict",
		},
		RateLimit: RateLimitPipelineConfig{
			Enabled:             true,
			IPPerIP:             6000,
			IPBurst:             50,
			IPCleanupInterval:   5 * time.Minute,
			UserPerUser:         6000,
			UserBurst:           50,
			UserCleanupInterval: 5 * time.Minute,
		},
		GlobalRateLimit: 60000,
	}

	mws := BuildPipeline(cfg)
	handler := ApplyPipeline(backendHandler, mws)
	defer stopRateLimiters(mws)

	// Create a bearer token
	payload := `{"sub":"alice@example.com"}`
	fakeJWT := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(payload)) +
		".fakesig"

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("Authorization", "Bearer "+fakeJWT)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, "ok") {
		t.Errorf("expected 'ok' in body, got %s", body)
	}
}

func TestPipelineAuthenticatedRateExceeded429(t *testing.T) {
	cfg := SecurityPipelineConfig{
		Auth: AuthPipelineConfig{
			Mode: "passthrough-strict",
		},
		RateLimit: RateLimitPipelineConfig{
			Enabled:             true,
			IPPerIP:             60,
			IPBurst:             2, // low burst to trigger quickly
			IPCleanupInterval:   5 * time.Minute,
			UserPerUser:         6000,
			UserBurst:           50,
			UserCleanupInterval: 5 * time.Minute,
		},
		GlobalRateLimit: 60000,
	}

	mws := BuildPipeline(cfg)
	handler := ApplyPipeline(backendHandler, mws)
	defer stopRateLimiters(mws)

	payload := `{"sub":"alice@example.com"}`
	fakeJWT := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(payload)) +
		".fakesig"

	// Exhaust IP burst
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("Authorization", "Bearer "+fakeJWT)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("burst request %d: expected 200, got %d", i, rec.Code)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("Authorization", "Bearer "+fakeJWT)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestBuildPipelineOrder(t *testing.T) {
	cfg := SecurityPipelineConfig{
		Auth: AuthPipelineConfig{
			Mode: "passthrough-strict",
		},
		RateLimit: RateLimitPipelineConfig{
			Enabled:             true,
			IPPerIP:             200,
			IPBurst:             50,
			IPCleanupInterval:   5 * time.Minute,
			UserPerUser:         100,
			UserBurst:           20,
			UserCleanupInterval: 5 * time.Minute,
		},
		GlobalRateLimit: 5000,
	}

	mws := BuildPipeline(cfg)
	defer stopRateLimiters(mws)

	// Verify order: global_rate_limiter, ip_rate_limiter, auth, user_rate_limiter, stubs...
	expectedNames := []string{
		"global_rate_limiter",
		"ip_rate_limiter",
		"auth",
		"user_rate_limiter",
		"jws_verifier",
		"replay_detector",
		"ssrf_checker",
	}

	if len(mws) != len(expectedNames) {
		t.Fatalf("expected %d middlewares, got %d", len(expectedNames), len(mws))
	}

	for i, name := range expectedNames {
		if mws[i].Name() != name {
			t.Errorf("middleware[%d]: expected %q, got %q", i, name, mws[i].Name())
		}
	}
}

func TestBuildPipelineNoRateLimit(t *testing.T) {
	cfg := SecurityPipelineConfig{
		Auth: AuthPipelineConfig{
			Mode: "passthrough",
		},
		RateLimit: RateLimitPipelineConfig{
			Enabled: false,
		},
		GlobalRateLimit: 0,
	}

	mws := BuildPipeline(cfg)

	// Should have: auth + 3 stubs = 4
	expectedNames := []string{
		"auth",
		"jws_verifier",
		"replay_detector",
		"ssrf_checker",
	}

	if len(mws) != len(expectedNames) {
		t.Fatalf("expected %d middlewares, got %d", len(expectedNames), len(mws))
	}

	for i, name := range expectedNames {
		if mws[i].Name() != name {
			t.Errorf("middleware[%d]: expected %q, got %q", i, name, mws[i].Name())
		}
	}
}

func TestApplyPipelineExecutionOrder(t *testing.T) {
	// Verify that the first middleware in the slice executes first
	var order []string

	mw1 := &testMiddleware{name: "first", fn: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "first")
			next.ServeHTTP(w, r)
		})
	}}
	mw2 := &testMiddleware{name: "second", fn: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "second")
			next.ServeHTTP(w, r)
		})
	}}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "inner")
		w.WriteHeader(http.StatusOK)
	})

	handler := ApplyPipeline(inner, []Middleware{mw1, mw2})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if len(order) != 3 {
		t.Fatalf("expected 3 calls, got %d: %v", len(order), order)
	}
	if order[0] != "first" || order[1] != "second" || order[2] != "inner" {
		t.Errorf("unexpected execution order: %v", order)
	}
}

// testMiddleware is a simple Middleware implementation for testing.
type testMiddleware struct {
	name string
	fn   func(next http.Handler) http.Handler
}

func (m *testMiddleware) Process(next http.Handler) http.Handler {
	return m.fn(next)
}
func (m *testMiddleware) Name() string { return m.name }

func TestGlobalRateLimiterDisabledBurst(t *testing.T) {
	// rpm < 60 → burst = rpm/60 = 0 → clamped to 1
	// This exercises the "if burst < 1 { burst = 1 }" branch in NewGlobalRateLimiter
	rl := NewGlobalRateLimiter(1) // 1 rpm → perSecond ≈ 0.0167, burst = 0 → clamped to 1
	if rl.limiter == nil {
		t.Fatal("expected non-nil limiter")
	}
	handler := rl.Process(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request should be allowed (burst = 1)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 on first request, got %d", rec.Code)
	}

	// Second immediate request should be rate limited
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 on second request with burst=1, got %d", rec.Code)
	}
}

func TestGlobalRateLimiterExceeded(t *testing.T) {
	// Use burst=1 to reliably trigger rate limit exceeded on second request
	rl := NewGlobalRateLimiter(1) // burst clamped to 1
	handler := rl.Process(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Consume the single burst token
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Next request hits the rate limit
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when global rate limit exceeded, got %d", rec.Code)
	}
}

func TestGlobalRateLimiterName(t *testing.T) {
	rl := NewGlobalRateLimiter(60)
	if rl.Name() != "global_rate_limiter" {
		t.Errorf("expected 'global_rate_limiter', got %q", rl.Name())
	}
}

// stopRateLimiters stops all rate limiters in the middleware chain.
func stopRateLimiters(mws []Middleware) {
	for _, mw := range mws {
		switch rl := mw.(type) {
		case *IPRateLimiter:
			rl.Stop()
		case *UserRateLimiter:
			rl.Stop()
		}
	}
}
