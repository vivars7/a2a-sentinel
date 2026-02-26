package security

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/config"
	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
)

// integrationBackend returns 200 and writes AuthInfo for verification.
var integrationBackend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	info, ok := ctxkeys.AuthInfoFrom(r.Context())
	if !ok {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok no-auth")
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "ok mode=%s subject=%s verified=%t", info.Mode, info.Subject, info.SubjectVerified)
})

// makeFakeJWT creates a minimal fake JWT with the given subject for testing.
func makeFakeJWT(subject string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"%s"}`, subject)))
	return header + "." + payload + ".fakesig"
}

// defaultIntegrationConfig returns a SecurityPipelineConfig suitable for integration tests
// with all features enabled at generous limits (won't trigger unless intended).
func defaultIntegrationConfig() SecurityPipelineConfig {
	return SecurityPipelineConfig{
		Auth: AuthPipelineConfig{
			Mode:                 "passthrough-strict",
			AllowUnauthenticated: false,
		},
		RateLimit: RateLimitPipelineConfig{
			Enabled:             true,
			IPPerIP:             6000,
			IPBurst:             100,
			IPCleanupInterval:   5 * time.Minute,
			UserPerUser:         6000,
			UserBurst:           100,
			UserCleanupInterval: 5 * time.Minute,
		},
		Replay: ReplayDetectorConfig{
			Enabled:         true,
			Window:          5 * time.Minute,
			NoncePolicy:     "require",
			CleanupInterval: 1 * time.Minute,
		},
		GlobalRateLimit: 60000,
		Push: config.PushConfig{
			BlockPrivateNetworks: true,
			RequireHTTPS:         true,
		},
	}
}

// stopAllMiddlewares stops all stoppable middlewares to prevent goroutine leaks.
func stopAllMiddlewares(mws []Middleware) {
	for _, mw := range mws {
		switch m := mw.(type) {
		case *IPRateLimiter:
			m.Stop()
		case *UserRateLimiter:
			m.Stop()
		case *ReplayDetector:
			m.Stop()
		}
	}
}

func TestSecurityPipeline_Integration_NormalFlow(t *testing.T) {
	cfg := defaultIntegrationConfig()
	mws := BuildPipeline(cfg)
	defer stopAllMiddlewares(mws)

	handler := ApplyPipeline(integrationBackend, mws)

	// Create a normal authenticated request
	token := makeFakeJWT("alice@example.com")
	body := `{"jsonrpc":"2.0","method":"message/send","id":"unique-1","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.1:12345"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	respBody := rec.Body.String()
	if !strings.Contains(respBody, "ok") {
		t.Errorf("expected 'ok' in body, got %q", respBody)
	}
	if !strings.Contains(respBody, "passthrough-strict") {
		t.Errorf("expected passthrough-strict mode, got %q", respBody)
	}
}

func TestSecurityPipeline_Integration_IPRateLimited(t *testing.T) {
	cfg := defaultIntegrationConfig()
	// Set very low IP burst to trigger quickly
	cfg.RateLimit.IPPerIP = 60
	cfg.RateLimit.IPBurst = 1

	mws := BuildPipeline(cfg)
	defer stopAllMiddlewares(mws)

	handler := ApplyPipeline(integrationBackend, mws)

	token := makeFakeJWT("bob@example.com")

	// First request should pass (uses the single burst token)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "198.51.100.1:12345"
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Second request from same IP should be rate limited
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "198.51.100.1:12345"
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestSecurityPipeline_Integration_AuthFailure(t *testing.T) {
	cfg := defaultIntegrationConfig()
	cfg.Auth.Mode = "passthrough-strict"
	cfg.Auth.AllowUnauthenticated = false

	mws := BuildPipeline(cfg)
	defer stopAllMiddlewares(mws)

	handler := ApplyPipeline(integrationBackend, mws)

	// Request without Authorization header
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.2:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify the error body contains educational fields
	var errResp sentinelerrors.HTTPErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	if errResp.Error.Hint == "" {
		t.Error("expected hint in error response")
	}
	if errResp.Error.DocsURL == "" {
		t.Error("expected docs_url in error response")
	}
}

func TestSecurityPipeline_Integration_UserRateLimited(t *testing.T) {
	cfg := defaultIntegrationConfig()
	// High IP limit, low user limit
	cfg.RateLimit.IPPerIP = 60000
	cfg.RateLimit.IPBurst = 1000
	cfg.RateLimit.UserPerUser = 60
	cfg.RateLimit.UserBurst = 1

	mws := BuildPipeline(cfg)
	defer stopAllMiddlewares(mws)

	handler := ApplyPipeline(integrationBackend, mws)

	token := makeFakeJWT("charlie@example.com")

	// First request should pass
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.3:12345"
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Second request from same user (different IP) should be rate limited
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.4:12345" // different IP
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestSecurityPipeline_Integration_ReplayDetected(t *testing.T) {
	cfg := defaultIntegrationConfig()
	cfg.Replay.Enabled = true
	cfg.Replay.NoncePolicy = "require"
	cfg.Replay.Window = 5 * time.Minute
	cfg.Replay.CleanupInterval = 1 * time.Minute

	mws := BuildPipeline(cfg)
	defer stopAllMiddlewares(mws)

	handler := ApplyPipeline(integrationBackend, mws)

	token := makeFakeJWT("dave@example.com")
	jsonBody := `{"jsonrpc":"2.0","method":"message/send","id":"replay-test-001","params":{}}`

	// First request with this ID should pass
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(jsonBody))
	req.RemoteAddr = "203.0.113.5:12345"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Second request with same ID should be rejected as replay
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(jsonBody))
	req.RemoteAddr = "203.0.113.5:12345"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("replay request: expected 429, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestSecurityPipeline_Integration_SSRFBlocked(t *testing.T) {
	cfg := defaultIntegrationConfig()
	cfg.Push.BlockPrivateNetworks = true
	cfg.Push.RequireHTTPS = true

	mws := BuildPipeline(cfg)
	defer stopAllMiddlewares(mws)

	handler := ApplyPipeline(integrationBackend, mws)

	token := makeFakeJWT("eve@example.com")

	// JSON-RPC push notification request with private URL
	jsonBody := `{
		"jsonrpc": "2.0",
		"method": "tasks/pushNotificationConfig/set",
		"id": "ssrf-test-001",
		"params": {
			"pushNotificationConfig": {
				"url": "http://127.0.0.1:8080/callback"
			}
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(jsonBody))
	req.RemoteAddr = "203.0.113.6:12345"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("SSRF request: expected 403, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestSecurityPipeline_Integration_TwoLayerRateLimit(t *testing.T) {
	cfg := defaultIntegrationConfig()
	// Both IP and user limits set to burst of 2
	cfg.RateLimit.IPPerIP = 60
	cfg.RateLimit.IPBurst = 2
	cfg.RateLimit.UserPerUser = 60
	cfg.RateLimit.UserBurst = 2

	mws := BuildPipeline(cfg)
	defer stopAllMiddlewares(mws)

	handler := ApplyPipeline(integrationBackend, mws)

	tokenAlice := makeFakeJWT("alice@example.com")
	tokenBob := makeFakeJWT("bob@example.com")

	// Alice sends 2 requests from IP A (exhausts IP A's burst)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "198.51.100.10:12345"
		req.Header.Set("Authorization", "Bearer "+tokenAlice)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("alice req %d from IP A: expected 200, got %d", i, rec.Code)
		}
	}

	// Alice's 3rd request from IP A should be blocked by IP rate limit
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("Authorization", "Bearer "+tokenAlice)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("alice req 3 from IP A: expected 429 (IP limit), got %d", rec.Code)
	}

	// Bob from a different IP should still be allowed (independent IP bucket)
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "198.51.100.20:12345"
	req.Header.Set("Authorization", "Bearer "+tokenBob)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("bob req 1 from IP B: expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Alice from a different IP should pass IP limit but still have her user burst
	// (She used 2 user tokens above from IP A, so user burst is exhausted)
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "198.51.100.30:12345" // new IP
	req.Header.Set("Authorization", "Bearer "+tokenAlice)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("alice from IP C: expected 429 (user limit), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestSecurityPipeline_Integration_ErrorFormat(t *testing.T) {
	// Verify all blocked responses include hint + docs_url
	tests := []struct {
		name       string
		setupCfg   func(cfg *SecurityPipelineConfig)
		setupReq   func(req *http.Request)
		wantCode   int
		wantFields []string // fields that must be present in the error JSON
	}{
		{
			name: "auth_required",
			setupCfg: func(cfg *SecurityPipelineConfig) {
				cfg.Auth.Mode = "passthrough-strict"
				cfg.Auth.AllowUnauthenticated = false
			},
			setupReq: func(req *http.Request) {
				// No Authorization header
			},
			wantCode:   http.StatusUnauthorized,
			wantFields: []string{"hint", "docs_url"},
		},
		{
			name: "ip_rate_limited",
			setupCfg: func(cfg *SecurityPipelineConfig) {
				cfg.RateLimit.IPPerIP = 60
				cfg.RateLimit.IPBurst = 0 // will be clamped to 1 internally
			},
			setupReq: func(req *http.Request) {
				// Send to exhaust burst — we send 2 requests in a row
				// This test sends one request before this to exhaust
			},
			wantCode:   http.StatusTooManyRequests,
			wantFields: []string{"hint", "docs_url"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultIntegrationConfig()
			tt.setupCfg(&cfg)

			mws := BuildPipeline(cfg)
			defer stopAllMiddlewares(mws)

			handler := ApplyPipeline(integrationBackend, mws)

			token := makeFakeJWT("errfmt@example.com")

			if tt.name == "ip_rate_limited" {
				// Exhaust burst first
				req := httptest.NewRequest(http.MethodPost, "/", nil)
				req.RemoteAddr = "198.51.100.99:12345"
				req.Header.Set("Authorization", "Bearer "+token)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
			}

			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.RemoteAddr = "198.51.100.99:12345"
			if tt.name != "auth_required" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			tt.setupReq(req)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("expected %d, got %d; body: %s", tt.wantCode, rec.Code, rec.Body.String())
			}

			// Verify educational error fields
			var errResp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("failed to parse error body: %v; raw: %s", err, rec.Body.String())
			}

			errorObj, ok := errResp["error"].(map[string]interface{})
			if !ok {
				t.Fatalf("expected error object in response, got: %v", errResp)
			}

			for _, field := range tt.wantFields {
				val, exists := errorObj[field]
				if !exists {
					t.Errorf("expected %q field in error response", field)
					continue
				}
				if str, ok := val.(string); !ok || str == "" {
					t.Errorf("expected non-empty string for %q, got %v", field, val)
				}
			}
		})
	}
}
