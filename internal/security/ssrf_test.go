package security

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/vivars7/a2a-sentinel/internal/config"
)

func TestSSRFChecker_DNSFailPolicy_Block(t *testing.T) {
	// Default: block on DNS failure
	checker := NewSSRFChecker(config.PushConfig{
		BlockPrivateNetworks: true,
		DNSFailPolicy:        "block",
	}, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	// Non-existent domain should be blocked (DNS fails -> block)
	err := checker.ValidatePushURL("https://this-domain-definitely-does-not-exist-xyz123.example.invalid/callback")
	if err == nil {
		t.Error("expected error for unresolvable domain with block policy")
	}
}

func TestSSRFChecker_DNSFailPolicy_Allow(t *testing.T) {
	// Allow on DNS failure
	checker := NewSSRFChecker(config.PushConfig{
		BlockPrivateNetworks: true,
		DNSFailPolicy:        "allow",
	}, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	// Non-existent domain should be allowed (DNS fails -> allow)
	err := checker.ValidatePushURL("https://this-domain-definitely-does-not-exist-xyz123.example.invalid/callback")
	if err != nil {
		t.Errorf("expected no error for unresolvable domain with allow policy, got: %v", err)
	}
}

func TestSSRFChecker_PrivateNetwork_Blocked(t *testing.T) {
	checker := NewSSRFChecker(config.PushConfig{
		BlockPrivateNetworks: true,
		DNSFailPolicy:        "block",
	}, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	privateURLs := []string{
		"https://127.0.0.1/callback",
		"https://localhost/callback",
		"https://10.0.0.1/callback",
		"https://192.168.1.1/callback",
		"https://172.16.0.1/callback",
	}

	for _, u := range privateURLs {
		if err := checker.ValidatePushURL(u); err == nil {
			t.Errorf("expected private network block for %s", u)
		}
	}
}

func TestSSRFChecker_RequireHTTPS(t *testing.T) {
	checker := NewSSRFChecker(config.PushConfig{
		RequireHTTPS:  true,
		DNSFailPolicy: "block",
	}, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if err := checker.ValidatePushURL("http://example.com/callback"); err == nil {
		t.Error("expected error for non-HTTPS URL")
	}
}

func TestSSRFChecker_AllowedDomains(t *testing.T) {
	checker := NewSSRFChecker(config.PushConfig{
		AllowedDomains: []string{"example.com"},
		DNSFailPolicy:  "block",
	}, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	// Not allowed domain should be rejected
	if err := checker.ValidatePushURL("https://evil.com/callback"); err == nil {
		t.Error("expected error for domain not in allowed list")
	}
}

func TestSSRFChecker_ProcessPassthrough(t *testing.T) {
	checker := NewSSRFChecker(config.PushConfig{
		BlockPrivateNetworks: true,
		DNSFailPolicy:        "block",
	}, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := checker.Process(backend)

	// GET request should pass through
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET should pass through, got %d", rec.Code)
	}

	// POST with non-push body should pass through
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"message/send","id":1,"params":{"message":{"role":"user","parts":[{"text":"hello"}]}}}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("non-push POST should pass through, got %d", rec.Code)
	}
}

func TestSSRFChecker_Name(t *testing.T) {
	checker := NewSSRFChecker(config.PushConfig{}, nil)
	if checker.Name() != "ssrf_checker" {
		t.Errorf("expected 'ssrf_checker', got %q", checker.Name())
	}
}

func TestSSRFChecker_DefaultDNSFailPolicy(t *testing.T) {
	// When DNSFailPolicy is empty, should default to "block"
	checker := NewSSRFChecker(config.PushConfig{
		BlockPrivateNetworks: true,
	}, nil)
	if checker.dnsFailPolicy != "block" {
		t.Errorf("expected default dns_fail_policy 'block', got %q", checker.dnsFailPolicy)
	}
}

func TestIsPrivateNetwork_PublicFunction(t *testing.T) {
	// The public IsPrivateNetwork function should still work (backward compat)
	if !IsPrivateNetwork("127.0.0.1") {
		t.Error("127.0.0.1 should be private")
	}
	if !IsPrivateNetwork("localhost") {
		t.Error("localhost should be private")
	}
	if IsPrivateNetwork("8.8.8.8") {
		t.Error("8.8.8.8 should not be private")
	}
}
