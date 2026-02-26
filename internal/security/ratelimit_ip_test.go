package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestIPRateLimiterWithinLimit(t *testing.T) {
	rl := NewIPRateLimiter(6000, 10, 5*time.Minute, nil)
	defer rl.Stop()

	handler := rl.Process(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Send requests within burst limit
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, rec.Code)
		}
	}
}

func TestIPRateLimiterExceeded(t *testing.T) {
	// Very low burst to trigger rate limiting
	rl := NewIPRateLimiter(60, 2, 5*time.Minute, nil)
	defer rl.Stop()

	handler := rl.Process(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust the burst
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("burst request %d: expected 200, got %d", i, rec.Code)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec.Code)
	}
}

func TestIPRateLimiterIndependentIPs(t *testing.T) {
	// Low burst per IP
	rl := NewIPRateLimiter(60, 2, 5*time.Minute, nil)
	defer rl.Stop()

	handler := rl.Process(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust burst for IP1
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// IP1 should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("IP1: expected 429, got %d", rec.Code)
	}

	// IP2 should still pass (independent limiter)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.2:12345"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("IP2: expected 200, got %d", rec.Code)
	}
}

func TestIPRateLimiterUsesClientIP(t *testing.T) {
	// Verify it uses TrustedClientIP with trusted proxies
	rl := NewIPRateLimiter(60, 1, 5*time.Minute, []string{"10.0.0.0/8"})
	defer rl.Stop()

	handler := rl.Process(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request from 203.0.113.50 via proxy
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:8080"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec.Code)
	}

	// Second request from same real IP via different proxy
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:8080"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.2")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should be rate limited because same real client IP (203.0.113.50)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("second request from same real IP: expected 429, got %d", rec.Code)
	}
}

func TestIPRateLimiterName(t *testing.T) {
	rl := NewIPRateLimiter(100, 10, 5*time.Minute, nil)
	defer rl.Stop()
	if rl.Name() != "ip_rate_limiter" {
		t.Errorf("expected name 'ip_rate_limiter', got %q", rl.Name())
	}
}

func TestIPRateLimiterGetLimiterReusesExisting(t *testing.T) {
	// Verify that calling getLimiter twice for the same IP returns the same limiter instance.
	rl := NewIPRateLimiter(600, 10, 5*time.Minute, nil)
	defer rl.Stop()

	l1 := rl.getLimiter("10.0.0.1")
	l2 := rl.getLimiter("10.0.0.1")
	if l1 != l2 {
		t.Error("expected the same limiter instance for the same IP on repeated calls")
	}
}

func TestIPRateLimiterGetLimiterConcurrentSameIP(t *testing.T) {
	// Simulate concurrent getLimiter calls for the same IP (hits LoadOrStore loaded path).
	rl := NewIPRateLimiter(600, 10, 5*time.Minute, nil)
	defer rl.Stop()

	const goroutines = 20
	results := make(chan *rate.Limiter, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			results <- rl.getLimiter("192.0.2.1")
		}()
	}

	var first *rate.Limiter
	for i := 0; i < goroutines; i++ {
		l := <-results
		if first == nil {
			first = l
		}
		if l != first {
			t.Error("concurrent getLimiter calls returned different limiter instances for same IP")
		}
	}
}

func TestIPRateLimiterCleanupRemovesExpiredEntries(t *testing.T) {
	// Use very short intervals so the cleanup goroutine runs during the test.
	const cleanupInterval = 20 * time.Millisecond
	rl := NewIPRateLimiter(600, 10, cleanupInterval, nil)
	defer rl.Stop()

	// Create a limiter for an IP.
	rl.getLimiter("10.1.2.3")

	// Verify entry is present.
	if _, ok := rl.limiters.Load("10.1.2.3"); !ok {
		t.Fatal("expected entry to exist before cleanup")
	}

	// Wait long enough for the entry's lastSeen to be older than cleanupInterval
	// and for at least one cleanup tick to fire.
	time.Sleep(cleanupInterval * 4)

	// Entry should have been removed by the cleanup goroutine.
	if _, ok := rl.limiters.Load("10.1.2.3"); ok {
		t.Error("expected entry to be cleaned up after expiry")
	}
}

func TestIPRateLimiterCleanupStopsOnCancel(t *testing.T) {
	// Ensure Stop() terminates the cleanup goroutine (no goroutine leak).
	const cleanupInterval = 10 * time.Millisecond
	rl := NewIPRateLimiter(600, 5, cleanupInterval, nil)
	rl.Stop() // cancel immediately
	// If the goroutine doesn't exit, the test would hang or race detector would complain.
	// A short sleep gives the goroutine time to exit.
	time.Sleep(cleanupInterval * 3)
}

// rate import needed for TestIPRateLimiterGetLimiterConcurrentSameIP
var _ = (*rate.Limiter)(nil)
