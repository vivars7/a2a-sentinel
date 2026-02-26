package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
	"golang.org/x/time/rate"
)

func TestUserRateLimiterWithinLimit(t *testing.T) {
	rl := NewUserRateLimiter(6000, 10, 5*time.Minute)
	defer rl.Stop()

	handler := rl.Process(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := ctxkeys.WithAuthInfo(req.Context(), ctxkeys.AuthInfo{
			Mode:    "terminate",
			Subject: "alice@example.com",
		})
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, rec.Code)
		}
	}
}

func TestUserRateLimiterExceeded(t *testing.T) {
	rl := NewUserRateLimiter(60, 2, 5*time.Minute)
	defer rl.Stop()

	handler := rl.Process(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust burst
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := ctxkeys.WithAuthInfo(req.Context(), ctxkeys.AuthInfo{
			Mode:    "terminate",
			Subject: "alice@example.com",
		})
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("burst request %d: expected 200, got %d", i, rec.Code)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := ctxkeys.WithAuthInfo(req.Context(), ctxkeys.AuthInfo{
		Mode:    "terminate",
		Subject: "alice@example.com",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec.Code)
	}
}

func TestUserRateLimiterUnauthenticatedSkipped(t *testing.T) {
	rl := NewUserRateLimiter(60, 1, 5*time.Minute)
	defer rl.Stop()

	handler := rl.Process(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Send many requests without AuthInfo — should all pass
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unauthenticated request %d: expected 200, got %d", i, rec.Code)
		}
	}
}

func TestUserRateLimiterEmptySubjectSkipped(t *testing.T) {
	rl := NewUserRateLimiter(60, 1, 5*time.Minute)
	defer rl.Stop()

	handler := rl.Process(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// AuthInfo present but Subject is empty — should skip
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := ctxkeys.WithAuthInfo(req.Context(), ctxkeys.AuthInfo{
			Mode:    "passthrough",
			Subject: "",
		})
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("empty subject request %d: expected 200, got %d", i, rec.Code)
		}
	}
}

func TestUserRateLimiterIndependentUsers(t *testing.T) {
	rl := NewUserRateLimiter(60, 2, 5*time.Minute)
	defer rl.Stop()

	handler := rl.Process(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust burst for alice
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := ctxkeys.WithAuthInfo(req.Context(), ctxkeys.AuthInfo{
			Mode:    "terminate",
			Subject: "alice",
		})
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// Alice should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := ctxkeys.WithAuthInfo(req.Context(), ctxkeys.AuthInfo{
		Mode:    "terminate",
		Subject: "alice",
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("alice: expected 429, got %d", rec.Code)
	}

	// Bob should still pass (independent limiter)
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	ctx = ctxkeys.WithAuthInfo(req.Context(), ctxkeys.AuthInfo{
		Mode:    "terminate",
		Subject: "bob",
	})
	req = req.WithContext(ctx)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("bob: expected 200, got %d", rec.Code)
	}
}

func TestUserRateLimiterName(t *testing.T) {
	rl := NewUserRateLimiter(100, 10, 5*time.Minute)
	defer rl.Stop()
	if rl.Name() != "user_rate_limiter" {
		t.Errorf("expected name 'user_rate_limiter', got %q", rl.Name())
	}
}

func TestUserRateLimiterGetLimiterReusesExisting(t *testing.T) {
	// Verify that calling getLimiter twice for the same subject returns the same limiter.
	rl := NewUserRateLimiter(600, 10, 5*time.Minute)
	defer rl.Stop()

	l1 := rl.getLimiter("alice@example.com")
	l2 := rl.getLimiter("alice@example.com")
	if l1 != l2 {
		t.Error("expected the same limiter instance for the same subject on repeated calls")
	}
}

func TestUserRateLimiterGetLimiterConcurrentSameSubject(t *testing.T) {
	// Simulate concurrent getLimiter calls for the same subject (hits LoadOrStore loaded path).
	rl := NewUserRateLimiter(600, 10, 5*time.Minute)
	defer rl.Stop()

	const goroutines = 20
	results := make(chan *rate.Limiter, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			results <- rl.getLimiter("bob@example.com")
		}()
	}

	var first *rate.Limiter
	for i := 0; i < goroutines; i++ {
		l := <-results
		if first == nil {
			first = l
		}
		if l != first {
			t.Error("concurrent getLimiter calls returned different limiter instances for same subject")
		}
	}
}

func TestUserRateLimiterCleanupRemovesExpiredEntries(t *testing.T) {
	// Use very short intervals so the cleanup goroutine runs during the test.
	const cleanupInterval = 20 * time.Millisecond
	rl := NewUserRateLimiter(600, 10, cleanupInterval)
	defer rl.Stop()

	// Create a limiter for a subject.
	rl.getLimiter("eve@example.com")

	// Verify entry is present.
	if _, ok := rl.limiters.Load("eve@example.com"); !ok {
		t.Fatal("expected entry to exist before cleanup")
	}

	// Wait long enough for the entry's lastSeen to be older than cleanupInterval
	// and for at least one cleanup tick to fire.
	time.Sleep(cleanupInterval * 4)

	// Entry should have been removed by the cleanup goroutine.
	if _, ok := rl.limiters.Load("eve@example.com"); ok {
		t.Error("expected entry to be cleaned up after expiry")
	}
}

func TestUserRateLimiterCleanupStopsOnCancel(t *testing.T) {
	// Ensure Stop() terminates the cleanup goroutine (no goroutine leak).
	const cleanupInterval = 10 * time.Millisecond
	rl := NewUserRateLimiter(600, 5, cleanupInterval)
	rl.Stop() // cancel immediately
	// A short sleep gives the goroutine time to exit cleanly.
	time.Sleep(cleanupInterval * 3)
}
