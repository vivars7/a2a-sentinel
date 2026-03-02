package security

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMemoryNonceStore_NewNonce(t *testing.T) {
	store := NewMemoryNonceStore(5*time.Minute, 1*time.Minute)
	defer store.Stop()

	isNew, err := store.CheckAndStore("nonce-1", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isNew {
		t.Error("expected nonce to be new, got replay")
	}
}

func TestMemoryNonceStore_ReplayDetected(t *testing.T) {
	store := NewMemoryNonceStore(5*time.Minute, 1*time.Minute)
	defer store.Stop()

	now := time.Now()

	// First insertion — new
	isNew, err := store.CheckAndStore("nonce-dup", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isNew {
		t.Error("first call: expected new, got replay")
	}

	// Second insertion — replay
	isNew, err = store.CheckAndStore("nonce-dup", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isNew {
		t.Error("second call: expected replay, got new")
	}
}

func TestMemoryNonceStore_ExpiredNonce(t *testing.T) {
	// Use a very short window so nonces expire quickly
	store := NewMemoryNonceStore(50*time.Millisecond, 10*time.Millisecond)
	defer store.Stop()

	isNew, err := store.CheckAndStore("nonce-expire", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isNew {
		t.Fatal("expected new nonce")
	}

	// Wait for the nonce to expire
	time.Sleep(100 * time.Millisecond)

	// Same nonce should now be treated as new
	isNew, err = store.CheckAndStore("nonce-expire", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isNew {
		t.Error("expected expired nonce to be treated as new")
	}
}

func TestMemoryNonceStore_Cleanup(t *testing.T) {
	store := NewMemoryNonceStore(50*time.Millisecond, 30*time.Millisecond)
	defer store.Stop()

	// Add some nonces
	store.CheckAndStore("cleanup-1", time.Now())
	store.CheckAndStore("cleanup-2", time.Now())

	// Wait for expiry + cleanup interval
	time.Sleep(150 * time.Millisecond)

	// Verify entries were cleaned up by checking they are treated as new
	isNew, _ := store.CheckAndStore("cleanup-1", time.Now())
	if !isNew {
		t.Error("expected cleanup-1 to be cleaned up and treated as new")
	}
	isNew, _ = store.CheckAndStore("cleanup-2", time.Now())
	if !isNew {
		t.Error("expected cleanup-2 to be cleaned up and treated as new")
	}
}

func TestMemoryNonceStore_Concurrent(t *testing.T) {
	store := NewMemoryNonceStore(5*time.Minute, 1*time.Minute)
	defer store.Stop()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Each goroutine uses a unique nonce — all should be new
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			nonce := "concurrent-" + strings.Repeat("x", id)
			isNew, err := store.CheckAndStore(nonce, time.Now())
			if err != nil {
				t.Errorf("goroutine %d: unexpected error: %v", id, err)
			}
			if !isNew {
				t.Errorf("goroutine %d: expected new nonce", id)
			}
		}(i)
	}
	wg.Wait()

	// Now test concurrent replays of the same nonce
	var replayWg sync.WaitGroup
	replayWg.Add(goroutines)
	newCount := int64(0)
	var mu sync.Mutex

	for i := 0; i < goroutines; i++ {
		go func() {
			defer replayWg.Done()
			isNew, err := store.CheckAndStore("shared-nonce", time.Now())
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if isNew {
				mu.Lock()
				newCount++
				mu.Unlock()
			}
		}()
	}
	replayWg.Wait()

	// Due to sync.Map race semantics, at least 1 should succeed as new,
	// but the majority should be detected as replays
	if newCount == 0 {
		t.Error("expected at least one goroutine to see the nonce as new")
	}
	if newCount == int64(goroutines) {
		t.Error("expected some goroutines to detect replay, but all saw new")
	}
}

func TestMemoryNonceStore_StopIdempotent(t *testing.T) {
	store := NewMemoryNonceStore(5*time.Minute, 1*time.Minute)
	// Should not panic when called multiple times
	store.Stop()
	store.Stop()
}

// newTestLogger returns a logger that writes to the given writer for test inspection.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestReplayDetector_Disabled(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled: false,
	}, newTestLogger())
	defer rd.Stop()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := rd.Process(backend)

	body := `{"jsonrpc":"2.0","method":"message/send","id":"req-1"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("disabled detector: expected 200, got %d", rec.Code)
	}
}

func TestReplayDetector_WarnPolicy(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "warn",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	var backendCalls int
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	})

	handler := rd.Process(backend)

	body := `{"jsonrpc":"2.0","method":"message/send","id":"warn-1"}`

	// First request — should pass
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", rec.Code)
	}

	// Second request (replay) — should also pass in warn mode
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("replay with warn policy: expected 200, got %d", rec.Code)
	}

	if backendCalls != 2 {
		t.Errorf("expected backend called 2 times, got %d", backendCalls)
	}
}

func TestReplayDetector_RequirePolicy(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	var backendCalls int
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	})

	handler := rd.Process(backend)

	body := `{"jsonrpc":"2.0","method":"message/send","id":"req-block-1"}`

	// First request — should pass
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Second request (replay) — should be blocked with 429
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("replay with require policy: expected 429, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify error body contains hint and docs_url
	respBody := rec.Body.String()
	if !strings.Contains(respBody, "replay-protection") {
		t.Errorf("expected docs_url in response, got: %s", respBody)
	}
	if !strings.Contains(respBody, "Request ID already seen") {
		t.Errorf("expected hint in response, got: %s", respBody)
	}

	if backendCalls != 1 {
		t.Errorf("expected backend called 1 time (blocked on replay), got %d", backendCalls)
	}
}

func TestReplayDetector_RequirePolicy_DifferentIDs(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := rd.Process(backend)

	// Different IDs should all pass
	ids := []string{`"id-a"`, `"id-b"`, `"id-c"`, `1`, `2`, `3`}
	for _, id := range ids {
		body := `{"jsonrpc":"2.0","method":"message/send","id":` + id + `}`
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("id=%s: expected 200, got %d", id, rec.Code)
		}
	}
}

func TestReplayDetector_NonJSONRPC(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := rd.Process(backend)

	tests := []struct {
		name   string
		method string
		ct     string
		body   string
	}{
		{
			name:   "GET request",
			method: http.MethodGet,
			ct:     "",
			body:   "",
		},
		{
			name:   "PUT request",
			method: http.MethodPut,
			ct:     "application/json",
			body:   `{"id":"put-1"}`,
		},
		{
			name:   "POST with non-JSON content type",
			method: http.MethodPost,
			ct:     "text/plain",
			body:   "hello",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bodyReader *strings.Reader
			if tc.body != "" {
				bodyReader = strings.NewReader(tc.body)
			}
			var req *http.Request
			if bodyReader != nil {
				req = httptest.NewRequest(tc.method, "/", bodyReader)
			} else {
				req = httptest.NewRequest(tc.method, "/", nil)
			}
			if tc.ct != "" {
				req.Header.Set("Content-Type", tc.ct)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("%s: expected 200, got %d", tc.name, rec.Code)
			}
		})
	}
}

func TestReplayDetector_NoID(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	var backendCalls int
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	})

	handler := rd.Process(backend)

	// JSON-RPC notification (no id field) — require mode blocks missing nonce with 400
	body := `{"jsonrpc":"2.0","method":"notification/test"}`

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("request %d: expected 400 (require mode, no nonce), got %d", i, rec.Code)
		}
	}

	if backendCalls != 0 {
		t.Errorf("expected backend called 0 times (all blocked), got %d", backendCalls)
	}
}

func TestReplayDetector_NullID(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	var backendCalls int
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	})

	handler := rd.Process(backend)

	// null id is treated as no nonce — require mode returns 400
	body := `{"jsonrpc":"2.0","method":"test","id":null}`
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("null id request %d: expected 400 (require mode, no nonce), got %d", i, rec.Code)
		}
	}

	if backendCalls != 0 {
		t.Errorf("expected backend called 0 times (all blocked), got %d", backendCalls)
	}
}

func TestReplayDetector_NumericID(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := rd.Process(backend)

	body := `{"jsonrpc":"2.0","method":"test","id":42}`

	// First request passes
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec.Code)
	}

	// Replay blocked
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("replay of numeric ID: expected 429, got %d", rec.Code)
	}
}

func TestReplayDetector_BodyRewind(t *testing.T) {
	// Verify that the body is rewound and available to downstream handlers
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "warn",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	originalBody := `{"jsonrpc":"2.0","method":"test","id":"rewind-1","params":{"key":"value"}}`

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		if buf.String() != originalBody {
			t.Errorf("body not rewound correctly:\ngot:  %s\nwant: %s", buf.String(), originalBody)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := rd.Process(backend)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(originalBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestReplayDetector_EmptyBody(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	var backendCalls int
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	})

	handler := rd.Process(backend)

	// Empty body has no nonce — require mode returns 400
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty body: expected 400 (require mode, no nonce), got %d", rec.Code)
	}

	if backendCalls != 0 {
		t.Errorf("expected backend called 0 times (blocked), got %d", backendCalls)
	}
}

func TestReplayDetector_NoContentType(t *testing.T) {
	// POST with no content-type header should still be checked
	// (content-type "" passes the check)
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := rd.Process(backend)

	body := `{"jsonrpc":"2.0","method":"test","id":"no-ct-1"}`

	// First request
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec.Code)
	}

	// Replay should be blocked
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("replay with no content-type: expected 429, got %d", rec.Code)
	}
}

func TestReplayDetector_Name(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{}, nil)
	if rd.Name() != "replay_detector" {
		t.Errorf("expected 'replay_detector', got %q", rd.Name())
	}
}

func TestExtractNonce(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantEmpty bool
	}{
		{name: "string id", body: `{"id":"abc-123"}`, wantEmpty: false},
		{name: "numeric id", body: `{"id":42}`, wantEmpty: false},
		{name: "null id", body: `{"id":null}`, wantEmpty: true},
		{name: "no id", body: `{"method":"test"}`, wantEmpty: true},
		{name: "empty body", body: `{}`, wantEmpty: true},
		{name: "invalid json", body: `not json`, wantEmpty: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nonce := extractNonce([]byte(tc.body))
			if tc.wantEmpty && nonce != "" {
				t.Errorf("expected empty nonce, got %q", nonce)
			}
			if !tc.wantEmpty && nonce == "" {
				t.Errorf("expected non-empty nonce, got empty")
			}
		})
	}
}

func TestExtractNonce_DistinctTypes(t *testing.T) {
	// String "1" and number 1 should produce different nonces
	strNonce := extractNonce([]byte(`{"id":"1"}`))
	numNonce := extractNonce([]byte(`{"id":1}`))

	if strNonce == numNonce {
		t.Errorf("string id '1' and numeric id 1 should produce different nonces: both got %q", strNonce)
	}
}

func TestReplayDetector_HeaderNonce(t *testing.T) {
	// X-Sentinel-Nonce header should be used as nonce
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		NonceSource:     "auto",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	var backendCalls int
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	})
	handler := rd.Process(backend)

	// First request with header nonce
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":"different-id-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "header-nonce-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec.Code)
	}

	// Second request with same header nonce but different body id — should be blocked (header takes priority)
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":"different-id-2"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "header-nonce-1")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("replay with same header nonce: expected 429, got %d", rec.Code)
	}

	if backendCalls != 1 {
		t.Errorf("expected 1 backend call, got %d", backendCalls)
	}
}

func TestReplayDetector_HeaderNoncePriority(t *testing.T) {
	// When nonce_source=auto, header nonce takes priority over JSON-RPC id
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		NonceSource:     "auto",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rd.Process(backend)

	// Request with header nonce
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":"same-body-id"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "unique-header-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Same body id but different header nonce — should pass (header is the nonce, not body id)
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":"same-body-id"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "unique-header-2")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("different header nonce should pass: expected 200, got %d", rec.Code)
	}
}

func TestReplayDetector_NonceSourceHeader(t *testing.T) {
	// nonce_source=header: only use header, ignore body id
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		NonceSource:     "header",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	var backendCalls int
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	})
	handler := rd.Process(backend)

	// No header nonce — require mode blocks with 400 (header source, no header present)
	body := `{"jsonrpc":"2.0","method":"test","id":"req-1"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("no header with source=header (require mode): expected 400, got %d", rec.Code)
	}

	// Same body sent again (no header) — also blocked
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("replay without header in header mode (require): expected 400, got %d", rec.Code)
	}

	if backendCalls != 0 {
		t.Errorf("expected backend called 0 times (all blocked), got %d", backendCalls)
	}

	// With header present — should pass
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "header-nonce-unique-1")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("with header nonce (require): expected 200, got %d", rec.Code)
	}
}

func TestReplayDetector_NonceSourceJSONRPCID(t *testing.T) {
	// nonce_source=jsonrpc-id: only use body id, ignore header
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		NonceSource:     "jsonrpc-id",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	var backendCalls int
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	})
	handler := rd.Process(backend)

	body := `{"jsonrpc":"2.0","method":"test","id":"jsonrpc-only-1"}`

	// First request — passes
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "ignored-header")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first: expected 200, got %d", rec.Code)
	}

	// Second request with different header but same body id — blocked (uses body id)
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "different-header")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("replay of body id: expected 429, got %d", rec.Code)
	}

	if backendCalls != 1 {
		t.Errorf("expected 1 backend call, got %d", backendCalls)
	}
}

func TestReplayDetector_TimestampValidation(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		NonceSource:     "auto",
		ClockSkew:       5 * time.Second,
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rd.Process(backend)

	// Valid RFC3339 timestamp
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":"ts-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "ts-nonce-1")
	req.Header.Set("X-Sentinel-Timestamp", time.Now().UTC().Format(time.RFC3339))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("valid timestamp: expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Expired timestamp (way in the past)
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":"ts-2"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "ts-nonce-2")
	req.Header.Set("X-Sentinel-Timestamp", time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expired timestamp: expected 429, got %d", rec.Code)
	}

	// Future timestamp (beyond clock_skew)
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":"ts-3"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "ts-nonce-3")
	req.Header.Set("X-Sentinel-Timestamp", time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("future timestamp: expected 429, got %d", rec.Code)
	}
}

func TestReplayDetector_TimestampEpoch(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		NonceSource:     "auto",
		ClockSkew:       5 * time.Second,
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rd.Process(backend)

	// Valid epoch timestamp (10 digits)
	epoch := fmt.Sprintf("%d", time.Now().Unix())
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":"epoch-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "epoch-nonce-1")
	req.Header.Set("X-Sentinel-Timestamp", epoch)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("valid epoch: expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestReplayDetector_TimestampWarnMode(t *testing.T) {
	// In warn mode, expired timestamps should warn but still pass through
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "warn",
		NonceSource:     "auto",
		ClockSkew:       5 * time.Second,
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	var backendCalls int
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	})
	handler := rd.Process(backend)

	// Expired timestamp in warn mode — should pass through
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":"warn-ts-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "warn-ts-nonce-1")
	req.Header.Set("X-Sentinel-Timestamp", time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("warn mode with expired timestamp: expected 200, got %d", rec.Code)
	}

	// Replay in warn mode — should also pass through
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":"warn-ts-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Nonce", "warn-ts-nonce-1")
	req.Header.Set("X-Sentinel-Timestamp", time.Now().UTC().Format(time.RFC3339))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("warn mode replay: expected 200, got %d", rec.Code)
	}

	if backendCalls != 2 {
		t.Errorf("warn mode: expected 2 backend calls, got %d", backendCalls)
	}
}

func TestReplayDetector_NoTimestampHeader(t *testing.T) {
	// Without X-Sentinel-Timestamp header, timestamp validation should not apply
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		NonceSource:     "auto",
		ClockSkew:       5 * time.Second,
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rd.Process(backend)

	// No timestamp header — should use time.Now() and pass through
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"test","id":"no-ts-1"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("no timestamp header: expected 200, got %d", rec.Code)
	}
}

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"RFC3339", time.Now().UTC().Format(time.RFC3339), true},
		{"epoch 10 digits", "1700000000", true},
		{"epoch 9 digits", "170000000", false},
		{"epoch 11 digits", "17000000000", false},
		{"not a number", "abcdefghij", false},
		{"empty", "", false},
		{"RFC3339 with millis", "2025-01-01T00:00:00.000Z", true}, // Go's time.RFC3339 accepts fractional seconds
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := parseTimestamp(tc.input)
			if ok != tc.valid {
				t.Errorf("parseTimestamp(%q) = _, %v; want %v", tc.input, ok, tc.valid)
			}
		})
	}
}

func TestReplayDetector_AutoFallbackToBodyID(t *testing.T) {
	// When nonce_source=auto and no header, should fall back to JSON-RPC id
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		NonceSource:     "auto",
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	var backendCalls int
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	})
	handler := rd.Process(backend)

	body := `{"jsonrpc":"2.0","method":"test","id":"fallback-1"}`

	// First request without header — uses body id
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first: expected 200, got %d", rec.Code)
	}

	// Replay of same body id — blocked
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("body id replay: expected 429, got %d", rec.Code)
	}

	if backendCalls != 1 {
		t.Errorf("expected 1 backend call, got %d", backendCalls)
	}
}

func TestReplayDetector_TimestampAsymmetric(t *testing.T) {
	rd := NewReplayDetector(ReplayDetectorConfig{
		Enabled:         true,
		Window:          5 * time.Minute,
		NoncePolicy:     "require",
		NonceSource:     "auto",
		ClockSkew:       5 * time.Second,
		CleanupInterval: 1 * time.Minute,
	}, newTestLogger())
	defer rd.Stop()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rd.Process(backend)

	tests := []struct {
		name     string
		offset   time.Duration
		wantCode int
	}{
		{"past within window", -4 * time.Minute, http.StatusOK},
		{"past at window boundary", -5*time.Minute + time.Second, http.StatusOK},
		{"past beyond window", -5*time.Minute - time.Second, http.StatusTooManyRequests},
		{"future within clock_skew", 3 * time.Second, http.StatusOK},
		{"future at clock_skew boundary", 4 * time.Second, http.StatusOK},
		{"future beyond clock_skew", 6 * time.Second, http.StatusTooManyRequests},
		{"future at old symmetric boundary (60s)", 60 * time.Second, http.StatusTooManyRequests},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := time.Now().Add(tc.offset).UTC().Format(time.RFC3339)
			nonce := fmt.Sprintf("asym-nonce-%d", i)
			body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"test","id":"asym-%d"}`, i)

			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Sentinel-Nonce", nonce)
			req.Header.Set("X-Sentinel-Timestamp", ts)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Errorf("offset=%v: expected %d, got %d; body: %s", tc.offset, tc.wantCode, rec.Code, rec.Body.String())
			}
		})
	}
}
