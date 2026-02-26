package proxy

import (
	"context"
	cryptotls "crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newFakeSSEServer creates a test HTTP server that emits SSE events.
// Each event string should be a complete SSE event including the trailing empty line.
// The delay is applied between events.
func newFakeSSEServer(events []string, delay time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		flusher.Flush()

		for _, event := range events {
			fmt.Fprint(w, event)
			flusher.Flush()
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}))
}

// newFakeSSEServerWithSignal creates a test SSE server that waits on a channel
// before closing, allowing tests to control when the backend disconnects.
func newFakeSSEServerWithSignal(events []string, doneCh <-chan struct{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		flusher.Flush()

		for _, event := range events {
			fmt.Fprint(w, event)
			flusher.Flush()
		}

		// Wait until signaled to close
		<-doneCh
	}))
}

// newFakeSSEServerSlow creates a test SSE server that sends events slowly,
// with a ready channel to signal when the first event is sent.
func newFakeSSEServerSlow(events []string, delay time.Duration, readyCh chan<- struct{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		flusher.Flush()

		for i, event := range events {
			fmt.Fprint(w, event)
			flusher.Flush()
			if i == 0 && readyCh != nil {
				close(readyCh)
			}
			time.Sleep(delay)
		}
	}))
}

func newTestSSEProxy(targetURL string) (*SSEProxy, *StreamManager) {
	sm := NewStreamManager()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := NewStreamTransport()
	p := NewSSEProxy(transport, sm, logger)
	return p, sm
}

// readSSEResponse reads the full body from a response recorder via pipe.
// This helper is used for tests that need to capture streamed output.
func readSSEFromPipe(pr *io.PipeReader, done chan<- string) {
	buf, _ := io.ReadAll(pr)
	done <- string(buf)
}

func TestSSEProxy_NormalStreaming(t *testing.T) {
	events := []string{
		"event: message\ndata: {\"id\":1}\n\n",
		"event: message\ndata: {\"id\":2}\n\n",
		"event: message\ndata: {\"id\":3}\n\n",
	}
	backend := newFakeSSEServer(events, 10*time.Millisecond)
	defer backend.Close()

	proxy, _ := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(5 * time.Second)

	// Use a pipe to capture streamed output
	pr, pw := io.Pipe()
	bodyCh := make(chan string, 1)
	go readSSEFromPipe(pr, bodyCh)

	rec := httptest.NewRecorder()
	// Wrap recorder to also write to pipe
	mw := &multiWriter{ResponseRecorder: rec, extra: pw}

	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)

	err := proxy.ProxyStream(mw, req, "test-agent", backend.URL, "/", 10)
	pw.Close()

	if err != nil {
		t.Fatalf("ProxyStream returned error: %v", err)
	}

	body := <-bodyCh

	// Verify all three events are present
	for i := 1; i <= 3; i++ {
		expected := fmt.Sprintf("data: {\"id\":%d}", i)
		if !strings.Contains(body, expected) {
			t.Errorf("response body missing event %d\ngot: %s", i, body)
		}
	}
}

func TestSSEProxy_ClientDisconnect(t *testing.T) {
	// Backend sends events forever until it detects client gone
	doneCh := make(chan struct{})
	backend := newFakeSSEServerWithSignal(
		[]string{"event: message\ndata: first\n\n"},
		doneCh,
	)
	defer backend.Close()
	defer close(doneCh) // ensure backend server handler exits

	proxy, sm := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(10 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil).WithContext(ctx)

	rec := httptest.NewRecorder()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	}()

	// Wait a bit for stream to establish, then cancel
	time.Sleep(100 * time.Millisecond)
	cancel()

	err := <-errCh
	// Client disconnect returns nil (not an error from proxy's perspective)
	if err != nil {
		t.Fatalf("expected nil error on client disconnect, got: %v", err)
	}

	// Verify stream was released
	time.Sleep(50 * time.Millisecond)
	if count := sm.ActiveStreams("test-agent"); count != 0 {
		t.Errorf("expected 0 active streams after disconnect, got %d", count)
	}
}

func TestSSEProxy_BackendDisconnect(t *testing.T) {
	// Backend sends one event then closes immediately
	events := []string{
		"event: message\ndata: only-event\n\n",
	}
	backend := newFakeSSEServer(events, 0)
	defer backend.Close()

	proxy, sm := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)

	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	if err != nil {
		t.Fatalf("expected nil error on backend disconnect, got: %v", err)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "data: only-event") {
		t.Errorf("expected event in response, got: %s", body)
	}

	// Verify stream was released
	if count := sm.ActiveStreams("test-agent"); count != 0 {
		t.Errorf("expected 0 active streams after backend disconnect, got %d", count)
	}
}

func TestSSEProxy_IdleTimeout(t *testing.T) {
	// Backend sends one event then holds connection open without sending more
	doneCh := make(chan struct{})
	backend := newFakeSSEServerWithSignal(
		[]string{"event: message\ndata: initial\n\n"},
		doneCh,
	)
	defer backend.Close()
	defer close(doneCh)

	proxy, sm := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(200 * time.Millisecond) // Short timeout for test

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)

	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	if err == nil {
		t.Fatal("expected error on idle timeout, got nil")
	}
	if !strings.Contains(err.Error(), "idle timeout") {
		t.Errorf("expected idle timeout error, got: %v", err)
	}

	body := rec.Body.String()
	// Should have received the initial event
	if !strings.Contains(body, "data: initial") {
		t.Errorf("expected initial event in response, got: %s", body)
	}
	// Should have received the error event
	if !strings.Contains(body, "event: error") {
		t.Errorf("expected error event in response, got: %s", body)
	}

	// Verify stream was released
	if count := sm.ActiveStreams("test-agent"); count != 0 {
		t.Errorf("expected 0 active streams after idle timeout, got %d", count)
	}
}

func TestSSEProxy_ConcurrentStreamLimit(t *testing.T) {
	const maxStreams = 2

	// Backend that stays open until signaled
	doneCh := make(chan struct{})
	backend := newFakeSSEServerWithSignal(
		[]string{"event: message\ndata: hello\n\n"},
		doneCh,
	)
	defer backend.Close()
	defer close(doneCh)

	sm := NewStreamManager()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := NewStreamTransport()
	proxy := NewSSEProxy(transport, sm, logger)
	proxy.SetIdleTimeout(10 * time.Second)

	// Start maxStreams concurrent streams
	var wg sync.WaitGroup
	ctxs := make([]context.CancelFunc, maxStreams)

	for i := 0; i < maxStreams; i++ {
		wg.Add(1)
		ctx, cancel := context.WithCancel(context.Background())
		ctxs[i] = cancel
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/a2a", nil).WithContext(ctx)
			proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", maxStreams)
		}()
	}

	// Wait for streams to be acquired
	time.Sleep(200 * time.Millisecond)

	// Verify we have maxStreams active
	if count := sm.ActiveStreams("test-agent"); count != maxStreams {
		t.Errorf("expected %d active streams, got %d", maxStreams, count)
	}

	// Try to acquire one more — should fail
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)
	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", maxStreams)
	if err == nil {
		t.Fatal("expected error when stream limit exceeded")
	}
	if !strings.Contains(err.Error(), "stream limit exceeded") {
		t.Errorf("expected stream limit error, got: %v", err)
	}

	// Verify error response
	if rec.Code != 429 {
		t.Errorf("expected status 429, got %d", rec.Code)
	}

	// Clean up
	for _, cancel := range ctxs {
		cancel()
	}
	wg.Wait()
}

func TestSSEProxy_LargeEvent(t *testing.T) {
	// Create an event near max size (use a smaller limit for test speed)
	const testMaxSize = 64 * 1024 // 64KB for test
	largeData := strings.Repeat("x", testMaxSize-100)
	events := []string{
		fmt.Sprintf("event: large\ndata: %s\n\n", largeData),
	}
	backend := newFakeSSEServer(events, 0)
	defer backend.Close()

	proxy, _ := newTestSSEProxy(backend.URL)
	proxy.SetMaxEventSize(testMaxSize)
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)

	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	if err != nil {
		t.Fatalf("ProxyStream returned error: %v", err)
	}

	body := rec.Body.String()
	if !strings.Contains(body, largeData) {
		t.Errorf("large event data not found in response (got %d bytes)", len(body))
	}
}

func TestSSEProxy_FlushAtEventBoundary(t *testing.T) {
	// Send events with explicit boundaries to verify flush behavior
	events := []string{
		"event: msg\ndata: first\n\n",
		"event: msg\ndata: second\n\n",
	}
	backend := newFakeSSEServer(events, 50*time.Millisecond)
	defer backend.Close()

	proxy, _ := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)

	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	if err != nil {
		t.Fatalf("ProxyStream returned error: %v", err)
	}

	body := rec.Body.String()

	// Both events must be present, separated by empty lines
	if !strings.Contains(body, "data: first") {
		t.Error("missing first event")
	}
	if !strings.Contains(body, "data: second") {
		t.Error("missing second event")
	}

	// Verify event boundary format: each event ends with \n\n
	// In our output, the empty line between events shows as \n after the data line's \n
	parts := strings.Split(body, "\n\n")
	// Filter out any trailing empty string
	var nonEmpty []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	if len(nonEmpty) < 2 {
		t.Errorf("expected at least 2 event blocks separated by empty lines, got %d: %q", len(nonEmpty), body)
	}
}

func TestSSEProxy_SSEHeaders(t *testing.T) {
	events := []string{"event: test\ndata: hi\n\n"}
	backend := newFakeSSEServer(events, 0)
	defer backend.Close()

	proxy, _ := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)

	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	if err != nil {
		t.Fatalf("ProxyStream returned error: %v", err)
	}

	headers := rec.Header()

	tests := []struct {
		header   string
		expected string
	}{
		{"Content-Type", "text/event-stream"},
		{"Cache-Control", "no-cache"},
		{"Connection", "keep-alive"},
		{"X-Accel-Buffering", "no"},
	}

	for _, tt := range tests {
		got := headers.Get(tt.header)
		if got != tt.expected {
			t.Errorf("header %s = %q, want %q", tt.header, got, tt.expected)
		}
	}
}

// errReader is an io.Reader that returns some bytes then an error.
type errReader struct {
	data []byte
	pos  int
	err  error
}

func (e *errReader) Read(p []byte) (int, error) {
	if e.pos < len(e.data) {
		n := copy(p, e.data[e.pos:])
		e.pos += n
		return n, nil
	}
	return 0, e.err
}

// errorBodyTransport is an http.RoundTripper that returns a response whose
// body yields some initial bytes then returns a non-EOF error, triggering
// the scanner error path in ProxyStream.
type errorBodyTransport struct {
	initialData string
	bodyErr     error
}

func (t *errorBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := &errReader{
		data: []byte(t.initialData),
		err:  t.bodyErr,
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":  []string{"text/event-stream"},
			"Cache-Control": []string{"no-cache"},
		},
		Body:    io.NopCloser(body),
		Request: req,
	}
	return resp, nil
}

// TestSSEProxy_BackendReadError verifies that a backend read error (scanner error)
// sends an SSE error event and returns an error.
func TestSSEProxy_BackendReadError(t *testing.T) {
	bodyErr := fmt.Errorf("simulated read error")
	transport := &errorBodyTransport{
		// Send one valid event, then the reader will hit bodyErr.
		initialData: "event: message\ndata: first\n\n",
		bodyErr:     bodyErr,
	}

	sm := NewStreamManager()
	logger := testLogger()
	proxy := NewSSEProxy(transport, sm, logger)
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)

	err := proxy.ProxyStream(rec, req, "test-agent", "http://unused", "/", 10)
	if err == nil {
		t.Fatal("expected error on backend read error, got nil")
	}
	if !strings.Contains(err.Error(), "backend read error") {
		t.Errorf("expected 'backend read error', got: %v", err)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "event: error") {
		t.Errorf("expected SSE error event in response, got: %s", body)
	}
}

// TestSSEProxy_QueryStringForwarded verifies query strings are forwarded in SSE requests.
func TestSSEProxy_QueryStringForwarded(t *testing.T) {
	var receivedQuery string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		fmt.Fprint(w, "event: done\ndata: ok\n\n")
		flusher.Flush()
	}))
	defer backend.Close()

	proxy, _ := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a?session=123&mode=stream", nil)

	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedQuery != "session=123&mode=stream" {
		t.Errorf("expected query session=123&mode=stream, got %q", receivedQuery)
	}
}

// TestSSEProxy_InvalidBackendURL verifies error when SSE backend URL is invalid.
func TestSSEProxy_InvalidBackendURL(t *testing.T) {
	proxy, _ := newTestSSEProxy("http://unused")
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)

	err := proxy.ProxyStream(rec, req, "test-agent", "://\x7f", "/", 10)
	if err == nil {
		t.Fatal("expected error for invalid backend URL in SSE")
	}
	if !strings.Contains(err.Error(), "creating backend request") {
		t.Errorf("expected 'creating backend request' error, got: %v", err)
	}

	resp := rec.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}

// TestSSEProxy_XForwardedFor_Append verifies existing X-Forwarded-For is appended to in SSE.
func TestSSEProxy_XForwardedFor_Append(t *testing.T) {
	var receivedXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedXFF = r.Header.Get("X-Forwarded-For")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		fmt.Fprint(w, "event: done\ndata: ok\n\n")
		flusher.Flush()
	}))
	defer backend.Close()

	proxy, _ := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")

	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "203.0.113.50, 10.0.0.1"
	if receivedXFF != expected {
		t.Errorf("expected X-Forwarded-For=%q, got %q", expected, receivedXFF)
	}
}

// TestSSEProxy_TLSRequest verifies X-Forwarded-Proto is "https" in SSE when r.TLS is set.
func TestSSEProxy_TLSRequest(t *testing.T) {
	var receivedProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedProto = r.Header.Get("X-Forwarded-Proto")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		fmt.Fprint(w, "event: done\ndata: ok\n\n")
		flusher.Flush()
	}))
	defer backend.Close()

	proxy, _ := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://sentinel/a2a", nil)
	req.TLS = &cryptotls.ConnectionState{}

	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedProto != "https" {
		t.Errorf("expected X-Forwarded-Proto=https, got %q", receivedProto)
	}
}

// TestSSEProxy_SentinelHeadersRemoved verifies X-Sentinel-* headers are stripped in SSE.
func TestSSEProxy_SentinelHeadersRemoved(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		fmt.Fprint(w, "event: done\ndata: ok\n\n")
		flusher.Flush()
	}))
	defer backend.Close()

	proxy, _ := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)
	req.Header.Set("X-Sentinel-Auth", "internal-token")
	req.Header.Set("Authorization", "Bearer user-token")

	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for key := range receivedHeaders {
		if strings.HasPrefix(strings.ToLower(key), "x-sentinel-") {
			t.Errorf("sentinel header %s should not be forwarded to backend", key)
		}
	}
	if receivedHeaders.Get("Authorization") != "Bearer user-token" {
		t.Errorf("Authorization header should be forwarded")
	}
}

// noFlusherResponseWriter is an http.ResponseWriter that does not implement http.Flusher.
type noFlusherResponseWriter struct {
	header http.Header
	body   strings.Builder
	code   int
}

func (w *noFlusherResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *noFlusherResponseWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (w *noFlusherResponseWriter) WriteHeader(code int) {
	w.code = code
}

// TestSSEProxy_NoFlusher verifies error when ResponseWriter does not support flushing.
func TestSSEProxy_NoFlusher(t *testing.T) {
	events := []string{"event: msg\ndata: hi\n\n"}
	backend := newFakeSSEServer(events, 0)
	defer backend.Close()

	proxy, _ := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(5 * time.Second)

	w := &noFlusherResponseWriter{}
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)

	err := proxy.ProxyStream(w, req, "test-agent", backend.URL, "/", 10)
	if err == nil {
		t.Fatal("expected error when ResponseWriter does not support flushing")
	}
	if !strings.Contains(err.Error(), "does not support flushing") {
		t.Errorf("expected 'does not support flushing' error, got: %v", err)
	}
}

// TestSSEProxy_BackendResponseHeadersCopied verifies that non-SSE, non-hop-by-hop
// headers from the backend response are forwarded to the client.
func TestSSEProxy_BackendResponseHeadersCopied(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		// Set a custom backend header that should be copied through.
		w.Header().Set("X-Agent-Id", "agent-42")
		// Set a hop-by-hop header that should NOT be copied.
		w.Header().Set("Keep-Alive", "timeout=5")
		flusher, _ := w.(http.Flusher)
		fmt.Fprint(w, "event: done\ndata: ok\n\n")
		flusher.Flush()
	}))
	defer backend.Close()

	proxy, _ := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)

	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Custom header should be forwarded.
	if rec.Header().Get("X-Agent-Id") != "agent-42" {
		t.Errorf("expected X-Agent-Id=agent-42, got %q", rec.Header().Get("X-Agent-Id"))
	}
	// Hop-by-hop header should NOT be forwarded.
	if rec.Header().Get("Keep-Alive") != "" {
		t.Errorf("hop-by-hop Keep-Alive should not be forwarded, got %q", rec.Header().Get("Keep-Alive"))
	}
}

// TestSSEProxy_BackendDown verifies error when backend is unreachable.
func TestSSEProxy_BackendDown(t *testing.T) {
	proxy, _ := newTestSSEProxy("http://127.0.0.1:1")
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)

	err := proxy.ProxyStream(rec, req, "test-agent", "http://127.0.0.1:1", "/", 10)
	if err == nil {
		t.Fatal("expected error for unreachable backend")
	}
	if !strings.Contains(err.Error(), "backend request failed") {
		t.Errorf("expected 'backend request failed', got: %v", err)
	}

	resp := rec.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", resp.StatusCode)
	}
}

// TestExtractSSEClientIP_NoPort verifies extractSSEClientIP fallback when RemoteAddr has no port.
func TestExtractSSEClientIP_NoPort(t *testing.T) {
	// Use a backend that echoes back the X-Forwarded-For header.
	var receivedXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedXFF = r.Header.Get("X-Forwarded-For")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		fmt.Fprint(w, "event: done\ndata: ok\n\n")
		flusher.Flush()
	}))
	defer backend.Close()

	proxy, _ := newTestSSEProxy(backend.URL)
	proxy.SetIdleTimeout(5 * time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/a2a", nil)
	// Set RemoteAddr without a port to trigger SplitHostPort error path.
	req.RemoteAddr = "10.0.0.99"

	err := proxy.ProxyStream(rec, req, "test-agent", backend.URL, "/", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The raw RemoteAddr (no port) should be used as-is for X-Forwarded-For.
	if receivedXFF != "10.0.0.99" {
		t.Errorf("expected X-Forwarded-For=10.0.0.99, got %q", receivedXFF)
	}
}

// --- StreamManager Tests ---

func TestStreamManager_AcquireRelease(t *testing.T) {
	sm := NewStreamManager()

	// Acquire increments count
	if !sm.AcquireStream("agent-a", 5) {
		t.Fatal("expected AcquireStream to succeed")
	}
	if count := sm.ActiveStreams("agent-a"); count != 1 {
		t.Errorf("expected 1 active stream, got %d", count)
	}

	// Acquire again
	if !sm.AcquireStream("agent-a", 5) {
		t.Fatal("expected second AcquireStream to succeed")
	}
	if count := sm.ActiveStreams("agent-a"); count != 2 {
		t.Errorf("expected 2 active streams, got %d", count)
	}

	// Release decrements count
	sm.ReleaseStream("agent-a")
	if count := sm.ActiveStreams("agent-a"); count != 1 {
		t.Errorf("expected 1 active stream after release, got %d", count)
	}

	sm.ReleaseStream("agent-a")
	if count := sm.ActiveStreams("agent-a"); count != 0 {
		t.Errorf("expected 0 active streams after release, got %d", count)
	}
}

func TestStreamManager_AcquireRespectsLimit(t *testing.T) {
	sm := NewStreamManager()

	// Fill to limit
	if !sm.AcquireStream("agent-a", 2) {
		t.Fatal("expected first AcquireStream to succeed")
	}
	if !sm.AcquireStream("agent-a", 2) {
		t.Fatal("expected second AcquireStream to succeed")
	}

	// Third should fail
	if sm.AcquireStream("agent-a", 2) {
		t.Fatal("expected AcquireStream to fail at limit")
	}

	// Different agent should still work
	if !sm.AcquireStream("agent-b", 2) {
		t.Fatal("expected AcquireStream for different agent to succeed")
	}

	// Release one from agent-a, should be able to acquire again
	sm.ReleaseStream("agent-a")
	if !sm.AcquireStream("agent-a", 2) {
		t.Fatal("expected AcquireStream to succeed after release")
	}
}

func TestStreamManager_DrainAll(t *testing.T) {
	sm := NewStreamManager()

	// Acquire some streams
	sm.AcquireStream("agent-a", 10)
	sm.AcquireStream("agent-a", 10)
	sm.AcquireStream("agent-b", 10)

	// Start draining in background
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	drainDone := make(chan error, 1)
	go func() {
		drainDone <- sm.DrainAll(ctx)
	}()

	// Draining should block new streams immediately
	time.Sleep(50 * time.Millisecond)
	if sm.AcquireStream("agent-a", 10) {
		t.Fatal("expected AcquireStream to fail during drain")
	}

	// Release all streams
	sm.ReleaseStream("agent-a")
	sm.ReleaseStream("agent-a")
	sm.ReleaseStream("agent-b")

	// Drain should complete
	select {
	case err := <-drainDone:
		if err != nil {
			t.Fatalf("DrainAll returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DrainAll did not complete in time")
	}
}

func TestStreamManager_DrainTimeout(t *testing.T) {
	sm := NewStreamManager()

	// Acquire a stream but never release it
	sm.AcquireStream("agent-a", 10)

	// Drain with a short context
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := sm.DrainAll(ctx)
	if err == nil {
		t.Fatal("expected error from DrainAll with expired context")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}
}

func TestStreamManager_ActiveStreams(t *testing.T) {
	sm := NewStreamManager()

	// Unknown agent returns 0
	if count := sm.ActiveStreams("unknown"); count != 0 {
		t.Errorf("expected 0 for unknown agent, got %d", count)
	}

	sm.AcquireStream("agent-a", 10)
	sm.AcquireStream("agent-a", 10)
	sm.AcquireStream("agent-b", 10)

	if count := sm.ActiveStreams("agent-a"); count != 2 {
		t.Errorf("expected 2 for agent-a, got %d", count)
	}
	if count := sm.ActiveStreams("agent-b"); count != 1 {
		t.Errorf("expected 1 for agent-b, got %d", count)
	}

	sm.ReleaseStream("agent-a")
	if count := sm.ActiveStreams("agent-a"); count != 1 {
		t.Errorf("expected 1 for agent-a after release, got %d", count)
	}
}

func TestStreamManager_ConcurrentAccess(t *testing.T) {
	sm := NewStreamManager()
	const goroutines = 50
	const maxStreams = 100

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sm.AcquireStream("agent-a", maxStreams) {
				// Hold briefly then release
				time.Sleep(time.Millisecond)
				sm.ReleaseStream("agent-a")
			}
		}()
	}
	wg.Wait()

	if count := sm.ActiveStreams("agent-a"); count != 0 {
		t.Errorf("expected 0 active streams after all goroutines complete, got %d", count)
	}
}

// multiWriter wraps httptest.ResponseRecorder and also writes body data to an extra writer.
// This allows capturing streamed output via a pipe while using the recorder for headers/status.
type multiWriter struct {
	*httptest.ResponseRecorder
	extra io.Writer
}

func (mw *multiWriter) Write(b []byte) (int, error) {
	n, err := mw.ResponseRecorder.Write(b)
	if err != nil {
		return n, err
	}
	if mw.extra != nil {
		mw.extra.Write(b)
	}
	return n, nil
}

func (mw *multiWriter) Flush() {
	mw.ResponseRecorder.Flush()
}
