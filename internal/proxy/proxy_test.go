package proxy

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestHTTPProxy_NormalForward verifies basic proxying: backend returns 200 with body.
func TestHTTPProxy_NormalForward(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Response", "hello")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test", nil)
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend response" {
		t.Errorf("expected 'backend response', got %q", string(body))
	}

	if resp.Header.Get("X-Custom-Response") != "hello" {
		t.Errorf("expected X-Custom-Response=hello, got %q", resp.Header.Get("X-Custom-Response"))
	}
}

// TestHTTPProxy_HeaderCopy verifies that request headers are forwarded to the backend.
func TestHTTPProxy_HeaderCopy(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom-Header", "custom-value")
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		header string
		want   string
	}{
		{"Authorization", "Bearer token123"},
		{"Content-Type", "application/json"},
		{"X-Custom-Header", "custom-value"},
	}

	for _, tc := range tests {
		got := receivedHeaders.Get(tc.header)
		if got != tc.want {
			t.Errorf("header %s: expected %q, got %q", tc.header, tc.want, got)
		}
	}
}

// TestHTTPProxy_HopByHopRemoved verifies hop-by-hop headers are NOT forwarded.
func TestHTTPProxy_HopByHopRemoved(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		// Also set hop-by-hop headers in response
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test", nil)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Upgrade", "websocket")
	// Also include a normal header to confirm it passes through
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify hop-by-hop headers were NOT forwarded to backend
	hopHeaders := []string{"Connection", "Keep-Alive", "Transfer-Encoding", "Proxy-Authorization", "Te", "Upgrade"}
	for _, h := range hopHeaders {
		if receivedHeaders.Get(h) != "" {
			t.Errorf("hop-by-hop header %s should not be forwarded, got %q", h, receivedHeaders.Get(h))
		}
	}

	// Verify normal header was forwarded
	if receivedHeaders.Get("Accept") != "application/json" {
		t.Errorf("normal header Accept should be forwarded")
	}

	// Verify hop-by-hop headers removed from response
	resp := rec.Result()
	defer resp.Body.Close()
	if resp.Header.Get("Keep-Alive") != "" {
		t.Errorf("hop-by-hop Keep-Alive should not be in response, got %q", resp.Header.Get("Keep-Alive"))
	}
}

// TestHTTPProxy_XForwardedFor verifies X-Forwarded-For is added with client IP.
func TestHTTPProxy_XForwardedFor(t *testing.T) {
	var receivedXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedXFF != "192.168.1.100" {
		t.Errorf("expected X-Forwarded-For=192.168.1.100, got %q", receivedXFF)
	}
}

// TestHTTPProxy_XForwardedFor_Append verifies existing XFF is appended to.
func TestHTTPProxy_XForwardedFor_Append(t *testing.T) {
	var receivedXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "203.0.113.50, 10.0.0.1"
	if receivedXFF != expected {
		t.Errorf("expected X-Forwarded-For=%q, got %q", expected, receivedXFF)
	}
}

// TestHTTPProxy_XForwardedProto verifies X-Forwarded-Proto is set correctly.
func TestHTTPProxy_XForwardedProto(t *testing.T) {
	var receivedProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	// Test HTTP (no TLS)
	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test", nil)
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedProto != "http" {
		t.Errorf("expected X-Forwarded-Proto=http, got %q", receivedProto)
	}
}

// TestHTTPProxy_NoSentinelHeaders verifies X-Sentinel-* headers are NOT forwarded.
func TestHTTPProxy_NoSentinelHeaders(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test", nil)
	req.Header.Set("X-Sentinel-Auth", "internal-token")
	req.Header.Set("X-Sentinel-Request-Id", "req-123")
	req.Header.Set("Authorization", "Bearer user-token")
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// X-Sentinel-* headers must NOT reach the backend
	for key := range receivedHeaders {
		if strings.HasPrefix(strings.ToLower(key), "x-sentinel-") {
			t.Errorf("sentinel header %s should not be forwarded to backend", key)
		}
	}

	// Normal headers should still be forwarded
	if receivedHeaders.Get("Authorization") != "Bearer user-token" {
		t.Errorf("Authorization header should be forwarded")
	}
}

// TestHTTPProxy_BackendError500 verifies that backend 500 is passed through.
func TestHTTPProxy_BackendError500(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal failure"}`))
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test", nil)
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"error":"internal failure"}` {
		t.Errorf("expected backend error body, got %q", string(body))
	}
}

// TestHTTPProxy_BackendDown verifies that unreachable backend returns ErrAgentUnavailable (503).
func TestHTTPProxy_BackendDown(t *testing.T) {
	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test", nil)
	rec := httptest.NewRecorder()

	// Use a URL that will definitely fail to connect
	err := proxy.Forward(rec, req, "http://127.0.0.1:1", "/test")
	if err == nil {
		t.Fatal("expected error for unreachable backend")
	}

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Target agent unavailable") {
		t.Errorf("expected ErrAgentUnavailable message, got %q", string(body))
	}
}

// TestHTTPProxy_QueryStringPreserved verifies query strings are forwarded correctly.
func TestHTTPProxy_QueryStringPreserved(t *testing.T) {
	var receivedQuery string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test?foo=bar&baz=123", nil)
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedQuery != "foo=bar&baz=123" {
		t.Errorf("expected query foo=bar&baz=123, got %q", receivedQuery)
	}
}

// TestHTTPProxy_PostBody verifies POST body is forwarded correctly.
func TestHTTPProxy_PostBody(t *testing.T) {
	var receivedBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	body := `{"jsonrpc":"2.0","method":"tasks/send","id":1}`
	req := httptest.NewRequest(http.MethodPost, "http://sentinel/a2a", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/a2a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedBody != body {
		t.Errorf("expected body %q, got %q", body, receivedBody)
	}
}

// TestCopyHeadersFiltered is a unit test for the header filtering function.
func TestCopyHeadersFiltered(t *testing.T) {
	tests := []struct {
		name     string
		src      http.Header
		wantKeys []string
		denyKeys []string
	}{
		{
			name: "normal headers pass through",
			src: http.Header{
				"Content-Type":  {"application/json"},
				"Authorization": {"Bearer token"},
				"X-Custom":      {"value"},
			},
			wantKeys: []string{"Content-Type", "Authorization", "X-Custom"},
			denyKeys: nil,
		},
		{
			name: "hop-by-hop headers filtered",
			src: http.Header{
				"Content-Type":      {"application/json"},
				"Connection":        {"keep-alive"},
				"Keep-Alive":        {"timeout=5"},
				"Transfer-Encoding": {"chunked"},
				"Proxy-Authorize":   {"Basic abc"}, // not hop-by-hop (note: Proxy-Authorization IS)
			},
			wantKeys: []string{"Content-Type", "Proxy-Authorize"},
			denyKeys: []string{"Connection", "Keep-Alive", "Transfer-Encoding"},
		},
		{
			name: "all hop-by-hop headers filtered",
			src: http.Header{
				"Connection":         {"keep-alive"},
				"Keep-Alive":         {"timeout=5"},
				"Proxy-Authenticate": {"Basic"},
				"Proxy-Authorization": {"Basic abc"},
				"Te":                  {"trailers"},
				"Trailers":            {"X-Foo"},
				"Transfer-Encoding":  {"chunked"},
				"Upgrade":            {"websocket"},
			},
			wantKeys: nil,
			denyKeys: []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade"},
		},
		{
			name: "multiple values for same header",
			src: http.Header{
				"Accept-Language": {"en-US", "ko-KR"},
			},
			wantKeys: []string{"Accept-Language"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dst := make(http.Header)
			CopyHeadersFiltered(dst, tc.src)

			for _, key := range tc.wantKeys {
				if dst.Get(key) == "" {
					t.Errorf("expected header %s to be present", key)
				}
			}
			for _, key := range tc.denyKeys {
				if dst.Get(key) != "" {
					t.Errorf("expected header %s to be filtered out, got %q", key, dst.Get(key))
				}
			}
		})
	}

	// Test multiple values preserved
	t.Run("multiple values preserved", func(t *testing.T) {
		src := http.Header{"Accept-Language": {"en-US", "ko-KR"}}
		dst := make(http.Header)
		CopyHeadersFiltered(dst, src)

		values := dst.Values("Accept-Language")
		if len(values) != 2 {
			t.Errorf("expected 2 values for Accept-Language, got %d", len(values))
		}
	})
}

// TestNewHTTPTransport verifies HTTP transport settings.
func TestNewHTTPTransport(t *testing.T) {
	tr := NewHTTPTransport()

	if tr.MaxIdleConns != 100 {
		t.Errorf("expected MaxIdleConns=100, got %d", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 10 {
		t.Errorf("expected MaxIdleConnsPerHost=10, got %d", tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("expected IdleConnTimeout=90s, got %v", tr.IdleConnTimeout)
	}
	if tr.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("expected ResponseHeaderTimeout=30s, got %v", tr.ResponseHeaderTimeout)
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("expected TLSHandshakeTimeout=10s, got %v", tr.TLSHandshakeTimeout)
	}
}

// TestHTTPProxy_InvalidBackendURL verifies that an invalid backend URL triggers request creation error.
func TestHTTPProxy_InvalidBackendURL(t *testing.T) {
	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	// Use a URL scheme that causes http.NewRequestWithContext to fail when combined with a bad URL.
	// A URL with a space in the host causes url.Parse to fail during request construction.
	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test", nil)
	rec := httptest.NewRecorder()

	// "://\x7f" is an invalid URL that will fail in http.NewRequestWithContext.
	err := proxy.Forward(rec, req, "://\x7f", "/test")
	if err == nil {
		t.Fatal("expected error for invalid backend URL")
	}

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", resp.StatusCode)
	}
}

// TestHTTPProxy_TLSRequest verifies X-Forwarded-Proto is "https" when r.TLS is set.
func TestHTTPProxy_TLSRequest(t *testing.T) {
	var receivedProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "https://sentinel/test", nil)
	// Set TLS field to a non-nil value to simulate a TLS connection.
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedProto != "https" {
		t.Errorf("expected X-Forwarded-Proto=https, got %q", receivedProto)
	}
}

// TestExtractClientIP_NoPort verifies extractClientIP fallback when RemoteAddr has no port.
func TestExtractClientIP_NoPort(t *testing.T) {
	// When RemoteAddr has no port, net.SplitHostPort returns error,
	// so extractClientIP returns the raw RemoteAddr.
	var receivedXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := NewHTTPProxy(NewHTTPTransport(), testLogger())

	req := httptest.NewRequest(http.MethodGet, "http://sentinel/test", nil)
	// Set RemoteAddr without a port to trigger the SplitHostPort error path.
	req.RemoteAddr = "192.168.1.50"
	rec := httptest.NewRecorder()

	err := proxy.Forward(rec, req, backend.URL, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The raw RemoteAddr should be used as-is.
	if receivedXFF != "192.168.1.50" {
		t.Errorf("expected X-Forwarded-For=192.168.1.50, got %q", receivedXFF)
	}
}

// TestNewStreamTransport verifies stream transport has no timeouts for long-lived connections.
func TestNewStreamTransport(t *testing.T) {
	tr := NewStreamTransport()

	if tr.MaxIdleConns != 100 {
		t.Errorf("expected MaxIdleConns=100, got %d", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 10 {
		t.Errorf("expected MaxIdleConnsPerHost=10, got %d", tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 0 {
		t.Errorf("expected IdleConnTimeout=0 for streaming, got %v", tr.IdleConnTimeout)
	}
	if tr.ResponseHeaderTimeout != 0 {
		t.Errorf("expected ResponseHeaderTimeout=0 for streaming, got %v", tr.ResponseHeaderTimeout)
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("expected TLSHandshakeTimeout=10s, got %v", tr.TLSHandshakeTimeout)
	}
}
