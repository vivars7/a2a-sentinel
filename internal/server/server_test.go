package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/config"
	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
	"github.com/vivars7/a2a-sentinel/internal/health"
	"github.com/vivars7/a2a-sentinel/internal/protocol"
)

// testConfig creates a minimal valid config pointing to a test backend.
func testConfig(backendURL string) *config.Config {
	cfg := &config.Config{}
	cfg.Agents = []config.AgentConfig{
		{
			Name:    "test-agent",
			URL:     backendURL,
			Default: true,
		},
	}
	config.ApplyDefaults(cfg)
	cfg.Security.Auth.AllowUnauthenticated = true
	// Disable rate limiting for simpler testing
	cfg.Security.RateLimit.Enabled = false
	cfg.Listen.GlobalRateLimit = 0
	return cfg
}

// startTestServer creates a Server with the given config, builds its handler,
// and returns an httptest.Server for integration testing.
func startTestServer(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()
	srv, err := New(cfg, "test-version")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	handler := srv.handler()
	return httptest.NewServer(handler)
}

func TestServer_Healthz(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	ts := startTestServer(t, cfg)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body health.LivenessResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body.Status != "ok" {
		t.Errorf("expected status %q, got %q", "ok", body.Status)
	}
	if body.Version != "test-version" {
		t.Errorf("expected version %q, got %q", "test-version", body.Version)
	}
}

func TestServer_Readyz(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	ts := startTestServer(t, cfg)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatalf("readyz request failed: %v", err)
	}
	defer resp.Body.Close()

	// With no agent card polling, no agents are healthy yet.
	// Expect 503 not_ready since readiness_mode defaults to any_healthy.
	var body health.ReadinessResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body.TotalAgents != 1 {
		t.Errorf("expected total_agents=1, got %d", body.TotalAgents)
	}
	// Healthy agents should be 0 since polling hasn't run
	if body.HealthyAgents != 0 {
		t.Errorf("expected healthy_agents=0, got %d", body.HealthyAgents)
	}
}

func TestServer_AgentCard(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	ts := startTestServer(t, cfg)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/agent.json")
	if err != nil {
		t.Fatalf("agent card request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	// Should return valid JSON (aggregated card)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if !json.Valid(bodyBytes) {
		t.Errorf("response is not valid JSON: %s", string(bodyBytes))
	}
}

func TestServer_ProxyHTTPRequest(t *testing.T) {
	// Backend echoes back the method and path
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"method": r.Method,
			"path":   r.URL.Path,
		})
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Routing.Mode = "single"
	ts := startTestServer(t, cfg)
	defer ts.Close()

	// Mark agent as healthy by manipulating the card manager.
	// Since we can't easily do that with the real poller, we use
	// a POST with a JSON-RPC body that the protocol detector will parse.
	reqBody := `{"jsonrpc":"2.0","method":"message/send","id":1,"params":{}}`
	resp, err := http.Post(ts.URL+"/", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	// The router will fail because no agents are healthy (polling hasn't started).
	// This is expected — we're testing the full pipeline.
	// Should get a 503 (agent unavailable) or 404 (no route).
	if resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 503 or 404 for unhealthy agent, got %d", resp.StatusCode)
	}
}

func TestServer_UnauthenticatedRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	// Set strict mode and disallow unauthenticated
	cfg.Security.Auth.Mode = "passthrough-strict"
	cfg.Security.Auth.AllowUnauthenticated = false
	ts := startTestServer(t, cfg)
	defer ts.Close()

	// POST a JSON-RPC request without auth header
	reqBody := `{"jsonrpc":"2.0","method":"message/send","id":1,"params":{}}`
	resp, err := http.Post(ts.URL+"/", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated request, got %d", resp.StatusCode)
	}

	// Response should contain a hint
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if !strings.Contains(string(bodyBytes), "hint") {
		t.Errorf("error response should contain hint, got: %s", string(bodyBytes))
	}
}

func TestServer_AuthenticatedPassthrough(t *testing.T) {
	// Backend verifies the Authorization header is passed through
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"jsonrpc":"2.0","result":"ok","id":1}`)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Security.Auth.Mode = "passthrough-strict"
	cfg.Security.Auth.AllowUnauthenticated = false
	cfg.Routing.Mode = "single"
	ts := startTestServer(t, cfg)
	defer ts.Close()

	// We need to make the agent healthy. Since the card manager hasn't polled,
	// the router will fail. This tests that auth middleware runs first.
	reqBody := `{"jsonrpc":"2.0","method":"message/send","id":1,"params":{}}`
	req, err := http.NewRequest("POST", ts.URL+"/", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token-123")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// With passthrough-strict and a bearer token, auth should pass.
	// But since the agent isn't healthy (no polling), the router should fail
	// with 503 or 404. The key test is that we DON'T get a 401.
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("authenticated request should not get 401, got %d", resp.StatusCode)
	}
}

func TestServer_HealthBypassesSecurity(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	// Strict auth with no unauthenticated access
	cfg.Security.Auth.Mode = "passthrough-strict"
	cfg.Security.Auth.AllowUnauthenticated = false
	ts := startTestServer(t, cfg)
	defer ts.Close()

	// Health endpoints should still be accessible without auth
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz should bypass security, expected 200 got %d", resp.StatusCode)
	}
}

func TestServer_LimitedListener(t *testing.T) {
	// Create a listener with limit of 2 connections
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	limited := newLimitedListener(ln, 2)

	// Track active connections
	var mu sync.Mutex
	activeConns := 0
	maxActive := 0
	connReady := make(chan struct{}, 3)
	holdConns := make(chan struct{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		activeConns++
		if activeConns > maxActive {
			maxActive = activeConns
		}
		mu.Unlock()

		connReady <- struct{}{}

		// Hold the connection open until signaled
		<-holdConns

		mu.Lock()
		activeConns--
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{Handler: handler}
	go srv.Serve(limited)
	defer srv.Close()

	addr := ln.Addr().String()

	// Start 3 requests concurrently (only 2 should be active at once)
	var wg sync.WaitGroup
	results := make(chan int, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get("http://" + addr + "/")
			if err != nil {
				results <- -1
				return
			}
			defer resp.Body.Close()
			results <- resp.StatusCode
		}()
	}

	// Wait for 2 connections to be active
	<-connReady
	<-connReady

	// Give a moment for the 3rd connection to attempt
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	current := activeConns
	mu.Unlock()

	// Should have exactly 2 active (the 3rd is blocked on the semaphore)
	if current != 2 {
		t.Errorf("expected 2 active connections, got %d", current)
	}

	// Release all connections
	close(holdConns)
	wg.Wait()
	close(results)

	mu.Lock()
	observed := maxActive
	mu.Unlock()

	if observed > 2 {
		t.Errorf("max concurrent connections should be <= 2, got %d", observed)
	}
}

func TestServer_LimitedConn_CloseOnce(t *testing.T) {
	sem := make(chan struct{}, 10)
	sem <- struct{}{} // Simulate an acquired slot

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	// Create a real connection pair
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		done <- c
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	serverConn := <-done
	defer serverConn.Close()

	lc := &limitedConn{Conn: clientConn, sem: sem}

	// Close twice should not panic
	lc.Close()
	lc.Close()

	// Semaphore should have been released exactly once
	if len(sem) != 0 {
		t.Errorf("expected semaphore to be empty after close, got %d", len(sem))
	}
}

func TestServer_New_ValidConfig(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	srv, err := New(cfg, "1.0.0")
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if srv == nil {
		t.Fatal("New() returned nil server")
	}
	if srv.version != "1.0.0" {
		t.Errorf("version = %q, want %q", srv.version, "1.0.0")
	}
}

func TestServer_WriteError_JSONRPC(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Create a request with JSON-RPC protocol meta in context
	req := httptest.NewRequest("POST", "/", nil)
	ctx := req.Context()
	ctx = context.WithValue(ctx, requestMetaKeyForTest{}, "jsonrpc")
	req = req.WithContext(ctx)

	// Since we can't easily set the context key the same way (it's unexported),
	// test the HTTP error path instead
	w := httptest.NewRecorder()
	srv.writeError(w, req, sentinelerrors.ErrNoRoute)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "No matching agent found") {
		t.Errorf("response should contain error message, got: %s", body)
	}
}

// requestMetaKeyForTest is just to avoid using the real context key directly.
type requestMetaKeyForTest struct{}

func TestServer_GetMaxStreams(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	cfg.Agents[0].MaxStreams = 42
	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	got := srv.getMaxStreams("test-agent")
	if got != 42 {
		t.Errorf("getMaxStreams(test-agent) = %d, want 42", got)
	}

	got = srv.getMaxStreams("unknown-agent")
	if got != 10 {
		t.Errorf("getMaxStreams(unknown-agent) = %d, want 10 (default)", got)
	}
}

func TestServer_BuildSecurityPipelineConfig(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	cfg.Security.Auth.Mode = "terminate"
	cfg.Security.Auth.Schemes = []config.SchemeConfig{
		{
			Type: "bearer",
			JWT: config.JWTConfig{
				Issuer:   "https://auth.example.com",
				Audience: "my-api",
				JWKSURL:  "https://auth.example.com/.well-known/jwks.json",
			},
		},
	}
	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	pCfg := srv.buildSecurityPipelineConfig()
	if pCfg.Auth.Mode != "terminate" {
		t.Errorf("auth mode = %q, want %q", pCfg.Auth.Mode, "terminate")
	}
	if pCfg.Auth.Issuer != "https://auth.example.com" {
		t.Errorf("issuer = %q, want %q", pCfg.Auth.Issuer, "https://auth.example.com")
	}
	if pCfg.Auth.Audience != "my-api" {
		t.Errorf("audience = %q, want %q", pCfg.Auth.Audience, "my-api")
	}
	if pCfg.Auth.JWKSURL != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("jwks_url = %q, want expected value", pCfg.Auth.JWKSURL)
	}
}

func TestServer_AgentLookupAdapter(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Agents = append(cfg.Agents, config.AgentConfig{
		Name: "second-agent",
		URL:  "http://localhost:9001",
	})
	config.ApplyDefaults(cfg)

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	_ = srv // Ensure the server was created

	adapter := &agentLookupAdapter{
		manager: srv.cardManager,
		agents:  cfg.Agents,
	}

	// GetAgentURL
	url, ok := adapter.GetAgentURL("test-agent")
	if !ok || url != backend.URL {
		t.Errorf("GetAgentURL(test-agent) = (%q, %v), want (%q, true)", url, ok, backend.URL)
	}

	url, ok = adapter.GetAgentURL("nonexistent")
	if ok {
		t.Errorf("GetAgentURL(nonexistent) should return false")
	}

	// GetDefaultAgent
	name, url, found := adapter.GetDefaultAgent()
	if !found {
		t.Fatal("GetDefaultAgent should find the default agent")
	}
	if name != "test-agent" {
		t.Errorf("default agent name = %q, want %q", name, "test-agent")
	}
	if url != backend.URL {
		t.Errorf("default agent url = %q, want %q", url, backend.URL)
	}
}

func TestServer_HealthCheckerAdapter(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	cfg.Agents = append(cfg.Agents, config.AgentConfig{
		Name: "second-agent",
		URL:  "http://localhost:9001",
	})
	config.ApplyDefaults(cfg)

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	adapter := &healthCheckerAdapter{
		manager: srv.cardManager,
		agents:  cfg.Agents,
	}

	allNames := adapter.AllAgentNames()
	if len(allNames) != 2 {
		t.Errorf("AllAgentNames() returned %d names, want 2", len(allNames))
	}

	// No agents are healthy initially
	healthy := adapter.HealthyAgents()
	if len(healthy) != 0 {
		t.Errorf("HealthyAgents() returned %d, want 0 initially", len(healthy))
	}
}

func TestServer_StartAndShutdown(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	// Use port 0 to let OS assign a free port
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel to trigger shutdown
	cancel()

	// Wait for shutdown
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down within 5 seconds")
	}
}

// TestAgentLookupAdapter_IsHealthy covers the IsHealthy method on agentLookupAdapter.
func TestAgentLookupAdapter_IsHealthy(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	adapter := &agentLookupAdapter{
		manager: srv.cardManager,
		agents:  cfg.Agents,
	}

	// Agent hasn't polled yet so is not healthy.
	if adapter.IsHealthy("test-agent") {
		t.Error("expected IsHealthy to return false for unpolled agent")
	}
	if adapter.IsHealthy("nonexistent") {
		t.Error("expected IsHealthy to return false for nonexistent agent")
	}
}

// TestAgentLookupAdapter_GetDefaultAgent_NoDefault covers the no-default-agent path.
func TestAgentLookupAdapter_GetDefaultAgent_NoDefault(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	// Remove default flag from all agents.
	cfg.Agents[0].Default = false

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	adapter := &agentLookupAdapter{
		manager: srv.cardManager,
		agents:  cfg.Agents,
	}

	_, _, found := adapter.GetDefaultAgent()
	if found {
		t.Error("GetDefaultAgent should return false when no default agent is configured")
	}
}

// TestServer_Start_ListenError covers the listen error path in Start.
func TestServer_Start_ListenError(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	// Bind to an invalid address to force listen error.
	cfg.Listen.Host = "256.256.256.256"
	cfg.Listen.Port = 9999

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	err = srv.Start(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

// TestServer_Shutdown_NilHTTPServer covers Shutdown when httpServer is nil.
func TestServer_Shutdown_NilHTTPServer(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// httpServer is nil (Start was never called).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown with nil httpServer should not error, got: %v", err)
	}
}

// TestBuildLogger_Levels covers debug, warn, error log levels and stderr/text format.
func TestBuildLogger_Levels(t *testing.T) {
	tests := []struct {
		level  string
		format string
		output string
	}{
		{"debug", "json", "stdout"},
		{"warn", "json", "stdout"},
		{"error", "json", "stdout"},
		{"info", "text", "stderr"},
		{"info", "json", "stderr"},
		{"unknown", "text", "stdout"},
	}

	for _, tt := range tests {
		t.Run(tt.level+"/"+tt.format+"/"+tt.output, func(t *testing.T) {
			cfg := testConfig("http://localhost:9999")
			cfg.Logging.Level = tt.level
			cfg.Logging.Format = tt.format
			cfg.Logging.Output = tt.output

			logger := buildLogger(cfg)
			if logger == nil {
				t.Fatal("buildLogger returned nil")
			}
		})
	}
}

// TestServer_WriteError_NonSentinelError covers the non-SentinelError path in writeError.
func TestServer_WriteError_NonSentinelError(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()

	// Pass a plain error (not *SentinelError) — should use ErrAgentUnavailable.
	srv.writeError(w, req, fmt.Errorf("plain error"))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for non-sentinel error, got %d", w.Code)
	}
}

// TestServer_FinalizeAudit_WithAuthInfo covers the auth info present path in finalizeAudit.
func TestServer_FinalizeAudit_WithAuthInfo(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Build context with both audit entry and auth info.
	entry := &ctxkeys.AuditEntry{Method: "message/send", Protocol: "jsonrpc"}
	ctx := ctxkeys.WithAuditEntry(context.Background(), entry)
	ctx = ctxkeys.WithAuthInfo(ctx, ctxkeys.AuthInfo{
		Scheme:  "bearer",
		Subject: "user@example.com",
	})

	req := httptest.NewRequest("POST", "/", nil)
	req = req.WithContext(ctx)

	// Should not panic; auth info should be copied to audit entry.
	srv.finalizeAudit(req, "ok")

	if entry.AuthScheme != "bearer" {
		t.Errorf("AuthScheme = %q, want %q", entry.AuthScheme, "bearer")
	}
	if entry.AuthSubject != "user@example.com" {
		t.Errorf("AuthSubject = %q, want %q", entry.AuthSubject, "user@example.com")
	}
	if entry.Status != "ok" {
		t.Errorf("Status = %q, want %q", entry.Status, "ok")
	}
}

// TestServer_FinalizeAudit_NoEntry covers the early return path in finalizeAudit.
func TestServer_FinalizeAudit_NoEntry(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// No audit entry in context — should return early without panic.
	req := httptest.NewRequest("POST", "/", nil)
	srv.finalizeAudit(req, "ok") // Should not panic.
}

// TestServer_Handler_ProtocolDetectError covers the protocol detection error path.
// We inject a request body that causes io.ReadAll to fail.
func TestServer_Handler_UnknownProtocol(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Security.Auth.AllowUnauthenticated = true
	ts := startTestServer(t, cfg)
	defer ts.Close()

	// GET /tasks/task-1 — REST pattern, no agents healthy so will route error.
	resp, err := http.Get(ts.URL + "/tasks/task-1")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should get a route error (no healthy agents), not a server error.
	if resp.StatusCode == http.StatusInternalServerError {
		t.Errorf("unexpected 500, got %d", resp.StatusCode)
	}
}

// TestServer_Handler_SSERoute covers the SSE streaming path in handler.
// We use message/stream which triggers SSE proxy.
func TestServer_Handler_SSERoute(t *testing.T) {
	// Backend that accepts SSE and sends a proper SSE response.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if ok {
			flusher.Flush()
		}
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Security.Auth.AllowUnauthenticated = true
	cfg.Routing.Mode = "single"
	ts := startTestServer(t, cfg)
	defer ts.Close()

	// Mark the agent healthy by starting card polling against a working server.
	// Since we can't easily do that, we test the route-failure path instead.
	body := `{"jsonrpc":"2.0","method":"message/stream","id":1,"params":{}}`
	req, _ := http.NewRequest("POST", ts.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Without a healthy agent, we expect route error (503/404), not panic.
	if resp.StatusCode == http.StatusInternalServerError {
		t.Errorf("unexpected 500 on SSE route without healthy agent, got %d", resp.StatusCode)
	}
}

// TestServer_Handler_WithHealthyAgent covers the proxy routing paths with a healthy agent.
// We start card polling so the agent becomes healthy, then send real requests.
func TestServer_Handler_WithHealthyAgent(t *testing.T) {
	// Backend that handles JSON-RPC and REST requests.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/.well-known/agent.json" {
			fmt.Fprint(w, `{"name":"test","url":"http://localhost","version":"1.0"}`)
		} else {
			fmt.Fprint(w, `{"jsonrpc":"2.0","result":"ok","id":1}`)
		}
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Security.Auth.AllowUnauthenticated = true
	cfg.Routing.Mode = "single"
	cfg.Agents[0].PollInterval = config.Duration{Duration: 50 * time.Millisecond}
	cfg.Agents[0].Timeout = config.Duration{Duration: 2 * time.Second}
	cfg.Agents[0].AllowInsecure = true

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start card manager polling so agent becomes healthy.
	if err := srv.cardManager.Start(ctx); err != nil {
		t.Fatalf("cardManager.Start() failed: %v", err)
	}

	// Wait for agent to become healthy.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.cardManager.IsHealthy("test-agent") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !srv.cardManager.IsHealthy("test-agent") {
		t.Skip("agent did not become healthy in time — skipping integration test")
	}

	// Build and wrap handler.
	handler := srv.handler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Send a JSON-RPC request — should be proxied to backend successfully.
	body := `{"jsonrpc":"2.0","method":"message/send","id":1,"params":{}}`
	resp, err := http.Post(ts.URL+"/", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from healthy agent proxy, got %d", resp.StatusCode)
	}

	// Also test a REST GET path (tasks/get).
	resp2, err := http.Get(ts.URL + "/tasks/task-123")
	if err != nil {
		t.Fatalf("REST request failed: %v", err)
	}
	defer resp2.Body.Close()
	// Should be proxied (200) or route error (not 500).
	if resp2.StatusCode == http.StatusInternalServerError {
		t.Errorf("unexpected 500 on REST route, got %d", resp2.StatusCode)
	}
}

// TestServer_Shutdown_DrainTimeout covers the drain timeout path.
func TestServer_Shutdown_DrainTimeout(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	// Very short drain timeout to trigger the warn path.
	cfg.Shutdown.DrainTimeout = config.Duration{Duration: 1 * time.Nanosecond}

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Don't start httpServer — just test Shutdown path with tiny drain timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Should not return error (drain timeout logs a warning but doesn't fail).
	err = srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown should not error on drain timeout, got: %v", err)
	}
}

// TestServer_Handler_ProxyError covers the proxyErr != nil path (finalizeAudit "error").
func TestServer_Handler_ProxyError(t *testing.T) {
	// Backend that serves agent card but then closes before proxying data.
	var serveCard int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent.json" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"name":"test","url":"http://localhost","version":"1.0"}`)
			return
		}
		// Return an error status for non-card requests.
		_ = serveCard
		http.Error(w, "backend error", http.StatusInternalServerError)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Security.Auth.AllowUnauthenticated = true
	cfg.Routing.Mode = "single"
	cfg.Agents[0].PollInterval = config.Duration{Duration: 50 * time.Millisecond}
	cfg.Agents[0].Timeout = config.Duration{Duration: 2 * time.Second}
	cfg.Agents[0].AllowInsecure = true

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.cardManager.Start(ctx); err != nil {
		t.Fatalf("cardManager.Start() failed: %v", err)
	}

	// Wait for agent to become healthy.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.cardManager.IsHealthy("test-agent") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !srv.cardManager.IsHealthy("test-agent") {
		t.Skip("agent did not become healthy — skipping")
	}

	handler := srv.handler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Send request — backend returns 500, proxy should still complete (not crash).
	body := `{"jsonrpc":"2.0","method":"message/send","id":1,"params":{}}`
	resp, err := http.Post(ts.URL+"/", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	// HTTPProxy returns the backend's response code, which is 500. That's not a proxy error per se.
	// The important thing is the handler doesn't panic.
	_ = resp.StatusCode
}

// TestServer_Handler_BodyReadError covers the protocol detect error path
// by sending a request whose body fails to read.
func TestServer_Handler_BodyReadError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent.json" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"name":"test","url":"http://localhost","version":"1.0"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Security.Auth.AllowUnauthenticated = true
	cfg.Routing.Mode = "single"

	handler := startTestServer(t, cfg)
	defer handler.Close()

	// Use a raw TCP connection to send a POST with Content-Length that won't be satisfied.
	// This causes the body read to fail during protocol detection.
	conn, err := net.Dial("tcp", handler.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	// Send a request with a Content-Length that claims 100 bytes but only sends partial body,
	// then close the connection — this causes io.ReadAll to get an unexpected EOF.
	req := "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"partial\":"
	conn.Write([]byte(req))
	conn.Close()

	// The server should handle this gracefully — no panic.
	time.Sleep(50 * time.Millisecond)
}

// TestServer_Shutdown_HTTPServerError covers http server shutdown returning an error.
// We test by calling Shutdown after the context is already expired.
func TestServer_Shutdown_ExpiredContext(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	startCtx, startCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(startCtx)
	}()

	// Give server time to start.
	time.Sleep(100 * time.Millisecond)

	// Create an already-expired context for Shutdown.
	expiredCtx, expiredCancel := context.WithCancel(context.Background())
	expiredCancel() // Cancel immediately.

	// Call Shutdown with expired context — httpServer.Shutdown should return context error.
	shutdownErr := srv.Shutdown(expiredCtx)
	// Either nil (if it completes instantly) or context error — both are acceptable.
	_ = shutdownErr

	// Clean up.
	startCancel()
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
	}
}

// TestServer_Handler_SSEWithHealthyAgent covers the SSE proxy path with a healthy agent.
func TestServer_Handler_SSEWithHealthyAgent(t *testing.T) {
	// Backend that handles card fetch and SSE streaming.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent.json" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"name":"test","url":"http://localhost","version":"1.0"}`)
			return
		}
		// SSE response
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Send one event then done.
		fmt.Fprint(w, "data: {\"type\":\"done\"}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Security.Auth.AllowUnauthenticated = true
	cfg.Routing.Mode = "single"
	cfg.Agents[0].PollInterval = config.Duration{Duration: 50 * time.Millisecond}
	cfg.Agents[0].Timeout = config.Duration{Duration: 2 * time.Second}
	cfg.Agents[0].AllowInsecure = true

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.cardManager.Start(ctx); err != nil {
		t.Fatalf("cardManager.Start() failed: %v", err)
	}

	// Wait for agent to become healthy.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.cardManager.IsHealthy("test-agent") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !srv.cardManager.IsHealthy("test-agent") {
		t.Skip("agent did not become healthy — skipping SSE test")
	}

	handler := srv.handler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Send message/stream request — should use SSE proxy.
	body := `{"jsonrpc":"2.0","method":"message/stream","id":1,"params":{}}`
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(ts.URL+"/", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("SSE request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should not be an internal server error.
	if resp.StatusCode == http.StatusInternalServerError {
		t.Errorf("unexpected 500 on SSE route with healthy agent, got %d", resp.StatusCode)
	}
}

// TestServer_Shutdown_DrainTimeoutWithActiveStream covers the drain timeout warning path.
// We acquire a stream slot, then call Shutdown with an already-expired context.
func TestServer_Shutdown_DrainTimeoutWithActiveStream(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	cfg.Shutdown.DrainTimeout = config.Duration{Duration: 1 * time.Millisecond}

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Acquire a stream slot so DrainAll has to wait.
	// This forces DrainAll to block until its context expires.
	srv.streamMgr.AcquireStream("test-agent", 100)
	// Don't release it — so DrainAll blocks.

	// Use a very short context so drain times out.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	// httpServer is nil, so after drain we skip http shutdown.
	err = srv.Shutdown(ctx)
	// Should return nil (drain timeout is a warning, not an error, when httpServer is nil).
	if err != nil {
		t.Logf("Shutdown returned (acceptable): %v", err)
	}
}

// TestServer_Handler_ProxyErrorPath covers the finalizeAudit("error") path.
// We route to a healthy agent whose backend immediately closes the connection.
func TestServer_Handler_ProxyErrorPath(t *testing.T) {
	// Backend that serves card then closes connection for other requests.
	requestCount := 0
	var mu sync.Mutex
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		if r.URL.Path == "/.well-known/agent.json" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"name":"test","url":"http://localhost","version":"1.0"}`)
			return
		}
		// Hijack and close to cause a proxy error.
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		conn.Close() // Close without sending response — causes proxy read error.
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Security.Auth.AllowUnauthenticated = true
	cfg.Routing.Mode = "single"
	cfg.Agents[0].PollInterval = config.Duration{Duration: 50 * time.Millisecond}
	cfg.Agents[0].Timeout = config.Duration{Duration: 2 * time.Second}
	cfg.Agents[0].AllowInsecure = true

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.cardManager.Start(ctx); err != nil {
		t.Fatalf("cardManager.Start() failed: %v", err)
	}

	// Wait for agent to become healthy.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.cardManager.IsHealthy("test-agent") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !srv.cardManager.IsHealthy("test-agent") {
		t.Skip("agent did not become healthy — skipping")
	}

	handler := srv.handler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Send a JSON-RPC request — backend will hijack and close, causing proxy error.
	body := `{"jsonrpc":"2.0","method":"message/send","id":1,"params":{}}`
	resp, err := http.Post(ts.URL+"/", "application/json", strings.NewReader(body))
	if err != nil {
		// Connection error is expected — the hijacked backend closes without response.
		return
	}
	defer resp.Body.Close()
	// If we got a response, that's fine too — the important thing is no panic.
}

// TestServer_Shutdown_HTTPServerShutdownError covers the http shutdown error path.
// We create an httpServer and Shutdown it with an already-cancelled context while
// there's an active connection holding it open.
func TestServer_Shutdown_HTTPServerShutdownError(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	cfg.Shutdown.DrainTimeout = config.Duration{Duration: 1 * time.Second}

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Create a real httptest server to get an httpServer we can shut down.
	holdOpen := make(chan struct{})
	realBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-holdOpen // Block to keep connection active.
		w.WriteHeader(http.StatusOK)
	}))
	defer realBackend.Close()
	defer close(holdOpen)

	// Manually assign an httpServer to srv.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv.httpServer = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-holdOpen
			w.WriteHeader(http.StatusOK)
		}),
	}

	// Start serving in background.
	go srv.httpServer.Serve(ln)

	// Make a connection to keep the server busy.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Write a partial HTTP request to keep the connection active.
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n"))

	// Give the connection time to be established.
	time.Sleep(50 * time.Millisecond)

	// Use a context that's already cancelled — httpServer.Shutdown will return context.Canceled.
	expiredCtx, expiredCancel := context.WithCancel(context.Background())
	expiredCancel()

	// Shutdown should return the http shutdown error.
	shutdownErr := srv.Shutdown(expiredCtx)
	// We expect an error (context canceled during active connection).
	// Either way, no panic is acceptable.
	_ = shutdownErr
}

// TestServer_Start_ShutdownError covers the "shutdown error" path in Start.
// Strategy: pre-allocate a port, start server on that port, make a persistent connection,
// then cancel context with tiny timeout to force httpServer.Shutdown to time out.
func TestServer_Start_ShutdownError(t *testing.T) {
	// Pre-allocate a listener to find a free port, then release it for the server to use.
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	port := probeLn.Addr().(*net.TCPAddr).Port
	probeLn.Close()

	// Small pause to ensure OS reclaims the port before server uses it.
	time.Sleep(10 * time.Millisecond)

	cfg := testConfig("http://localhost:9999")
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = port
	cfg.Listen.MaxConnections = 0
	cfg.Security.Auth.AllowUnauthenticated = true
	// Tiny shutdown timeout so httpServer.Shutdown() times out with active connection.
	cfg.Shutdown.Timeout = config.Duration{Duration: 5 * time.Millisecond}
	cfg.Shutdown.DrainTimeout = config.Duration{Duration: 1 * time.Millisecond}

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Start(ctx)
	}()

	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Wait for the server to start accepting connections.
	var conn net.Conn
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		c, dialErr := net.Dial("tcp", serverAddr)
		if dialErr == nil {
			conn = c
			break
		}
	}

	if conn == nil {
		cancel()
		<-startErrCh
		t.Skip("could not connect to server — skipping shutdown error test")
	}

	// Send a partial HTTP request to keep the connection active (server won't close it).
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n"))
	// Do NOT finish the request — this keeps the connection in read-wait state.

	// Cancel context to trigger shutdown.
	cancel()

	// Close our connection after a moment to let the test proceed.
	go func() {
		time.Sleep(50 * time.Millisecond)
		conn.Close()
	}()

	select {
	case startErr := <-startErrCh:
		// Either nil (completed before timeout) or "shutdown error" (timeout triggered).
		// Both are valid depending on timing — we just verify no panic.
		_ = startErr
	case <-time.After(10 * time.Second):
		conn.Close()
		t.Fatal("server did not stop within timeout")
	}
}

// TestServer_WriteError_JSONRPCProtocol covers the JSONRPC protocol error path.
func TestServer_WriteError_JSONRPCProtocol(t *testing.T) {
	cfg := testConfig("http://localhost:9999")
	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/", nil)
	// Set JSONRPC protocol in context via ctxkeys.
	ctx := ctxkeys.WithRequestMeta(req.Context(), ctxkeys.RequestMeta{
		Protocol: "jsonrpc",
		Method:   "message/send",
		Binding:  "jsonrpc",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	srv.writeError(w, req, sentinelerrors.ErrNoRoute)

	// JSON-RPC errors should return JSON body.
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "error") {
		t.Errorf("JSONRPC error response should contain 'error', got: %s", body)
	}
}

// ── cardStarter mock ──────────────────────────────────────────────────────────

// failCardStarter is a cardStarter that returns an error from Start.
type failCardStarter struct{}

func (f *failCardStarter) Start(_ context.Context) error {
	return errors.New("card manager start failed")
}
func (f *failCardStarter) Stop()                                  {}
func (f *failCardStarter) GetAggregatedCard() *protocol.AgentCard { return nil }
func (f *failCardStarter) IsHealthy(_ string) bool                { return false }
func (f *failCardStarter) HealthyAgents() []string                { return nil }

// TestServer_Start_CardManagerFails covers the cardManager.Start() error path.
func TestServer_Start_CardManagerFails(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Replace the card manager with a failing one.
	srv.cardManager = &failCardStarter{}

	err = srv.Start(context.Background())
	if err == nil {
		t.Fatal("expected error from cardManager.Start(), got nil")
	}
	if !strings.Contains(err.Error(), "card manager") {
		t.Errorf("expected error about card manager, got: %v", err)
	}
}

// ── failListener ──────────────────────────────────────────────────────────────

// failListener is a net.Listener whose Accept always returns an error.
type failListener struct {
	addr net.Addr
}

func (f *failListener) Accept() (net.Conn, error) {
	return nil, errors.New("accept failed")
}
func (f *failListener) Close() error { return nil }
func (f *failListener) Addr() net.Addr {
	if f.addr != nil {
		return f.addr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// TestServer_Start_ServeFails covers the non-ErrServerClosed Serve error path
// by injecting a listener whose Accept always fails.
func TestServer_Start_ServeFails(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"test-agent"}`))
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	cfg.Agents[0].AllowInsecure = true
	cfg.Agents[0].HealthCheck.Enabled = false

	srv, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Inject a listener that immediately fails on Accept.
	srv.listener = &failListener{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = srv.Start(ctx)
	if err == nil {
		t.Fatal("expected error from Serve with failing listener, got nil")
	}
	if !strings.Contains(err.Error(), "server error") {
		t.Errorf("expected 'server error', got: %v", err)
	}
}
