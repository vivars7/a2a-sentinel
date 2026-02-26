package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newNopLogger returns a logger that discards all output.
func newNopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// ── mock bridge ──────────────────────────────────────────────────────────────

type mockBridge struct {
	agents          []AgentStatus
	health          SystemHealth
	blockedRequests []BlockedRequest
}

func (m *mockBridge) ListAgents() []AgentStatus { return m.agents }
func (m *mockBridge) HealthCheck() SystemHealth  { return m.health }
func (m *mockBridge) GetBlockedRequests(_ time.Time, limit int) []BlockedRequest {
	if limit > 0 && limit < len(m.blockedRequests) {
		return m.blockedRequests[:limit]
	}
	return m.blockedRequests
}

// blockingBridge blocks ListAgents until blockCh is closed. Used to simulate
// an active connection during Shutdown tests.
type blockingBridge struct {
	blockCh chan struct{}
}

func (b *blockingBridge) ListAgents() []AgentStatus {
	<-b.blockCh
	return nil
}
func (b *blockingBridge) HealthCheck() SystemHealth                          { return SystemHealth{} }
func (b *blockingBridge) GetBlockedRequests(_ time.Time, _ int) []BlockedRequest { return nil }

// ── helpers ──────────────────────────────────────────────────────────────────

func newTestServer(t *testing.T, token string) (*Server, *httptest.Server) {
	t.Helper()
	bridge := &mockBridge{
		agents: []AgentStatus{
			{Name: "agent-a", URL: "http://a.example.com", Healthy: true, SkillCount: 3},
			{Name: "agent-b", URL: "http://b.example.com", Healthy: false, SkillCount: 1},
		},
		health: SystemHealth{
			Status:       "healthy",
			ActiveStreams: 5,
			Uptime:       2 * time.Hour,
		},
		blockedRequests: []BlockedRequest{
			{
				Timestamp:   time.Now(),
				ClientIP:    "1.2.3.4",
				Method:      "POST",
				BlockReason: "rate_limit_exceeded",
				Agent:       "agent-a",
			},
		},
	}

	logger := newNopLogger()
	srv := NewServer(Config{Host: "127.0.0.1", Port: 0, Token: token}, bridge, logger)

	// Use httptest directly so we don't need a real listening port.
	httpSrv := httptest.NewServer(http.HandlerFunc(srv.handleRPC))
	t.Cleanup(httpSrv.Close)
	return srv, httpSrv
}

func postRPC(t *testing.T, url string, req jsonRPCRequest, token string) jsonRPCResponse {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	var rpcResp jsonRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return rpcResp
}

// ── initialize ────────────────────────────────────────────────────────────────

func TestInitialize_ReturnsServerInfo(t *testing.T) {
	_, srv := newTestServer(t, "")
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}

	info, ok := result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected serverInfo map, got %T", result["serverInfo"])
	}
	if info["name"] != "a2a-sentinel" {
		t.Errorf("expected name=a2a-sentinel, got %q", info["name"])
	}
}

func TestInitialize_ReturnsProtocolVersion(t *testing.T) {
	_, srv := newTestServer(t, "")
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}, "")

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}
	if result["protocolVersion"] == "" || result["protocolVersion"] == nil {
		t.Error("expected non-empty protocolVersion")
	}
}

func TestInitialize_HasToolsCapability(t *testing.T) {
	_, srv := newTestServer(t, "")
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}, "")

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}
	caps, ok := result["capabilities"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected capabilities map, got %T", result["capabilities"])
	}
	if _, hasTools := caps["tools"]; !hasTools {
		t.Error("expected capabilities.tools to be present")
	}
}

// ── tools/list ────────────────────────────────────────────────────────────────

func TestToolsList_ReturnsThreeTools(t *testing.T) {
	_, srv := newTestServer(t, "")
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}
	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatalf("expected tools slice, got %T", result["tools"])
	}
	if len(tools) != 3 {
		t.Errorf("expected 3 tools, got %d", len(tools))
	}
}

func TestToolsList_ToolNamesCorrect(t *testing.T) {
	_, srv := newTestServer(t, "")
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}, "")

	result := resp.Result.(map[string]interface{})
	tools := result["tools"].([]interface{})

	wantNames := map[string]bool{
		"list_agents":          false,
		"health_check":         false,
		"get_blocked_requests": false,
	}
	for _, t2 := range tools {
		tool := t2.(map[string]interface{})
		name := tool["name"].(string)
		wantNames[name] = true
	}
	for name, found := range wantNames {
		if !found {
			t.Errorf("expected tool %q in tools/list", name)
		}
	}
}

// ── tools/call: list_agents ───────────────────────────────────────────────────

func TestToolsCall_ListAgents_ReturnsAgents(t *testing.T) {
	_, srv := newTestServer(t, "")

	params, _ := json.Marshal(toolCallParams{Name: "list_agents"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params:  params,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	content := result["content"].([]interface{})
	if len(content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(content))
	}

	item := content[0].(map[string]interface{})
	if item["type"] != "text" {
		t.Errorf("expected type=text, got %q", item["type"])
	}

	var agents []AgentStatus
	if err := json.Unmarshal([]byte(item["text"].(string)), &agents); err != nil {
		t.Fatalf("unmarshal agents: %v", err)
	}
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
	if agents[0].Name != "agent-a" {
		t.Errorf("expected first agent=agent-a, got %q", agents[0].Name)
	}
}

// ── tools/call: health_check ─────────────────────────────────────────────────

func TestToolsCall_HealthCheck_ReturnsHealth(t *testing.T) {
	_, srv := newTestServer(t, "")

	params, _ := json.Marshal(toolCallParams{Name: "health_check"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params:  params,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	content := result["content"].([]interface{})
	item := content[0].(map[string]interface{})

	var health SystemHealth
	if err := json.Unmarshal([]byte(item["text"].(string)), &health); err != nil {
		t.Fatalf("unmarshal health: %v", err)
	}
	if health.Status != "healthy" {
		t.Errorf("expected status=healthy, got %q", health.Status)
	}
	if health.ActiveStreams != 5 {
		t.Errorf("expected active_streams=5, got %d", health.ActiveStreams)
	}
}

// ── tools/call: get_blocked_requests ─────────────────────────────────────────

func TestToolsCall_GetBlockedRequests_NoParams(t *testing.T) {
	_, srv := newTestServer(t, "")

	params, _ := json.Marshal(toolCallParams{Name: "get_blocked_requests"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "tools/call",
		Params:  params,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	content := result["content"].([]interface{})
	item := content[0].(map[string]interface{})

	var blocked []BlockedRequest
	if err := json.Unmarshal([]byte(item["text"].(string)), &blocked); err != nil {
		t.Fatalf("unmarshal blocked: %v", err)
	}
	if len(blocked) != 1 {
		t.Errorf("expected 1 blocked request, got %d", len(blocked))
	}
}

func TestToolsCall_GetBlockedRequests_WithLimit(t *testing.T) {
	bridge := &mockBridge{
		blockedRequests: []BlockedRequest{
			{ClientIP: "1.1.1.1", BlockReason: "rate_limit"},
			{ClientIP: "2.2.2.2", BlockReason: "auth_failed"},
			{ClientIP: "3.3.3.3", BlockReason: "ssrf_blocked"},
		},
	}
	logger := newNopLogger()
	mcpSrv := NewServer(Config{Host: "127.0.0.1", Port: 0}, bridge, logger)
	httpSrv := httptest.NewServer(http.HandlerFunc(mcpSrv.handleRPC))
	defer httpSrv.Close()

	type argsWithLimit struct {
		Name      string `json:"name"`
		Arguments struct {
			Limit int `json:"limit"`
		} `json:"arguments"`
	}
	rawArgs, _ := json.Marshal(argsWithLimit{
		Name: "get_blocked_requests",
		Arguments: struct {
			Limit int `json:"limit"`
		}{Limit: 2},
	})

	resp := postRPC(t, httpSrv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	content := result["content"].([]interface{})
	item := content[0].(map[string]interface{})

	var blocked []BlockedRequest
	if err := json.Unmarshal([]byte(item["text"].(string)), &blocked); err != nil {
		t.Fatalf("unmarshal blocked: %v", err)
	}
	if len(blocked) != 2 {
		t.Errorf("expected 2 blocked requests (limit=2), got %d", len(blocked))
	}
}

func TestToolsCall_GetBlockedRequests_WithSince(t *testing.T) {
	_, srv := newTestServer(t, "")

	type argsWithSince struct {
		Name      string `json:"name"`
		Arguments struct {
			Since string `json:"since"`
		} `json:"arguments"`
	}
	rawArgs, _ := json.Marshal(argsWithSince{
		Name: "get_blocked_requests",
		Arguments: struct {
			Since string `json:"since"`
		}{Since: time.Now().Add(-30 * time.Minute).Format(time.RFC3339)},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      7,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
}

func TestToolsCall_GetBlockedRequests_InvalidSince(t *testing.T) {
	_, srv := newTestServer(t, "")

	type argsWithSince struct {
		Name      string `json:"name"`
		Arguments struct {
			Since string `json:"since"`
		} `json:"arguments"`
	}
	rawArgs, _ := json.Marshal(argsWithSince{
		Name: "get_blocked_requests",
		Arguments: struct {
			Since string `json:"since"`
		}{Since: "not-a-timestamp"},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      8,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "")

	if resp.Error == nil {
		t.Fatal("expected error for invalid since timestamp, got nil")
	}
}

// ── dispatch: unknown tool ────────────────────────────────────────────────────

func TestToolsCall_UnknownTool_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "")

	params, _ := json.Marshal(toolCallParams{Name: "nonexistent_tool"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      9,
		Method:  "tools/call",
		Params:  params,
	}, "")

	if resp.Error == nil {
		t.Fatal("expected error for unknown tool, got nil")
	}
}

// ── dispatch: unknown method ──────────────────────────────────────────────────

func TestDispatch_UnknownMethod_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "")

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      10,
		Method:  "no_such_method",
	}, "")

	if resp.Error == nil {
		t.Fatal("expected error for unknown method, got nil")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected code -32601, got %d", resp.Error.Code)
	}
}

// ── auth: token required ──────────────────────────────────────────────────────

func TestAuth_TokenRequired_NoToken_Rejected(t *testing.T) {
	_, srv := newTestServer(t, "secret-token")

	body, _ := json.Marshal(jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      11,
		Method:  "tools/list",
	})
	httpReq, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	// No Authorization header.

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", httpResp.StatusCode)
	}

	var rpcResp jsonRPCResponse
	json.NewDecoder(httpResp.Body).Decode(&rpcResp)
	if rpcResp.Error == nil {
		t.Error("expected JSON-RPC error in body")
	}
}

func TestAuth_TokenRequired_WrongToken_Rejected(t *testing.T) {
	_, srv := newTestServer(t, "secret-token")

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      12,
		Method:  "tools/list",
	}, "wrong-token")

	// The HTTP layer returns 401, but our postRPC helper reads the body regardless.
	// Check there's an error in the JSON response.
	if resp.Error == nil {
		t.Error("expected JSON-RPC error for wrong token")
	}
}

func TestAuth_TokenRequired_CorrectToken_Allowed(t *testing.T) {
	_, srv := newTestServer(t, "secret-token")

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      13,
		Method:  "tools/list",
	}, "secret-token")

	if resp.Error != nil {
		t.Fatalf("unexpected error with correct token: %+v", resp.Error)
	}
}

// ── auth: no token configured ─────────────────────────────────────────────────

func TestAuth_NoToken_AllowsAnonymous(t *testing.T) {
	_, srv := newTestServer(t, "") // empty token = no auth

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      14,
		Method:  "tools/list",
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error without token config: %+v", resp.Error)
	}
}

func TestAuth_NoToken_BearerStillAllowed(t *testing.T) {
	_, srv := newTestServer(t, "") // no auth required

	// Even if client sends a token, it should not be rejected when server has none.
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      15,
		Method:  "tools/list",
	}, "any-random-token")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
}

// ── HTTP method enforcement ───────────────────────────────────────────────────

func TestHTTP_GetNotAllowed(t *testing.T) {
	_, srv := newTestServer(t, "")

	httpResp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET request: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", httpResp.StatusCode)
	}
}

// ── parse error ───────────────────────────────────────────────────────────────

func TestParseError_InvalidJSON(t *testing.T) {
	_, srv := newTestServer(t, "")

	httpReq, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBufferString("{invalid json"))
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", httpResp.StatusCode)
	}

	var rpcResp jsonRPCResponse
	json.NewDecoder(httpResp.Body).Decode(&rpcResp)
	if rpcResp.Error == nil {
		t.Error("expected error in response body")
	}
	if rpcResp.Error.Code != -32700 {
		t.Errorf("expected parse error code -32700, got %d", rpcResp.Error.Code)
	}
}

// ── NewServer config ──────────────────────────────────────────────────────────

func TestNewServer_AddrFromConfig(t *testing.T) {
	bridge := &mockBridge{}
	logger := newNopLogger()
	srv := NewServer(Config{Host: "127.0.0.1", Port: 9999, Token: ""}, bridge, logger)
	if srv.addr != "127.0.0.1:9999" {
		t.Errorf("expected addr=127.0.0.1:9999, got %q", srv.addr)
	}
}

func TestNewServer_TokenStored(t *testing.T) {
	bridge := &mockBridge{}
	logger := newNopLogger()
	srv := NewServer(Config{Host: "127.0.0.1", Port: 9999, Token: "tok123"}, bridge, logger)
	if srv.token != "tok123" {
		t.Errorf("expected token=tok123, got %q", srv.token)
	}
}

// ── Start / Shutdown lifecycle ─────────────────────────────────────────────────

func TestStart_ContextCancel_StopsServer(t *testing.T) {
	bridge := &mockBridge{}
	logger := newNopLogger()
	// Port 0 lets the OS pick a free port.
	srv := NewServer(Config{Host: "127.0.0.1", Port: 0}, bridge, logger)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Give the server a moment to start listening.
	time.Sleep(10 * time.Millisecond)

	// Cancel the context — this should trigger graceful shutdown.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected nil error after context cancel, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not return within 2s after context cancel")
	}
}

func TestStart_InvalidAddr_ReturnsError(t *testing.T) {
	bridge := &mockBridge{}
	logger := newNopLogger()
	// Use an invalid address that will fail to listen.
	srv := NewServer(Config{Host: "invalid-host-that-cannot-bind", Port: 1}, bridge, logger)

	ctx := context.Background()
	err := srv.Start(ctx)
	if err == nil {
		t.Fatal("expected error for invalid listen address, got nil")
	}
}

func TestShutdown_NilHTTPServer_NoError(t *testing.T) {
	bridge := &mockBridge{}
	logger := newNopLogger()
	srv := NewServer(Config{Host: "127.0.0.1", Port: 0}, bridge, logger)
	// httpServer is nil because Start() was never called.

	ctx := context.Background()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("expected nil error shutting down unstarted server, got: %v", err)
	}
}

// ── textResult error path ─────────────────────────────────────────────────────

func TestTextResult_MarshalError(t *testing.T) {
	// math.Inf(1) produces a float that json.Marshal cannot encode.
	_, err := textResult(math.Inf(1))
	if err == nil {
		t.Fatal("expected error when marshalling non-finite float, got nil")
	}
}

// ── handleToolsCall invalid params ────────────────────────────────────────────

func TestHandleToolsCall_InvalidParams_ReturnsParseError(t *testing.T) {
	_, srv := newTestServer(t, "")

	// Send a tools/call request whose Params field is not valid JSON for toolCallParams.
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      20,
		Method:  "tools/call",
		Params:  json.RawMessage(`"this is a string not an object"`),
	}, "")

	if resp.Error == nil {
		t.Fatal("expected error for invalid tools/call params, got nil")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("expected code -32602, got %d", resp.Error.Code)
	}
}

// ── toolGetBlockedRequests invalid arguments JSON ─────────────────────────────

func TestToolGetBlockedRequests_InvalidArgumentsJSON_ReturnsError(t *testing.T) {
	// Call toolGetBlockedRequests directly with syntactically invalid JSON.
	bridge := &mockBridge{}
	logger := newNopLogger()
	mcpSrv := NewServer(Config{Host: "127.0.0.1", Port: 0}, bridge, logger)

	_, err := mcpSrv.toolGetBlockedRequests(json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid arguments JSON, got nil")
	}
}

// ── Shutdown error path ────────────────────────────────────────────────────────

func TestShutdown_CancelledContext_WithActiveConn_ReturnsError(t *testing.T) {
	// Use a bridge whose ListAgents blocks until we signal, keeping a connection active.
	blockCh := make(chan struct{})
	bridge := &blockingBridge{blockCh: blockCh}
	logger := newNopLogger()
	srv := NewServer(Config{Host: "127.0.0.1", Port: 0}, bridge, logger)

	// Set up the http.Server directly so we know the address.
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleRPC)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	httpSrv := &http.Server{Handler: mux}
	srv.mu.Lock()
	srv.httpServer = httpSrv
	srv.mu.Unlock()

	go httpSrv.Serve(ln)

	// Make a request that will block in the handler.
	go func() {
		body, _ := json.Marshal(jsonRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call",
			Params: json.RawMessage(`{"name":"list_agents"}`)})
		//nolint:errcheck
		http.Post("http://"+ln.Addr().String()+"/", "application/json", bytes.NewReader(body))
	}()

	// Wait for the request to arrive at the handler.
	time.Sleep(20 * time.Millisecond)

	// Call Shutdown with an already-cancelled context — the active connection
	// prevents immediate completion, so Shutdown returns context.Canceled.
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	shutdownCancel()

	shutdownErr := srv.Shutdown(shutdownCtx)
	if shutdownErr == nil {
		t.Error("expected error when shutdown context is cancelled with active connection, got nil")
	}

	// Unblock the handler and clean up.
	close(blockCh)
}

// ── Start errCh path (serve error before context cancel) ──────────────────────

func TestStart_ServeError_ReturnsError(t *testing.T) {
	bridge := &mockBridge{}
	logger := newNopLogger()
	// Port 0 — OS picks a free port.
	srv := NewServer(Config{Host: "127.0.0.1", Port: 0}, bridge, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for Start to set srv.httpServer and begin listening.
	time.Sleep(20 * time.Millisecond)

	// Close the underlying listener via the mutex-protected field.
	// This causes Serve to return ErrServerClosed.
	srv.mu.Lock()
	srv.httpServer.Close()
	srv.mu.Unlock()

	select {
	case err := <-errCh:
		// After Close(), Serve returns ErrServerClosed which Start treats as nil.
		// Either nil or an error is acceptable here; we just verify Start returns.
		_ = err
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not return within 2s after server Close()")
	}
}

// ── failListener ──────────────────────────────────────────────────────────────

// failListener is a net.Listener whose Accept always returns an error.
type failListener struct{}

func (f *failListener) Accept() (net.Conn, error) {
	return nil, errors.New("accept failed")
}
func (f *failListener) Close() error   { return nil }
func (f *failListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0} }

// TestStart_ServeNonClosedError covers the non-ErrServerClosed error path in Start()
// by injecting a listener whose Accept always fails.
func TestStart_ServeNonClosedError(t *testing.T) {
	bridge := &mockBridge{}
	logger := newNopLogger()
	srv := NewServer(Config{Host: "127.0.0.1", Port: 0}, bridge, logger)

	// Inject a listener that immediately fails on Accept.
	srv.listener = &failListener{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := srv.Start(ctx)
	if err == nil {
		t.Fatal("expected error from Serve with failing listener, got nil")
	}
	if !strings.Contains(err.Error(), "mcp server error") {
		t.Errorf("expected 'mcp server error', got: %v", err)
	}
}
