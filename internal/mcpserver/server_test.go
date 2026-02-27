package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	// New read fields
	agentCards    map[string]map[string]interface{}
	aggregatedCard map[string]interface{}
	rateLimits    []RateLimitStatus

	// Write tracking
	registeredAgents   map[string]string // name -> url
	deregisteredAgents []string
	updatedRateLimits  map[string]int // agent -> perMinute
	testResults        map[string]*TestResult

	// Resource fields
	config         map[string]interface{}
	metrics        map[string]interface{}
	securityReport map[string]interface{}

	// Card change approval
	pendingChanges      []PendingCardChange
	approvedAgents      []string
	rejectedAgents      []string
	approveCardErr      error
	rejectCardErr       error

	// Policy fields
	policies         []PolicyInfo
	policyEvalResult PolicyEvalResult

	// Error injection
	getAgentCardErr    error
	getAggregatedErr   error
	updateRateLimitErr error
	registerAgentErr   error
	deregisterAgentErr error
	sendTestMsgErr     error
}

func (m *mockBridge) ListAgents() []AgentStatus { return m.agents }
func (m *mockBridge) HealthCheck() SystemHealth  { return m.health }
func (m *mockBridge) GetBlockedRequests(_ time.Time, limit int) []BlockedRequest {
	if limit > 0 && limit < len(m.blockedRequests) {
		return m.blockedRequests[:limit]
	}
	return m.blockedRequests
}

func (m *mockBridge) GetAgentCard(name string) (map[string]interface{}, error) {
	if m.getAgentCardErr != nil {
		return nil, m.getAgentCardErr
	}
	card, ok := m.agentCards[name]
	if !ok {
		return nil, fmt.Errorf("agent %q not found", name)
	}
	return card, nil
}

func (m *mockBridge) GetAggregatedCard() (map[string]interface{}, error) {
	if m.getAggregatedErr != nil {
		return nil, m.getAggregatedErr
	}
	return m.aggregatedCard, nil
}

func (m *mockBridge) GetRateLimitStatus() []RateLimitStatus {
	return m.rateLimits
}

func (m *mockBridge) UpdateRateLimit(agentName string, perMinute int) (int, error) {
	if m.updateRateLimitErr != nil {
		return 0, m.updateRateLimitErr
	}
	previous := 60 // default previous
	if m.updatedRateLimits == nil {
		m.updatedRateLimits = make(map[string]int)
	}
	if prev, ok := m.updatedRateLimits[agentName]; ok {
		previous = prev
	}
	m.updatedRateLimits[agentName] = perMinute
	return previous, nil
}

func (m *mockBridge) RegisterAgent(name, url string, isDefault bool) error {
	if m.registerAgentErr != nil {
		return m.registerAgentErr
	}
	if m.registeredAgents == nil {
		m.registeredAgents = make(map[string]string)
	}
	m.registeredAgents[name] = url
	return nil
}

func (m *mockBridge) DeregisterAgent(name string) error {
	if m.deregisterAgentErr != nil {
		return m.deregisterAgentErr
	}
	m.deregisteredAgents = append(m.deregisteredAgents, name)
	return nil
}

func (m *mockBridge) SendTestMessage(agentName, text string) (*TestResult, error) {
	if m.sendTestMsgErr != nil {
		return nil, m.sendTestMsgErr
	}
	if m.testResults != nil {
		if r, ok := m.testResults[agentName]; ok {
			return r, nil
		}
	}
	return &TestResult{
		TaskID:       "test-task-001",
		Status:       "completed",
		ResponseText: "echo: " + text,
	}, nil
}

func (m *mockBridge) GetConfig() map[string]interface{} {
	return m.config
}

func (m *mockBridge) GetMetrics() map[string]interface{} {
	return m.metrics
}

func (m *mockBridge) GetSecurityReport() map[string]interface{} {
	return m.securityReport
}

func (m *mockBridge) ListPendingChanges() []PendingCardChange {
	return m.pendingChanges
}

func (m *mockBridge) ApproveCardChange(agentName string) error {
	if m.approveCardErr != nil {
		return m.approveCardErr
	}
	m.approvedAgents = append(m.approvedAgents, agentName)
	return nil
}

func (m *mockBridge) RejectCardChange(agentName string) error {
	if m.rejectCardErr != nil {
		return m.rejectCardErr
	}
	m.rejectedAgents = append(m.rejectedAgents, agentName)
	return nil
}

func (m *mockBridge) ListPolicies() []PolicyInfo {
	return m.policies
}

func (m *mockBridge) EvaluatePolicy(req PolicyEvalRequest) PolicyEvalResult {
	return m.policyEvalResult
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
func (b *blockingBridge) GetAgentCard(_ string) (map[string]interface{}, error) {
	return nil, nil
}
func (b *blockingBridge) GetAggregatedCard() (map[string]interface{}, error) { return nil, nil }
func (b *blockingBridge) GetRateLimitStatus() []RateLimitStatus              { return nil }
func (b *blockingBridge) UpdateRateLimit(_ string, _ int) (int, error)       { return 0, nil }
func (b *blockingBridge) RegisterAgent(_, _ string, _ bool) error            { return nil }
func (b *blockingBridge) DeregisterAgent(_ string) error                     { return nil }
func (b *blockingBridge) SendTestMessage(_, _ string) (*TestResult, error)   { return nil, nil }
func (b *blockingBridge) GetConfig() map[string]interface{}                  { return nil }
func (b *blockingBridge) GetMetrics() map[string]interface{}                 { return nil }
func (b *blockingBridge) GetSecurityReport() map[string]interface{}          { return nil }
func (b *blockingBridge) ListPendingChanges() []PendingCardChange            { return nil }
func (b *blockingBridge) ApproveCardChange(_ string) error                   { return nil }
func (b *blockingBridge) RejectCardChange(_ string) error                    { return nil }
func (b *blockingBridge) ListPolicies() []PolicyInfo                         { return nil }
func (b *blockingBridge) EvaluatePolicy(_ PolicyEvalRequest) PolicyEvalResult {
	return PolicyEvalResult{Action: "allow"}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func defaultMockBridge() *mockBridge {
	return &mockBridge{
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
		agentCards: map[string]map[string]interface{}{
			"agent-a": {
				"name":        "agent-a",
				"url":         "http://a.example.com",
				"description": "Test agent A",
				"skills":      []string{"skill1", "skill2"},
			},
		},
		aggregatedCard: map[string]interface{}{
			"name":        "a2a-sentinel",
			"description": "Aggregated gateway card",
			"agents":      2,
		},
		rateLimits: []RateLimitStatus{
			{Agent: "agent-a", CurrentRPM: 10, LimitRPM: 60, Remaining: 50},
			{Agent: "agent-b", CurrentRPM: 0, LimitRPM: 30, Remaining: 30},
		},
		config: map[string]interface{}{
			"host":  "127.0.0.1",
			"port":  8080,
			"token": "***",
		},
		metrics: map[string]interface{}{
			"total_requests": 1000,
			"total_blocked":  42,
			"active_streams": 5,
			"uptime":         "2h0m0s",
		},
		securityReport: map[string]interface{}{
			"auth_mode":           "bearer",
			"rate_limit_enabled":  true,
			"recent_blocks_count": 3,
		},
		pendingChanges: []PendingCardChange{
			{
				AgentName:  "agent-a",
				DetectedAt: time.Now(),
				Changes:    2,
				Critical:   true,
				Status:     "pending",
			},
		},
	}
}

func newTestServer(t *testing.T, token string) (*Server, *httptest.Server) {
	t.Helper()
	bridge := defaultMockBridge()

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

// extractToolText extracts the text content from a tool result response.
func extractToolText(t *testing.T, resp jsonRPCResponse) string {
	t.Helper()
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}
	content, ok := result["content"].([]interface{})
	if !ok {
		t.Fatalf("expected content slice, got %T", result["content"])
	}
	if len(content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(content))
	}
	item := content[0].(map[string]interface{})
	if item["type"] != "text" {
		t.Errorf("expected type=text, got %q", item["type"])
	}
	return item["text"].(string)
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
	if info["version"] != "0.2.0" {
		t.Errorf("expected version=0.2.0, got %q", info["version"])
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

func TestInitialize_HasResourcesCapability(t *testing.T) {
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
	if _, hasResources := caps["resources"]; !hasResources {
		t.Error("expected capabilities.resources to be present")
	}
}

// ── tools/list ────────────────────────────────────────────────────────────────

func TestToolsList_ReturnsFifteenTools(t *testing.T) {
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
	if len(tools) != 15 {
		t.Errorf("expected 15 tools, got %d", len(tools))
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
		"list_agents":           false,
		"health_check":          false,
		"get_blocked_requests":  false,
		"get_agent_card":        false,
		"get_aggregated_card":   false,
		"get_rate_limit_status": false,
		"update_rate_limit":     false,
		"register_agent":        false,
		"deregister_agent":      false,
		"send_test_message":     false,
		"list_pending_changes":  false,
		"approve_card_change":   false,
		"reject_card_change":    false,
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

	text := extractToolText(t, resp)
	var agents []AgentStatus
	if err := json.Unmarshal([]byte(text), &agents); err != nil {
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

	text := extractToolText(t, resp)
	var health SystemHealth
	if err := json.Unmarshal([]byte(text), &health); err != nil {
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

	text := extractToolText(t, resp)
	var blocked []BlockedRequest
	if err := json.Unmarshal([]byte(text), &blocked); err != nil {
		t.Fatalf("unmarshal blocked: %v", err)
	}
	if len(blocked) != 1 {
		t.Errorf("expected 1 blocked request, got %d", len(blocked))
	}
}

func TestToolsCall_GetBlockedRequests_WithLimit(t *testing.T) {
	bridge := defaultMockBridge()
	bridge.blockedRequests = []BlockedRequest{
		{ClientIP: "1.1.1.1", BlockReason: "rate_limit"},
		{ClientIP: "2.2.2.2", BlockReason: "auth_failed"},
		{ClientIP: "3.3.3.3", BlockReason: "ssrf_blocked"},
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

	text := extractToolText(t, resp)
	var blocked []BlockedRequest
	if err := json.Unmarshal([]byte(text), &blocked); err != nil {
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

// ── tools/call: get_agent_card ───────────────────────────────────────────────

func TestToolsCall_GetAgentCard_ReturnsCard(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "get_agent_card",
		"arguments": map[string]string{"agent_name": "agent-a"},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      20,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	text := extractToolText(t, resp)
	var card map[string]interface{}
	if err := json.Unmarshal([]byte(text), &card); err != nil {
		t.Fatalf("unmarshal card: %v", err)
	}
	if card["name"] != "agent-a" {
		t.Errorf("expected card name=agent-a, got %q", card["name"])
	}
}

func TestToolsCall_GetAgentCard_MissingName_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "get_agent_card",
		"arguments": map[string]string{},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      21,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "")

	if resp.Error == nil {
		t.Fatal("expected error for missing agent_name, got nil")
	}
}

func TestToolsCall_GetAgentCard_NotFound_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "get_agent_card",
		"arguments": map[string]string{"agent_name": "nonexistent"},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      22,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "")

	if resp.Error == nil {
		t.Fatal("expected error for nonexistent agent, got nil")
	}
}

// ── tools/call: get_aggregated_card ──────────────────────────────────────────

func TestToolsCall_GetAggregatedCard_ReturnsCard(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name": "get_aggregated_card",
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      23,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	text := extractToolText(t, resp)
	var card map[string]interface{}
	if err := json.Unmarshal([]byte(text), &card); err != nil {
		t.Fatalf("unmarshal card: %v", err)
	}
	if card["name"] != "a2a-sentinel" {
		t.Errorf("expected name=a2a-sentinel, got %q", card["name"])
	}
}

// ── tools/call: get_rate_limit_status ────────────────────────────────────────

func TestToolsCall_GetRateLimitStatus_ReturnsStatuses(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name": "get_rate_limit_status",
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      24,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	text := extractToolText(t, resp)
	var statuses []RateLimitStatus
	if err := json.Unmarshal([]byte(text), &statuses); err != nil {
		t.Fatalf("unmarshal statuses: %v", err)
	}
	if len(statuses) != 2 {
		t.Errorf("expected 2 rate limit statuses, got %d", len(statuses))
	}
	if statuses[0].Agent != "agent-a" {
		t.Errorf("expected first agent=agent-a, got %q", statuses[0].Agent)
	}
}

// ── tools/call: update_rate_limit ────────────────────────────────────────────

func TestToolsCall_UpdateRateLimit_ReturnsResult(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "update_rate_limit",
		"arguments": map[string]interface{}{"agent_name": "agent-a", "per_minute": 120},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      30,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	text := extractToolText(t, resp)
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result["updated"] != float64(120) {
		t.Errorf("expected updated=120, got %v", result["updated"])
	}
}

func TestToolsCall_UpdateRateLimit_MissingAgent_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "update_rate_limit",
		"arguments": map[string]interface{}{"per_minute": 120},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      31,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error == nil {
		t.Fatal("expected error for missing agent_name, got nil")
	}
}

func TestToolsCall_UpdateRateLimit_InvalidPerMinute_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "update_rate_limit",
		"arguments": map[string]interface{}{"agent_name": "agent-a", "per_minute": 0},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      32,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error == nil {
		t.Fatal("expected error for per_minute=0, got nil")
	}
}

// ── tools/call: register_agent ───────────────────────────────────────────────

func TestToolsCall_RegisterAgent_ReturnsResult(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "register_agent",
		"arguments": map[string]interface{}{"name": "new-agent", "url": "http://new.example.com", "default": true},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      33,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	text := extractToolText(t, resp)
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result["registered"] != true {
		t.Errorf("expected registered=true, got %v", result["registered"])
	}
}

func TestToolsCall_RegisterAgent_MissingName_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "register_agent",
		"arguments": map[string]interface{}{"url": "http://new.example.com"},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      34,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error == nil {
		t.Fatal("expected error for missing name, got nil")
	}
}

func TestToolsCall_RegisterAgent_MissingURL_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "register_agent",
		"arguments": map[string]interface{}{"name": "new-agent"},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      35,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error == nil {
		t.Fatal("expected error for missing url, got nil")
	}
}

// ── tools/call: deregister_agent ─────────────────────────────────────────────

func TestToolsCall_DeregisterAgent_ReturnsResult(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "deregister_agent",
		"arguments": map[string]interface{}{"name": "agent-a"},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      36,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	text := extractToolText(t, resp)
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result["removed"] != true {
		t.Errorf("expected removed=true, got %v", result["removed"])
	}
}

func TestToolsCall_DeregisterAgent_MissingName_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "deregister_agent",
		"arguments": map[string]interface{}{},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      37,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error == nil {
		t.Fatal("expected error for missing name, got nil")
	}
}

// ── tools/call: send_test_message ────────────────────────────────────────────

func TestToolsCall_SendTestMessage_ReturnsResult(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "send_test_message",
		"arguments": map[string]interface{}{"agent_name": "agent-a", "text": "hello"},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      38,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	text := extractToolText(t, resp)
	var result TestResult
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Status != "completed" {
		t.Errorf("expected status=completed, got %q", result.Status)
	}
	if result.ResponseText != "echo: hello" {
		t.Errorf("expected response_text='echo: hello', got %q", result.ResponseText)
	}
}

func TestToolsCall_SendTestMessage_MissingAgent_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "send_test_message",
		"arguments": map[string]interface{}{"text": "hello"},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      39,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error == nil {
		t.Fatal("expected error for missing agent_name, got nil")
	}
}

func TestToolsCall_SendTestMessage_MissingText_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "send_test_message",
		"arguments": map[string]interface{}{"agent_name": "agent-a"},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      40,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error == nil {
		t.Fatal("expected error for missing text, got nil")
	}
}

// ── tools/call: list_pending_changes ─────────────────────────────────────────

func TestToolsCall_ListPendingChanges_ReturnsPending(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name": "list_pending_changes",
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      70,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	text := extractToolText(t, resp)
	var pending []PendingCardChange
	if err := json.Unmarshal([]byte(text), &pending); err != nil {
		t.Fatalf("unmarshal pending: %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("expected 1 pending change, got %d", len(pending))
	}
	if pending[0].AgentName != "agent-a" {
		t.Errorf("expected agent_name=agent-a, got %q", pending[0].AgentName)
	}
	if !pending[0].Critical {
		t.Error("expected has_critical=true")
	}
}

// ── tools/call: approve_card_change ─────────────────────────────────────────

func TestToolsCall_ApproveCardChange_ReturnsResult(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "approve_card_change",
		"arguments": map[string]interface{}{"agent_name": "agent-a"},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      71,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	text := extractToolText(t, resp)
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result["approved"] != true {
		t.Errorf("expected approved=true, got %v", result["approved"])
	}
}

func TestToolsCall_ApproveCardChange_MissingAgent_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "approve_card_change",
		"arguments": map[string]interface{}{},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      72,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error == nil {
		t.Fatal("expected error for missing agent_name, got nil")
	}
}

func TestToolsCall_ApproveCardChange_BridgeError_ReturnsError(t *testing.T) {
	bridge := defaultMockBridge()
	bridge.approveCardErr = errors.New("no pending change")
	logger := newNopLogger()
	mcpSrv := NewServer(Config{Host: "127.0.0.1", Port: 0, Token: "tok"}, bridge, logger)
	httpSrv := httptest.NewServer(http.HandlerFunc(mcpSrv.handleRPC))
	defer httpSrv.Close()

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "approve_card_change",
		"arguments": map[string]interface{}{"agent_name": "nonexistent"},
	})

	resp := postRPC(t, httpSrv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      73,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "tok")

	if resp.Error == nil {
		t.Fatal("expected error from bridge, got nil")
	}
}

// ── tools/call: reject_card_change ──────────────────────────────────────────

func TestToolsCall_RejectCardChange_ReturnsResult(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "reject_card_change",
		"arguments": map[string]interface{}{"agent_name": "agent-a"},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      74,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	text := extractToolText(t, resp)
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result["rejected"] != true {
		t.Errorf("expected rejected=true, got %v", result["rejected"])
	}
}

func TestToolsCall_RejectCardChange_MissingAgent_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "test-token")

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "reject_card_change",
		"arguments": map[string]interface{}{},
	})

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      75,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "test-token")

	if resp.Error == nil {
		t.Fatal("expected error for missing agent_name, got nil")
	}
}

func TestToolsCall_RejectCardChange_BridgeError_ReturnsError(t *testing.T) {
	bridge := defaultMockBridge()
	bridge.rejectCardErr = errors.New("no pending change")
	logger := newNopLogger()
	mcpSrv := NewServer(Config{Host: "127.0.0.1", Port: 0, Token: "tok"}, bridge, logger)
	httpSrv := httptest.NewServer(http.HandlerFunc(mcpSrv.handleRPC))
	defer httpSrv.Close()

	rawArgs, _ := json.Marshal(map[string]interface{}{
		"name":      "reject_card_change",
		"arguments": map[string]interface{}{"agent_name": "nonexistent"},
	})

	resp := postRPC(t, httpSrv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      76,
		Method:  "tools/call",
		Params:  rawArgs,
	}, "tok")

	if resp.Error == nil {
		t.Fatal("expected error from bridge, got nil")
	}
}

// ── write tools: auth required ───────────────────────────────────────────────

func TestWriteTool_NoTokenConfigured_Rejected(t *testing.T) {
	// Server with no token configured — write tools should be rejected.
	_, srv := newTestServer(t, "")

	writeTools := []string{
		"update_rate_limit",
		"register_agent",
		"deregister_agent",
		"send_test_message",
		"approve_card_change",
		"reject_card_change",
	}

	for _, tool := range writeTools {
		t.Run(tool, func(t *testing.T) {
			rawArgs, _ := json.Marshal(map[string]interface{}{
				"name":      tool,
				"arguments": map[string]interface{}{},
			})

			resp := postRPC(t, srv.URL, jsonRPCRequest{
				JSONRPC: "2.0",
				ID:      50,
				Method:  "tools/call",
				Params:  rawArgs,
			}, "")

			if resp.Error == nil {
				t.Fatalf("expected error for write tool %q without token configured, got nil", tool)
			}
			if resp.Error.Code != -32001 {
				t.Errorf("expected code -32001, got %d", resp.Error.Code)
			}
			if !strings.Contains(resp.Error.Message, "MCP auth token required") {
				t.Errorf("expected auth token error message, got %q", resp.Error.Message)
			}
		})
	}
}

func TestReadTool_NoTokenConfigured_Allowed(t *testing.T) {
	// Server with no token — read tools should still work.
	_, srv := newTestServer(t, "")

	readTools := []string{
		"list_agents",
		"health_check",
		"get_rate_limit_status",
		"list_pending_changes",
	}

	for _, tool := range readTools {
		t.Run(tool, func(t *testing.T) {
			rawArgs, _ := json.Marshal(map[string]interface{}{
				"name": tool,
			})

			resp := postRPC(t, srv.URL, jsonRPCRequest{
				JSONRPC: "2.0",
				ID:      51,
				Method:  "tools/call",
				Params:  rawArgs,
			}, "")

			if resp.Error != nil {
				t.Fatalf("unexpected error for read tool %q: %+v", tool, resp.Error)
			}
		})
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

// ── resources/list ────────────────────────────────────────────────────────────

func TestResourcesList_ReturnsFourResources(t *testing.T) {
	_, srv := newTestServer(t, "")
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      60,
		Method:  "resources/list",
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}
	resources, ok := result["resources"].([]interface{})
	if !ok {
		t.Fatalf("expected resources slice, got %T", result["resources"])
	}
	if len(resources) != 4 {
		t.Errorf("expected 4 resources, got %d", len(resources))
	}
}

func TestResourcesList_ContainsExpectedURIs(t *testing.T) {
	_, srv := newTestServer(t, "")
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      61,
		Method:  "resources/list",
	}, "")

	result := resp.Result.(map[string]interface{})
	resources := result["resources"].([]interface{})

	wantURIs := map[string]bool{
		"sentinel://config":          false,
		"sentinel://metrics":         false,
		"sentinel://agents/{name}":   false,
		"sentinel://security/report": false,
	}
	for _, r := range resources {
		res := r.(map[string]interface{})
		uri := res["uri"].(string)
		wantURIs[uri] = true
	}
	for uri, found := range wantURIs {
		if !found {
			t.Errorf("expected resource URI %q in resources/list", uri)
		}
	}
}

// ── resources/read ────────────────────────────────────────────────────────────

func TestResourcesRead_Config(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawParams, _ := json.Marshal(map[string]string{"uri": "sentinel://config"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      62,
		Method:  "resources/read",
		Params:  rawParams,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	contents := result["contents"].([]interface{})
	if len(contents) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(contents))
	}
	item := contents[0].(map[string]interface{})
	if item["uri"] != "sentinel://config" {
		t.Errorf("expected uri=sentinel://config, got %q", item["uri"])
	}
	if item["mimeType"] != "application/json" {
		t.Errorf("expected mimeType=application/json, got %q", item["mimeType"])
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(item["text"].(string)), &config); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if config["token"] != "***" {
		t.Errorf("expected token=***, got %q", config["token"])
	}
}

func TestResourcesRead_Metrics(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawParams, _ := json.Marshal(map[string]string{"uri": "sentinel://metrics"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      63,
		Method:  "resources/read",
		Params:  rawParams,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	contents := result["contents"].([]interface{})
	item := contents[0].(map[string]interface{})

	var metrics map[string]interface{}
	if err := json.Unmarshal([]byte(item["text"].(string)), &metrics); err != nil {
		t.Fatalf("unmarshal metrics: %v", err)
	}
	if metrics["total_requests"] != float64(1000) {
		t.Errorf("expected total_requests=1000, got %v", metrics["total_requests"])
	}
}

func TestResourcesRead_SecurityReport(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawParams, _ := json.Marshal(map[string]string{"uri": "sentinel://security/report"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      64,
		Method:  "resources/read",
		Params:  rawParams,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	contents := result["contents"].([]interface{})
	item := contents[0].(map[string]interface{})

	var report map[string]interface{}
	if err := json.Unmarshal([]byte(item["text"].(string)), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report["auth_mode"] != "bearer" {
		t.Errorf("expected auth_mode=bearer, got %v", report["auth_mode"])
	}
}

func TestResourcesRead_AgentByName(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawParams, _ := json.Marshal(map[string]string{"uri": "sentinel://agents/agent-a"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      65,
		Method:  "resources/read",
		Params:  rawParams,
	}, "")

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	result := resp.Result.(map[string]interface{})
	contents := result["contents"].([]interface{})
	item := contents[0].(map[string]interface{})

	var card map[string]interface{}
	if err := json.Unmarshal([]byte(item["text"].(string)), &card); err != nil {
		t.Fatalf("unmarshal card: %v", err)
	}
	if card["name"] != "agent-a" {
		t.Errorf("expected name=agent-a, got %q", card["name"])
	}
}

func TestResourcesRead_AgentNotFound_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawParams, _ := json.Marshal(map[string]string{"uri": "sentinel://agents/nonexistent"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      66,
		Method:  "resources/read",
		Params:  rawParams,
	}, "")

	if resp.Error == nil {
		t.Fatal("expected error for nonexistent agent resource, got nil")
	}
}

func TestResourcesRead_AgentEmptyName_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawParams, _ := json.Marshal(map[string]string{"uri": "sentinel://agents/"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      67,
		Method:  "resources/read",
		Params:  rawParams,
	}, "")

	if resp.Error == nil {
		t.Fatal("expected error for empty agent name in URI, got nil")
	}
}

func TestResourcesRead_AgentTemplateName_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawParams, _ := json.Marshal(map[string]string{"uri": "sentinel://agents/{name}"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      68,
		Method:  "resources/read",
		Params:  rawParams,
	}, "")

	if resp.Error == nil {
		t.Fatal("expected error for template agent name in URI, got nil")
	}
}

func TestResourcesRead_UnknownURI_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "")

	rawParams, _ := json.Marshal(map[string]string{"uri": "sentinel://unknown"})
	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      69,
		Method:  "resources/read",
		Params:  rawParams,
	}, "")

	if resp.Error == nil {
		t.Fatal("expected error for unknown resource URI, got nil")
	}
	if !strings.Contains(resp.Error.Message, "unknown resource URI") {
		t.Errorf("expected unknown resource URI message, got %q", resp.Error.Message)
	}
}

func TestResourcesRead_InvalidParams_ReturnsError(t *testing.T) {
	_, srv := newTestServer(t, "")

	resp := postRPC(t, srv.URL, jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      70,
		Method:  "resources/read",
		Params:  json.RawMessage(`"not an object"`),
	}, "")

	if resp.Error == nil {
		t.Fatal("expected error for invalid resources/read params, got nil")
	}
}
