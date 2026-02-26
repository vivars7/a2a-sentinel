package mcpserver

import (
	"encoding/json"
	"fmt"
	"time"
)

// toolCallParams is the params block for a tools/call request.
type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// toolResult is the MCP tool result envelope.
type toolResult struct {
	Content []toolContent `json:"content"`
}

// toolContent is a single content item within a tool result.
type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// textResult wraps a value as a JSON text tool result.
func textResult(v interface{}) (toolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return toolResult{}, fmt.Errorf("marshalling tool result: %w", err)
	}
	return toolResult{
		Content: []toolContent{
			{Type: "text", Text: string(b)},
		},
	}, nil
}

// writeToolNames lists tools that modify state and require auth.
var writeToolNames = map[string]bool{
	"update_rate_limit":    true,
	"register_agent":       true,
	"deregister_agent":     true,
	"send_test_message":    true,
	"approve_card_change":  true,
	"reject_card_change":   true,
}

// isWriteTool reports whether a tool name identifies a write operation.
func isWriteTool(name string) bool {
	return writeToolNames[name]
}

// handleToolsCall dispatches a tools/call request to the correct tool handler.
func (s *Server) handleToolsCall(req jsonRPCRequest) jsonRPCResponse {
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32602, Message: "invalid params: " + err.Error()},
		}
	}

	// Write tools require an auth token to be configured.
	if isWriteTool(params.Name) && s.token == "" {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32001, Message: "MCP auth token required for write operations"},
		}
	}

	var (
		result toolResult
		err    error
	)

	switch params.Name {
	// Read tools
	case "list_agents":
		result, err = s.toolListAgents()
	case "health_check":
		result, err = s.toolHealthCheck()
	case "get_blocked_requests":
		result, err = s.toolGetBlockedRequests(params.Arguments)
	case "get_agent_card":
		result, err = s.toolGetAgentCard(params.Arguments)
	case "get_aggregated_card":
		result, err = s.toolGetAggregatedCard()
	case "get_rate_limit_status":
		result, err = s.toolGetRateLimitStatus()

	// Write tools
	case "update_rate_limit":
		result, err = s.toolUpdateRateLimit(params.Arguments)
	case "register_agent":
		result, err = s.toolRegisterAgent(params.Arguments)
	case "deregister_agent":
		result, err = s.toolDeregisterAgent(params.Arguments)
	case "send_test_message":
		result, err = s.toolSendTestMessage(params.Arguments)

	// Card change approval tools
	case "list_pending_changes":
		result, err = s.toolListPendingChanges()
	case "approve_card_change":
		result, err = s.toolApproveCardChange(params.Arguments)
	case "reject_card_change":
		result, err = s.toolRejectCardChange(params.Arguments)

	default:
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32602, Message: fmt.Sprintf("unknown tool: %s", params.Name)},
		}
	}

	if err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32603, Message: "internal error: " + err.Error()},
		}
	}

	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// ── read tool handlers ──────────────────────────────────────────────────────

// toolListAgents calls bridge.ListAgents and returns the result.
func (s *Server) toolListAgents() (toolResult, error) {
	agents := s.bridge.ListAgents()
	return textResult(agents)
}

// toolHealthCheck calls bridge.HealthCheck and returns the result.
func (s *Server) toolHealthCheck() (toolResult, error) {
	health := s.bridge.HealthCheck()
	return textResult(health)
}

// blockedRequestsArgs holds the optional arguments for get_blocked_requests.
type blockedRequestsArgs struct {
	Since string `json:"since,omitempty"`
	Limit *int   `json:"limit,omitempty"`
}

const (
	// defaultBlockedLimit is the default max results for get_blocked_requests.
	defaultBlockedLimit = 100
	// defaultBlockedWindow is how far back to look when no since is provided.
	defaultBlockedWindow = time.Hour
)

// toolGetBlockedRequests calls bridge.GetBlockedRequests with parsed arguments.
func (s *Server) toolGetBlockedRequests(raw json.RawMessage) (toolResult, error) {
	var args blockedRequestsArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return toolResult{}, fmt.Errorf("parsing arguments: %w", err)
		}
	}

	since := time.Now().Add(-defaultBlockedWindow)
	if args.Since != "" {
		t, err := time.Parse(time.RFC3339, args.Since)
		if err != nil {
			return toolResult{}, fmt.Errorf("invalid since timestamp %q: %w", args.Since, err)
		}
		since = t
	}

	limit := defaultBlockedLimit
	if args.Limit != nil {
		limit = *args.Limit
	}

	blocked := s.bridge.GetBlockedRequests(since, limit)
	return textResult(blocked)
}

// agentCardArgs holds the arguments for get_agent_card.
type agentCardArgs struct {
	AgentName string `json:"agent_name"`
}

// toolGetAgentCard calls bridge.GetAgentCard for a specific agent.
func (s *Server) toolGetAgentCard(raw json.RawMessage) (toolResult, error) {
	var args agentCardArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return toolResult{}, fmt.Errorf("parsing arguments: %w", err)
		}
	}
	if args.AgentName == "" {
		return toolResult{}, fmt.Errorf("agent_name is required")
	}

	card, err := s.bridge.GetAgentCard(args.AgentName)
	if err != nil {
		return toolResult{}, err
	}
	return textResult(card)
}

// toolGetAggregatedCard calls bridge.GetAggregatedCard.
func (s *Server) toolGetAggregatedCard() (toolResult, error) {
	card, err := s.bridge.GetAggregatedCard()
	if err != nil {
		return toolResult{}, err
	}
	return textResult(card)
}

// toolGetRateLimitStatus calls bridge.GetRateLimitStatus.
func (s *Server) toolGetRateLimitStatus() (toolResult, error) {
	statuses := s.bridge.GetRateLimitStatus()
	return textResult(statuses)
}

// ── write tool handlers ─────────────────────────────────────────────────────

// updateRateLimitArgs holds the arguments for update_rate_limit.
type updateRateLimitArgs struct {
	AgentName string `json:"agent_name"`
	PerMinute int    `json:"per_minute"`
}

// toolUpdateRateLimit calls bridge.UpdateRateLimit and returns old/new values.
func (s *Server) toolUpdateRateLimit(raw json.RawMessage) (toolResult, error) {
	var args updateRateLimitArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return toolResult{}, fmt.Errorf("parsing arguments: %w", err)
	}
	if args.AgentName == "" {
		return toolResult{}, fmt.Errorf("agent_name is required")
	}
	if args.PerMinute <= 0 {
		return toolResult{}, fmt.Errorf("per_minute must be positive")
	}

	previous, err := s.bridge.UpdateRateLimit(args.AgentName, args.PerMinute)
	if err != nil {
		return toolResult{}, err
	}
	return textResult(map[string]int{"previous": previous, "updated": args.PerMinute})
}

// registerAgentArgs holds the arguments for register_agent.
type registerAgentArgs struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Default bool   `json:"default,omitempty"`
}

// toolRegisterAgent calls bridge.RegisterAgent.
func (s *Server) toolRegisterAgent(raw json.RawMessage) (toolResult, error) {
	var args registerAgentArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return toolResult{}, fmt.Errorf("parsing arguments: %w", err)
	}
	if args.Name == "" {
		return toolResult{}, fmt.Errorf("name is required")
	}
	if args.URL == "" {
		return toolResult{}, fmt.Errorf("url is required")
	}

	if err := s.bridge.RegisterAgent(args.Name, args.URL, args.Default); err != nil {
		return toolResult{}, err
	}
	return textResult(map[string]bool{"registered": true})
}

// deregisterAgentArgs holds the arguments for deregister_agent.
type deregisterAgentArgs struct {
	Name string `json:"name"`
}

// toolDeregisterAgent calls bridge.DeregisterAgent.
func (s *Server) toolDeregisterAgent(raw json.RawMessage) (toolResult, error) {
	var args deregisterAgentArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return toolResult{}, fmt.Errorf("parsing arguments: %w", err)
	}
	if args.Name == "" {
		return toolResult{}, fmt.Errorf("name is required")
	}

	if err := s.bridge.DeregisterAgent(args.Name); err != nil {
		return toolResult{}, err
	}
	return textResult(map[string]bool{"removed": true})
}

// sendTestMessageArgs holds the arguments for send_test_message.
type sendTestMessageArgs struct {
	AgentName string `json:"agent_name"`
	Text      string `json:"text"`
}

// toolSendTestMessage calls bridge.SendTestMessage.
func (s *Server) toolSendTestMessage(raw json.RawMessage) (toolResult, error) {
	var args sendTestMessageArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return toolResult{}, fmt.Errorf("parsing arguments: %w", err)
	}
	if args.AgentName == "" {
		return toolResult{}, fmt.Errorf("agent_name is required")
	}
	if args.Text == "" {
		return toolResult{}, fmt.Errorf("text is required")
	}

	result, err := s.bridge.SendTestMessage(args.AgentName, args.Text)
	if err != nil {
		return toolResult{}, err
	}
	return textResult(result)
}

// ── card change approval tool handlers ──────────────────────────────────────

// toolListPendingChanges calls bridge.ListPendingChanges and returns the result.
func (s *Server) toolListPendingChanges() (toolResult, error) {
	pending := s.bridge.ListPendingChanges()
	return textResult(pending)
}

// approveRejectArgs holds the arguments for approve_card_change and reject_card_change.
type approveRejectArgs struct {
	AgentName string `json:"agent_name"`
}

// toolApproveCardChange calls bridge.ApproveCardChange for a specific agent.
func (s *Server) toolApproveCardChange(raw json.RawMessage) (toolResult, error) {
	var args approveRejectArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return toolResult{}, fmt.Errorf("parsing arguments: %w", err)
	}
	if args.AgentName == "" {
		return toolResult{}, fmt.Errorf("agent_name is required")
	}

	if err := s.bridge.ApproveCardChange(args.AgentName); err != nil {
		return toolResult{}, err
	}
	return textResult(map[string]bool{"approved": true})
}

// toolRejectCardChange calls bridge.RejectCardChange for a specific agent.
func (s *Server) toolRejectCardChange(raw json.RawMessage) (toolResult, error) {
	var args approveRejectArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return toolResult{}, fmt.Errorf("parsing arguments: %w", err)
	}
	if args.AgentName == "" {
		return toolResult{}, fmt.Errorf("agent_name is required")
	}

	if err := s.bridge.RejectCardChange(args.AgentName); err != nil {
		return toolResult{}, err
	}
	return textResult(map[string]bool{"rejected": true})
}
