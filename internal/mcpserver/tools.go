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

	var (
		result toolResult
		err    error
	)

	switch params.Name {
	case "list_agents":
		result, err = s.toolListAgents()
	case "health_check":
		result, err = s.toolHealthCheck()
	case "get_blocked_requests":
		result, err = s.toolGetBlockedRequests(params.Arguments)
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
