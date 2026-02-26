package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Config holds MCP server configuration.
type Config struct {
	Enabled bool
	Host    string
	Port    int
	Token   string // empty means no auth required
}

// Server is an MCP management server bound to localhost.
type Server struct {
	bridge     SentinelBridge
	addr       string
	token      string
	mu         sync.Mutex
	httpServer *http.Server
	listener   net.Listener // if non-nil, Start uses this instead of creating one
	logger     *slog.Logger
}

// jsonRPCRequest is a minimal JSON-RPC 2.0 request envelope.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// jsonRPCResponse is a minimal JSON-RPC 2.0 response envelope.
type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

// rpcError represents a JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewServer creates an MCP server from configuration.
func NewServer(cfg Config, bridge SentinelBridge, logger *slog.Logger) *Server {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	return &Server{
		bridge: bridge,
		addr:   addr,
		token:  cfg.Token,
		logger: logger,
	}
}

// Start begins listening on the configured address. It blocks until ctx is
// cancelled or a fatal error occurs.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRPC)

	// Use injected listener or create one
	ln := s.listener
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", s.addr)
		if err != nil {
			return fmt.Errorf("mcp server listen %s: %w", s.addr, err)
		}
	}

	srv := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	s.mu.Lock()
	s.httpServer = srv
	s.mu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("mcp server listening", "addr", s.addr)
		errCh <- srv.Serve(ln)
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("mcp server error: %w", err)
		}
	case <-ctx.Done():
		s.logger.Info("mcp server shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	return s.Shutdown(shutdownCtx)
}

// Shutdown gracefully stops the MCP server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.httpServer
	s.mu.Unlock()

	if srv != nil {
		if err := srv.Shutdown(ctx); err != nil {
			return fmt.Errorf("mcp server shutdown: %w", err)
		}
	}
	return nil
}

// handleRPC is the single HTTP endpoint that processes all JSON-RPC requests.
func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	// Only POST is valid for JSON-RPC.
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Bearer token auth check.
	if s.token != "" {
		authHeader := r.Header.Get("Authorization")
		expected := "Bearer " + s.token
		if !strings.EqualFold(strings.TrimSpace(authHeader), expected) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(jsonRPCResponse{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: -32001, Message: "Unauthorized: valid Bearer token required"},
			})
			return
		}
	}

	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			Error:   &rpcError{Code: -32700, Message: "Parse error"},
		})
		return
	}

	resp := s.dispatch(req)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// dispatch routes a JSON-RPC request to the appropriate handler.
func (s *Server) dispatch(req jsonRPCRequest) jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req)
	case "resources/list":
		return s.handleResourcesList(req)
	case "resources/read":
		return s.handleResourcesRead(req)
	default:
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
		}
	}
}

// serverInfo is returned in the initialize response.
type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// initializeResult is the full response body for the initialize method.
type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	ServerInfo      serverInfo     `json:"serverInfo"`
	Capabilities    map[string]any `json:"capabilities"`
}

// toolDefinition describes a single MCP tool.
type toolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// handleInitialize returns server info and the list of available tools.
func (s *Server) handleInitialize(req jsonRPCRequest) jsonRPCResponse {
	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: initializeResult{
			ProtocolVersion: "2024-11-05",
			ServerInfo:      serverInfo{Name: "a2a-sentinel", Version: "0.2.0"},
			Capabilities: map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{},
			},
		},
	}
}

// toolsList is the fixed list of tools exposed by the MCP server.
func toolsList() []toolDefinition {
	return []toolDefinition{
		// Read tools
		{
			Name:        "list_agents",
			Description: "List all configured backend A2A agents and their current health status.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "health_check",
			Description: "Return overall system health including active streams and uptime.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "get_blocked_requests",
			Description: "Retrieve requests blocked by the security pipeline within a time window.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"since": map[string]any{
						"type":        "string",
						"description": "RFC3339 timestamp to filter from (optional, defaults to last hour)",
					},
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum number of results to return (optional, defaults to 100)",
					},
				},
			},
		},
		{
			Name:        "get_agent_card",
			Description: "Retrieve the Agent Card for a specific backend agent.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_name": map[string]any{
						"type":        "string",
						"description": "Name of the agent whose card to retrieve",
					},
				},
				"required": []string{"agent_name"},
			},
		},
		{
			Name:        "get_aggregated_card",
			Description: "Retrieve the aggregated Agent Card published by the sentinel gateway.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "get_rate_limit_status",
			Description: "Retrieve current rate-limit status for all agents.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		// Write tools
		{
			Name:        "update_rate_limit",
			Description: "Update the rate limit (requests per minute) for a specific agent.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_name": map[string]any{
						"type":        "string",
						"description": "Name of the agent to update",
					},
					"per_minute": map[string]any{
						"type":        "integer",
						"description": "New requests-per-minute limit",
					},
				},
				"required": []string{"agent_name", "per_minute"},
			},
		},
		{
			Name:        "register_agent",
			Description: "Register a new backend A2A agent with the gateway.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{
						"type":        "string",
						"description": "Unique name for the agent",
					},
					"url": map[string]any{
						"type":        "string",
						"description": "Backend URL of the agent",
					},
					"default": map[string]any{
						"type":        "boolean",
						"description": "Whether this agent should be the default route (optional)",
					},
				},
				"required": []string{"name", "url"},
			},
		},
		{
			Name:        "deregister_agent",
			Description: "Remove a backend A2A agent from the gateway.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{
						"type":        "string",
						"description": "Name of the agent to remove",
					},
				},
				"required": []string{"name"},
			},
		},
		{
			Name:        "send_test_message",
			Description: "Send a test message to a specific agent and return the response.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_name": map[string]any{
						"type":        "string",
						"description": "Name of the agent to test",
					},
					"text": map[string]any{
						"type":        "string",
						"description": "Text content of the test message",
					},
				},
				"required": []string{"agent_name", "text"},
			},
		},
		// Card change approval tools
		{
			Name:        "list_pending_changes",
			Description: "List all pending Agent Card changes awaiting approval.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "approve_card_change",
			Description: "Approve a pending Agent Card change and apply the new card.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_name": map[string]any{
						"type":        "string",
						"description": "Name of the agent whose card change to approve",
					},
				},
				"required": []string{"agent_name"},
			},
		},
		{
			Name:        "reject_card_change",
			Description: "Reject a pending Agent Card change, keeping the old card.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_name": map[string]any{
						"type":        "string",
						"description": "Name of the agent whose card change to reject",
					},
				},
				"required": []string{"agent_name"},
			},
		},
	}
}

// handleToolsList returns the list of available tools.
func (s *Server) handleToolsList(req jsonRPCRequest) jsonRPCResponse {
	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]any{"tools": toolsList()},
	}
}

// ── resources ────────────────────────────────────────────────────────────────

// resourceDefinition describes a single MCP resource.
type resourceDefinition struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType"`
}

// resourceReadParams holds the params for a resources/read request.
type resourceReadParams struct {
	URI string `json:"uri"`
}

// resourceContent is a single content item within a resource read result.
type resourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// resourcesList returns the fixed list of resources exposed by the MCP server.
func resourcesList() []resourceDefinition {
	return []resourceDefinition{
		{
			URI:         "sentinel://config",
			Name:        "Sentinel Configuration",
			Description: "Current gateway configuration with secrets masked.",
			MimeType:    "application/json",
		},
		{
			URI:         "sentinel://metrics",
			Name:        "Request Metrics",
			Description: "Basic request metrics including total requests, blocked count, active streams, and uptime.",
			MimeType:    "application/json",
		},
		{
			URI:         "sentinel://agents/{name}",
			Name:        "Agent Detail",
			Description: "Per-agent detail including status, card, and skills. Replace {name} with agent name.",
			MimeType:    "application/json",
		},
		{
			URI:         "sentinel://security/report",
			Name:        "Security Report",
			Description: "Security summary including auth mode, rate limit status, and recent blocks count.",
			MimeType:    "application/json",
		},
	}
}

// handleResourcesList returns the list of available resources.
func (s *Server) handleResourcesList(req jsonRPCRequest) jsonRPCResponse {
	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]any{"resources": resourcesList()},
	}
}

// handleResourcesRead reads a specific resource by URI.
func (s *Server) handleResourcesRead(req jsonRPCRequest) jsonRPCResponse {
	var params resourceReadParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32602, Message: "invalid params: " + err.Error()},
		}
	}

	var data interface{}
	var err error

	switch {
	case params.URI == "sentinel://config":
		data = s.bridge.GetConfig()
	case params.URI == "sentinel://metrics":
		data = s.bridge.GetMetrics()
	case params.URI == "sentinel://security/report":
		data = s.bridge.GetSecurityReport()
	case strings.HasPrefix(params.URI, "sentinel://agents/"):
		agentName := strings.TrimPrefix(params.URI, "sentinel://agents/")
		if agentName == "" || agentName == "{name}" {
			return jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: -32602, Message: "agent name required in URI: sentinel://agents/{name}"},
			}
		}
		data, err = s.bridge.GetAgentCard(agentName)
		if err != nil {
			return jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: -32603, Message: "internal error: " + err.Error()},
			}
		}
	default:
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32602, Message: fmt.Sprintf("unknown resource URI: %s", params.URI)},
		}
	}

	b, err := json.Marshal(data)
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
		Result: map[string]any{
			"contents": []resourceContent{
				{
					URI:      params.URI,
					MimeType: "application/json",
					Text:     string(b),
				},
			},
		},
	}
}
