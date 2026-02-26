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

// Server is a read-only MCP management server bound to localhost.
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
			ServerInfo:      serverInfo{Name: "a2a-sentinel", Version: "0.1.0"},
			Capabilities:    map[string]any{"tools": map[string]any{}},
		},
	}
}

// toolsList is the fixed list of tools exposed by the MCP server.
func toolsList() []toolDefinition {
	return []toolDefinition{
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
