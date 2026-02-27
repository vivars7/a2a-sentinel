package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	a2av1 "github.com/vivars7/a2a-sentinel/gen/a2a/v1"
	"github.com/vivars7/a2a-sentinel/internal/config"
	"github.com/vivars7/a2a-sentinel/internal/protocol"
	"github.com/vivars7/a2a-sentinel/internal/proxy"
	"github.com/vivars7/a2a-sentinel/internal/router"
	"github.com/vivars7/a2a-sentinel/internal/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"log/slog"
	"os"
)

// testLogger returns a logger for test usage.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testConfig creates a minimal config pointing to a test backend.
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
	cfg.Security.RateLimit.Enabled = false
	cfg.Listen.GlobalRateLimit = 0
	return cfg
}

// stubAgentLookup implements router.AgentLookup for testing.
type stubAgentLookup struct {
	url string
}

func (s *stubAgentLookup) IsHealthy(name string) bool              { return true }
func (s *stubAgentLookup) HealthyAgents() []string                 { return []string{"test-agent"} }
func (s *stubAgentLookup) GetAgentURL(name string) (string, bool)  { return s.url, true }
func (s *stubAgentLookup) GetDefaultAgent() (string, string, bool) { return "test-agent", s.url, true }

// startGRPCServer starts a gRPC server with the given backend and returns a client connection.
func startGRPCServer(t *testing.T, backend *httptest.Server) (a2av1.A2AServiceClient, func()) {
	t.Helper()

	cfg := testConfig(backend.URL)
	logger := testLogger()

	lookup := &stubAgentLookup{url: backend.URL}
	rtr := router.NewRouter("single", lookup)
	httpTransport := proxy.NewHTTPTransport()
	httpProxy := proxy.NewHTTPProxy(httpTransport, logger)
	streamMgr := proxy.NewStreamManager()
	streamTransport := proxy.NewStreamTransport()
	sseProxy := proxy.NewSSEProxy(streamTransport, streamMgr, logger)

	// Build security pipeline (permissive for tests)
	pipelineCfg := security.SecurityPipelineConfig{
		Auth: security.AuthPipelineConfig{
			Mode:                 "passthrough",
			AllowUnauthenticated: true,
		},
		Logger: logger,
	}
	middlewares := security.BuildPipeline(pipelineCfg)

	grpcSrv := NewGRPCServer(cfg, rtr, httpProxy, sseProxy, middlewares, logger)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		if err := grpcSrv.Serve(lis); err != nil {
			// Ignore errors after stop
		}
	}()

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	client := a2av1.NewA2AServiceClient(conn)

	cleanup := func() {
		conn.Close()
		grpcSrv.GracefulStop()
	}

	return client, cleanup
}

// ── SendMessage Tests ──

func TestSendMessage_Success(t *testing.T) {
	// Backend returns a JSON-RPC response with a task
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it's a JSON-RPC request
		var rpcReq protocol.JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&rpcReq); err != nil {
			t.Errorf("failed to decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if rpcReq.Method != "message/send" {
			t.Errorf("expected method message/send, got %s", rpcReq.Method)
		}

		task := protocol.Task{
			ID: "task-123",
			Status: protocol.TaskStatus{
				State:     protocol.TaskStateSubmitted,
				Timestamp: "2025-01-01T00:00:00Z",
			},
		}
		taskJSON, _ := json.Marshal(task)

		resp := protocol.JSONRPCResponse{
			JSONRPC: "2.0",
			Result:  taskJSON,
			ID:      rpcReq.ID,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer backend.Close()

	client, cleanup := startGRPCServer(t, backend)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.SendMessage(ctx, &a2av1.SendMessageRequest{
		Message: &a2av1.Message{
			Role: "user",
			Parts: []*a2av1.Part{
				{Type: "text", Text: "Hello"},
			},
		},
	})
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	if resp.GetTask().GetId() != "task-123" {
		t.Errorf("expected task ID 'task-123', got %q", resp.GetTask().GetId())
	}
	if resp.GetTask().GetStatus().GetState() != "submitted" {
		t.Errorf("expected state 'submitted', got %q", resp.GetTask().GetStatus().GetState())
	}
}

func TestSendMessage_WithConfiguration(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rpcReq protocol.JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&rpcReq)

		// Verify configuration is included in params
		var params protocol.SendMessageRequest
		json.Unmarshal(rpcReq.Params, &params)

		if params.Configuration == nil {
			t.Error("expected configuration in params")
		}
		if params.Configuration != nil && len(params.Configuration.AcceptedOutputModes) == 0 {
			t.Error("expected accepted output modes")
		}

		task := protocol.Task{ID: "task-456", Status: protocol.TaskStatus{State: protocol.TaskStateWorking}}
		taskJSON, _ := json.Marshal(task)
		resp := protocol.JSONRPCResponse{JSONRPC: "2.0", Result: taskJSON, ID: rpcReq.ID}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer backend.Close()

	client, cleanup := startGRPCServer(t, backend)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	blocking := true
	resp, err := client.SendMessage(ctx, &a2av1.SendMessageRequest{
		Message: &a2av1.Message{
			Role:  "user",
			Parts: []*a2av1.Part{{Type: "text", Text: "test"}},
		},
		Configuration: &a2av1.SendMessageConfiguration{
			AcceptedOutputModes: []string{"text"},
			Blocking:            &blocking,
		},
	})
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}
	if resp.GetTask().GetId() != "task-456" {
		t.Errorf("expected task ID 'task-456', got %q", resp.GetTask().GetId())
	}
}

// ── GetTask Tests ──

func TestGetTask_Success(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rpcReq protocol.JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&rpcReq)

		if rpcReq.Method != "tasks/get" {
			t.Errorf("expected method tasks/get, got %s", rpcReq.Method)
		}

		task := protocol.Task{
			ID:        "task-789",
			SessionID: "session-1",
			Status: protocol.TaskStatus{
				State: protocol.TaskStateCompleted,
			},
			Artifacts: []protocol.Artifact{
				{
					ArtifactID: "art-1",
					Name:       "result",
					Parts:      []protocol.Part{{Type: "text", Text: "Done"}},
				},
			},
		}
		taskJSON, _ := json.Marshal(task)
		resp := protocol.JSONRPCResponse{JSONRPC: "2.0", Result: taskJSON, ID: rpcReq.ID}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer backend.Close()

	client, cleanup := startGRPCServer(t, backend)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetTask(ctx, &a2av1.GetTaskRequest{TaskId: "task-789"})
	if err != nil {
		t.Fatalf("GetTask failed: %v", err)
	}

	if resp.GetTask().GetId() != "task-789" {
		t.Errorf("expected task ID 'task-789', got %q", resp.GetTask().GetId())
	}
	if resp.GetTask().GetSessionId() != "session-1" {
		t.Errorf("expected session ID 'session-1', got %q", resp.GetTask().GetSessionId())
	}
	if len(resp.GetTask().GetArtifacts()) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(resp.GetTask().GetArtifacts()))
	}
	if resp.GetTask().GetArtifacts()[0].GetName() != "result" {
		t.Errorf("expected artifact name 'result', got %q", resp.GetTask().GetArtifacts()[0].GetName())
	}
}

// ── CancelTask Tests ──

func TestCancelTask_Success(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rpcReq protocol.JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&rpcReq)

		if rpcReq.Method != "tasks/cancel" {
			t.Errorf("expected method tasks/cancel, got %s", rpcReq.Method)
		}

		task := protocol.Task{
			ID:     "task-cancel",
			Status: protocol.TaskStatus{State: protocol.TaskStateCanceled},
		}
		taskJSON, _ := json.Marshal(task)
		resp := protocol.JSONRPCResponse{JSONRPC: "2.0", Result: taskJSON, ID: rpcReq.ID}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer backend.Close()

	client, cleanup := startGRPCServer(t, backend)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.CancelTask(ctx, &a2av1.CancelTaskRequest{TaskId: "task-cancel"})
	if err != nil {
		t.Fatalf("CancelTask failed: %v", err)
	}
	if resp.GetTask().GetStatus().GetState() != "canceled" {
		t.Errorf("expected state 'canceled', got %q", resp.GetTask().GetStatus().GetState())
	}
}

// ── StreamMessage Tests ──

func TestStreamMessage_Success(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response writer does not support flushing")
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		// Send status update events
		events := []struct {
			eventType string
			data      string
		}{
			{
				eventType: "status",
				data:      `{"id":"task-stream","status":{"state":"working","timestamp":"2025-01-01T00:00:00Z"},"final":false}`,
			},
			{
				eventType: "status",
				data:      `{"id":"task-stream","status":{"state":"completed","timestamp":"2025-01-01T00:01:00Z"},"final":true}`,
			},
		}

		for _, evt := range events {
			fmt.Fprintf(w, "event: %s\n", evt.eventType)
			fmt.Fprintf(w, "data: %s\n\n", evt.data)
			flusher.Flush()
		}
	}))
	defer backend.Close()

	client, cleanup := startGRPCServer(t, backend)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamMessage(ctx, &a2av1.SendMessageRequest{
		Message: &a2av1.Message{
			Role:  "user",
			Parts: []*a2av1.Part{{Type: "text", Text: "stream test"}},
		},
	})
	if err != nil {
		t.Fatalf("StreamMessage failed: %v", err)
	}

	var events []*a2av1.StreamEvent
	for {
		evt, err := stream.Recv()
		if err != nil {
			break
		}
		events = append(events, evt)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	// First event: working
	su := events[0].GetStatusUpdate()
	if su == nil {
		t.Fatal("expected status update event")
	}
	if su.GetId() != "task-stream" {
		t.Errorf("expected task ID 'task-stream', got %q", su.GetId())
	}
	if su.GetStatus().GetState() != "working" {
		t.Errorf("expected state 'working', got %q", su.GetStatus().GetState())
	}

	// Second event: completed + final
	su2 := events[1].GetStatusUpdate()
	if su2 == nil {
		t.Fatal("expected status update event")
	}
	if su2.GetStatus().GetState() != "completed" {
		t.Errorf("expected state 'completed', got %q", su2.GetStatus().GetState())
	}
	if !su2.GetFinal() {
		t.Error("expected final=true on last event")
	}
}

func TestStreamMessage_ArtifactEvent(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		fmt.Fprintf(w, "event: artifact\n")
		fmt.Fprintf(w, "data: %s\n\n", `{"id":"task-art","artifact":{"artifactId":"a1","name":"output","parts":[{"type":"text","text":"result"}]}}`)
		flusher.Flush()
	}))
	defer backend.Close()

	client, cleanup := startGRPCServer(t, backend)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamMessage(ctx, &a2av1.SendMessageRequest{
		Message: &a2av1.Message{
			Role:  "user",
			Parts: []*a2av1.Part{{Type: "text", Text: "artifact test"}},
		},
	})
	if err != nil {
		t.Fatalf("StreamMessage failed: %v", err)
	}

	evt, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv failed: %v", err)
	}

	au := evt.GetArtifactUpdate()
	if au == nil {
		t.Fatal("expected artifact update event")
	}
	if au.GetArtifact().GetName() != "output" {
		t.Errorf("expected artifact name 'output', got %q", au.GetArtifact().GetName())
	}
}

// ── Security Interceptor Tests ──

func TestSecurityInterceptor_BlocksUnauthenticated(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be called when auth is required")
	}))
	defer backend.Close()

	cfg := testConfig(backend.URL)
	logger := testLogger()

	lookup := &stubAgentLookup{url: backend.URL}
	rtr := router.NewRouter("single", lookup)
	httpTransport := proxy.NewHTTPTransport()
	httpProxy := proxy.NewHTTPProxy(httpTransport, logger)
	streamMgr := proxy.NewStreamManager()
	streamTransport := proxy.NewStreamTransport()
	sseProxy := proxy.NewSSEProxy(streamTransport, streamMgr, logger)

	// Build restrictive security pipeline (require auth)
	pipelineCfg := security.SecurityPipelineConfig{
		Auth: security.AuthPipelineConfig{
			Mode:                 "passthrough-strict",
			AllowUnauthenticated: false,
		},
		Logger: logger,
	}
	middlewares := security.BuildPipeline(pipelineCfg)

	grpcSrv := NewGRPCServer(cfg, rtr, httpProxy, sseProxy, middlewares, logger)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go grpcSrv.Serve(lis)
	defer grpcSrv.GracefulStop()

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	client := a2av1.NewA2AServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.SendMessage(ctx, &a2av1.SendMessageRequest{
		Message: &a2av1.Message{
			Role:  "user",
			Parts: []*a2av1.Part{{Type: "text", Text: "should be blocked"}},
		},
	})

	if err == nil {
		t.Fatal("expected error for unauthenticated request")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.Unauthenticated && st.Code() != codes.PermissionDenied {
		t.Errorf("expected Unauthenticated or PermissionDenied, got %s", st.Code())
	}
}

func TestSecurityInterceptor_PassesWithMetadata(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		task := protocol.Task{ID: "authed-task", Status: protocol.TaskStatus{State: protocol.TaskStateSubmitted}}
		taskJSON, _ := json.Marshal(task)
		resp := protocol.JSONRPCResponse{JSONRPC: "2.0", Result: taskJSON, ID: 1}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer backend.Close()

	client, cleanup := startGRPCServer(t, backend)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Add metadata (simulates auth header)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer test-token")

	resp, err := client.SendMessage(ctx, &a2av1.SendMessageRequest{
		Message: &a2av1.Message{
			Role:  "user",
			Parts: []*a2av1.Part{{Type: "text", Text: "authed request"}},
		},
	})
	if err != nil {
		t.Fatalf("SendMessage with metadata failed: %v", err)
	}
	if resp.GetTask().GetId() != "authed-task" {
		t.Errorf("expected task ID 'authed-task', got %q", resp.GetTask().GetId())
	}
}

// ── Translation Tests ──

func TestTranslation_SendMessageRequest(t *testing.T) {
	tests := []struct {
		name    string
		input   *a2av1.SendMessageRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			input:   nil,
			wantErr: true,
		},
		{
			name: "basic message",
			input: &a2av1.SendMessageRequest{
				Message: &a2av1.Message{
					Role:  "user",
					Parts: []*a2av1.Part{{Type: "text", Text: "hello"}},
				},
			},
			wantErr: false,
		},
		{
			name: "message with file part",
			input: &a2av1.SendMessageRequest{
				Message: &a2av1.Message{
					Role: "user",
					Parts: []*a2av1.Part{
						{
							Type: "file",
							File: &a2av1.FileContent{
								Name:     "test.txt",
								MimeType: "text/plain",
								Uri:      "https://example.com/file.txt",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "message with metadata",
			input: &a2av1.SendMessageRequest{
				Message: &a2av1.Message{
					Role:      "user",
					Parts:     []*a2av1.Part{{Type: "text", Text: "test"}},
					MessageId: "msg-1",
				},
				Metadata: mustStruct(map[string]interface{}{"key": "value"}),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sendMessageRequestToInternal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

func TestTranslation_TaskRoundTrip(t *testing.T) {
	// Create an internal task
	original := &protocol.Task{
		ID:        "roundtrip-task",
		SessionID: "session-rt",
		Status: protocol.TaskStatus{
			State:     protocol.TaskStateWorking,
			Timestamp: "2025-06-01T12:00:00Z",
			Message: &protocol.Message{
				Role:  "agent",
				Parts: []protocol.Part{{Type: "text", Text: "processing"}},
			},
		},
		History: []protocol.Message{
			{Role: "user", Parts: []protocol.Part{{Type: "text", Text: "hello"}}},
		},
		Artifacts: []protocol.Artifact{
			{
				ArtifactID: "art-rt",
				Name:       "output",
				Parts:      []protocol.Part{{Type: "text", Text: "result data"}},
				Index:      1,
			},
		},
	}

	// Convert to proto
	protoTask := taskToProto(original)

	// Verify fields
	if protoTask.GetId() != "roundtrip-task" {
		t.Errorf("ID mismatch: got %q", protoTask.GetId())
	}
	if protoTask.GetSessionId() != "session-rt" {
		t.Errorf("SessionID mismatch: got %q", protoTask.GetSessionId())
	}
	if protoTask.GetStatus().GetState() != "working" {
		t.Errorf("State mismatch: got %q", protoTask.GetStatus().GetState())
	}
	if protoTask.GetStatus().GetMessage().GetRole() != "agent" {
		t.Errorf("Status message role mismatch: got %q", protoTask.GetStatus().GetMessage().GetRole())
	}
	if len(protoTask.GetHistory()) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(protoTask.GetHistory()))
	}
	if protoTask.GetHistory()[0].GetRole() != "user" {
		t.Errorf("history role mismatch: got %q", protoTask.GetHistory()[0].GetRole())
	}
	if len(protoTask.GetArtifacts()) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(protoTask.GetArtifacts()))
	}
	if protoTask.GetArtifacts()[0].GetIndex() != 1 {
		t.Errorf("artifact index mismatch: got %d", protoTask.GetArtifacts()[0].GetIndex())
	}
}

func TestTranslation_PushNotificationConfigRoundTrip(t *testing.T) {
	original := &protocol.PushNotificationConfig{
		URL:   "https://example.com/webhook",
		Token: "token-123",
		Authentication: &protocol.PushNotificationAuthenticationInfo{
			Schemes:     []string{"bearer"},
			Credentials: "secret",
		},
	}

	proto := pushNotifConfigToProto(original)
	if proto.GetUrl() != "https://example.com/webhook" {
		t.Errorf("URL mismatch: got %q", proto.GetUrl())
	}
	if proto.GetToken() != "token-123" {
		t.Errorf("Token mismatch: got %q", proto.GetToken())
	}
	if proto.GetAuthentication().GetCredentials() != "secret" {
		t.Errorf("Credentials mismatch: got %q", proto.GetAuthentication().GetCredentials())
	}

	// Reverse
	back := pushNotifConfigToInternal(proto)
	if back.URL != original.URL {
		t.Errorf("reverse URL mismatch: got %q", back.URL)
	}
	if back.Token != original.Token {
		t.Errorf("reverse Token mismatch: got %q", back.Token)
	}
}

// ── JSON-RPC Translation Tests ──

func TestWrapJSONRPC(t *testing.T) {
	params := map[string]interface{}{"id": "task-1"}
	body, err := wrapJSONRPC("tasks/get", params, 42)
	if err != nil {
		t.Fatalf("wrapJSONRPC failed: %v", err)
	}

	var rpcReq protocol.JSONRPCRequest
	if err := json.Unmarshal(body, &rpcReq); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if rpcReq.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", rpcReq.JSONRPC)
	}
	if rpcReq.Method != "tasks/get" {
		t.Errorf("expected method tasks/get, got %q", rpcReq.Method)
	}
}

func TestUnwrapJSONRPCResult(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "valid result",
			body:    `{"jsonrpc":"2.0","result":{"id":"task-1"},"id":1}`,
			wantErr: false,
		},
		{
			name:    "error response",
			body:    `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":1}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			body:    `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := unwrapJSONRPCResult([]byte(tt.body))
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

// ── gRPC Method Mapping Tests ──

func TestGRPCMethodToA2AMapping(t *testing.T) {
	tests := []struct {
		grpcMethod string
		a2aMethod  string
	}{
		{a2av1.A2AService_SendMessage_FullMethodName, "message/send"},
		{a2av1.A2AService_StreamMessage_FullMethodName, "message/stream"},
		{a2av1.A2AService_GetTask_FullMethodName, "tasks/get"},
		{a2av1.A2AService_CancelTask_FullMethodName, "tasks/cancel"},
		{a2av1.A2AService_SetPushNotificationConfig_FullMethodName, "tasks/pushNotificationConfig/set"},
		{a2av1.A2AService_GetPushNotificationConfig_FullMethodName, "tasks/pushNotificationConfig/get"},
	}

	for _, tt := range tests {
		t.Run(tt.a2aMethod, func(t *testing.T) {
			mapped, ok := grpcMethodToA2A[tt.grpcMethod]
			if !ok {
				t.Fatalf("no mapping for %q", tt.grpcMethod)
			}
			if mapped != tt.a2aMethod {
				t.Errorf("expected %q, got %q", tt.a2aMethod, mapped)
			}
		})
	}
}

// ── HTTP Status to gRPC Code Mapping ──

func TestHTTPStatusToGRPCCode(t *testing.T) {
	tests := []struct {
		httpCode int
		grpcCode codes.Code
	}{
		{400, codes.InvalidArgument},
		{401, codes.Unauthenticated},
		{403, codes.PermissionDenied},
		{404, codes.NotFound},
		{409, codes.AlreadyExists},
		{429, codes.ResourceExhausted},
		{503, codes.Unavailable},
		{500, codes.Internal},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("http_%d", tt.httpCode), func(t *testing.T) {
			got := httpStatusToGRPCCode(tt.httpCode)
			if got != tt.grpcCode {
				t.Errorf("httpStatusToGRPCCode(%d) = %s, want %s", tt.httpCode, got, tt.grpcCode)
			}
		})
	}
}

// ── Backend Error Handling ──

func TestSendMessage_BackendError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer backend.Close()

	client, cleanup := startGRPCServer(t, backend)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.SendMessage(ctx, &a2av1.SendMessageRequest{
		Message: &a2av1.Message{
			Role:  "user",
			Parts: []*a2av1.Part{{Type: "text", Text: "fail"}},
		},
	})

	if err == nil {
		t.Fatal("expected error for backend failure")
	}
	st, _ := status.FromError(err)
	if st.Code() == codes.OK {
		t.Errorf("expected non-OK code, got OK")
	}
}

// ── SSE Parse Tests ──

func TestParseSSEEvent(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		data      string
		wantNil   bool
		wantErr   bool
	}{
		{
			name:      "status event",
			eventType: "status",
			data:      `{"id":"t1","status":{"state":"working"},"final":false}`,
			wantNil:   false,
			wantErr:   false,
		},
		{
			name:      "artifact event",
			eventType: "artifact",
			data:      `{"id":"t1","artifact":{"artifactId":"a1","parts":[{"type":"text","text":"data"}]}}`,
			wantNil:   false,
			wantErr:   false,
		},
		{
			name:      "error event skipped",
			eventType: "error",
			data:      `{"code":500,"message":"oops"}`,
			wantNil:   true,
			wantErr:   false,
		},
		{
			name:      "unknown event skipped",
			eventType: "custom",
			data:      `{}`,
			wantNil:   true,
			wantErr:   false,
		},
		{
			name:      "invalid json",
			eventType: "status",
			data:      `not json`,
			wantNil:   false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt, err := parseSSEEvent(tt.eventType, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if (evt == nil) != tt.wantNil && !tt.wantErr {
				t.Errorf("event nil = %v, wantNil %v", evt == nil, tt.wantNil)
			}
		})
	}
}

// ── SSE to Stream Forwarding ──

func TestForwardSSEToStream(t *testing.T) {
	sseData := strings.Join([]string{
		"event: status",
		`data: {"id":"t1","status":{"state":"working"},"final":false}`,
		"",
		"event: status",
		`data: {"id":"t1","status":{"state":"completed"},"final":true}`,
		"",
	}, "\n")

	reader := strings.NewReader(sseData)
	collector := &streamCollector{}

	logger := testLogger()
	s := &GRPCServer{logger: logger}
	err := s.forwardSSEToStream(reader, collector)
	if err != nil {
		t.Fatalf("forwardSSEToStream failed: %v", err)
	}

	if len(collector.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(collector.events))
	}
}

// ── Config Validation Tests ──

func TestGRPCPort_DisabledByDefault(t *testing.T) {
	cfg := &config.Config{}
	cfg.Agents = []config.AgentConfig{
		{Name: "agent", URL: "http://localhost:8080", Default: true},
	}
	config.ApplyDefaults(cfg)

	if cfg.Listen.GRPCPort != 0 {
		t.Errorf("expected gRPC port 0 (disabled), got %d", cfg.Listen.GRPCPort)
	}
}

// ── Nil safety tests for translate ──

func TestTranslation_NilSafety(t *testing.T) {
	if taskToProto(nil) != nil {
		t.Error("taskToProto(nil) should return nil")
	}
	if taskStatusToProto(nil) != nil {
		t.Error("taskStatusToProto(nil) should return nil")
	}
	if messageToProto(nil) != nil {
		t.Error("messageToProto(nil) should return nil")
	}
	if partToProto(nil) != nil {
		t.Error("partToProto(nil) should return nil")
	}
	if artifactToProto(nil) != nil {
		t.Error("artifactToProto(nil) should return nil")
	}
	if pushNotifConfigToProto(nil) != nil {
		t.Error("pushNotifConfigToProto(nil) should return nil")
	}
	if pushNotifConfigToInternal(nil) != nil {
		t.Error("pushNotifConfigToInternal(nil) should return nil")
	}
	if structToMap(nil) != nil {
		t.Error("structToMap(nil) should return nil")
	}
	if mapToStruct(nil) != nil {
		t.Error("mapToStruct(nil) should return nil")
	}
}

// ── Helpers ──

// mustStruct creates a structpb.Struct from a map, panicking on error.
func mustStruct(m map[string]interface{}) *structpb.Struct {
	s, err := structpb.NewStruct(m)
	if err != nil {
		panic(err)
	}
	return s
}

// streamCollector implements grpc.ServerStreamingServer for testing.
type streamCollector struct {
	grpc.ServerStream
	events []*a2av1.StreamEvent
	ctx    context.Context
}

func (s *streamCollector) Send(evt *a2av1.StreamEvent) error {
	s.events = append(s.events, evt)
	return nil
}

func (s *streamCollector) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}
