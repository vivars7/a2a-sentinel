package grpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	a2av1 "github.com/vivars7/a2a-sentinel/gen/a2a/v1"
	"github.com/vivars7/a2a-sentinel/internal/config"
	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
	"github.com/vivars7/a2a-sentinel/internal/protocol"
	"github.com/vivars7/a2a-sentinel/internal/proxy"
	"github.com/vivars7/a2a-sentinel/internal/router"
	"github.com/vivars7/a2a-sentinel/internal/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// defaultRequestID is a counter for generating JSON-RPC request IDs.
var requestIDCounter atomic.Int64

// GRPCServer implements the A2AServiceServer interface, translating gRPC
// requests to the internal HTTP proxy pipeline.
type GRPCServer struct {
	a2av1.UnimplementedA2AServiceServer

	cfg       *config.Config
	router    *router.Router
	httpProxy *proxy.HTTPProxy
	sseProxy  *proxy.SSEProxy
	pipeline  []security.Middleware
	logger    *slog.Logger
	server    *grpc.Server
}

// NewGRPCServer creates a new GRPCServer that translates gRPC calls to backend
// HTTP requests through the existing security pipeline, router, and proxy.
func NewGRPCServer(
	cfg *config.Config,
	rtr *router.Router,
	httpProxy *proxy.HTTPProxy,
	sseProxy *proxy.SSEProxy,
	pipeline []security.Middleware,
	logger *slog.Logger,
) *GRPCServer {
	s := &GRPCServer{
		cfg:       cfg,
		router:    rtr,
		httpProxy: httpProxy,
		sseProxy:  sseProxy,
		pipeline:  pipeline,
		logger:    logger,
	}

	// Create gRPC server with security interceptors
	gs := grpc.NewServer(
		grpc.UnaryInterceptor(SecurityUnaryInterceptor(pipeline, logger)),
		grpc.StreamInterceptor(SecurityStreamInterceptor(pipeline, logger)),
	)
	a2av1.RegisterA2AServiceServer(gs, s)
	s.server = gs

	return s
}

// Serve starts the gRPC server on the given listener.
func (s *GRPCServer) Serve(lis net.Listener) error {
	s.logger.Info("gRPC server listening", "addr", lis.Addr().String())
	return s.server.Serve(lis)
}

// GracefulStop performs a graceful shutdown of the gRPC server.
func (s *GRPCServer) GracefulStop() {
	s.server.GracefulStop()
}

// Server returns the underlying grpc.Server for direct access if needed.
func (s *GRPCServer) Server() *grpc.Server {
	return s.server
}

// SendMessage implements the A2AServiceServer SendMessage RPC.
// It translates the gRPC request to a JSON-RPC call, forwards it via HTTP proxy,
// and translates the response back to gRPC.
func (s *GRPCServer) SendMessage(ctx context.Context, req *a2av1.SendMessageRequest) (*a2av1.SendMessageResponse, error) {
	// 1. Translate gRPC request to internal type
	internal, err := sendMessageRequestToInternal(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	// 2. Forward via HTTP and get response
	body, err := s.forwardUnary(ctx, "message/send", internal)
	if err != nil {
		return nil, err
	}

	// 3. Parse response as Task
	var task protocol.Task
	if err := json.Unmarshal(body, &task); err != nil {
		return nil, status.Errorf(codes.Internal, "parsing backend response: %v", err)
	}

	return &a2av1.SendMessageResponse{
		Task: taskToProto(&task),
	}, nil
}

// StreamMessage implements the A2AServiceServer StreamMessage RPC.
// It translates the gRPC request to a JSON-RPC SSE call, reads the SSE stream,
// and sends events back on the gRPC server stream.
func (s *GRPCServer) StreamMessage(req *a2av1.SendMessageRequest, stream grpc.ServerStreamingServer[a2av1.StreamEvent]) error {
	ctx := stream.Context()

	// 1. Translate gRPC request to internal type
	internal, err := sendMessageRequestToInternal(req)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	// 2. Build JSON-RPC request body
	reqID := requestIDCounter.Add(1)
	jsonBody, err := wrapJSONRPC("message/stream", internal, reqID)
	if err != nil {
		return status.Errorf(codes.Internal, "building request: %v", err)
	}

	// 3. Route request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(jsonBody))
	if err != nil {
		return status.Errorf(codes.Internal, "creating request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	target, routeErr := s.router.Route(httpReq)
	if routeErr != nil {
		return sentinelErrorToGRPC(routeErr)
	}

	// 4. Build backend request
	backendURL := s.getBackendURL(target)
	backendReq, err := http.NewRequestWithContext(ctx, http.MethodPost, backendURL+target.Path, bytes.NewReader(jsonBody))
	if err != nil {
		return status.Errorf(codes.Internal, "creating backend request: %v", err)
	}
	backendReq.Header.Set("Content-Type", "application/json")
	backendReq.Header.Set("Accept", "text/event-stream")

	// 5. Execute backend request
	client := &http.Client{Timeout: 0} // no timeout for streaming
	resp, err := client.Do(backendReq)
	if err != nil {
		return status.Errorf(codes.Unavailable, "backend request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return status.Errorf(codes.Internal, "backend returned status %d: %s", resp.StatusCode, string(body))
	}

	// 6. Read SSE events and forward as gRPC stream events
	return s.forwardSSEToStream(resp.Body, stream)
}

// GetTask implements the A2AServiceServer GetTask RPC.
func (s *GRPCServer) GetTask(ctx context.Context, req *a2av1.GetTaskRequest) (*a2av1.GetTaskResponse, error) {
	params := map[string]interface{}{
		"id": req.GetTaskId(),
	}
	if req.HistoryLength != nil {
		params["historyLength"] = req.GetHistoryLength()
	}

	body, err := s.forwardUnary(ctx, "tasks/get", params)
	if err != nil {
		return nil, err
	}

	var task protocol.Task
	if err := json.Unmarshal(body, &task); err != nil {
		return nil, status.Errorf(codes.Internal, "parsing backend response: %v", err)
	}

	return &a2av1.GetTaskResponse{
		Task: taskToProto(&task),
	}, nil
}

// CancelTask implements the A2AServiceServer CancelTask RPC.
func (s *GRPCServer) CancelTask(ctx context.Context, req *a2av1.CancelTaskRequest) (*a2av1.CancelTaskResponse, error) {
	params := map[string]interface{}{
		"id": req.GetTaskId(),
	}

	body, err := s.forwardUnary(ctx, "tasks/cancel", params)
	if err != nil {
		return nil, err
	}

	var task protocol.Task
	if err := json.Unmarshal(body, &task); err != nil {
		return nil, status.Errorf(codes.Internal, "parsing backend response: %v", err)
	}

	return &a2av1.CancelTaskResponse{
		Task: taskToProto(&task),
	}, nil
}

// SetPushNotificationConfig implements the A2AServiceServer SetPushNotificationConfig RPC.
func (s *GRPCServer) SetPushNotificationConfig(ctx context.Context, req *a2av1.SetPushNotifRequest) (*a2av1.PushNotificationConfig, error) {
	params := map[string]interface{}{
		"id":     req.GetTaskId(),
		"config": pushNotifConfigToInternal(req.GetConfig()),
	}

	body, err := s.forwardUnary(ctx, "tasks/pushNotificationConfig/set", params)
	if err != nil {
		return nil, err
	}

	var cfg protocol.PushNotificationConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, status.Errorf(codes.Internal, "parsing backend response: %v", err)
	}

	return pushNotifConfigToProto(&cfg), nil
}

// GetPushNotificationConfig implements the A2AServiceServer GetPushNotificationConfig RPC.
func (s *GRPCServer) GetPushNotificationConfig(ctx context.Context, req *a2av1.GetPushNotifRequest) (*a2av1.PushNotificationConfig, error) {
	params := map[string]interface{}{
		"id": req.GetTaskId(),
	}

	body, err := s.forwardUnary(ctx, "tasks/pushNotificationConfig/get", params)
	if err != nil {
		return nil, err
	}

	var cfg protocol.PushNotificationConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, status.Errorf(codes.Internal, "parsing backend response: %v", err)
	}

	return pushNotifConfigToProto(&cfg), nil
}

// ── Internal helpers ──

// forwardUnary wraps params in JSON-RPC, routes the request, forwards via HTTP,
// and extracts the JSON-RPC result.
func (s *GRPCServer) forwardUnary(ctx context.Context, a2aMethod string, params interface{}) (json.RawMessage, error) {
	// 1. Build JSON-RPC request
	reqID := requestIDCounter.Add(1)
	jsonBody, err := wrapJSONRPC(a2aMethod, params, reqID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "building request: %v", err)
	}

	// 2. Create synthetic HTTP request for routing
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// 3. Route request
	target, routeErr := s.router.Route(httpReq)
	if routeErr != nil {
		return nil, sentinelErrorToGRPC(routeErr)
	}

	// 4. Build and execute backend request
	backendURL := s.getBackendURL(target)
	backendReq, err := http.NewRequestWithContext(ctx, http.MethodPost, backendURL+target.Path, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating backend request: %v", err)
	}
	backendReq.Header.Set("Content-Type", "application/json")

	timeout := s.getAgentTimeout(target.AgentName)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(backendReq)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "backend request failed: %v", err)
	}
	defer resp.Body.Close()

	// 5. Read response
	const maxResponseSize = 10 * 1024 * 1024 // 10MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reading backend response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Internal, "backend returned status %d: %s", resp.StatusCode, string(body))
	}

	// 6. Unwrap JSON-RPC response
	result, err := unwrapJSONRPCResult(body)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unwrapping response: %v", err)
	}

	return result, nil
}

// forwardSSEToStream reads SSE events from an HTTP response body and sends them
// as gRPC stream events.
func (s *GRPCServer) forwardSSEToStream(body io.Reader, stream grpc.ServerStreamingServer[a2av1.StreamEvent]) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var eventType string
	var dataLines []string

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line = end of event
		if line == "" {
			if len(dataLines) > 0 {
				data := strings.Join(dataLines, "\n")
				evt, err := parseSSEEvent(eventType, data)
				if err != nil {
					s.logger.Warn("failed to parse SSE event",
						slog.String("event_type", eventType),
						slog.String("error", err.Error()),
					)
				} else if evt != nil {
					if err := stream.Send(evt); err != nil {
						return fmt.Errorf("sending stream event: %w", err)
					}
				}
			}
			eventType = ""
			dataLines = nil
			continue
		}

		// Parse SSE field
		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
		// Ignore id:, retry:, and comment lines
	}

	// Flush any remaining event data (stream may end without trailing blank line)
	if len(dataLines) > 0 {
		data := strings.Join(dataLines, "\n")
		evt, err := parseSSEEvent(eventType, data)
		if err != nil {
			s.logger.Warn("failed to parse final SSE event",
				slog.String("event_type", eventType),
				slog.String("error", err.Error()),
			)
		} else if evt != nil {
			if err := stream.Send(evt); err != nil {
				return fmt.Errorf("sending final stream event: %w", err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return status.Errorf(codes.Internal, "reading SSE stream: %v", err)
	}

	return nil
}

// parseSSEEvent converts an SSE event into a gRPC StreamEvent.
func parseSSEEvent(eventType string, data string) (*a2av1.StreamEvent, error) {
	switch eventType {
	case "status", "":
		var evt protocol.TaskStatusUpdateEvent
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			return nil, fmt.Errorf("parsing status event: %w", err)
		}
		return &a2av1.StreamEvent{
			Event: &a2av1.StreamEvent_StatusUpdate{
				StatusUpdate: taskStatusUpdateEventToProto(&evt),
			},
		}, nil

	case "artifact":
		var evt protocol.TaskArtifactUpdateEvent
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			return nil, fmt.Errorf("parsing artifact event: %w", err)
		}
		return &a2av1.StreamEvent{
			Event: &a2av1.StreamEvent_ArtifactUpdate{
				ArtifactUpdate: taskArtifactUpdateEventToProto(&evt),
			},
		}, nil

	case "error":
		// Log and skip error events; they don't map to StreamEvent
		return nil, nil

	default:
		// Unknown event type; skip
		return nil, nil
	}
}

// getBackendURL returns the appropriate backend URL for the target.
// Prefers the gRPC URL if configured, otherwise falls back to HTTP URL.
func (s *GRPCServer) getBackendURL(target *router.RouteTarget) string {
	// Check if agent has a specific gRPC URL configured
	for _, a := range s.cfg.Agents {
		if a.Name == target.AgentName && a.GRPCURL != "" {
			return a.GRPCURL
		}
	}
	return target.AgentURL
}

// getAgentTimeout returns the configured timeout for an agent.
func (s *GRPCServer) getAgentTimeout(agentName string) time.Duration {
	for _, a := range s.cfg.Agents {
		if a.Name == agentName {
			return a.Timeout.Duration
		}
	}
	return 30 * time.Second // default
}

// sentinelErrorToGRPC converts a SentinelError to a gRPC status error.
// It preserves the hint and docs_url in the error message for educational errors.
func sentinelErrorToGRPC(err error) error {
	sentErr, ok := err.(*sentinelerrors.SentinelError)
	if !ok {
		return status.Errorf(codes.Internal, "%v", err)
	}
	code := httpStatusToGRPCCode(sentErr.Code)
	msg := sentErr.Message
	if sentErr.Hint != "" {
		msg += " (hint: " + sentErr.Hint + ")"
	}
	if sentErr.DocsURL != "" {
		msg += " [docs: " + sentErr.DocsURL + "]"
	}
	return status.Errorf(code, "%s", msg)
}
