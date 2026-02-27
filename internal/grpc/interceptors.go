package grpc

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/vivars7/a2a-sentinel/internal/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// SecurityUnaryInterceptor returns a gRPC unary server interceptor that applies
// the existing security middleware pipeline. It creates a synthetic http.Request
// from gRPC metadata so the HTTP-based security middlewares can process it.
func SecurityUnaryInterceptor(middlewares []security.Middleware, logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Build synthetic HTTP request from gRPC metadata
		httpReq := buildSyntheticRequest(ctx, info.FullMethod)

		// Apply security pipeline
		err := applySecurityPipeline(httpReq, middlewares)
		if err != nil {
			logger.Warn("gRPC security pipeline rejected request",
				slog.String("method", info.FullMethod),
				slog.String("error", err.Error()),
			)
			return nil, err
		}

		// Propagate security context values to the gRPC context
		ctx = propagateSecurityContext(ctx, httpReq)

		return handler(ctx, req)
	}
}

// SecurityStreamInterceptor returns a gRPC stream server interceptor that applies
// the existing security middleware pipeline. It creates a synthetic http.Request
// from gRPC metadata so the HTTP-based security middlewares can process it.
func SecurityStreamInterceptor(middlewares []security.Middleware, logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()

		// Build synthetic HTTP request from gRPC metadata
		httpReq := buildSyntheticRequest(ctx, info.FullMethod)

		// Apply security pipeline
		err := applySecurityPipeline(httpReq, middlewares)
		if err != nil {
			logger.Warn("gRPC stream security pipeline rejected request",
				slog.String("method", info.FullMethod),
				slog.String("error", err.Error()),
			)
			return err
		}

		// Wrap the stream with updated context
		ctx = propagateSecurityContext(ctx, httpReq)
		wrappedStream := &contextServerStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		return handler(srv, wrappedStream)
	}
}

// buildSyntheticRequest creates an http.Request from gRPC metadata.
// This allows reuse of the existing HTTP-based security middlewares.
func buildSyntheticRequest(ctx context.Context, fullMethod string) *http.Request {
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/"+fullMethod, io.NopCloser(bytes.NewReader(nil)))

	// Copy gRPC metadata to HTTP headers
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		for key, values := range md {
			for _, v := range values {
				httpReq.Header.Add(key, v)
			}
		}
	}

	// Set RemoteAddr from peer info for IP-based rate limiting
	if p, ok := peer.FromContext(ctx); ok {
		httpReq.RemoteAddr = p.Addr.String()
	}

	return httpReq
}

// applySecurityPipeline runs the HTTP security pipeline against a synthetic request.
// Returns a gRPC status error if the pipeline rejects the request.
func applySecurityPipeline(req *http.Request, middlewares []security.Middleware) error {
	// Build the pipeline with a pass-through handler at the end
	passed := false
	passHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passed = true
		// Update the original request's context with any values set by middlewares
		*req = *r
	})

	handler := security.ApplyPipeline(passHandler, middlewares)

	// Execute the pipeline with a recorder to capture any error response
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if !passed {
		// Pipeline rejected the request; map HTTP status to gRPC code
		code := httpStatusToGRPCCode(recorder.Code)
		return status.Errorf(code, "%s", recorder.Body.String())
	}

	return nil
}

// propagateSecurityContext copies security-related context values from the
// synthetic HTTP request context to the gRPC context.
func propagateSecurityContext(grpcCtx context.Context, httpReq *http.Request) context.Context {
	// The security middlewares store AuthInfo and other values in the request context.
	// We need to propagate those to the gRPC context.
	httpCtx := httpReq.Context()

	// Use type assertion to transfer all context values.
	// Since ctxkeys uses unexported key types, we wrap the gRPC context
	// to delegate Value() lookups to the HTTP context for security keys.
	return &mergedContext{
		Context: grpcCtx,
		httpCtx: httpCtx,
	}
}

// mergedContext merges two contexts: it uses the gRPC context for deadlines
// and cancellation, but falls back to the HTTP context for Value() lookups.
type mergedContext struct {
	context.Context
	httpCtx context.Context
}

// Value returns the value from the gRPC context first, then falls back to the HTTP context.
func (c *mergedContext) Value(key interface{}) interface{} {
	if v := c.Context.Value(key); v != nil {
		return v
	}
	return c.httpCtx.Value(key)
}

// httpStatusToGRPCCode maps HTTP status codes to gRPC status codes.
func httpStatusToGRPCCode(httpCode int) codes.Code {
	switch httpCode {
	case http.StatusBadRequest:
		return codes.InvalidArgument
	case http.StatusUnauthorized:
		return codes.Unauthenticated
	case http.StatusForbidden:
		return codes.PermissionDenied
	case http.StatusNotFound:
		return codes.NotFound
	case http.StatusConflict:
		return codes.AlreadyExists
	case http.StatusTooManyRequests:
		return codes.ResourceExhausted
	case http.StatusBadGateway:
		return codes.Unavailable
	case http.StatusServiceUnavailable:
		return codes.Unavailable
	default:
		return codes.Internal
	}
}

// contextServerStream wraps a grpc.ServerStream with a custom context.
type contextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context.
func (s *contextServerStream) Context() context.Context {
	return s.ctx
}
