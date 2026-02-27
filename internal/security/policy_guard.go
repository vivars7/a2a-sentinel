package security

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
)

// policyViolationCode is the JSON-RPC error code for policy violations.
const policyViolationCode = -32001

// policyDocsURL is the documentation URL included in policy violation errors.
const policyDocsURL = "https://github.com/vivars7/a2a-sentinel/blob/main/docs/SECURITY.md#policy-engine"

// PolicyGuard is a security middleware that enforces ABAC policies.
// It evaluates each request against the configured PolicyEngine and blocks
// requests that match a "deny" policy.
type PolicyGuard struct {
	engine *PolicyEngine
	logger *slog.Logger
}

// NewPolicyGuard creates a PolicyGuard middleware from a PolicyEngine.
func NewPolicyGuard(engine *PolicyEngine, logger *slog.Logger) *PolicyGuard {
	if logger == nil {
		logger = slog.Default()
	}
	return &PolicyGuard{
		engine: engine,
		logger: logger,
	}
}

// Name returns the middleware name.
func (g *PolicyGuard) Name() string {
	return "policy_guard"
}

// Process returns an http.Handler that evaluates ABAC policies.
// It extracts request attributes from the context (AuthInfo, RouteResult,
// RequestMeta) and the HTTP request itself to build a PolicyRequest.
func (g *PolicyGuard) Process(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := g.buildPolicyRequest(r)
		decision := g.engine.Evaluate(r.Context(), req)

		if decision.Action == "deny" {
			g.logger.Warn("request blocked by policy",
				"policy", decision.MatchedPolicy,
				"user", req.User,
				"ip", req.IP,
				"agent", req.Agent,
				"method", req.Method,
			)
			sentinelerrors.WriteHTTPError(w, &sentinelerrors.SentinelError{
				Code:    403,
				Message: "Request blocked by policy",
				Hint:    fmt.Sprintf("Request blocked by policy '%s'. Contact your administrator.", decision.MatchedPolicy),
				DocsURL: policyDocsURL,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// buildPolicyRequest extracts all relevant attributes from the HTTP request
// and its context to construct a PolicyRequest for evaluation.
func (g *PolicyGuard) buildPolicyRequest(r *http.Request) *PolicyRequest {
	req := &PolicyRequest{
		Headers: r.Header,
		Time:    time.Now(),
		IP:      stripPort(r.RemoteAddr),
	}

	// Extract agent from RouteResult (set by router)
	if route, ok := ctxkeys.RouteResultFrom(r.Context()); ok {
		req.Agent = route.AgentName
	} else {
		// Fallback: use request path
		req.Agent = r.URL.Path
	}

	// Extract method from RequestMeta (set by protocol detector)
	if meta, ok := ctxkeys.RequestMetaFrom(r.Context()); ok {
		req.Method = meta.Method
	}

	// Extract user from AuthInfo (set by AuthMiddleware)
	if auth, ok := ctxkeys.AuthInfoFrom(r.Context()); ok {
		req.User = auth.Subject
	}

	return req
}
