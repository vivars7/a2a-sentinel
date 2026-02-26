// Package errors defines sentinel error types with educational messages.
// Every error includes a Hint for developer guidance and a DocsURL for reference.
package errors

import "fmt"

// SentinelError is the base error type for all sentinel errors.
// It includes educational Hint and DocsURL fields for developer guidance.
type SentinelError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	DocsURL string `json:"docs_url,omitempty"`
}

// Error implements the error interface.
func (e *SentinelError) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("[%d] %s (hint: %s)", e.Code, e.Message, e.Hint)
	}
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

// Predefined errors — each includes an educational hint and documentation URL.
var (
	ErrAuthRequired        = &SentinelError{Code: 401, Message: "Authentication required", Hint: "Set Authorization header: 'Bearer <token>'", DocsURL: "https://a2a-sentinel.dev/docs/auth"}
	ErrAuthInvalid         = &SentinelError{Code: 401, Message: "Invalid authentication token", Hint: "Check token expiry and issuer", DocsURL: "https://a2a-sentinel.dev/docs/auth"}
	ErrForbidden           = &SentinelError{Code: 403, Message: "Access denied", Hint: "Check agent permissions and scope configuration", DocsURL: "https://a2a-sentinel.dev/docs/security"}
	ErrRateLimited         = &SentinelError{Code: 429, Message: "Rate limit exceeded", Hint: "Wait before retrying. Configure security.rate_limit in sentinel.yaml", DocsURL: "https://a2a-sentinel.dev/docs/rate-limit"}
	ErrAgentUnavailable    = &SentinelError{Code: 503, Message: "Target agent unavailable", Hint: "Check agent health with GET /readyz", DocsURL: "https://a2a-sentinel.dev/docs/agents"}
	ErrStreamLimitExceeded = &SentinelError{Code: 429, Message: "Too many concurrent streams", Hint: "Max streams per agent reached. Configure agents[].max_streams", DocsURL: "https://a2a-sentinel.dev/docs/streaming"}
	ErrReplayDetected      = &SentinelError{Code: 409, Message: "Replay attack detected", Hint: "Include unique nonce and current timestamp in request", DocsURL: "https://a2a-sentinel.dev/docs/replay"}
	ErrSSRFBlocked         = &SentinelError{Code: 403, Message: "Push notification URL blocked", Hint: "URL resolves to private network. Use public URLs or configure security.push.allowed_domains", DocsURL: "https://a2a-sentinel.dev/docs/ssrf"}
	ErrInvalidRequest      = &SentinelError{Code: 400, Message: "Invalid request format", Hint: "Check A2A protocol specification for correct message format", DocsURL: "https://a2a-sentinel.dev/docs/protocol"}
	ErrNoRoute             = &SentinelError{Code: 404, Message: "No matching agent found", Hint: "Check routing path or set a default agent", DocsURL: "https://a2a-sentinel.dev/docs/routing"}
	ErrGlobalLimitReached  = &SentinelError{Code: 503, Message: "Gateway capacity reached", Hint: "Gateway is at maximum connections. Try again shortly", DocsURL: "https://a2a-sentinel.dev/docs/limits"}
)
