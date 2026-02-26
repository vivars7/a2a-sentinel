// Package ctxkeys defines context keys for passing data through the request pipeline.
// All context keys are unexported to prevent collisions. Use the With*/From accessor pairs.
package ctxkeys

import (
	"context"
	"time"
)

// ── Key types (unexported, collision-proof) ──

type authInfoKey struct{}
type auditEntryKey struct{}
type routeResultKey struct{}
type requestMetaKey struct{}
type inspectedBodyKey struct{} // v3: Body Inspection result

// ── Data types ──

// AuthInfo holds authentication information extracted by the security middleware.
type AuthInfo struct {
	Mode            string // "passthrough", "passthrough-strict", "terminate"
	Subject         string // authenticated user identifier (email, client_id, etc.)
	Scheme          string // "bearer", "apikey", "basic", etc.
	SubjectVerified bool   // v3: true only in terminate mode
}

// AuditEntry holds audit log data accumulated during request processing.
type AuditEntry struct {
	TraceID     string
	SpanID      string
	Method      string // A2A method (message/send, tasks/get, etc.)
	Protocol    string // "jsonrpc", "rest", "agentcard"
	TargetAgent string
	AuthScheme  string
	AuthSubject string
	Status      string // "ok", "blocked", "error"
	BlockReason string
	StartTime   time.Time
	// Streaming-specific
	StreamEvents   int
	StreamDuration time.Duration
}

// RouteResult holds the routing decision for a request.
type RouteResult struct {
	AgentName    string
	AgentURL     string
	MatchedSkill string
	IsStreaming  bool
}

// RequestMeta holds protocol detection results.
type RequestMeta struct {
	Protocol string // "jsonrpc", "rest", "agentcard"
	Method   string // "message/send", etc.
	Binding  string // "jsonrpc", "rest"
}

// ── Getter/Setter (With*/From pattern) ──

// WithAuthInfo stores AuthInfo in the context.
func WithAuthInfo(ctx context.Context, info AuthInfo) context.Context {
	return context.WithValue(ctx, authInfoKey{}, info)
}

// AuthInfoFrom retrieves AuthInfo from the context.
func AuthInfoFrom(ctx context.Context) (AuthInfo, bool) {
	info, ok := ctx.Value(authInfoKey{}).(AuthInfo)
	return info, ok
}

// WithAuditEntry stores an AuditEntry pointer in the context.
func WithAuditEntry(ctx context.Context, entry *AuditEntry) context.Context {
	return context.WithValue(ctx, auditEntryKey{}, entry)
}

// AuditEntryFrom retrieves the AuditEntry pointer from the context.
func AuditEntryFrom(ctx context.Context) (*AuditEntry, bool) {
	entry, ok := ctx.Value(auditEntryKey{}).(*AuditEntry)
	return entry, ok
}

// WithRouteResult stores RouteResult in the context.
func WithRouteResult(ctx context.Context, result RouteResult) context.Context {
	return context.WithValue(ctx, routeResultKey{}, result)
}

// RouteResultFrom retrieves RouteResult from the context.
func RouteResultFrom(ctx context.Context) (RouteResult, bool) {
	result, ok := ctx.Value(routeResultKey{}).(RouteResult)
	return result, ok
}

// WithRequestMeta stores RequestMeta in the context.
func WithRequestMeta(ctx context.Context, meta RequestMeta) context.Context {
	return context.WithValue(ctx, requestMetaKey{}, meta)
}

// RequestMetaFrom retrieves RequestMeta from the context.
func RequestMetaFrom(ctx context.Context) (RequestMeta, bool) {
	meta, ok := ctx.Value(requestMetaKey{}).(RequestMeta)
	return meta, ok
}

// WithInspectedBody stores the inspected body bytes in the context.
func WithInspectedBody(ctx context.Context, body []byte) context.Context {
	return context.WithValue(ctx, inspectedBodyKey{}, body)
}

// InspectedBodyFrom retrieves the inspected body bytes from the context.
func InspectedBodyFrom(ctx context.Context) ([]byte, bool) {
	body, ok := ctx.Value(inspectedBodyKey{}).([]byte)
	return body, ok
}
