package ctxkeys

import (
	"context"
	"testing"
	"time"
)

func TestAuthInfoRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		info AuthInfo
	}{
		{
			name: "passthrough mode",
			info: AuthInfo{Mode: "passthrough", Subject: "user@example.com", Scheme: "bearer", SubjectVerified: false},
		},
		{
			name: "terminate mode with verified subject",
			info: AuthInfo{Mode: "terminate", Subject: "client_abc", Scheme: "apikey", SubjectVerified: true},
		},
		{
			name: "zero value",
			info: AuthInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithAuthInfo(context.Background(), tt.info)
			got, ok := AuthInfoFrom(ctx)
			if !ok {
				t.Fatal("expected ok=true, got false")
			}
			if got != tt.info {
				t.Errorf("got %+v, want %+v", got, tt.info)
			}
		})
	}
}

func TestAuthInfoFromEmptyContext(t *testing.T) {
	got, ok := AuthInfoFrom(context.Background())
	if ok {
		t.Fatal("expected ok=false for empty context")
	}
	if got != (AuthInfo{}) {
		t.Errorf("expected zero AuthInfo, got %+v", got)
	}
}

func TestAuditEntryRoundTrip(t *testing.T) {
	entry := &AuditEntry{
		TraceID:        "trace-123",
		SpanID:         "span-456",
		Method:         "message/send",
		Protocol:       "jsonrpc",
		TargetAgent:    "agent-1",
		AuthScheme:     "bearer",
		AuthSubject:    "user@example.com",
		Status:         "ok",
		StartTime:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		StreamEvents:   42,
		StreamDuration: 5 * time.Second,
	}

	ctx := WithAuditEntry(context.Background(), entry)
	got, ok := AuditEntryFrom(ctx)
	if !ok {
		t.Fatal("expected ok=true, got false")
	}
	if got != entry {
		t.Error("expected same pointer")
	}
	if got.TraceID != "trace-123" {
		t.Errorf("TraceID: got %q, want %q", got.TraceID, "trace-123")
	}
}

func TestAuditEntryPointerMutation(t *testing.T) {
	entry := &AuditEntry{Status: "pending"}
	ctx := WithAuditEntry(context.Background(), entry)

	// Mutate the original pointer
	entry.Status = "ok"
	entry.StreamEvents = 10

	got, ok := AuditEntryFrom(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got.Status != "ok" {
		t.Errorf("Status: got %q, want %q (mutation should propagate)", got.Status, "ok")
	}
	if got.StreamEvents != 10 {
		t.Errorf("StreamEvents: got %d, want %d", got.StreamEvents, 10)
	}
}

func TestAuditEntryFromEmptyContext(t *testing.T) {
	got, ok := AuditEntryFrom(context.Background())
	if ok {
		t.Fatal("expected ok=false for empty context")
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestRouteResultRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		result RouteResult
	}{
		{
			name:   "streaming route",
			result: RouteResult{AgentName: "echo", AgentURL: "http://localhost:8080", MatchedSkill: "chat", IsStreaming: true},
		},
		{
			name:   "non-streaming route",
			result: RouteResult{AgentName: "math", AgentURL: "http://localhost:9090", MatchedSkill: "calculate", IsStreaming: false},
		},
		{
			name:   "zero value",
			result: RouteResult{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithRouteResult(context.Background(), tt.result)
			got, ok := RouteResultFrom(ctx)
			if !ok {
				t.Fatal("expected ok=true, got false")
			}
			if got != tt.result {
				t.Errorf("got %+v, want %+v", got, tt.result)
			}
		})
	}
}

func TestRouteResultFromEmptyContext(t *testing.T) {
	got, ok := RouteResultFrom(context.Background())
	if ok {
		t.Fatal("expected ok=false for empty context")
	}
	if got != (RouteResult{}) {
		t.Errorf("expected zero RouteResult, got %+v", got)
	}
}

func TestRequestMetaRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		meta RequestMeta
	}{
		{
			name: "jsonrpc binding",
			meta: RequestMeta{Protocol: "jsonrpc", Method: "message/send", Binding: "jsonrpc"},
		},
		{
			name: "rest binding",
			meta: RequestMeta{Protocol: "rest", Method: "tasks/get", Binding: "rest"},
		},
		{
			name: "agentcard",
			meta: RequestMeta{Protocol: "agentcard", Method: "", Binding: ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithRequestMeta(context.Background(), tt.meta)
			got, ok := RequestMetaFrom(ctx)
			if !ok {
				t.Fatal("expected ok=true, got false")
			}
			if got != tt.meta {
				t.Errorf("got %+v, want %+v", got, tt.meta)
			}
		})
	}
}

func TestRequestMetaFromEmptyContext(t *testing.T) {
	got, ok := RequestMetaFrom(context.Background())
	if ok {
		t.Fatal("expected ok=false for empty context")
	}
	if got != (RequestMeta{}) {
		t.Errorf("expected zero RequestMeta, got %+v", got)
	}
}

func TestInspectedBodyRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "json body",
			body: []byte(`{"jsonrpc":"2.0","method":"message/send"}`),
		},
		{
			name: "empty body",
			body: []byte{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithInspectedBody(context.Background(), tt.body)
			got, ok := InspectedBodyFrom(ctx)
			if !ok {
				t.Fatal("expected ok=true, got false")
			}
			if string(got) != string(tt.body) {
				t.Errorf("got %q, want %q", got, tt.body)
			}
		})
	}
}

func TestInspectedBodyFromEmptyContext(t *testing.T) {
	got, ok := InspectedBodyFrom(context.Background())
	if ok {
		t.Fatal("expected ok=false for empty context")
	}
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestKeysDontInterfere(t *testing.T) {
	authInfo := AuthInfo{Mode: "terminate", Subject: "user@test.com", Scheme: "bearer", SubjectVerified: true}
	entry := &AuditEntry{TraceID: "t-1", Method: "message/send"}
	route := RouteResult{AgentName: "echo", AgentURL: "http://localhost:8080"}
	meta := RequestMeta{Protocol: "jsonrpc", Method: "message/send", Binding: "jsonrpc"}
	body := []byte(`{"test":true}`)

	ctx := context.Background()
	ctx = WithAuthInfo(ctx, authInfo)
	ctx = WithAuditEntry(ctx, entry)
	ctx = WithRouteResult(ctx, route)
	ctx = WithRequestMeta(ctx, meta)
	ctx = WithInspectedBody(ctx, body)

	// Verify each key retrieves its own value
	gotAuth, ok := AuthInfoFrom(ctx)
	if !ok || gotAuth != authInfo {
		t.Errorf("AuthInfo: got %+v, want %+v", gotAuth, authInfo)
	}

	gotEntry, ok := AuditEntryFrom(ctx)
	if !ok || gotEntry != entry {
		t.Errorf("AuditEntry: got %+v, want %+v", gotEntry, entry)
	}

	gotRoute, ok := RouteResultFrom(ctx)
	if !ok || gotRoute != route {
		t.Errorf("RouteResult: got %+v, want %+v", gotRoute, route)
	}

	gotMeta, ok := RequestMetaFrom(ctx)
	if !ok || gotMeta != meta {
		t.Errorf("RequestMeta: got %+v, want %+v", gotMeta, meta)
	}

	gotBody, ok := InspectedBodyFrom(ctx)
	if !ok || string(gotBody) != string(body) {
		t.Errorf("InspectedBody: got %q, want %q", gotBody, body)
	}
}
