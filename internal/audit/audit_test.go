package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
)

// captureLog runs fn with a JSON slog logger writing to a buffer and returns the output.
func captureLog(fn func(*slog.Logger)) string {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	fn(logger)
	return buf.String()
}

func makeEntry() *ctxkeys.AuditEntry {
	return &ctxkeys.AuditEntry{
		TraceID:     "trace-abc",
		SpanID:      "span-xyz",
		Method:      "message/send",
		Protocol:    "jsonrpc",
		TargetAgent: "agent-1",
		AuthScheme:  "bearer",
		AuthSubject: "user@example.com",
		Status:      "ok",
		BlockReason: "",
		StartTime:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestLogRequest_Normal(t *testing.T) {
	entry := makeEntry()
	ctx := ctxkeys.WithAuditEntry(context.Background(), entry)

	output := captureLog(func(logger *slog.Logger) {
		l := NewLogger(logger, SamplingConfig{Rate: 1.0, ErrorRate: 1.0})
		l.LogRequest(ctx)
	})

	if output == "" {
		t.Fatal("expected log output, got empty string")
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(output), &m); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %s", err, output)
	}

	checks := map[string]string{
		"trace_id": "trace-abc",
		"span_id":  "span-xyz",
	}
	for k, want := range checks {
		got, ok := m[k]
		if !ok {
			t.Errorf("missing field %q", k)
			continue
		}
		if got != want {
			t.Errorf("field %q: got %q, want %q", k, got, want)
		}
	}

	attrs, ok := m["attributes"].(map[string]any)
	if !ok {
		t.Fatal("missing 'attributes' group in log output")
	}
	attrChecks := map[string]string{
		"a2a.method":       "message/send",
		"a2a.protocol":     "jsonrpc",
		"a2a.target_agent": "agent-1",
		"a2a.auth.scheme":  "bearer",
		"a2a.auth.subject": "user@example.com",
		"a2a.status":       "ok",
	}
	for k, want := range attrChecks {
		got, ok := attrs[k]
		if !ok {
			t.Errorf("missing attribute %q", k)
			continue
		}
		if got != want {
			t.Errorf("attribute %q: got %q, want %q", k, got, want)
		}
	}
}

func TestLogRequest_Blocked(t *testing.T) {
	entry := makeEntry()
	entry.Status = "blocked"
	entry.BlockReason = "rate_limit_exceeded"
	ctx := ctxkeys.WithAuditEntry(context.Background(), entry)

	output := captureLog(func(logger *slog.Logger) {
		l := NewLogger(logger, SamplingConfig{Rate: 1.0, ErrorRate: 1.0})
		l.LogRequest(ctx)
	})

	if output == "" {
		t.Fatal("expected log output for blocked request")
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(output), &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	attrs, ok := m["attributes"].(map[string]any)
	if !ok {
		t.Fatal("missing 'attributes' group")
	}
	if attrs["a2a.block_reason"] != "rate_limit_exceeded" {
		t.Errorf("block_reason: got %v, want rate_limit_exceeded", attrs["a2a.block_reason"])
	}
	if attrs["a2a.status"] != "blocked" {
		t.Errorf("status: got %v, want blocked", attrs["a2a.status"])
	}
}

func TestLogRequest_Streaming(t *testing.T) {
	entry := makeEntry()
	entry.StreamEvents = 42
	entry.StreamDuration = 500 * time.Millisecond
	ctx := ctxkeys.WithAuditEntry(context.Background(), entry)

	output := captureLog(func(logger *slog.Logger) {
		l := NewLogger(logger, SamplingConfig{Rate: 1.0, ErrorRate: 1.0})
		l.LogRequest(ctx)
	})

	if output == "" {
		t.Fatal("expected log output for streaming request")
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(output), &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	stream, ok := m["stream"].(map[string]any)
	if !ok {
		t.Fatal("missing 'stream' group in log output")
	}
	// JSON numbers decode as float64
	if stream["events"] != float64(42) {
		t.Errorf("stream.events: got %v, want 42", stream["events"])
	}
	if stream["duration_ms"] != float64(500) {
		t.Errorf("stream.duration_ms: got %v, want 500", stream["duration_ms"])
	}
}

func TestLogRequest_NoEntry(t *testing.T) {
	ctx := context.Background() // no audit entry

	output := captureLog(func(logger *slog.Logger) {
		l := NewLogger(logger, SamplingConfig{Rate: 1.0, ErrorRate: 1.0})
		l.LogRequest(ctx)
	})

	if output != "" {
		t.Errorf("expected no log output for empty context, got: %s", output)
	}
}

func TestSampling_AlwaysLog(t *testing.T) {
	s := SamplingConfig{Rate: 1.0, ErrorRate: 1.0}
	for i := 0; i < 100; i++ {
		if !s.ShouldLog("ok") {
			t.Errorf("Rate=1.0 should always log, failed at iteration %d", i)
		}
	}
}

func TestSampling_NeverLog(t *testing.T) {
	s := SamplingConfig{Rate: 0.0, ErrorRate: 0.0}
	for i := 0; i < 100; i++ {
		if s.ShouldLog("ok") {
			t.Errorf("Rate=0.0 should never log, passed at iteration %d", i)
		}
	}
}

func TestSampling_ErrorAlwaysLog(t *testing.T) {
	s := SamplingConfig{Rate: 0.0, ErrorRate: 1.0}
	for i := 0; i < 100; i++ {
		if s.ShouldLog("ok") {
			t.Errorf("Rate=0.0 should never log normal, passed at iteration %d", i)
		}
		if !s.ShouldLog("error") {
			t.Errorf("ErrorRate=1.0 should always log errors, failed at iteration %d", i)
		}
		if !s.ShouldLog("blocked") {
			t.Errorf("ErrorRate=1.0 should always log blocked, failed at iteration %d", i)
		}
	}
}

func TestTruncateBody(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		maxSize int
		want    string
	}{
		{
			name:    "within limit",
			body:    []byte("hello"),
			maxSize: 10,
			want:    "hello",
		},
		{
			name:    "exact limit",
			body:    []byte("hello"),
			maxSize: 5,
			want:    "hello",
		},
		{
			name:    "exceeds limit",
			body:    []byte("hello world"),
			maxSize: 5,
			want:    "hello...(truncated)",
		},
		{
			name:    "empty body",
			body:    []byte{},
			maxSize: 10,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateBody(tt.body, tt.maxSize)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSampling_HalfRate(t *testing.T) {
	s := SamplingConfig{Rate: 0.5, ErrorRate: 1.0}
	count := 0
	const n = 1000
	for i := 0; i < n; i++ {
		if s.ShouldLog("ok") {
			count++
		}
	}
	// Expect roughly 500, allow 400-600 (±20%)
	if count < 400 || count > 600 {
		t.Errorf("Rate=0.5: expected 400-600 logs out of 1000, got %d", count)
	}
}

// TestLogRequest_SamplingSkip covers the path where ShouldLog returns false.
func TestLogRequest_SamplingSkip(t *testing.T) {
	entry := makeEntry()
	entry.Status = "ok"
	ctx := ctxkeys.WithAuditEntry(context.Background(), entry)

	output := captureLog(func(logger *slog.Logger) {
		// Rate=0.0 means normal requests are never logged.
		l := NewLogger(logger, SamplingConfig{Rate: 0.0, ErrorRate: 1.0})
		l.LogRequest(ctx)
	})

	if output != "" {
		t.Errorf("expected no log output when sampling skips, got: %s", output)
	}
}

func TestLogRequest_OTelFieldNames(t *testing.T) {
	entry := makeEntry()
	ctx := ctxkeys.WithAuditEntry(context.Background(), entry)

	output := captureLog(func(logger *slog.Logger) {
		l := NewLogger(logger, SamplingConfig{Rate: 1.0, ErrorRate: 1.0})
		l.LogRequest(ctx)
	})

	// OTel convention: snake_case, not camelCase
	otelFields := []string{"trace_id", "span_id"}
	for _, field := range otelFields {
		if !strings.Contains(output, `"`+field+`"`) {
			t.Errorf("OTel field %q not found in output: %s", field, output)
		}
	}

	// Must NOT use camelCase variants
	antiPatterns := []string{"traceId", "spanId", "traceID", "spanID"}
	for _, bad := range antiPatterns {
		if strings.Contains(output, `"`+bad+`"`) {
			t.Errorf("found non-OTel camelCase field %q in output: %s", bad, output)
		}
	}

	// Attributes must use dot-separated OTel convention under "attributes" group
	if !strings.Contains(output, `"a2a.method"`) {
		t.Errorf("OTel attribute 'a2a.method' not found in output: %s", output)
	}
	if !strings.Contains(output, `"attributes"`) {
		t.Errorf("'attributes' group not found in output: %s", output)
	}
}
