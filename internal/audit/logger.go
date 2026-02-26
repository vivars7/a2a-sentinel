package audit

import (
	"context"
	"log/slog"

	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
)

// Logger provides OpenTelemetry-compatible structured audit logging.
type Logger struct {
	slogger  *slog.Logger
	sampling SamplingConfig
}

// NewLogger creates an audit logger with the given sampling configuration.
func NewLogger(slogger *slog.Logger, sampling SamplingConfig) *Logger {
	return &Logger{slogger: slogger, sampling: sampling}
}

// LogRequest logs an audit entry from the request context.
// Uses OTel semantic convention field names.
func (l *Logger) LogRequest(ctx context.Context) {
	entry, ok := ctxkeys.AuditEntryFrom(ctx)
	if !ok {
		return
	}

	if !l.sampling.ShouldLog(entry.Status) {
		return
	}

	// Build OTel-compatible attributes
	attrs := []slog.Attr{
		slog.String("trace_id", entry.TraceID),
		slog.String("span_id", entry.SpanID),
		slog.Group("attributes",
			slog.String("a2a.method", entry.Method),
			slog.String("a2a.protocol", entry.Protocol),
			slog.String("a2a.target_agent", entry.TargetAgent),
			slog.String("a2a.auth.scheme", entry.AuthScheme),
			slog.String("a2a.auth.subject", entry.AuthSubject),
			slog.String("a2a.status", entry.Status),
			slog.String("a2a.block_reason", entry.BlockReason),
			slog.Time("a2a.start_time", entry.StartTime),
		),
	}

	// Add streaming fields if present
	if entry.StreamEvents > 0 {
		attrs = append(attrs, slog.Group("stream",
			slog.Int("events", entry.StreamEvents),
			slog.Int64("duration_ms", entry.StreamDuration.Milliseconds()),
		))
	}

	l.slogger.LogAttrs(ctx, slog.LevelInfo, "audit", attrs...)
}

// TruncateBody truncates body content for logging if it exceeds maxSize.
func TruncateBody(body []byte, maxSize int) string {
	if len(body) <= maxSize {
		return string(body)
	}
	return string(body[:maxSize]) + "...(truncated)"
}
