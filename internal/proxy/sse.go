package proxy

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
)

// SSEProxy proxies Server-Sent Events streams from backend agents.
// It uses a goroutine+channel pattern for reliable timeout and
// client disconnect detection.
type SSEProxy struct {
	client       *http.Client
	maxEventSize int
	idleTimeout  time.Duration
	streams      *StreamManager
	logger       *slog.Logger
}

// NewSSEProxy creates an SSE proxy with the given configuration.
// The transport should be created via NewStreamTransport() for long-lived connections.
func NewSSEProxy(transport http.RoundTripper, streams *StreamManager, logger *slog.Logger) *SSEProxy {
	return &SSEProxy{
		client:       &http.Client{Transport: transport},
		maxEventSize: 1024 * 1024, // 1MB default
		idleTimeout:  5 * time.Minute,
		streams:      streams,
		logger:       logger,
	}
}

// SetMaxEventSize configures the maximum allowed SSE event size in bytes.
func (p *SSEProxy) SetMaxEventSize(size int) {
	p.maxEventSize = size
}

// SetIdleTimeout configures the idle timeout for SSE streams.
func (p *SSEProxy) SetIdleTimeout(d time.Duration) {
	p.idleTimeout = d
}

// ProxyStream handles SSE streaming from backend to client.
// It uses a goroutine+channel pattern for reliable timeout and disconnect detection.
//
// Flow:
//  1. Acquire stream slot via StreamManager
//  2. Build and execute backend request
//  3. Set SSE response headers and flush
//  4. Reader goroutine reads lines from backend into a channel
//  5. Main select loop writes lines to client, handling timeouts and disconnects
func (p *SSEProxy) ProxyStream(w http.ResponseWriter, r *http.Request, agentName string, targetURL string, targetPath string, maxStreams int) error {
	// 1. Acquire stream slot
	if !p.streams.AcquireStream(agentName, maxStreams) {
		sentinelerrors.WriteHTTPError(w, sentinelerrors.ErrStreamLimitExceeded)
		return fmt.Errorf("stream limit exceeded for agent %s", agentName)
	}
	defer p.streams.ReleaseStream(agentName)

	// 2. Build backend request URL
	backendURL := targetURL + targetPath
	if r.URL.RawQuery != "" {
		backendURL += "?" + r.URL.RawQuery
	}

	// 3. Create backend request with original context
	backendReq, err := http.NewRequestWithContext(r.Context(), r.Method, backendURL, r.Body)
	if err != nil {
		sentinelerrors.WriteHTTPError(w, sentinelerrors.ErrAgentUnavailable)
		return fmt.Errorf("creating backend request: %w", err)
	}

	// 4. Copy headers (filter hop-by-hop)
	CopyHeadersFiltered(backendReq.Header, r.Header)

	// 5. Set forwarding headers
	clientIP := extractSSEClientIP(r)
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		backendReq.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		backendReq.Header.Set("X-Forwarded-For", clientIP)
	}

	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	backendReq.Header.Set("X-Forwarded-Proto", proto)

	// Remove any sentinel-specific headers (Zero Agent Dependency)
	for key := range backendReq.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-sentinel-") {
			backendReq.Header.Del(key)
		}
	}

	// 6. Execute backend request
	resp, err := p.client.Do(backendReq)
	if err != nil {
		sentinelerrors.WriteHTTPError(w, sentinelerrors.ErrAgentUnavailable)
		return fmt.Errorf("backend request failed: %w", err)
	}
	defer resp.Body.Close()

	// 7. Check flusher support
	flusher, ok := w.(http.Flusher)
	if !ok {
		sentinelerrors.WriteHTTPError(w, sentinelerrors.ErrAgentUnavailable)
		return fmt.Errorf("response writer does not support flushing")
	}

	// 8. Set SSE response headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Copy non-SSE headers from backend response (filter hop-by-hop)
	for key, values := range resp.Header {
		canonical := http.CanonicalHeaderKey(key)
		// Skip headers we've already set
		if canonical == "Content-Type" || canonical == "Cache-Control" ||
			canonical == "Connection" || canonical == "X-Accel-Buffering" {
			continue
		}
		if isHopByHop(key) {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	// 9. Flush headers to start the stream
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// 10. Start reader goroutine
	type lineResult struct {
		line string
		err  error
	}
	lineCh := make(chan lineResult, 1)

	go func() {
		defer close(lineCh)
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), p.maxEventSize)
		for scanner.Scan() {
			lineCh <- lineResult{line: scanner.Text()}
		}
		if err := scanner.Err(); err != nil {
			lineCh <- lineResult{err: err}
		}
	}()

	// 11. Main select loop
	idleTimer := time.NewTimer(p.idleTimeout)
	defer idleTimer.Stop()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			// Client disconnected
			p.logger.Info("SSE client disconnected",
				slog.String("agent", agentName),
			)
			return nil

		case <-idleTimer.C:
			// Idle timeout — send error event and close
			p.logger.Warn("SSE stream idle timeout",
				slog.String("agent", agentName),
				slog.Duration("timeout", p.idleTimeout),
			)
			// Send SSE error event to notify the client
			fmt.Fprintf(w, "event: error\ndata: {\"code\":408,\"message\":\"Stream idle timeout\"}\n\n")
			flusher.Flush()
			return fmt.Errorf("stream idle timeout for agent %s", agentName)

		case result, ok := <-lineCh:
			if !ok {
				// Backend closed the connection (channel closed, no error)
				p.logger.Info("SSE backend stream ended",
					slog.String("agent", agentName),
				)
				return nil
			}

			if result.err != nil {
				// Backend read error
				p.logger.Error("SSE backend read error",
					slog.String("agent", agentName),
					slog.String("error", result.err.Error()),
				)
				fmt.Fprintf(w, "event: error\ndata: {\"code\":502,\"message\":\"Backend stream error\"}\n\n")
				flusher.Flush()
				return fmt.Errorf("backend read error: %w", result.err)
			}

			// Write line to client
			fmt.Fprintf(w, "%s\n", result.line)

			// Flush at event boundary (empty line = end of event)
			if result.line == "" {
				flusher.Flush()
			}

			// Reset idle timer
			if !idleTimer.Stop() {
				// Drain the timer channel if it already fired
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(p.idleTimeout)
		}
	}
}

func extractSSEClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
