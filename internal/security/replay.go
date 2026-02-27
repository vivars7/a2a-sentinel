package security

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
	"github.com/vivars7/a2a-sentinel/internal/protocol"
)

// NonceStore tracks request nonces for replay detection.
type NonceStore interface {
	// CheckAndStore returns true if the nonce is new (not seen before).
	// Returns false if it's a replay (already seen within the window).
	CheckAndStore(nonce string, timestamp time.Time) (isNew bool, err error)
}

// MemoryNonceStore is an in-memory NonceStore using sync.Map.
// It periodically cleans up expired entries via a background goroutine.
type MemoryNonceStore struct {
	entries sync.Map // nonce string → time.Time (expiry)
	window  time.Duration
	done    chan struct{}
}

// NewMemoryNonceStore creates a new in-memory nonce store with the given
// replay window and cleanup interval. Call StartCleanup to begin periodic
// eviction of expired entries, and Stop to terminate the cleanup goroutine.
func NewMemoryNonceStore(window, cleanupInterval time.Duration) *MemoryNonceStore {
	s := &MemoryNonceStore{
		window: window,
		done:   make(chan struct{}),
	}
	go s.startCleanup(cleanupInterval)
	return s
}

// CheckAndStore checks whether the nonce has been seen within the replay window.
// Returns true if the nonce is new (first time seen), false if it is a replay.
func (s *MemoryNonceStore) CheckAndStore(nonce string, timestamp time.Time) (bool, error) {
	expiry := timestamp.Add(s.window)

	// Check if nonce already exists and is not expired
	if v, ok := s.entries.Load(nonce); ok {
		existingExpiry := v.(time.Time)
		if time.Now().Before(existingExpiry) {
			// Nonce exists and hasn't expired — replay
			return false, nil
		}
		// Nonce expired — treat as new, update expiry
	}

	// Store the nonce with its expiry
	s.entries.Store(nonce, expiry)
	return true, nil
}

// startCleanup runs a background goroutine that periodically removes expired entries.
func (s *MemoryNonceStore) startCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			now := time.Now()
			s.entries.Range(func(key, value interface{}) bool {
				expiry := value.(time.Time)
				if now.After(expiry) {
					s.entries.Delete(key)
				}
				return true
			})
		}
	}
}

// Stop stops the cleanup goroutine. Must be called to prevent goroutine leaks.
func (s *MemoryNonceStore) Stop() {
	select {
	case <-s.done:
		// Already closed
	default:
		close(s.done)
	}
}

// ReplayDetectorConfig holds configuration for the ReplayDetector middleware.
type ReplayDetectorConfig struct {
	Enabled         bool
	Window          time.Duration
	NoncePolicy     string // "warn" or "require"
	NonceSource     string // "auto", "header", "jsonrpc-id"
	ClockSkew       time.Duration
	CleanupInterval time.Duration
}

// ReplayDetector is a middleware that detects replayed JSON-RPC requests
// by tracking the id field as a nonce within a configurable time window.
type ReplayDetector struct {
	store       NonceStore
	policy      string // "warn" or "require"
	nonceSource string // "auto", "header", "jsonrpc-id"
	window      time.Duration
	clockSkew   time.Duration
	enabled     bool
	logger      *slog.Logger
}

// NewReplayDetector creates a ReplayDetector with the given configuration.
// When enabled, it creates a MemoryNonceStore for tracking request IDs.
// When disabled, it passes all requests through without inspection.
func NewReplayDetector(cfg ReplayDetectorConfig, logger *slog.Logger) *ReplayDetector {
	if logger == nil {
		logger = slog.Default()
	}

	nonceSource := cfg.NonceSource
	if nonceSource == "" {
		nonceSource = "auto"
	}

	rd := &ReplayDetector{
		policy:      cfg.NoncePolicy,
		nonceSource: nonceSource,
		window:      cfg.Window,
		clockSkew:   cfg.ClockSkew,
		enabled:     cfg.Enabled,
		logger:      logger,
	}

	if cfg.Enabled {
		rd.store = NewMemoryNonceStore(cfg.Window, cfg.CleanupInterval)
	}

	return rd
}

// Process returns an http.Handler that checks for replayed requests.
// It inspects requests based on the configured nonce_source, extracts a nonce,
// and checks it against the nonce store. When an X-Sentinel-Timestamp header is
// present, it validates the timestamp against the window and clock skew.
// Behavior on replay depends on the configured policy:
// "warn" logs and always passes through, "require" returns a 429 error.
func (d *ReplayDetector) Process(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !d.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Only check POST requests
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		// Only check JSON content
		ct := r.Header.Get("Content-Type")
		if ct != "" && ct != "application/json" &&
			ct != "application/json; charset=utf-8" &&
			ct != "application/json;charset=utf-8" {
			next.ServeHTTP(w, r)
			return
		}

		// Extract nonce based on nonce_source
		var nonce string
		switch d.nonceSource {
		case "header":
			nonce = r.Header.Get("X-Sentinel-Nonce")
		case "jsonrpc-id":
			body, err := protocol.InspectAndRewind(r, 1024*1024)
			if err != nil {
				d.logger.Warn("replay: failed to read request body", "error", err)
				next.ServeHTTP(w, r)
				return
			}
			if len(body) > 0 {
				nonce = extractNonce(body)
			}
		default: // "auto"
			// Try header first, fall back to JSON-RPC id
			nonce = r.Header.Get("X-Sentinel-Nonce")
			if nonce == "" {
				body, err := protocol.InspectAndRewind(r, 1024*1024)
				if err != nil {
					d.logger.Warn("replay: failed to read request body", "error", err)
					next.ServeHTTP(w, r)
					return
				}
				if len(body) > 0 {
					nonce = extractNonce(body)
				}
			}
		}

		if nonce == "" {
			// No nonce available — can't check for replay, pass through
			next.ServeHTTP(w, r)
			return
		}

		// Determine timestamp
		now := time.Now()
		tsHeader := r.Header.Get("X-Sentinel-Timestamp")
		var ts time.Time
		hasTimestampHeader := tsHeader != ""

		if hasTimestampHeader {
			parsed, ok := parseTimestamp(tsHeader)
			if !ok {
				d.logger.Warn("replay: invalid timestamp header", "value", tsHeader)
				if d.policy == "require" {
					sentinelerrors.WriteHTTPError(w, &sentinelerrors.SentinelError{
						Code:    429,
						Message: "Invalid replay timestamp",
						Hint:    "X-Sentinel-Timestamp must be RFC3339 or 10-digit Unix epoch.",
						DocsURL: "https://a2a-sentinel.dev/docs/replay-protection",
					})
					return
				}
				// warn mode: pass through
				next.ServeHTTP(w, r)
				return
			}
			ts = parsed
		} else {
			ts = now
		}

		// Timestamp validation (only when header is present)
		if hasTimestampHeader {
			diff := now.Sub(ts)
			if diff < 0 {
				diff = -diff
			}
			if diff > d.window+d.clockSkew {
				d.logger.Warn("replay: timestamp outside allowed window",
					"timestamp", ts,
					"diff", diff,
					"window", d.window,
					"clock_skew", d.clockSkew,
					"policy", d.policy,
				)
				if d.policy == "require" {
					sentinelerrors.WriteHTTPError(w, &sentinelerrors.SentinelError{
						Code:    429,
						Message: "Replay attack detected",
						Hint:    "Request timestamp is outside the allowed window. Ensure clocks are synchronized.",
						DocsURL: "https://a2a-sentinel.dev/docs/replay-protection",
					})
					return
				}
				// warn mode: log only, pass through
				next.ServeHTTP(w, r)
				return
			}
		}

		// Check nonce against store
		isNew, err := d.store.CheckAndStore(nonce, ts)
		if err != nil {
			d.logger.Error("replay: nonce store error", "error", err)
			next.ServeHTTP(w, r)
			return
		}

		if !isNew {
			// Replay detected
			d.logger.Warn("replay: duplicate request nonce detected",
				"nonce", nonce,
				"policy", d.policy,
			)

			if d.policy == "require" {
				sentinelerrors.WriteHTTPError(w, &sentinelerrors.SentinelError{
					Code:    429,
					Message: "Replay attack detected",
					Hint:    "Request ID already seen within replay window. Use unique IDs for each request.",
					DocsURL: "https://a2a-sentinel.dev/docs/replay-protection",
				})
				return
			}
			// policy == "warn": log only, always pass through
		}

		next.ServeHTTP(w, r)
	})
}

// parseTimestamp parses X-Sentinel-Timestamp as RFC3339 or Unix epoch (10-digit).
func parseTimestamp(s string) (time.Time, bool) {
	// Try RFC3339 first
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	// Try Unix epoch (must be exactly 10 digits)
	if len(s) == 10 {
		var epoch int64
		for _, c := range s {
			if c < '0' || c > '9' {
				return time.Time{}, false
			}
			epoch = epoch*10 + int64(c-'0')
		}
		return time.Unix(epoch, 0), true
	}
	return time.Time{}, false
}

// Name returns the middleware name.
func (d *ReplayDetector) Name() string {
	return "replay_detector"
}

// Stop cleans up the nonce store's background goroutine.
// Must be called when the ReplayDetector is no longer needed.
func (d *ReplayDetector) Stop() {
	if d.store != nil {
		if ms, ok := d.store.(*MemoryNonceStore); ok {
			ms.Stop()
		}
	}
}

// extractNonce extracts the JSON-RPC id field from the request body as a string nonce.
// It handles string, numeric, and null id values by converting them to a canonical
// string representation suitable for nonce comparison.
func extractNonce(body []byte) string {
	var envelope struct {
		ID json.RawMessage `json:"id"`
	}

	if err := json.Unmarshal(body, &envelope); err != nil {
		return ""
	}

	if len(envelope.ID) == 0 || string(envelope.ID) == "null" {
		return ""
	}

	// Try as string first
	var strID string
	if err := json.Unmarshal(envelope.ID, &strID); err == nil {
		return fmt.Sprintf("s:%s", strID)
	}

	// Try as number
	var numID float64
	if err := json.Unmarshal(envelope.ID, &numID); err == nil {
		return fmt.Sprintf("n:%g", numID)
	}

	// Fallback: use raw JSON representation
	return fmt.Sprintf("r:%s", string(envelope.ID))
}
