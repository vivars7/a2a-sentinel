package audit

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Metrics tracks gateway metrics and serves them in Prometheus text format.
// It uses sync/atomic and sync.Map for lock-free concurrent access,
// avoiding any external dependency on OTel SDK or Prometheus client libraries.
type Metrics struct {
	requestsTotal   sync.Map // "agent:method:status" -> *int64
	requestDuration sync.Map // "agent:method" -> *histogram (simplified: sum of ms)
	activeStreams    atomic.Int64
	rateLimitHits   sync.Map // "layer:agent" -> *int64
	agentHealth     sync.Map // "agent" -> *int64 (1=healthy, 0=unhealthy)
}

// NewMetrics creates a new Metrics collector with zero-initialized counters.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// RecordRequest increments the request counter for the given agent, method, and status code.
func (m *Metrics) RecordRequest(agent, method string, status int) {
	key := fmt.Sprintf("%s:%s:%d", agent, method, status)
	m.atomicAdd(&m.requestsTotal, key, 1)
}

// RecordLatency records request duration in milliseconds for the given agent and method.
// Durations are accumulated as a sum for simplicity (no histogram buckets).
func (m *Metrics) RecordLatency(agent, method string, ms float64) {
	key := fmt.Sprintf("%s:%s", agent, method)
	// Store as int64 microseconds for atomic operations
	usec := int64(ms * 1000)
	m.atomicAdd(&m.requestDuration, key, usec)
}

// SetActiveStreams sets the current active stream count to the given value.
func (m *Metrics) SetActiveStreams(n int64) {
	m.activeStreams.Store(n)
}

// IncrActiveStreams increments the active stream count by one.
func (m *Metrics) IncrActiveStreams() {
	m.activeStreams.Add(1)
}

// DecrActiveStreams decrements the active stream count by one.
func (m *Metrics) DecrActiveStreams() {
	m.activeStreams.Add(-1)
}

// RecordRateLimitHit records a rate limit event for the given layer and agent.
// Layer is typically "ip" or "user".
func (m *Metrics) RecordRateLimitHit(layer, agent string) {
	key := fmt.Sprintf("%s:%s", layer, agent)
	m.atomicAdd(&m.rateLimitHits, key, 1)
}

// SetAgentHealth sets agent health status. Pass true for healthy, false for unhealthy.
func (m *Metrics) SetAgentHealth(agent string, healthy bool) {
	var val int64
	if healthy {
		val = 1
	}
	ptr := new(int64)
	atomic.StoreInt64(ptr, val)
	if existing, loaded := m.agentHealth.LoadOrStore(agent, ptr); loaded {
		atomic.StoreInt64(existing.(*int64), val)
	}
}

// Handler returns an HTTP handler that serves /metrics in Prometheus text format.
// The output follows the Prometheus exposition format (text/plain; version=0.0.4).
func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var lines []string

		// sentinel_requests_total{agent="echo",method="message/send",status="200"} 42
		m.requestsTotal.Range(func(key, value any) bool {
			k := key.(string)
			parts := strings.SplitN(k, ":", 3)
			if len(parts) == 3 {
				v := atomic.LoadInt64(value.(*int64))
				lines = append(lines, fmt.Sprintf(
					`sentinel_requests_total{agent="%s",method="%s",status="%s"} %d`,
					parts[0], parts[1], parts[2], v))
			}
			return true
		})

		// sentinel_request_duration_usec{agent="echo",method="message/send"} 12345
		m.requestDuration.Range(func(key, value any) bool {
			k := key.(string)
			parts := strings.SplitN(k, ":", 2)
			if len(parts) == 2 {
				v := atomic.LoadInt64(value.(*int64))
				lines = append(lines, fmt.Sprintf(
					`sentinel_request_duration_usec{agent="%s",method="%s"} %d`,
					parts[0], parts[1], v))
			}
			return true
		})

		// sentinel_active_streams
		lines = append(lines, fmt.Sprintf("sentinel_active_streams %d", m.activeStreams.Load()))

		// sentinel_rate_limit_hits_total{layer="ip",agent="echo"} 5
		m.rateLimitHits.Range(func(key, value any) bool {
			k := key.(string)
			parts := strings.SplitN(k, ":", 2)
			if len(parts) == 2 {
				v := atomic.LoadInt64(value.(*int64))
				lines = append(lines, fmt.Sprintf(
					`sentinel_rate_limit_hits_total{layer="%s",agent="%s"} %d`,
					parts[0], parts[1], v))
			}
			return true
		})

		// sentinel_agent_health{agent="echo"} 1
		m.agentHealth.Range(func(key, value any) bool {
			v := atomic.LoadInt64(value.(*int64))
			lines = append(lines, fmt.Sprintf(
				`sentinel_agent_health{agent="%s"} %d`, key, v))
			return true
		})

		sort.Strings(lines)
		fmt.Fprintln(w, strings.Join(lines, "\n"))
	}
}

// atomicAdd atomically increments a counter in a sync.Map by delta.
// If the key does not exist, it creates a new counter initialized to delta.
func (m *Metrics) atomicAdd(store *sync.Map, key string, delta int64) {
	if existing, ok := store.Load(key); ok {
		atomic.AddInt64(existing.(*int64), delta)
		return
	}
	ptr := new(int64)
	*ptr = delta
	if existing, loaded := store.LoadOrStore(key, ptr); loaded {
		atomic.AddInt64(existing.(*int64), delta)
	}
}
