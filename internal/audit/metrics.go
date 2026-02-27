package audit

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// millisecondsPerSecond is the conversion factor from milliseconds to seconds.
const millisecondsPerSecond = 1000.0

// Metrics tracks gateway metrics and serves them in Prometheus text format.
// It uses a custom prometheus.Registry for isolation and testability,
// with proper histograms, HELP/TYPE annotations, and standard exposition format.
type Metrics struct {
	registry *prometheus.Registry

	// Existing metrics (upgraded to proper Prometheus types)
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	activeStreams    prometheus.Gauge
	rateLimitHits   *prometheus.CounterVec
	agentHealth     *prometheus.GaugeVec

	// New metrics for v0.3
	configReloads       *prometheus.CounterVec
	configReloadTime    prometheus.Gauge
	grpcRequestsTotal   *prometheus.CounterVec
	grpcRequestDuration *prometheus.HistogramVec
	agentCardChanges    *prometheus.CounterVec
	mcpRequestsTotal    *prometheus.CounterVec
	securityBlocks      *prometheus.CounterVec
	upstreamLatency     *prometheus.HistogramVec
	buildInfo           *prometheus.GaugeVec
}

// NewMetrics creates a new Metrics collector with a custom Prometheus registry.
// All metric families are pre-registered with HELP and TYPE metadata.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		registry: reg,

		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sentinel_requests_total",
			Help: "Total number of requests processed by the sentinel gateway.",
		}, []string{"agent", "method", "status"}),

		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "sentinel_request_duration_seconds",
			Help:    "Request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"agent", "method"}),

		activeStreams: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sentinel_active_streams",
			Help: "Number of currently active SSE streams.",
		}),

		rateLimitHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sentinel_rate_limit_hits_total",
			Help: "Total number of rate limit hits.",
		}, []string{"layer", "agent"}),

		agentHealth: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sentinel_agent_health",
			Help: "Health status of backend agents (1=healthy, 0=unhealthy).",
		}, []string{"agent"}),

		configReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sentinel_config_reloads_total",
			Help: "Total number of configuration reload attempts.",
		}, []string{"result"}),

		configReloadTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sentinel_config_reload_timestamp_seconds",
			Help: "Unix timestamp of the last successful configuration reload.",
		}),

		grpcRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sentinel_grpc_requests_total",
			Help: "Total number of gRPC requests processed.",
		}, []string{"agent", "method", "status"}),

		grpcRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "sentinel_grpc_request_duration_seconds",
			Help:    "gRPC request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"agent", "method"}),

		agentCardChanges: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sentinel_agent_card_changes_total",
			Help: "Total number of agent card change events.",
		}, []string{"agent", "action"}),

		mcpRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sentinel_mcp_requests_total",
			Help: "Total number of MCP tool requests.",
		}, []string{"tool", "status"}),

		securityBlocks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sentinel_security_blocks_total",
			Help: "Total number of requests blocked for security reasons.",
		}, []string{"reason"}),

		upstreamLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "sentinel_upstream_latency_seconds",
			Help:    "Backend upstream response time in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"agent"}),

		buildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sentinel_build_info",
			Help: "Build information about the sentinel binary. Value is always 1.",
		}, []string{"version", "go_version"}),
	}

	reg.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.activeStreams,
		m.rateLimitHits,
		m.agentHealth,
		m.configReloads,
		m.configReloadTime,
		m.grpcRequestsTotal,
		m.grpcRequestDuration,
		m.agentCardChanges,
		m.mcpRequestsTotal,
		m.securityBlocks,
		m.upstreamLatency,
		m.buildInfo,
	)

	return m
}

// RecordRequest increments the request counter for the given agent, method, and status code.
func (m *Metrics) RecordRequest(agent, method string, status int) {
	m.requestsTotal.WithLabelValues(agent, method, statusString(status)).Inc()
}

// RecordLatency records request duration in milliseconds for the given agent and method.
// The value is converted to seconds internally for Prometheus convention compliance.
func (m *Metrics) RecordLatency(agent, method string, ms float64) {
	m.requestDuration.WithLabelValues(agent, method).Observe(ms / millisecondsPerSecond)
}

// SetActiveStreams sets the current active stream count to the given value.
func (m *Metrics) SetActiveStreams(n int64) {
	m.activeStreams.Set(float64(n))
}

// IncrActiveStreams increments the active stream count by one.
func (m *Metrics) IncrActiveStreams() {
	m.activeStreams.Inc()
}

// DecrActiveStreams decrements the active stream count by one.
func (m *Metrics) DecrActiveStreams() {
	m.activeStreams.Dec()
}

// RecordRateLimitHit records a rate limit event for the given layer and agent.
// Layer is typically "ip" or "user".
func (m *Metrics) RecordRateLimitHit(layer, agent string) {
	m.rateLimitHits.WithLabelValues(layer, agent).Inc()
}

// SetAgentHealth sets agent health status. Pass true for healthy, false for unhealthy.
func (m *Metrics) SetAgentHealth(agent string, healthy bool) {
	var val float64
	if healthy {
		val = 1
	}
	m.agentHealth.WithLabelValues(agent).Set(val)
}

// Handler returns an HTTP handler that serves /metrics in Prometheus text format.
// The output includes proper HELP and TYPE annotations per the Prometheus exposition format.
func (m *Metrics) Handler() http.HandlerFunc {
	h := promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
	return func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}
}

// RecordConfigReload records a configuration reload attempt.
// Pass true for a successful reload, false for a failure.
func (m *Metrics) RecordConfigReload(success bool) {
	result := "failure"
	if success {
		result = "success"
	}
	m.configReloads.WithLabelValues(result).Inc()
}

// SetConfigReloadTime records the timestamp of the last configuration reload.
func (m *Metrics) SetConfigReloadTime(t time.Time) {
	m.configReloadTime.Set(float64(t.Unix()))
}

// RecordGRPCRequest increments the gRPC request counter for the given agent, method, and status code.
func (m *Metrics) RecordGRPCRequest(agent, method string, status int) {
	m.grpcRequestsTotal.WithLabelValues(agent, method, statusString(status)).Inc()
}

// RecordGRPCLatency records gRPC request duration in seconds for the given agent and method.
func (m *Metrics) RecordGRPCLatency(agent, method string, seconds float64) {
	m.grpcRequestDuration.WithLabelValues(agent, method).Observe(seconds)
}

// RecordAgentCardChange records an agent card change event.
// Action should be one of: "auto", "alert", "approve", "reject".
func (m *Metrics) RecordAgentCardChange(agent, action string) {
	m.agentCardChanges.WithLabelValues(agent, action).Inc()
}

// RecordMCPRequest records an MCP tool request.
// Pass true for a successful request, false for a failure.
func (m *Metrics) RecordMCPRequest(tool string, success bool) {
	status := "error"
	if success {
		status = "success"
	}
	m.mcpRequestsTotal.WithLabelValues(tool, status).Inc()
}

// RecordSecurityBlock records a request blocked for security reasons.
// Reason should be one of: "auth_fail", "rate_limit", "replay", "ssrf", "jws", "policy".
func (m *Metrics) RecordSecurityBlock(reason string) {
	m.securityBlocks.WithLabelValues(reason).Inc()
}

// RecordUpstreamLatency records backend upstream response time in seconds for the given agent.
func (m *Metrics) RecordUpstreamLatency(agent string, seconds float64) {
	m.upstreamLatency.WithLabelValues(agent).Observe(seconds)
}

// SetBuildInfo sets the build information gauge. The gauge value is always 1;
// version and Go version are exposed as labels.
func (m *Metrics) SetBuildInfo(version, goVersion string) {
	m.buildInfo.WithLabelValues(version, goVersion).Set(1)
}

// statusString converts an integer status code to its string representation.
func statusString(code int) string {
	// Avoid fmt.Sprintf for hot path performance
	switch code {
	case 200:
		return "200"
	case 201:
		return "201"
	case 204:
		return "204"
	case 400:
		return "400"
	case 401:
		return "401"
	case 403:
		return "403"
	case 404:
		return "404"
	case 429:
		return "429"
	case 500:
		return "500"
	case 502:
		return "502"
	case 503:
		return "503"
	default:
		// Fallback for uncommon status codes
		return intToString(code)
	}
}

// intToString converts a non-negative integer to a string without fmt.Sprintf.
func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	buf := make([]byte, 0, 5)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	if negative {
		buf = append(buf, '-')
	}
	// Reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
