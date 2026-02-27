package audit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func getMetricsBody(m *Metrics) string {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)
	return rec.Body.String()
}

func TestMetrics_RecordRequest(t *testing.T) {
	m := NewMetrics()

	m.RecordRequest("echo", "message/send", 200)
	m.RecordRequest("echo", "message/send", 200)
	m.RecordRequest("echo", "message/send", 429)

	body := getMetricsBody(m)
	if !strings.Contains(body, `sentinel_requests_total{agent="echo",method="message/send",status="200"} 2`) {
		t.Errorf("expected 2 requests with 200 status, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_requests_total{agent="echo",method="message/send",status="429"} 1`) {
		t.Errorf("expected 1 request with 429 status, got:\n%s", body)
	}
}

func TestMetrics_ActiveStreams(t *testing.T) {
	m := NewMetrics()

	m.IncrActiveStreams()
	m.IncrActiveStreams()
	m.IncrActiveStreams()
	m.DecrActiveStreams()

	body := getMetricsBody(m)
	if !strings.Contains(body, "sentinel_active_streams 2") {
		t.Errorf("expected active_streams=2, got:\n%s", body)
	}

	m.SetActiveStreams(10)
	body = getMetricsBody(m)
	if !strings.Contains(body, "sentinel_active_streams 10") {
		t.Errorf("expected active_streams=10, got:\n%s", body)
	}
}

func TestMetrics_RateLimitHits(t *testing.T) {
	m := NewMetrics()

	m.RecordRateLimitHit("ip", "echo")
	m.RecordRateLimitHit("ip", "echo")
	m.RecordRateLimitHit("user", "echo")

	body := getMetricsBody(m)
	if !strings.Contains(body, `sentinel_rate_limit_hits_total{agent="echo",layer="ip"} 2`) {
		t.Errorf("expected 2 IP rate limit hits, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_rate_limit_hits_total{agent="echo",layer="user"} 1`) {
		t.Errorf("expected 1 user rate limit hit, got:\n%s", body)
	}
}

func TestMetrics_AgentHealth(t *testing.T) {
	m := NewMetrics()

	m.SetAgentHealth("echo", true)
	m.SetAgentHealth("chat", false)

	body := getMetricsBody(m)
	if !strings.Contains(body, `sentinel_agent_health{agent="echo"} 1`) {
		t.Errorf("expected echo healthy=1, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_agent_health{agent="chat"} 0`) {
		t.Errorf("expected chat healthy=0, got:\n%s", body)
	}

	m.SetAgentHealth("echo", false)
	body = getMetricsBody(m)
	if !strings.Contains(body, `sentinel_agent_health{agent="echo"} 0`) {
		t.Errorf("expected echo healthy=0 after toggle, got:\n%s", body)
	}
}

func TestMetrics_Handler(t *testing.T) {
	m := NewMetrics()

	m.RecordRequest("agent1", "message/send", 200)
	m.RecordRateLimitHit("ip", "agent1")
	m.SetAgentHealth("agent1", true)
	m.IncrActiveStreams()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("unexpected Content-Type: %q", ct)
	}

	body := rec.Body.String()

	// Verify all metric families are present
	expectedPrefixes := []string{
		"sentinel_requests_total",
		"sentinel_active_streams",
		"sentinel_rate_limit_hits_total",
		"sentinel_agent_health",
	}
	for _, prefix := range expectedPrefixes {
		if !strings.Contains(body, prefix) {
			t.Errorf("expected %q in metrics output, got:\n%s", prefix, body)
		}
	}

	// Verify HELP and TYPE annotations exist (prometheus client feature)
	if !strings.Contains(body, "# HELP sentinel_requests_total") {
		t.Error("expected HELP annotation for sentinel_requests_total")
	}
	if !strings.Contains(body, "# TYPE sentinel_requests_total counter") {
		t.Error("expected TYPE annotation for sentinel_requests_total")
	}
}

func TestMetrics_Handler_Empty(t *testing.T) {
	m := NewMetrics()

	body := getMetricsBody(m)
	// Active streams gauge always present even with zero value
	if !strings.Contains(body, "sentinel_active_streams 0") {
		t.Errorf("expected active_streams=0 in empty metrics, got:\n%s", body)
	}
}

func TestMetrics_RecordLatency(t *testing.T) {
	m := NewMetrics()

	m.RecordLatency("echo", "message/send", 10.5)
	m.RecordLatency("echo", "message/send", 20.0)

	body := getMetricsBody(m)
	// Now uses histogram in seconds: 10.5ms = 0.0105s, 20.0ms = 0.02s, sum = 0.0305
	if !strings.Contains(body, `sentinel_request_duration_seconds_sum{agent="echo",method="message/send"}`) {
		t.Errorf("expected histogram sum metric, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_request_duration_seconds_count{agent="echo",method="message/send"} 2`) {
		t.Errorf("expected histogram count=2, got:\n%s", body)
	}
	// Verify histogram buckets exist
	if !strings.Contains(body, `sentinel_request_duration_seconds_bucket{`) {
		t.Errorf("expected histogram buckets, got:\n%s", body)
	}
}

func TestMetrics_Concurrent(t *testing.T) {
	m := NewMetrics()

	var wg sync.WaitGroup
	const goroutines = 50
	const iterations = 100

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				m.RecordRequest("echo", "message/send", 200)
				m.RecordRateLimitHit("ip", "echo")
				m.IncrActiveStreams()
				m.DecrActiveStreams()
				m.SetAgentHealth("echo", i%2 == 0)
				m.RecordLatency("echo", "message/send", 1.0)

				if i%10 == 0 {
					_ = getMetricsBody(m)
				}
			}
		}(g)
	}

	wg.Wait()

	body := getMetricsBody(m)
	// Total requests: 50 goroutines * 100 iterations = 5000
	if !strings.Contains(body, `sentinel_requests_total{agent="echo",method="message/send",status="200"} 5000`) {
		t.Errorf("expected 5000 total requests after concurrent access, got:\n%s", body)
	}

	// Active streams should be 0 (equal incr/decr)
	if !strings.Contains(body, "sentinel_active_streams 0") {
		t.Errorf("expected active_streams=0 after balanced incr/decr, got:\n%s", body)
	}
}

// ── New v0.3 Metrics Tests ──

func TestMetrics_ConfigReloads(t *testing.T) {
	m := NewMetrics()

	m.RecordConfigReload(true)
	m.RecordConfigReload(true)
	m.RecordConfigReload(false)

	body := getMetricsBody(m)
	if !strings.Contains(body, `sentinel_config_reloads_total{result="success"} 2`) {
		t.Errorf("expected 2 successful reloads, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_config_reloads_total{result="failure"} 1`) {
		t.Errorf("expected 1 failed reload, got:\n%s", body)
	}
}

func TestMetrics_ConfigReloadTime(t *testing.T) {
	m := NewMetrics()

	now := time.Now()
	m.SetConfigReloadTime(now)

	body := getMetricsBody(m)
	if !strings.Contains(body, "sentinel_config_reload_timestamp_seconds") {
		t.Errorf("expected config reload timestamp metric, got:\n%s", body)
	}
}

func TestMetrics_GRPCRequests(t *testing.T) {
	m := NewMetrics()

	m.RecordGRPCRequest("echo", "SendMessage", 0)
	m.RecordGRPCLatency("echo", "SendMessage", 0.05)

	body := getMetricsBody(m)
	if !strings.Contains(body, `sentinel_grpc_requests_total{agent="echo",method="SendMessage",status="0"} 1`) {
		t.Errorf("expected gRPC request counter, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_grpc_request_duration_seconds_count{agent="echo",method="SendMessage"} 1`) {
		t.Errorf("expected gRPC duration histogram, got:\n%s", body)
	}
}

func TestMetrics_AgentCardChanges(t *testing.T) {
	m := NewMetrics()

	m.RecordAgentCardChange("echo", "auto")
	m.RecordAgentCardChange("echo", "approve")
	m.RecordAgentCardChange("chat", "reject")

	body := getMetricsBody(m)
	if !strings.Contains(body, `sentinel_agent_card_changes_total{action="auto",agent="echo"} 1`) {
		t.Errorf("expected auto card change, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_agent_card_changes_total{action="approve",agent="echo"} 1`) {
		t.Errorf("expected approve card change, got:\n%s", body)
	}
}

func TestMetrics_MCPRequests(t *testing.T) {
	m := NewMetrics()

	m.RecordMCPRequest("list_agents", true)
	m.RecordMCPRequest("list_agents", false)

	body := getMetricsBody(m)
	if !strings.Contains(body, `sentinel_mcp_requests_total{status="success",tool="list_agents"} 1`) {
		t.Errorf("expected MCP success counter, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_mcp_requests_total{status="error",tool="list_agents"} 1`) {
		t.Errorf("expected MCP error counter, got:\n%s", body)
	}
}

func TestMetrics_SecurityBlocks(t *testing.T) {
	m := NewMetrics()

	reasons := []string{"auth_fail", "rate_limit", "replay", "ssrf", "jws", "policy"}
	for _, r := range reasons {
		m.RecordSecurityBlock(r)
	}
	m.RecordSecurityBlock("auth_fail") // second hit

	body := getMetricsBody(m)
	if !strings.Contains(body, `sentinel_security_blocks_total{reason="auth_fail"} 2`) {
		t.Errorf("expected 2 auth_fail blocks, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_security_blocks_total{reason="replay"} 1`) {
		t.Errorf("expected 1 replay block, got:\n%s", body)
	}
}

func TestMetrics_UpstreamLatency(t *testing.T) {
	m := NewMetrics()

	m.RecordUpstreamLatency("echo", 0.123)
	m.RecordUpstreamLatency("echo", 0.456)

	body := getMetricsBody(m)
	if !strings.Contains(body, `sentinel_upstream_latency_seconds_count{agent="echo"} 2`) {
		t.Errorf("expected upstream latency count=2, got:\n%s", body)
	}
}

func TestMetrics_BuildInfo(t *testing.T) {
	m := NewMetrics()

	m.SetBuildInfo("v0.3.0", "go1.26")

	body := getMetricsBody(m)
	if !strings.Contains(body, `sentinel_build_info{go_version="go1.26",version="v0.3.0"} 1`) {
		t.Errorf("expected build info gauge=1, got:\n%s", body)
	}
}
