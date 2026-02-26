package audit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMetrics_RecordRequest(t *testing.T) {
	m := NewMetrics()

	m.RecordRequest("echo", "message/send", 200)
	m.RecordRequest("echo", "message/send", 200)
	m.RecordRequest("echo", "message/send", 429)

	// Verify via handler output
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
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

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "sentinel_active_streams 2") {
		t.Errorf("expected active_streams=2, got:\n%s", body)
	}

	// Test SetActiveStreams
	m.SetActiveStreams(10)
	rec = httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	body = rec.Body.String()
	if !strings.Contains(body, "sentinel_active_streams 10") {
		t.Errorf("expected active_streams=10, got:\n%s", body)
	}
}

func TestMetrics_RateLimitHits(t *testing.T) {
	m := NewMetrics()

	m.RecordRateLimitHit("ip", "echo")
	m.RecordRateLimitHit("ip", "echo")
	m.RecordRateLimitHit("user", "echo")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `sentinel_rate_limit_hits_total{layer="ip",agent="echo"} 2`) {
		t.Errorf("expected 2 IP rate limit hits, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_rate_limit_hits_total{layer="user",agent="echo"} 1`) {
		t.Errorf("expected 1 user rate limit hit, got:\n%s", body)
	}
}

func TestMetrics_AgentHealth(t *testing.T) {
	m := NewMetrics()

	m.SetAgentHealth("echo", true)
	m.SetAgentHealth("chat", false)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `sentinel_agent_health{agent="echo"} 1`) {
		t.Errorf("expected echo healthy=1, got:\n%s", body)
	}
	if !strings.Contains(body, `sentinel_agent_health{agent="chat"} 0`) {
		t.Errorf("expected chat healthy=0, got:\n%s", body)
	}

	// Toggle health
	m.SetAgentHealth("echo", false)
	rec = httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	body = rec.Body.String()
	if !strings.Contains(body, `sentinel_agent_health{agent="echo"} 0`) {
		t.Errorf("expected echo healthy=0 after toggle, got:\n%s", body)
	}
}

func TestMetrics_Handler(t *testing.T) {
	m := NewMetrics()

	// Populate some data
	m.RecordRequest("agent1", "message/send", 200)
	m.RecordRateLimitHit("ip", "agent1")
	m.SetAgentHealth("agent1", true)
	m.IncrActiveStreams()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	// Verify content type
	ct := rec.Header().Get("Content-Type")
	if ct != "text/plain; version=0.0.4; charset=utf-8" {
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

	// Verify output is sorted (lines should be in alphabetical order)
	lines := strings.Split(strings.TrimSpace(body), "\n")
	for i := 1; i < len(lines); i++ {
		if lines[i] < lines[i-1] {
			t.Errorf("metrics output not sorted: line %d (%q) < line %d (%q)",
				i, lines[i], i-1, lines[i-1])
		}
	}
}

func TestMetrics_Handler_Empty(t *testing.T) {
	m := NewMetrics()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	// Should still have active_streams (always present)
	if !strings.Contains(body, "sentinel_active_streams 0") {
		t.Errorf("expected active_streams=0 in empty metrics, got:\n%s", body)
	}
}

func TestMetrics_RecordLatency(t *testing.T) {
	m := NewMetrics()

	m.RecordLatency("echo", "message/send", 10.5)
	m.RecordLatency("echo", "message/send", 20.0)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	// 10.5ms = 10500 usec, 20.0ms = 20000 usec, total = 30500
	if !strings.Contains(body, `sentinel_request_duration_usec{agent="echo",method="message/send"} 30500`) {
		t.Errorf("expected accumulated duration in usec, got:\n%s", body)
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

				// Also read metrics concurrently
				if i%10 == 0 {
					rec := httptest.NewRecorder()
					req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
					m.Handler().ServeHTTP(rec, req)
				}
			}
		}(g)
	}

	wg.Wait()

	// Verify final state is consistent
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	// Total requests: 50 goroutines * 100 iterations = 5000
	if !strings.Contains(body, `sentinel_requests_total{agent="echo",method="message/send",status="200"} 5000`) {
		t.Errorf("expected 5000 total requests after concurrent access, got:\n%s", body)
	}

	// Active streams should be 0 (equal incr/decr)
	if !strings.Contains(body, "sentinel_active_streams 0") {
		t.Errorf("expected active_streams=0 after balanced incr/decr, got:\n%s", body)
	}
}
