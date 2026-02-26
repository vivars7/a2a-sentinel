package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockChecker struct {
	healthy []string
	all     []string
}

func (m *mockChecker) HealthyAgents() []string { return m.healthy }
func (m *mockChecker) AllAgentNames() []string { return m.all }

func TestLiveness_Always200(t *testing.T) {
	h := NewHandler(&mockChecker{}, "v1.2.3", "any_healthy", "")
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp LivenessResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status=ok, got %q", resp.Status)
	}
}

func TestLiveness_VersionIncluded(t *testing.T) {
	const version = "v0.5.0"
	h := NewHandler(&mockChecker{}, version, "any_healthy", "")
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	var resp LivenessResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Version != version {
		t.Errorf("expected version=%q, got %q", version, resp.Version)
	}
}

func TestReadiness_AnyHealthy_SomeHealthy(t *testing.T) {
	checker := &mockChecker{
		healthy: []string{"agent-a", "agent-b"},
		all:     []string{"agent-a", "agent-b", "agent-c"},
	}
	h := NewHandler(checker, "v1.0.0", "any_healthy", "")
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp ReadinessResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "ready" {
		t.Errorf("expected status=ready, got %q", resp.Status)
	}
}

func TestReadiness_AnyHealthy_NoneHealthy(t *testing.T) {
	checker := &mockChecker{
		healthy: []string{},
		all:     []string{"agent-a", "agent-b", "agent-c"},
	}
	h := NewHandler(checker, "v1.0.0", "any_healthy", "")
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}

	var resp ReadinessResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "not_ready" {
		t.Errorf("expected status=not_ready, got %q", resp.Status)
	}
}

func TestReadiness_AllHealthy_AllUp(t *testing.T) {
	checker := &mockChecker{
		healthy: []string{"agent-a", "agent-b", "agent-c"},
		all:     []string{"agent-a", "agent-b", "agent-c"},
	}
	h := NewHandler(checker, "v1.0.0", "all_healthy", "")
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp ReadinessResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "ready" {
		t.Errorf("expected status=ready, got %q", resp.Status)
	}
}

func TestReadiness_AllHealthy_SomeDown(t *testing.T) {
	checker := &mockChecker{
		healthy: []string{"agent-a", "agent-b"},
		all:     []string{"agent-a", "agent-b", "agent-c"},
	}
	h := NewHandler(checker, "v1.0.0", "all_healthy", "")
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}

	var resp ReadinessResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "not_ready" {
		t.Errorf("expected status=not_ready, got %q", resp.Status)
	}
}

func TestReadiness_DefaultHealthy_DefaultUp(t *testing.T) {
	checker := &mockChecker{
		healthy: []string{"agent-a", "default-agent"},
		all:     []string{"agent-a", "default-agent", "agent-c"},
	}
	h := NewHandler(checker, "v1.0.0", "default_healthy", "default-agent")
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp ReadinessResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "ready" {
		t.Errorf("expected status=ready, got %q", resp.Status)
	}
}

func TestReadiness_DefaultHealthy_DefaultDown(t *testing.T) {
	checker := &mockChecker{
		healthy: []string{"agent-a"},
		all:     []string{"agent-a", "default-agent", "agent-c"},
	}
	h := NewHandler(checker, "v1.0.0", "default_healthy", "default-agent")
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}

	var resp ReadinessResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "not_ready" {
		t.Errorf("expected status=not_ready, got %q", resp.Status)
	}
}

func TestReadiness_ContentType(t *testing.T) {
	checker := &mockChecker{
		healthy: []string{"agent-a"},
		all:     []string{"agent-a"},
	}
	h := NewHandler(checker, "v1.0.0", "any_healthy", "")
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}
}

func TestReadiness_ResponseBody(t *testing.T) {
	checker := &mockChecker{
		healthy: []string{"agent-a", "agent-b"},
		all:     []string{"agent-a", "agent-b", "agent-c"},
	}
	h := NewHandler(checker, "v1.0.0", "any_healthy", "")
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	var resp ReadinessResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.HealthyAgents != 2 {
		t.Errorf("expected healthy_agents=2, got %d", resp.HealthyAgents)
	}
	if resp.TotalAgents != 3 {
		t.Errorf("expected total_agents=3, got %d", resp.TotalAgents)
	}
}

// TestSimpleAgentHealthChecker_HealthyAgents verifies delegation to HealthyFn.
func TestSimpleAgentHealthChecker_HealthyAgents(t *testing.T) {
	want := []string{"agent-a", "agent-b"}
	s := &SimpleAgentHealthChecker{
		HealthyFn:  func() []string { return want },
		AllNamesFn: func() []string { return nil },
	}
	got := s.HealthyAgents()
	if len(got) != len(want) {
		t.Fatalf("HealthyAgents() = %v, want %v", got, want)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("HealthyAgents()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

// TestSimpleAgentHealthChecker_AllAgentNames verifies delegation to AllNamesFn.
func TestSimpleAgentHealthChecker_AllAgentNames(t *testing.T) {
	want := []string{"agent-a", "agent-b", "agent-c"}
	s := &SimpleAgentHealthChecker{
		HealthyFn:  func() []string { return nil },
		AllNamesFn: func() []string { return want },
	}
	got := s.AllAgentNames()
	if len(got) != len(want) {
		t.Fatalf("AllAgentNames() = %v, want %v", got, want)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("AllAgentNames()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

// TestServeHTTP_UnknownPath verifies that an unknown path returns 404.
func TestServeHTTP_UnknownPath(t *testing.T) {
	h := NewHandler(&mockChecker{}, "v1.0.0", "any_healthy", "")
	req := httptest.NewRequest(http.MethodGet, "/unknown-path", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown path, got %d", rec.Code)
	}
}

// TestReadiness_DefaultMode_FallsBackToAnyHealthy verifies that an unknown
// readiness mode falls back to the "any_healthy" behavior.
func TestReadiness_DefaultMode_FallsBackToAnyHealthy(t *testing.T) {
	tests := []struct {
		name        string
		healthy     []string
		all         []string
		wantCode    int
		wantStatus  string
	}{
		{
			name:       "unknown mode with healthy agents is ready",
			healthy:    []string{"agent-a"},
			all:        []string{"agent-a"},
			wantCode:   http.StatusOK,
			wantStatus: "ready",
		},
		{
			name:       "unknown mode with no healthy agents is not ready",
			healthy:    []string{},
			all:        []string{"agent-a"},
			wantCode:   http.StatusServiceUnavailable,
			wantStatus: "not_ready",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := &mockChecker{healthy: tc.healthy, all: tc.all}
			// Use an unknown readiness mode to trigger the default branch.
			h := NewHandler(checker, "v1.0.0", "unknown_mode", "")
			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Errorf("expected status %d, got %d", tc.wantCode, rec.Code)
			}
			var resp ReadinessResponse
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp.Status != tc.wantStatus {
				t.Errorf("expected status=%q, got %q", tc.wantStatus, resp.Status)
			}
		})
	}
}
