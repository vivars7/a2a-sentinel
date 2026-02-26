package router

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
)

// ── Mock AgentLookup ──

// mockLookup implements AgentLookup for testing.
type mockLookup struct {
	agents       map[string]mockAgent // name → agent info
	defaultAgent string               // name of the default agent (empty = none)
}

type mockAgent struct {
	url     string
	healthy bool
}

func (m *mockLookup) IsHealthy(name string) bool {
	a, ok := m.agents[name]
	return ok && a.healthy
}

func (m *mockLookup) HealthyAgents() []string {
	var names []string
	for name, a := range m.agents {
		if a.healthy {
			names = append(names, name)
		}
	}
	return names
}

func (m *mockLookup) GetAgentURL(name string) (string, bool) {
	a, ok := m.agents[name]
	if !ok {
		return "", false
	}
	return a.url, true
}

func (m *mockLookup) GetDefaultAgent() (string, string, bool) {
	if m.defaultAgent == "" {
		return "", "", false
	}
	a, ok := m.agents[m.defaultAgent]
	if !ok {
		return "", "", false
	}
	return m.defaultAgent, a.url, true
}

// ── Helper ──

func newRequest(method, path string) *http.Request {
	return httptest.NewRequest(method, path, nil)
}

// ── Single Mode Tests ──

func TestRoute_SingleMode(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"echo": {url: "http://localhost:9000", healthy: true},
		},
	}
	r := NewRouter("single", lookup)

	target, err := r.Route(newRequest("POST", "/message/send"))
	if err != nil {
		t.Fatalf("Route() error: %v", err)
	}
	if target.AgentName != "echo" {
		t.Errorf("AgentName = %q, want %q", target.AgentName, "echo")
	}
	if target.AgentURL != "http://localhost:9000" {
		t.Errorf("AgentURL = %q, want %q", target.AgentURL, "http://localhost:9000")
	}
	if target.Path != "/message/send" {
		t.Errorf("Path = %q, want %q", target.Path, "/message/send")
	}
	if target.IsDefault {
		t.Error("expected IsDefault = false")
	}
}

func TestRoute_SingleMode_Unhealthy(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"echo": {url: "http://localhost:9000", healthy: false},
		},
	}
	r := NewRouter("single", lookup)

	_, err := r.Route(newRequest("POST", "/message/send"))
	if err == nil {
		t.Fatal("expected error for unhealthy single agent")
	}
	if !errors.Is(err, sentinelerrors.ErrAgentUnavailable) {
		t.Errorf("error = %v, want ErrAgentUnavailable", err)
	}
}

// TestRoute_SingleMode_URLNotFound verifies ErrAgentUnavailable when a healthy agent
// appears in HealthyAgents() but GetAgentURL() returns not-found (inconsistent state).
func TestRoute_SingleMode_URLNotFound(t *testing.T) {
	// mockLookup with a custom lookup that returns a healthy agent name
	// but GetAgentURL returns false for it.
	lookup := &inconsistentLookup{healthyName: "ghost"}
	r := NewRouter("single", lookup)

	_, err := r.Route(newRequest("POST", "/message/send"))
	if err == nil {
		t.Fatal("expected error when agent URL not found")
	}
	if !errors.Is(err, sentinelerrors.ErrAgentUnavailable) {
		t.Errorf("error = %v, want ErrAgentUnavailable", err)
	}
}

// inconsistentLookup reports a healthy agent by name but refuses to return its URL.
type inconsistentLookup struct {
	healthyName string
}

func (l *inconsistentLookup) IsHealthy(name string) bool        { return name == l.healthyName }
func (l *inconsistentLookup) HealthyAgents() []string           { return []string{l.healthyName} }
func (l *inconsistentLookup) GetAgentURL(name string) (string, bool) { return "", false }
func (l *inconsistentLookup) GetDefaultAgent() (string, string, bool) { return "", "", false }

// ── Path-Prefix Mode Tests ──

func TestRoute_PathPrefix_ExactMatch(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"echo":      {url: "http://localhost:9001", healthy: true},
			"translate": {url: "http://localhost:9002", healthy: true},
		},
	}
	r := NewRouter("path-prefix", lookup)

	target, err := r.Route(newRequest("POST", "/agents/echo/message:send"))
	if err != nil {
		t.Fatalf("Route() error: %v", err)
	}
	if target.AgentName != "echo" {
		t.Errorf("AgentName = %q, want %q", target.AgentName, "echo")
	}
	if target.AgentURL != "http://localhost:9001" {
		t.Errorf("AgentURL = %q, want %q", target.AgentURL, "http://localhost:9001")
	}
	if target.Path != "/message:send" {
		t.Errorf("Path = %q, want %q", target.Path, "/message:send")
	}
	if target.IsDefault {
		t.Error("expected IsDefault = false")
	}
}

func TestRoute_PathPrefix_DefaultFallback(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"echo":    {url: "http://localhost:9001", healthy: true},
			"default": {url: "http://localhost:9099", healthy: true},
		},
		defaultAgent: "default",
	}
	r := NewRouter("path-prefix", lookup)

	target, err := r.Route(newRequest("POST", "/agents/unknown-agent/tasks/get"))
	if err != nil {
		t.Fatalf("Route() error: %v", err)
	}
	if target.AgentName != "default" {
		t.Errorf("AgentName = %q, want %q", target.AgentName, "default")
	}
	if target.AgentURL != "http://localhost:9099" {
		t.Errorf("AgentURL = %q, want %q", target.AgentURL, "http://localhost:9099")
	}
	if !target.IsDefault {
		t.Error("expected IsDefault = true for default fallback")
	}
}

func TestRoute_PathPrefix_NoDefault(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"echo": {url: "http://localhost:9001", healthy: true},
		},
		// No defaultAgent set.
	}
	r := NewRouter("path-prefix", lookup)

	_, err := r.Route(newRequest("POST", "/agents/nonexistent/message:send"))
	if err == nil {
		t.Fatal("expected error when agent not found and no default")
	}
	if !errors.Is(err, sentinelerrors.ErrNoRoute) {
		t.Errorf("error = %v, want ErrNoRoute", err)
	}
}

func TestRoute_PathPrefix_UnhealthySkipped(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"echo":    {url: "http://localhost:9001", healthy: false}, // unhealthy
			"default": {url: "http://localhost:9099", healthy: true},
		},
		defaultAgent: "default",
	}
	r := NewRouter("path-prefix", lookup)

	target, err := r.Route(newRequest("POST", "/agents/echo/message:send"))
	if err != nil {
		t.Fatalf("Route() error: %v", err)
	}
	// Should fallback to default because echo is unhealthy.
	if target.AgentName != "default" {
		t.Errorf("AgentName = %q, want %q (unhealthy agent should be skipped)", target.AgentName, "default")
	}
	if !target.IsDefault {
		t.Error("expected IsDefault = true when falling back from unhealthy agent")
	}
}

func TestRoute_PathPrefix_RootPath(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"default": {url: "http://localhost:9099", healthy: true},
		},
		defaultAgent: "default",
	}
	r := NewRouter("path-prefix", lookup)

	target, err := r.Route(newRequest("GET", "/"))
	if err != nil {
		t.Fatalf("Route() error: %v", err)
	}
	if target.AgentName != "default" {
		t.Errorf("AgentName = %q, want %q", target.AgentName, "default")
	}
	if !target.IsDefault {
		t.Error("expected IsDefault = true for root path")
	}
	if target.Path != "/" {
		t.Errorf("Path = %q, want %q", target.Path, "/")
	}
}

func TestRoute_PathPrefix_StripPrefix(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"echo": {url: "http://localhost:9001", healthy: true},
		},
	}
	r := NewRouter("path-prefix", lookup)

	target, err := r.Route(newRequest("GET", "/agents/echo/tasks/123"))
	if err != nil {
		t.Fatalf("Route() error: %v", err)
	}
	if target.Path != "/tasks/123" {
		t.Errorf("Path = %q, want %q (prefix should be stripped)", target.Path, "/tasks/123")
	}
}

// ── Edge Cases ──

func TestRoute_PathPrefix_AgentNoTrailingPath(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"echo": {url: "http://localhost:9001", healthy: true},
		},
	}
	r := NewRouter("path-prefix", lookup)

	target, err := r.Route(newRequest("GET", "/agents/echo"))
	if err != nil {
		t.Fatalf("Route() error: %v", err)
	}
	if target.AgentName != "echo" {
		t.Errorf("AgentName = %q, want %q", target.AgentName, "echo")
	}
	if target.Path != "/" {
		t.Errorf("Path = %q, want %q", target.Path, "/")
	}
}

func TestRoute_PathPrefix_NonAgentPath_NoDefault(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"echo": {url: "http://localhost:9001", healthy: true},
		},
		// No default.
	}
	r := NewRouter("path-prefix", lookup)

	_, err := r.Route(newRequest("GET", "/some/other/path"))
	if err == nil {
		t.Fatal("expected error for non-agent path with no default")
	}
	if !errors.Is(err, sentinelerrors.ErrNoRoute) {
		t.Errorf("error = %v, want ErrNoRoute", err)
	}
}

func TestRoute_PathPrefix_UnhealthyDefault(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"default": {url: "http://localhost:9099", healthy: false},
		},
		defaultAgent: "default",
	}
	r := NewRouter("path-prefix", lookup)

	_, err := r.Route(newRequest("GET", "/"))
	if err == nil {
		t.Fatal("expected error when default agent is unhealthy")
	}
	if !errors.Is(err, sentinelerrors.ErrAgentUnavailable) {
		t.Errorf("error = %v, want ErrAgentUnavailable", err)
	}
}

func TestRoute_UnknownMode(t *testing.T) {
	lookup := &mockLookup{
		agents: map[string]mockAgent{
			"echo": {url: "http://localhost:9001", healthy: true},
		},
	}
	r := NewRouter("invalid-mode", lookup)

	_, err := r.Route(newRequest("GET", "/"))
	if err == nil {
		t.Fatal("expected error for unknown routing mode")
	}
	if !errors.Is(err, sentinelerrors.ErrNoRoute) {
		t.Errorf("error = %v, want ErrNoRoute", err)
	}
}

func TestPathPrefixAgentName(t *testing.T) {
	tests := []struct {
		path          string
		wantAgent     string
		wantRemaining string
	}{
		{"/agents/echo/message:send", "echo", "/message:send"},
		{"/agents/echo/tasks/123", "echo", "/tasks/123"},
		{"/agents/echo", "echo", "/"},
		{"/agents/echo/", "echo", "/"},
		{"/", "", "/"},
		{"/some/other/path", "", "/some/other/path"},
		{"/agents/", "", "/"},
		{"/agentsfoo/bar", "", "/agentsfoo/bar"},
		// Path without leading slash — triggers normalization branch.
		{"agents/echo/tasks/get", "echo", "/tasks/get"},
		{"agents/echo", "echo", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			agent, remaining := pathPrefixAgentName(tt.path)
			if agent != tt.wantAgent {
				t.Errorf("pathPrefixAgentName(%q) agent = %q, want %q", tt.path, agent, tt.wantAgent)
			}
			if remaining != tt.wantRemaining {
				t.Errorf("pathPrefixAgentName(%q) remaining = %q, want %q", tt.path, remaining, tt.wantRemaining)
			}
		})
	}
}
