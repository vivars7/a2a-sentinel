package health

import (
	"encoding/json"
	"net/http"
)

// AgentHealthChecker is the interface that the health handler needs from the agent card manager.
// This avoids a direct dependency on internal/agentcard.
type AgentHealthChecker interface {
	HealthyAgents() []string
	AllAgentNames() []string // returns all agent names regardless of health
}

// SimpleAgentHealthChecker is a basic implementation for when agentcard.Manager is available.
// It wraps a function that returns healthy and total counts.
type SimpleAgentHealthChecker struct {
	HealthyFn  func() []string
	AllNamesFn func() []string
}

// HealthyAgents returns the list of healthy agent names via the HealthyFn function.
func (s *SimpleAgentHealthChecker) HealthyAgents() []string { return s.HealthyFn() }

// AllAgentNames returns all agent names regardless of health via the AllNamesFn function.
func (s *SimpleAgentHealthChecker) AllAgentNames() []string { return s.AllNamesFn() }

// Handler provides HTTP health check endpoints.
type Handler struct {
	checker       AgentHealthChecker
	version       string
	readinessMode string // "any_healthy", "default_healthy", "all_healthy"
	defaultAgent  string // name of default agent (for default_healthy mode)
}

// NewHandler creates a health check handler.
func NewHandler(checker AgentHealthChecker, version string, readinessMode string, defaultAgent string) *Handler {
	return &Handler{
		checker:       checker,
		version:       version,
		readinessMode: readinessMode,
		defaultAgent:  defaultAgent,
	}
}

// ServeHTTP routes to the appropriate health endpoint.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		h.handleLiveness(w, r)
	case "/readyz":
		h.handleReadiness(w, r)
	default:
		http.NotFound(w, r)
	}
}

// LivenessResponse is the JSON response for /healthz.
type LivenessResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// ReadinessResponse is the JSON response for /readyz.
type ReadinessResponse struct {
	Status        string `json:"status"`
	HealthyAgents int    `json:"healthy_agents"`
	TotalAgents   int    `json:"total_agents"`
}

func (h *Handler) handleLiveness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LivenessResponse{
		Status:  "ok",
		Version: h.version,
	})
}

func (h *Handler) handleReadiness(w http.ResponseWriter, r *http.Request) {
	healthy := h.checker.HealthyAgents()
	allAgents := h.checker.AllAgentNames()

	healthyCount := len(healthy)
	totalCount := len(allAgents)

	isReady := false
	switch h.readinessMode {
	case "any_healthy":
		isReady = healthyCount > 0
	case "default_healthy":
		for _, name := range healthy {
			if name == h.defaultAgent {
				isReady = true
				break
			}
		}
	case "all_healthy":
		isReady = healthyCount == totalCount && totalCount > 0
	default:
		isReady = healthyCount > 0 // default to any_healthy
	}

	w.Header().Set("Content-Type", "application/json")

	resp := ReadinessResponse{
		HealthyAgents: healthyCount,
		TotalAgents:   totalCount,
	}

	if isReady {
		resp.Status = "ready"
		w.WriteHeader(http.StatusOK)
	} else {
		resp.Status = "not_ready"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(resp)
}
