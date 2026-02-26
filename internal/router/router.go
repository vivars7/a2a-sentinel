// Package router implements request routing strategies for backend agents.
// It supports "single" mode (one agent) and "path-prefix" mode (URL path-based routing).
package router

import (
	"net/http"
	"strings"

	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
)

// AgentLookup is the interface Router needs from the Agent Card Manager.
// This decouples routing from the concrete agentcard.Manager for testability.
type AgentLookup interface {
	// IsHealthy returns whether the named agent is currently healthy.
	IsHealthy(name string) bool
	// HealthyAgents returns the names of all healthy agents.
	HealthyAgents() []string
	// GetAgentURL returns the backend URL for the named agent.
	GetAgentURL(name string) (string, bool)
	// GetDefaultAgent returns the name, URL, and whether a default agent exists.
	GetDefaultAgent() (name string, url string, found bool)
}

// RouteTarget holds the routing decision for a single request.
type RouteTarget struct {
	AgentName string // name of the matched backend agent
	AgentURL  string // backend URL to proxy to
	Path      string // rewritten path for the backend
	IsDefault bool   // true if fallback to default agent
}

// Router routes incoming requests to backend agents based on the configured strategy.
type Router struct {
	mode   string      // "path-prefix" or "single"
	lookup AgentLookup // agent health and URL provider
}

// NewRouter creates a new Router with the given routing mode and agent lookup.
// mode must be "single" or "path-prefix".
func NewRouter(mode string, lookup AgentLookup) *Router {
	return &Router{mode: mode, lookup: lookup}
}

// Route determines which backend agent should handle the request.
// It returns the routing target or a SentinelError (ErrNoRoute, ErrAgentUnavailable).
func (r *Router) Route(req *http.Request) (*RouteTarget, error) {
	switch r.mode {
	case "single":
		return r.routeSingle(req)
	case "path-prefix":
		return r.routePathPrefix(req)
	default:
		return nil, sentinelerrors.ErrNoRoute
	}
}

// pathPrefixAgentName extracts the agent name from a /agents/{name}/... path.
// Returns the agent name and the remaining path after stripping the prefix.
// If the path does not match the /agents/{name} pattern, returns empty name.
func pathPrefixAgentName(path string) (agentName, remaining string) {
	// Normalize: ensure leading slash
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Must start with /agents/
	const prefix = "/agents/"
	if !strings.HasPrefix(path, prefix) {
		return "", path
	}

	// Extract agent name: everything between /agents/ and next /
	rest := path[len(prefix):]
	slashIdx := strings.IndexByte(rest, '/')
	if slashIdx < 0 {
		// /agents/echo — no trailing path
		return rest, "/"
	}

	agentName = rest[:slashIdx]
	remaining = rest[slashIdx:] // includes leading /
	return agentName, remaining
}
