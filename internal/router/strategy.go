package router

import (
	"net/http"

	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
)

// routeSingle handles the "single" routing mode.
// All requests are sent to the one configured agent.
func (r *Router) routeSingle(req *http.Request) (*RouteTarget, error) {
	agents := r.lookup.HealthyAgents()
	if len(agents) == 0 {
		// The single agent exists but is unhealthy.
		return nil, sentinelerrors.ErrAgentUnavailable
	}

	name := agents[0]
	url, ok := r.lookup.GetAgentURL(name)
	if !ok {
		return nil, sentinelerrors.ErrAgentUnavailable
	}

	return &RouteTarget{
		AgentName: name,
		AgentURL:  url,
		Path:      req.URL.Path,
		IsDefault: false,
	}, nil
}

// routePathPrefix handles the "path-prefix" routing mode.
// Requests to /agents/{name}/... are routed to the named agent with the prefix stripped.
// Requests that don't match /agents/{name} or target an unhealthy/unknown agent
// fall back to the default agent. If no default exists, ErrNoRoute is returned.
func (r *Router) routePathPrefix(req *http.Request) (*RouteTarget, error) {
	agentName, remaining := pathPrefixAgentName(req.URL.Path)

	// If we extracted an agent name, try to route to it.
	if agentName != "" {
		url, exists := r.lookup.GetAgentURL(agentName)
		if exists && r.lookup.IsHealthy(agentName) {
			return &RouteTarget{
				AgentName: agentName,
				AgentURL:  url,
				Path:      remaining,
				IsDefault: false,
			}, nil
		}
	}

	// Fallback: try the default agent.
	return r.routeDefault(req.URL.Path)
}

// routeDefault attempts to route to the default agent.
// Returns ErrNoRoute if no default agent is configured or it is unhealthy.
func (r *Router) routeDefault(originalPath string) (*RouteTarget, error) {
	name, url, found := r.lookup.GetDefaultAgent()
	if !found {
		return nil, sentinelerrors.ErrNoRoute
	}

	if !r.lookup.IsHealthy(name) {
		return nil, sentinelerrors.ErrAgentUnavailable
	}

	return &RouteTarget{
		AgentName: name,
		AgentURL:  url,
		Path:      originalPath,
		IsDefault: true,
	}, nil
}
