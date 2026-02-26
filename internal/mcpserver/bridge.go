// Package mcpserver implements a read-only MCP server for gateway management.
// It exposes sentinel internal state over a local-only JSON-RPC endpoint.
package mcpserver

import "time"

// SentinelBridge provides read-only access to sentinel internal state.
// Implementation is provided by the server package.
type SentinelBridge interface {
	ListAgents() []AgentStatus
	HealthCheck() SystemHealth
	GetBlockedRequests(since time.Time, limit int) []BlockedRequest
}

// AgentStatus describes the current status of a backend A2A agent.
type AgentStatus struct {
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Healthy    bool      `json:"healthy"`
	SkillCount int       `json:"skills_count"`
	LastPolled time.Time `json:"last_polled"`
}

// SystemHealth summarises the overall health of the sentinel gateway.
type SystemHealth struct {
	Status       string        `json:"status"`
	Agents       []AgentStatus `json:"agents"`
	ActiveStreams int           `json:"active_streams"`
	Uptime       time.Duration `json:"uptime"`
}

// BlockedRequest records a single request that was blocked by the security pipeline.
type BlockedRequest struct {
	Timestamp   time.Time `json:"timestamp"`
	ClientIP    string    `json:"client_ip"`
	Method      string    `json:"method"`
	BlockReason string    `json:"block_reason"`
	Agent       string    `json:"agent,omitempty"`
}
