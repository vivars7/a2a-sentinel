// Package mcpserver implements an MCP server for gateway management.
// It exposes sentinel internal state over a local-only JSON-RPC endpoint.
package mcpserver

import "time"

// SentinelBridge provides access to sentinel internal state.
// Implementation is provided by the server package.
type SentinelBridge interface {
	// Read methods
	ListAgents() []AgentStatus
	HealthCheck() SystemHealth
	GetBlockedRequests(since time.Time, limit int) []BlockedRequest
	GetAgentCard(name string) (map[string]interface{}, error)
	GetAggregatedCard() (map[string]interface{}, error)
	GetRateLimitStatus() []RateLimitStatus

	// Write methods
	UpdateRateLimit(agentName string, perMinute int) (previous int, err error)
	RegisterAgent(name, url string, isDefault bool) error
	DeregisterAgent(name string) error
	SendTestMessage(agentName, text string) (*TestResult, error)

	// Card change approval methods
	ListPendingChanges() []PendingCardChange
	ApproveCardChange(agentName string) error
	RejectCardChange(agentName string) error

	// Resource methods
	GetConfig() map[string]interface{}
	GetMetrics() map[string]interface{}
	GetSecurityReport() map[string]interface{}
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

// RateLimitStatus describes the current rate-limit state for a single agent.
type RateLimitStatus struct {
	Agent      string `json:"agent"`
	CurrentRPM int    `json:"current_rpm"`
	LimitRPM   int    `json:"limit_rpm"`
	Remaining  int    `json:"remaining"`
}

// TestResult holds the outcome of sending a test message to an agent.
type TestResult struct {
	TaskID       string `json:"task_id"`
	Status       string `json:"status"`
	ResponseText string `json:"response_text"`
}

// PendingCardChange describes a card change awaiting manual approval.
type PendingCardChange struct {
	AgentName  string    `json:"agent_name"`
	DetectedAt time.Time `json:"detected_at"`
	Changes    int       `json:"changes_count"`
	Critical   bool      `json:"has_critical"`
	Status     string    `json:"status"`
}
