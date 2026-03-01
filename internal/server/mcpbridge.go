package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/agentcard"
	"github.com/vivars7/a2a-sentinel/internal/config"
	"github.com/vivars7/a2a-sentinel/internal/mcpserver"
	"github.com/vivars7/a2a-sentinel/internal/proxy"
)

// mcpBridge implements mcpserver.SentinelBridge by delegating to
// existing server components (card manager, config, metrics, etc.).
type mcpBridge struct {
	cardManager *agentcard.Manager
	streamMgr   *proxy.StreamManager
	cfg         *config.Config
	version     string
	startTime   time.Time
}

// newMCPBridge creates a bridge from existing server components.
func newMCPBridge(
	cardManager *agentcard.Manager,
	streamMgr *proxy.StreamManager,
	cfg *config.Config,
	version string,
) *mcpBridge {
	return &mcpBridge{
		cardManager: cardManager,
		streamMgr:   streamMgr,
		cfg:         cfg,
		version:     version,
		startTime:   time.Now(),
	}
}

// ListAgents returns all configured agents and their health status.
func (b *mcpBridge) ListAgents() []mcpserver.AgentStatus {
	states := b.cardManager.AllAgentStates()
	result := make([]mcpserver.AgentStatus, len(states))
	for i, s := range states {
		result[i] = mcpserver.AgentStatus{
			Name:       s.Name,
			URL:        s.URL,
			Healthy:    s.Healthy,
			SkillCount: s.SkillCount,
			LastPolled: s.LastPolled,
		}
	}
	return result
}

// HealthCheck returns overall system health.
func (b *mcpBridge) HealthCheck() mcpserver.SystemHealth {
	agents := b.ListAgents()

	healthy := 0
	for _, a := range agents {
		if a.Healthy {
			healthy++
		}
	}

	status := "healthy"
	if healthy == 0 && len(agents) > 0 {
		status = "unhealthy"
	} else if healthy < len(agents) {
		status = "degraded"
	}

	return mcpserver.SystemHealth{
		Status:       status,
		Agents:       agents,
		ActiveStreams: b.totalActiveStreams(),
		Uptime:       time.Since(b.startTime),
	}
}

// totalActiveStreams sums active streams across all configured agents.
func (b *mcpBridge) totalActiveStreams() int {
	total := 0
	for _, a := range b.cfg.Agents {
		total += b.streamMgr.ActiveStreams(a.Name)
	}
	return total
}

// GetBlockedRequests returns blocked requests within the given time window.
// Not yet implemented; audit log does not expose a query API.
func (b *mcpBridge) GetBlockedRequests(_ time.Time, _ int) []mcpserver.BlockedRequest {
	return []mcpserver.BlockedRequest{}
}

// GetAgentCard returns the Agent Card for the named agent as a generic map.
func (b *mcpBridge) GetAgentCard(name string) (map[string]interface{}, error) {
	card, ok := b.cardManager.GetCard(name)
	if !ok {
		return nil, fmt.Errorf("agent %q not found", name)
	}
	return cardToMap(card)
}

// GetAggregatedCard returns the aggregated gateway Agent Card as a generic map.
func (b *mcpBridge) GetAggregatedCard() (map[string]interface{}, error) {
	card := b.cardManager.GetAggregatedCard()
	if card == nil {
		return map[string]interface{}{}, nil
	}
	return cardToMap(card)
}

// GetRateLimitStatus returns rate limit state for all agents.
// Not yet implemented; the rate limiter does not expose per-agent state.
func (b *mcpBridge) GetRateLimitStatus() []mcpserver.RateLimitStatus {
	return []mcpserver.RateLimitStatus{}
}

// UpdateRateLimit updates the rate limit for a specific agent.
// Not yet implemented.
func (b *mcpBridge) UpdateRateLimit(_ string, _ int) (int, error) {
	return 0, fmt.Errorf("rate limit update not implemented")
}

// RegisterAgent registers a new backend agent.
// Not yet implemented; agent list is static from config.
func (b *mcpBridge) RegisterAgent(_, _ string, _ bool) error {
	return fmt.Errorf("dynamic agent registration not implemented")
}

// DeregisterAgent removes a backend agent.
// Not yet implemented; agent list is static from config.
func (b *mcpBridge) DeregisterAgent(_ string) error {
	return fmt.Errorf("dynamic agent deregistration not implemented")
}

// SendTestMessage sends a test message to a specific agent.
// Not yet implemented.
func (b *mcpBridge) SendTestMessage(_, _ string) (*mcpserver.TestResult, error) {
	return nil, fmt.Errorf("test message sending not implemented")
}

// ListPendingChanges returns all pending Agent Card changes.
func (b *mcpBridge) ListPendingChanges() []mcpserver.PendingCardChange {
	pending := b.cardManager.ListPendingChanges()
	result := make([]mcpserver.PendingCardChange, len(pending))
	for i, p := range pending {
		hasCritical := false
		for _, c := range p.Changes {
			if c.Critical {
				hasCritical = true
				break
			}
		}
		result[i] = mcpserver.PendingCardChange{
			AgentName:  p.AgentName,
			DetectedAt: p.DetectedAt,
			Changes:    len(p.Changes),
			Critical:   hasCritical,
			Status:     p.Status,
		}
	}
	return result
}

// ApproveCardChange approves a pending card change.
func (b *mcpBridge) ApproveCardChange(agentName string) error {
	return b.cardManager.ApproveCardChange(agentName)
}

// RejectCardChange rejects a pending card change.
func (b *mcpBridge) RejectCardChange(agentName string) error {
	return b.cardManager.RejectCardChange(agentName)
}

// ListPolicies returns all configured ABAC policies.
func (b *mcpBridge) ListPolicies() []mcpserver.PolicyInfo {
	policies := b.cfg.Security.Policies
	result := make([]mcpserver.PolicyInfo, len(policies))
	for i, p := range policies {
		info := mcpserver.PolicyInfo{
			Name:        p.Name,
			Description: p.Description,
			Action:      p.Action,
			Priority:    p.Priority,
			Match: mcpserver.PolicyMatchInfo{
				Agents:  p.Match.Agents,
				Methods: p.Match.Methods,
				Users:   p.Match.Users,
				IPs:     p.Match.IPs,
				Headers: p.Match.Headers,
			},
		}
		if p.Match.TimeRange != nil {
			info.Match.TimeRange = &mcpserver.TimeRangeInfo{
				Start: p.Match.TimeRange.Start,
				End:   p.Match.TimeRange.End,
				TZ:    p.Match.TimeRange.TZ,
			}
		}
		result[i] = info
	}
	return result
}

// EvaluatePolicy evaluates what decision would be made for the given attributes.
// Currently returns allow for all requests (full policy engine not yet wired).
func (b *mcpBridge) EvaluatePolicy(req mcpserver.PolicyEvalRequest) mcpserver.PolicyEvalResult {
	return mcpserver.PolicyEvalResult{
		Action:        "allow",
		MatchedPolicy: "default",
		Reason:        "no matching deny policy",
	}
}

// GetConfig returns the current configuration with sensitive values masked.
func (b *mcpBridge) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"listen": map[string]interface{}{
			"host":             b.cfg.Listen.Host,
			"port":             b.cfg.Listen.Port,
			"max_connections":  b.cfg.Listen.MaxConnections,
			"global_rate_limit": b.cfg.Listen.GlobalRateLimit,
		},
		"routing": map[string]interface{}{
			"mode": b.cfg.Routing.Mode,
		},
		"security": map[string]interface{}{
			"auth_mode":      b.cfg.Security.Auth.Mode,
			"rate_limit":     b.cfg.Security.RateLimit.Enabled,
			"replay_detect":  b.cfg.Security.Replay.Enabled,
			"card_signature": b.cfg.Security.CardSignature.Require,
		},
		"agents": sanitizeAgents(b.cfg.Agents),
		"mcp": map[string]interface{}{
			"enabled": b.cfg.MCP.Enabled,
			"host":    b.cfg.MCP.Host,
			"port":    b.cfg.MCP.Port,
			"auth":    maskToken(b.cfg.MCP.Auth.Token),
		},
	}
}

// GetMetrics returns basic request metrics.
func (b *mcpBridge) GetMetrics() map[string]interface{} {
	agents := b.ListAgents()
	healthy := 0
	for _, a := range agents {
		if a.Healthy {
			healthy++
		}
	}

	return map[string]interface{}{
		"total_agents":   len(agents),
		"healthy_agents": healthy,
		"active_streams": b.totalActiveStreams(),
		"uptime_seconds": int(time.Since(b.startTime).Seconds()),
		"version":        b.version,
	}
}

// GetSecurityReport returns a security summary.
func (b *mcpBridge) GetSecurityReport() map[string]interface{} {
	return map[string]interface{}{
		"auth_mode":           b.cfg.Security.Auth.Mode,
		"allow_unauthenticated": b.cfg.Security.Auth.AllowUnauthenticated,
		"rate_limit_enabled":  b.cfg.Security.RateLimit.Enabled,
		"replay_detection":    b.cfg.Security.Replay.Enabled,
		"card_signature_required": b.cfg.Security.CardSignature.Require,
		"push_security": map[string]interface{}{
			"block_private_networks": b.cfg.Security.Push.BlockPrivateNetworks,
			"require_https":          b.cfg.Security.Push.RequireHTTPS,
			"require_challenge":      b.cfg.Security.Push.RequireChallenge,
		},
		"policy_count": len(b.cfg.Security.Policies),
	}
}

// cardToMap converts a protocol.AgentCard to a generic map via JSON round-trip.
func cardToMap(card interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(card)
	if err != nil {
		return nil, fmt.Errorf("marshalling agent card: %w", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("unmarshalling agent card: %w", err)
	}
	return m, nil
}

// sanitizeAgents returns agent info with URLs but without sensitive details.
func sanitizeAgents(agents []config.AgentConfig) []map[string]interface{} {
	result := make([]map[string]interface{}, len(agents))
	for i, a := range agents {
		result[i] = map[string]interface{}{
			"name":    a.Name,
			"url":     a.URL,
			"default": a.Default,
		}
	}
	return result
}

// maskToken returns a masked version of a token string.
func maskToken(token string) string {
	if token == "" {
		return "(none)"
	}
	if len(token) <= 4 {
		return strings.Repeat("*", len(token))
	}
	return token[:2] + strings.Repeat("*", len(token)-4) + token[len(token)-2:]
}
