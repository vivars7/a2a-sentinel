// Package agentcard manages Agent Card lifecycle including polling, caching,
// change detection, and aggregation for the a2a-sentinel gateway.
package agentcard

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/config"
	"github.com/vivars7/a2a-sentinel/internal/protocol"
)

// Manager manages Agent Card lifecycle for all configured agents.
type Manager struct {
	mu           sync.RWMutex
	agents       map[string]*agentState
	jwsVerifier  *JWSVerifier
	pendingStore *PendingStore
	logger       *slog.Logger
	cancel       context.CancelFunc
}

// agentState holds the runtime state for a single agent.
type agentState struct {
	name          string
	url           string
	cardPath      string
	pollInterval  time.Duration
	timeout       time.Duration
	maxStreams    int
	isDefault     bool
	allowInsecure bool
	changePolicy  CardChangePolicy

	card       *protocol.AgentCard
	healthy    bool
	lastPolled time.Time
	lastError  error
}

// AgentStatus exposes agent metadata for monitoring and MCP.
type AgentStatus struct {
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Healthy    bool      `json:"healthy"`
	SkillCount int       `json:"skills_count"`
	LastPolled time.Time `json:"last_polled"`
	LastError  string    `json:"last_error,omitempty"`
}

// NewManager creates a new Agent Card Manager from the agent configuration list.
// The sigCfg parameter controls JWS signature verification for fetched Agent Cards.
func NewManager(agents []config.AgentConfig, sigCfg config.CardSignatureConfig, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}

	states := make(map[string]*agentState, len(agents))
	for _, a := range agents {
		states[a.Name] = &agentState{
			name:          a.Name,
			url:           a.URL,
			cardPath:      a.CardPath,
			pollInterval:  a.PollInterval.Duration,
			timeout:       a.Timeout.Duration,
			maxStreams:    a.MaxStreams,
			isDefault:     a.Default,
			allowInsecure: a.AllowInsecure,
			changePolicy:  CardChangePolicy(a.CardChangePolicy),
		}
	}

	verifier := NewJWSVerifier(JWSVerifierConfig{
		Require:         sigCfg.Require,
		TrustedJWKSURLs: sigCfg.TrustedJWKSURLs,
		CacheTTL:        sigCfg.CacheTTL.Duration,
	})

	return &Manager{
		agents:       states,
		jwsVerifier:  verifier,
		pendingStore: NewPendingStore(),
		logger:       logger,
	}
}

// Start begins polling all agents for their Agent Cards.
// It initializes the JWKS cache (if configured) and launches one goroutine per agent.
func (m *Manager) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	// Initialize JWKS cache for Agent Card signature verification.
	if m.jwsVerifier != nil {
		if err := m.jwsVerifier.StartCache(ctx); err != nil {
			return fmt.Errorf("starting JWS verifier cache: %w", err)
		}
	}

	for _, state := range m.agents {
		go m.pollAgent(ctx, state)
	}

	return nil
}

// Stop halts all polling goroutines.
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

// GetCard returns the Agent Card for the named agent.
func (m *Manager) GetCard(name string) (*protocol.AgentCard, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.agents[name]
	if !ok || state.card == nil {
		return nil, false
	}
	return state.card, true
}

// GetAggregatedCard returns a gateway Agent Card that aggregates all healthy agents' skills.
// IMPORTANT: Must NOT add any sentinel-specific fields (Zero Agent Dependency).
func (m *Manager) GetAggregatedCard() *protocol.AgentCard {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return AggregateCards(m.agents, "")
}

// IsHealthy returns whether the named agent is healthy.
func (m *Manager) IsHealthy(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.agents[name]
	if !ok {
		return false
	}
	return state.healthy
}

// HealthyAgents returns the names of all healthy agents.
func (m *Manager) HealthyAgents() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var names []string
	for _, state := range m.agents {
		if state.healthy {
			names = append(names, state.name)
		}
	}
	return names
}

// GetAgentState returns agent metadata for MCP/monitoring.
func (m *Manager) GetAgentState(name string) (AgentStatus, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.agents[name]
	if !ok {
		return AgentStatus{}, false
	}
	return m.toAgentStatus(state), true
}

// AllAgentStates returns status for all agents.
func (m *Manager) AllAgentStates() []AgentStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	statuses := make([]AgentStatus, 0, len(m.agents))
	for _, state := range m.agents {
		statuses = append(statuses, m.toAgentStatus(state))
	}
	return statuses
}

// ApproveCardChange approves a pending change and applies the new card.
func (m *Manager) ApproveCardChange(agentName string) error {
	change, err := m.pendingStore.Approve(agentName)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if state, ok := m.agents[agentName]; ok {
		state.card = change.NewCard
		m.logger.Info("agent card change approved and applied",
			"agent", agentName,
			"changes", len(change.Changes),
		)
	}
	return nil
}

// RejectCardChange rejects a pending change, keeping the old card.
func (m *Manager) RejectCardChange(agentName string) error {
	err := m.pendingStore.Reject(agentName)
	if err != nil {
		return err
	}
	m.logger.Info("agent card change rejected",
		"agent", agentName,
	)
	return nil
}

// ListPendingChanges returns all pending card changes awaiting approval.
func (m *Manager) ListPendingChanges() []PendingChange {
	return m.pendingStore.List()
}

// toAgentStatus converts internal agentState to the public AgentStatus.
func (m *Manager) toAgentStatus(state *agentState) AgentStatus {
	status := AgentStatus{
		Name:       state.name,
		URL:        state.url,
		Healthy:    state.healthy,
		LastPolled: state.lastPolled,
	}
	if state.card != nil {
		status.SkillCount = len(state.card.Skills)
	}
	if state.lastError != nil {
		status.LastError = state.lastError.Error()
	}
	return status
}
