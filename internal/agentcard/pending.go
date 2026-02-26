package agentcard

import (
	"fmt"
	"sync"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/protocol"
)

// PendingChange represents a detected card change waiting for manual approval.
type PendingChange struct {
	AgentName  string             `json:"agent_name"`
	OldCard    *protocol.AgentCard `json:"old_card"`
	NewCard    *protocol.AgentCard `json:"new_card"`
	Changes    []Change           `json:"changes"`
	DetectedAt time.Time          `json:"detected_at"`
	Status     string             `json:"status"` // "pending", "approved", "rejected"
}

// PendingStore manages pending card changes awaiting approval.
// It is safe for concurrent use.
type PendingStore struct {
	mu      sync.RWMutex
	pending map[string]*PendingChange // agent name -> pending change
}

// NewPendingStore creates an empty PendingStore.
func NewPendingStore() *PendingStore {
	return &PendingStore{
		pending: make(map[string]*PendingChange),
	}
}

// Add stores a pending change for the given agent.
// If there is already a pending change for this agent, it is replaced.
func (s *PendingStore) Add(change *PendingChange) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[change.AgentName] = change
}

// Approve approves and removes a pending change, returning it.
// Returns an error if no pending change exists for the agent.
func (s *PendingStore) Approve(agentName string) (*PendingChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	change, ok := s.pending[agentName]
	if !ok {
		return nil, fmt.Errorf("no pending change for agent %q", agentName)
	}
	change.Status = "approved"
	delete(s.pending, agentName)
	return change, nil
}

// Reject removes a pending change without applying it.
// Returns an error if no pending change exists for the agent.
func (s *PendingStore) Reject(agentName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.pending[agentName]; !ok {
		return fmt.Errorf("no pending change for agent %q", agentName)
	}
	delete(s.pending, agentName)
	return nil
}

// List returns all pending changes.
func (s *PendingStore) List() []PendingChange {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]PendingChange, 0, len(s.pending))
	for _, change := range s.pending {
		result = append(result, *change)
	}
	return result
}

// Get returns the pending change for a specific agent, if any.
func (s *PendingStore) Get(agentName string) (*PendingChange, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	change, ok := s.pending[agentName]
	if !ok {
		return nil, false
	}
	return change, true
}
