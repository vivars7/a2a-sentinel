package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// StreamManager tracks and limits concurrent SSE streams per agent.
// It provides acquire/release semantics for stream slots and supports
// graceful draining during shutdown.
type StreamManager struct {
	mu       sync.Mutex
	counts   map[string]*int64 // agent name → active stream count
	draining atomic.Bool
}

// NewStreamManager creates a new stream manager.
func NewStreamManager() *StreamManager {
	return &StreamManager{
		counts: make(map[string]*int64),
	}
}

// AcquireStream attempts to acquire a stream slot for the agent.
// Returns false if the agent's maxStreams limit is reached or if draining.
// Uses atomic compare-and-swap to avoid races between limit check and increment.
func (sm *StreamManager) AcquireStream(agentName string, maxStreams int) bool {
	if sm.draining.Load() {
		return false
	}

	sm.mu.Lock()
	counter, ok := sm.counts[agentName]
	if !ok {
		var c int64
		counter = &c
		sm.counts[agentName] = counter
	}
	sm.mu.Unlock()

	// CAS loop to atomically check limit and increment
	for {
		current := atomic.LoadInt64(counter)
		if current >= int64(maxStreams) {
			return false
		}
		if atomic.CompareAndSwapInt64(counter, current, current+1) {
			return true
		}
	}
}

// ReleaseStream releases a stream slot for the agent.
func (sm *StreamManager) ReleaseStream(agentName string) {
	sm.mu.Lock()
	counter, ok := sm.counts[agentName]
	sm.mu.Unlock()
	if ok {
		atomic.AddInt64(counter, -1)
	}
}

// ActiveStreams returns the number of active streams for an agent.
func (sm *StreamManager) ActiveStreams(agentName string) int {
	sm.mu.Lock()
	counter, ok := sm.counts[agentName]
	sm.mu.Unlock()
	if !ok {
		return 0
	}
	return int(atomic.LoadInt64(counter))
}

// DrainAll stops accepting new streams and waits for existing ones to finish.
// It blocks until all streams are released or the context is canceled.
func (sm *StreamManager) DrainAll(ctx context.Context) error {
	sm.draining.Store(true)

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if sm.totalStreams() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Check again on next iteration
		}
	}
}

func (sm *StreamManager) totalStreams() int64 {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	var total int64
	for _, counter := range sm.counts {
		total += atomic.LoadInt64(counter)
	}
	return total
}
