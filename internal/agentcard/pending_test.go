package agentcard

import (
	"sync"
	"testing"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/protocol"
)

func testPendingChange(agentName string) *PendingChange {
	return &PendingChange{
		AgentName: agentName,
		OldCard: &protocol.AgentCard{
			Name:    agentName,
			URL:     "https://old.example.com",
			Version: "1.0",
		},
		NewCard: &protocol.AgentCard{
			Name:    agentName,
			URL:     "https://new.example.com",
			Version: "2.0",
		},
		Changes: []Change{
			{Field: "url", OldValue: "https://old.example.com", NewValue: "https://new.example.com", Critical: true},
			{Field: "version", OldValue: "1.0", NewValue: "2.0", Critical: true},
		},
		DetectedAt: time.Now(),
		Status:     "pending",
	}
}

func TestPendingStore_Add(t *testing.T) {
	store := NewPendingStore()
	change := testPendingChange("agent-a")

	store.Add(change)

	got, ok := store.Get("agent-a")
	if !ok {
		t.Fatal("expected pending change for agent-a")
	}
	if got.AgentName != "agent-a" {
		t.Errorf("AgentName = %q, want %q", got.AgentName, "agent-a")
	}
	if got.Status != "pending" {
		t.Errorf("Status = %q, want %q", got.Status, "pending")
	}
	if len(got.Changes) != 2 {
		t.Errorf("Changes count = %d, want 2", len(got.Changes))
	}
}

func TestPendingStore_Approve(t *testing.T) {
	store := NewPendingStore()
	change := testPendingChange("agent-a")
	store.Add(change)

	approved, err := store.Approve("agent-a")
	if err != nil {
		t.Fatalf("Approve() error: %v", err)
	}
	if approved.AgentName != "agent-a" {
		t.Errorf("approved AgentName = %q, want %q", approved.AgentName, "agent-a")
	}
	if approved.Status != "approved" {
		t.Errorf("approved Status = %q, want %q", approved.Status, "approved")
	}

	// Should be removed from store.
	_, ok := store.Get("agent-a")
	if ok {
		t.Error("expected agent-a to be removed after approval")
	}
}

func TestPendingStore_Approve_NotFound(t *testing.T) {
	store := NewPendingStore()

	_, err := store.Approve("nonexistent")
	if err == nil {
		t.Fatal("expected error for approving nonexistent agent")
	}
}

func TestPendingStore_Reject(t *testing.T) {
	store := NewPendingStore()
	change := testPendingChange("agent-b")
	store.Add(change)

	err := store.Reject("agent-b")
	if err != nil {
		t.Fatalf("Reject() error: %v", err)
	}

	// Should be removed from store.
	_, ok := store.Get("agent-b")
	if ok {
		t.Error("expected agent-b to be removed after rejection")
	}
}

func TestPendingStore_Reject_NotFound(t *testing.T) {
	store := NewPendingStore()

	err := store.Reject("nonexistent")
	if err == nil {
		t.Fatal("expected error for rejecting nonexistent agent")
	}
}

func TestPendingStore_List(t *testing.T) {
	store := NewPendingStore()
	store.Add(testPendingChange("agent-a"))
	store.Add(testPendingChange("agent-b"))
	store.Add(testPendingChange("agent-c"))

	list := store.List()
	if len(list) != 3 {
		t.Fatalf("List() returned %d items, want 3", len(list))
	}

	// Verify all agents are present.
	names := make(map[string]bool)
	for _, pc := range list {
		names[pc.AgentName] = true
	}
	for _, want := range []string{"agent-a", "agent-b", "agent-c"} {
		if !names[want] {
			t.Errorf("List() missing agent %q", want)
		}
	}
}

func TestPendingStore_List_Empty(t *testing.T) {
	store := NewPendingStore()

	list := store.List()
	if len(list) != 0 {
		t.Errorf("List() on empty store returned %d items, want 0", len(list))
	}
}

func TestPendingStore_Get_NotFound(t *testing.T) {
	store := NewPendingStore()

	_, ok := store.Get("nonexistent")
	if ok {
		t.Error("expected Get() to return false for nonexistent agent")
	}
}

func TestPendingStore_Replace(t *testing.T) {
	store := NewPendingStore()

	// Add initial change.
	first := testPendingChange("agent-a")
	first.Changes = []Change{{Field: "url", Critical: true}}
	store.Add(first)

	// Replace with new change.
	second := testPendingChange("agent-a")
	second.Changes = []Change{
		{Field: "url", Critical: true},
		{Field: "version", Critical: true},
		{Field: "name", Critical: false},
	}
	store.Add(second)

	// Should have the replacement.
	got, ok := store.Get("agent-a")
	if !ok {
		t.Fatal("expected pending change for agent-a")
	}
	if len(got.Changes) != 3 {
		t.Errorf("Changes count = %d, want 3 (replacement)", len(got.Changes))
	}

	// List should still have exactly 1 entry.
	list := store.List()
	if len(list) != 1 {
		t.Errorf("List() returned %d items, want 1 after replacement", len(list))
	}
}

func TestPendingStore_Concurrent(t *testing.T) {
	store := NewPendingStore()
	const goroutines = 50
	var wg sync.WaitGroup

	// Concurrent adds.
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			name := "agent-a" // all write to same key to stress contention
			store.Add(&PendingChange{
				AgentName:  name,
				DetectedAt: time.Now(),
				Status:     "pending",
				Changes:    []Change{{Field: "version", Critical: false}},
			})
		}(i)
	}
	wg.Wait()

	// Should have exactly 1 entry (last write wins).
	list := store.List()
	if len(list) != 1 {
		t.Errorf("List() after concurrent adds = %d, want 1", len(list))
	}

	// Concurrent reads + writes.
	wg.Add(goroutines * 3)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			store.List()
		}()
		go func() {
			defer wg.Done()
			store.Get("agent-a")
		}()
		go func() {
			defer wg.Done()
			store.Add(&PendingChange{
				AgentName:  "agent-a",
				DetectedAt: time.Now(),
				Status:     "pending",
				Changes:    []Change{{Field: "url", Critical: true}},
			})
		}()
	}
	wg.Wait()

	// No panic or race = success. Final state should still be valid.
	got, ok := store.Get("agent-a")
	if !ok {
		t.Fatal("expected agent-a to still exist after concurrent operations")
	}
	if got.Status != "pending" {
		t.Errorf("Status = %q, want %q", got.Status, "pending")
	}
}
