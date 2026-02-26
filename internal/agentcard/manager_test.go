package agentcard

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/config"
	"github.com/vivars7/a2a-sentinel/internal/protocol"
)

// ── Test helpers ──

// newFakeAgentCardServer creates an httptest.Server that serves the given AgentCard as JSON.
func newFakeAgentCardServer(card *protocol.AgentCard) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(card); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
}

// newMutableFakeServer creates a server whose card can be swapped at runtime.
func newMutableFakeServer() (*httptest.Server, *mutableCard) {
	mc := &mutableCard{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mc.mu.RLock()
		card := mc.card
		down := mc.down
		mc.mu.RUnlock()

		if down {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		if card == nil {
			http.Error(w, "no card", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	return srv, mc
}

type mutableCard struct {
	mu   sync.RWMutex
	card *protocol.AgentCard
	down bool
}

func (mc *mutableCard) setCard(card *protocol.AgentCard) {
	mc.mu.Lock()
	mc.card = card
	mc.down = false
	mc.mu.Unlock()
}

func (mc *mutableCard) setDown(down bool) {
	mc.mu.Lock()
	mc.down = down
	mc.mu.Unlock()
}

func testLogger() *slog.Logger {
	return slog.Default()
}

func testCard(name string, skills int) *protocol.AgentCard {
	card := &protocol.AgentCard{
		Name:    name,
		URL:     "https://example.com/" + name,
		Version: "1.0",
		Capabilities: &protocol.AgentCapabilities{
			Streaming: true,
		},
	}
	for i := 0; i < skills; i++ {
		card.Skills = append(card.Skills, protocol.AgentSkill{
			ID:   name + "-skill-" + string(rune('a'+i)),
			Name: name + " Skill " + string(rune('A'+i)),
		})
	}
	return card
}

func agentConfigFromServer(name string, srv *httptest.Server, overrides ...func(*config.AgentConfig)) config.AgentConfig {
	cfg := config.AgentConfig{
		Name:             name,
		URL:              srv.URL,
		CardPath:         "/.well-known/agent.json",
		PollInterval:     config.Duration{Duration: 50 * time.Millisecond},
		Timeout:          config.Duration{Duration: 5 * time.Second},
		MaxStreams:       10,
		AllowInsecure:    true, // httptest uses http://
		CardChangePolicy: "auto",
	}
	for _, fn := range overrides {
		fn(&cfg)
	}
	return cfg
}

// waitForCondition polls until condition is true or timeout.
func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for condition: %s", msg)
}

// ── Tests ──

func TestManager_NormalPolling(t *testing.T) {
	card := testCard("agent1", 3)
	srv := newFakeAgentCardServer(card)
	defer srv.Close()

	agents := []config.AgentConfig{
		agentConfigFromServer("agent1", srv),
	}

	mgr := NewManager(agents, config.CardSignatureConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer mgr.Stop()

	// Wait for the first poll to complete.
	waitForCondition(t, 2*time.Second, func() bool {
		_, ok := mgr.GetCard("agent1")
		return ok
	}, "agent1 card should be available")

	got, ok := mgr.GetCard("agent1")
	if !ok {
		t.Fatal("expected card for agent1")
	}
	if got.Name != "agent1" {
		t.Errorf("card name = %q, want %q", got.Name, "agent1")
	}
	if len(got.Skills) != 3 {
		t.Errorf("card skills = %d, want 3", len(got.Skills))
	}
	if !mgr.IsHealthy("agent1") {
		t.Error("expected agent1 to be healthy")
	}
}

func TestManager_ServerDown(t *testing.T) {
	// Start a server then immediately close it so it's unreachable.
	srv := newFakeAgentCardServer(testCard("agent-down", 1))
	srv.Close() // Close immediately — agent is unreachable.

	agents := []config.AgentConfig{
		agentConfigFromServer("agent-down", srv),
	}

	mgr := NewManager(agents, config.CardSignatureConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer mgr.Stop()

	// Wait enough time for the first poll attempt.
	waitForCondition(t, 2*time.Second, func() bool {
		status, ok := mgr.GetAgentState("agent-down")
		return ok && !status.LastPolled.IsZero()
	}, "agent-down should have been polled")

	if mgr.IsHealthy("agent-down") {
		t.Error("expected agent-down to be unhealthy")
	}

	status, ok := mgr.GetAgentState("agent-down")
	if !ok {
		t.Fatal("expected agent-down state")
	}
	if status.LastError == "" {
		t.Error("expected non-empty LastError")
	}
}

func TestManager_HealthRecovery(t *testing.T) {
	srv, mc := newMutableFakeServer()
	defer srv.Close()

	card := testCard("recoverable", 2)

	// Start down.
	mc.setDown(true)

	agents := []config.AgentConfig{
		agentConfigFromServer("recoverable", srv),
	}

	mgr := NewManager(agents, config.CardSignatureConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer mgr.Stop()

	// Wait for first poll — should be unhealthy.
	waitForCondition(t, 2*time.Second, func() bool {
		status, ok := mgr.GetAgentState("recoverable")
		return ok && !status.LastPolled.IsZero()
	}, "recoverable should have been polled")

	if mgr.IsHealthy("recoverable") {
		t.Error("expected agent to be unhealthy initially")
	}

	// Bring server back up.
	mc.setCard(card)

	// Wait for recovery.
	waitForCondition(t, 2*time.Second, func() bool {
		return mgr.IsHealthy("recoverable")
	}, "recoverable should recover to healthy")

	got, ok := mgr.GetCard("recoverable")
	if !ok {
		t.Fatal("expected card after recovery")
	}
	if got.Name != "recoverable" {
		t.Errorf("card name = %q, want %q", got.Name, "recoverable")
	}
}

func TestManager_CardChangeAlert(t *testing.T) {
	srv, mc := newMutableFakeServer()
	defer srv.Close()

	oldCard := testCard("alert-agent", 2)
	mc.setCard(oldCard)

	agents := []config.AgentConfig{
		agentConfigFromServer("alert-agent", srv, func(cfg *config.AgentConfig) {
			cfg.CardChangePolicy = "alert"
		}),
	}

	mgr := NewManager(agents, config.CardSignatureConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer mgr.Stop()

	// Wait for initial card.
	waitForCondition(t, 2*time.Second, func() bool {
		_, ok := mgr.GetCard("alert-agent")
		return ok
	}, "alert-agent initial card")

	// Verify initial card.
	got, _ := mgr.GetCard("alert-agent")
	if got.Version != "1.0" {
		t.Fatalf("initial version = %q, want %q", got.Version, "1.0")
	}

	// Change the card (critical change: URL).
	newCard := testCard("alert-agent", 2)
	newCard.URL = "https://new-url.example.com"
	newCard.Version = "2.0"
	mc.setCard(newCard)

	// Wait for a poll cycle to pick up the change.
	time.Sleep(200 * time.Millisecond)

	// In alert mode, old card should be kept.
	got, _ = mgr.GetCard("alert-agent")
	if got.Version != "1.0" {
		t.Errorf("alert policy should keep old card, got version %q, want %q", got.Version, "1.0")
	}
	if got.URL != "https://example.com/alert-agent" {
		t.Errorf("alert policy should keep old URL, got %q", got.URL)
	}
}

func TestManager_CardChangeAuto(t *testing.T) {
	srv, mc := newMutableFakeServer()
	defer srv.Close()

	oldCard := testCard("auto-agent", 2)
	mc.setCard(oldCard)

	agents := []config.AgentConfig{
		agentConfigFromServer("auto-agent", srv, func(cfg *config.AgentConfig) {
			cfg.CardChangePolicy = "auto"
		}),
	}

	mgr := NewManager(agents, config.CardSignatureConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer mgr.Stop()

	// Wait for initial card.
	waitForCondition(t, 2*time.Second, func() bool {
		_, ok := mgr.GetCard("auto-agent")
		return ok
	}, "auto-agent initial card")

	// Change the card.
	newCard := testCard("auto-agent", 5)
	newCard.Version = "2.0"
	mc.setCard(newCard)

	// Wait for auto-update.
	waitForCondition(t, 2*time.Second, func() bool {
		got, ok := mgr.GetCard("auto-agent")
		return ok && got.Version == "2.0"
	}, "auto-agent card should be updated to version 2.0")

	got, _ := mgr.GetCard("auto-agent")
	if len(got.Skills) != 5 {
		t.Errorf("auto policy should apply new card, got %d skills, want 5", len(got.Skills))
	}
}

func TestManager_AggregatedCard(t *testing.T) {
	card1 := testCard("agent-a", 2)
	card1.Capabilities = &protocol.AgentCapabilities{Streaming: true}

	card2 := testCard("agent-b", 3)
	card2.Capabilities = &protocol.AgentCapabilities{PushNotifications: true}

	srv1 := newFakeAgentCardServer(card1)
	defer srv1.Close()
	srv2 := newFakeAgentCardServer(card2)
	defer srv2.Close()

	agents := []config.AgentConfig{
		agentConfigFromServer("agent-a", srv1),
		agentConfigFromServer("agent-b", srv2),
	}

	mgr := NewManager(agents, config.CardSignatureConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer mgr.Stop()

	// Wait for both cards.
	waitForCondition(t, 2*time.Second, func() bool {
		_, a := mgr.GetCard("agent-a")
		_, b := mgr.GetCard("agent-b")
		return a && b
	}, "both agents should have cards")

	agg := mgr.GetAggregatedCard()
	if agg == nil {
		t.Fatal("expected aggregated card")
	}

	// Should have combined skills (2 + 3 = 5).
	if len(agg.Skills) != 5 {
		t.Errorf("aggregated skills = %d, want 5", len(agg.Skills))
	}

	// Capabilities should be OR'd.
	if !agg.Capabilities.Streaming {
		t.Error("expected aggregated streaming = true")
	}
	if !agg.Capabilities.PushNotifications {
		t.Error("expected aggregated pushNotifications = true")
	}
}

func TestManager_AggregatedCardNoSentinelFields(t *testing.T) {
	card := testCard("clean-agent", 1)
	srv := newFakeAgentCardServer(card)
	defer srv.Close()

	agents := []config.AgentConfig{
		agentConfigFromServer("clean-agent", srv),
	}

	mgr := NewManager(agents, config.CardSignatureConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer mgr.Stop()

	waitForCondition(t, 2*time.Second, func() bool {
		_, ok := mgr.GetCard("clean-agent")
		return ok
	}, "clean-agent card")

	agg := mgr.GetAggregatedCard()

	// Marshal to JSON and verify no sentinel-specific fields.
	data, err := json.Marshal(agg)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	jsonStr := string(data)

	// Verify no sentinel-specific fields exist.
	sentinelFields := []string{
		"x-sentinel",
		"X-Sentinel",
		"sentinel_",
		"sentinelVersion",
		"gatewayType",
	}
	for _, field := range sentinelFields {
		if strings.Contains(jsonStr, field) {
			t.Errorf("aggregated card contains sentinel-specific field %q: %s", field, jsonStr)
		}
	}

	// Verify it only contains standard A2A fields.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	allowedTopLevel := map[string]bool{
		"name": true, "description": true, "url": true, "version": true,
		"documentationUrl": true, "provider": true, "capabilities": true,
		"securitySchemes": true, "security": true, "skills": true,
		"defaultInputModes": true, "defaultOutputModes": true, "interfaces": true,
		"supportsAuthenticatedExtendedCard": true,
	}
	for key := range raw {
		if !allowedTopLevel[key] {
			t.Errorf("unexpected top-level field in aggregated card: %q", key)
		}
	}
}

func TestManager_AllowInsecureFalse(t *testing.T) {
	// Use a plain HTTP server.
	card := testCard("secure-agent", 1)
	srv := newFakeAgentCardServer(card)
	defer srv.Close()

	// Configure with allow_insecure=false — should reject http:// URL.
	agents := []config.AgentConfig{
		agentConfigFromServer("secure-agent", srv, func(cfg *config.AgentConfig) {
			cfg.AllowInsecure = false
		}),
	}

	mgr := NewManager(agents, config.CardSignatureConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer mgr.Stop()

	// Wait for poll attempt.
	waitForCondition(t, 2*time.Second, func() bool {
		status, ok := mgr.GetAgentState("secure-agent")
		return ok && !status.LastPolled.IsZero()
	}, "secure-agent should have been polled")

	// Agent should be unhealthy because http:// is rejected.
	if mgr.IsHealthy("secure-agent") {
		t.Error("expected agent to be unhealthy when allow_insecure=false with http:// URL")
	}

	status, _ := mgr.GetAgentState("secure-agent")
	if !strings.Contains(status.LastError, "insecure HTTP URL not allowed") {
		t.Errorf("expected insecure HTTP error, got: %s", status.LastError)
	}
}

func TestDetectChanges(t *testing.T) {
	tests := []struct {
		name           string
		old            *protocol.AgentCard
		new            *protocol.AgentCard
		wantCount      int
		wantCritical   bool
		wantFieldNames []string
	}{
		{
			name:           "url change is critical",
			old:            &protocol.AgentCard{URL: "https://old.example.com", Name: "a"},
			new:            &protocol.AgentCard{URL: "https://new.example.com", Name: "a"},
			wantCount:      1,
			wantCritical:   true,
			wantFieldNames: []string{"url"},
		},
		{
			name:           "version change is critical",
			old:            &protocol.AgentCard{Version: "1.0", Name: "a"},
			new:            &protocol.AgentCard{Version: "2.0", Name: "a"},
			wantCount:      1,
			wantCritical:   true,
			wantFieldNames: []string{"version"},
		},
		{
			name: "skill count >50% change is critical",
			old: &protocol.AgentCard{
				Name: "a",
				Skills: []protocol.AgentSkill{
					{ID: "s1", Name: "Skill 1"},
					{ID: "s2", Name: "Skill 2"},
				},
			},
			new: &protocol.AgentCard{
				Name: "a",
				Skills: []protocol.AgentSkill{
					{ID: "s1", Name: "Skill 1"},
					{ID: "s2", Name: "Skill 2"},
					{ID: "s3", Name: "Skill 3"},
					{ID: "s4", Name: "Skill 4"},
				},
			},
			wantCount:      1,
			wantCritical:   true,
			wantFieldNames: []string{"skills"},
		},
		{
			name: "skill count <=50% change is not critical",
			old: &protocol.AgentCard{
				Name: "a",
				Skills: []protocol.AgentSkill{
					{ID: "s1", Name: "Skill 1"},
					{ID: "s2", Name: "Skill 2"},
					{ID: "s3", Name: "Skill 3"},
					{ID: "s4", Name: "Skill 4"},
				},
			},
			new: &protocol.AgentCard{
				Name: "a",
				Skills: []protocol.AgentSkill{
					{ID: "s1", Name: "Skill 1"},
					{ID: "s2", Name: "Skill 2"},
					{ID: "s3", Name: "Skill 3"},
				},
			},
			wantCount:      1,
			wantCritical:   false,
			wantFieldNames: []string{"skills"},
		},
		{
			name: "securitySchemes count change is critical",
			old: &protocol.AgentCard{
				Name:            "a",
				SecuritySchemes: map[string]protocol.SecurityScheme{"bearer": {Type: "http"}},
			},
			new: &protocol.AgentCard{
				Name:            "a",
				SecuritySchemes: map[string]protocol.SecurityScheme{},
			},
			wantCount:      1,
			wantCritical:   true,
			wantFieldNames: []string{"securitySchemes"},
		},
		{
			name:           "name change is not critical",
			old:            &protocol.AgentCard{Name: "old-name"},
			new:            &protocol.AgentCard{Name: "new-name"},
			wantCount:      1,
			wantCritical:   false,
			wantFieldNames: []string{"name"},
		},
		{
			name:      "no changes",
			old:       &protocol.AgentCard{Name: "same", URL: "https://same.com", Version: "1.0"},
			new:       &protocol.AgentCard{Name: "same", URL: "https://same.com", Version: "1.0"},
			wantCount: 0,
		},
		{
			name:         "nil old returns nil",
			old:          nil,
			new:          &protocol.AgentCard{Name: "new"},
			wantCount:    0,
			wantCritical: false,
		},
		{
			name:           "multiple changes",
			old:            &protocol.AgentCard{Name: "a", URL: "https://old.com", Version: "1.0"},
			new:            &protocol.AgentCard{Name: "b", URL: "https://new.com", Version: "2.0"},
			wantCount:      3,
			wantCritical:   true,
			wantFieldNames: []string{"url", "version", "name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changes := DetectChanges(tt.old, tt.new)

			if len(changes) != tt.wantCount {
				t.Errorf("DetectChanges() returned %d changes, want %d", len(changes), tt.wantCount)
				for _, c := range changes {
					t.Logf("  field=%s old=%s new=%s critical=%v", c.Field, c.OldValue, c.NewValue, c.Critical)
				}
				return
			}

			if tt.wantCount > 0 && tt.wantCritical != hasCriticalChanges(changes) {
				t.Errorf("hasCriticalChanges() = %v, want %v", hasCriticalChanges(changes), tt.wantCritical)
			}

			if len(tt.wantFieldNames) > 0 {
				gotFields := make([]string, len(changes))
				for i, c := range changes {
					gotFields[i] = c.Field
				}
				sort.Strings(gotFields)
				sort.Strings(tt.wantFieldNames)
				if len(gotFields) != len(tt.wantFieldNames) {
					t.Errorf("fields = %v, want %v", gotFields, tt.wantFieldNames)
				} else {
					for i := range gotFields {
						if gotFields[i] != tt.wantFieldNames[i] {
							t.Errorf("field[%d] = %q, want %q", i, gotFields[i], tt.wantFieldNames[i])
						}
					}
				}
			}
		})
	}
}

func TestManager_UnhealthyExcluded(t *testing.T) {
	card := testCard("healthy-one", 1)
	srv := newFakeAgentCardServer(card)
	defer srv.Close()

	// Second server is immediately closed (unreachable).
	srv2 := newFakeAgentCardServer(testCard("down-one", 1))
	srv2.Close()

	agents := []config.AgentConfig{
		agentConfigFromServer("healthy-one", srv),
		agentConfigFromServer("down-one", srv2),
	}

	mgr := NewManager(agents, config.CardSignatureConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer mgr.Stop()

	// Wait for both to be polled.
	waitForCondition(t, 2*time.Second, func() bool {
		s1, ok1 := mgr.GetAgentState("healthy-one")
		s2, ok2 := mgr.GetAgentState("down-one")
		return ok1 && ok2 && !s1.LastPolled.IsZero() && !s2.LastPolled.IsZero()
	}, "both agents polled")

	healthy := mgr.HealthyAgents()
	if len(healthy) != 1 {
		t.Fatalf("HealthyAgents() = %v, want exactly 1 healthy", healthy)
	}
	if healthy[0] != "healthy-one" {
		t.Errorf("HealthyAgents()[0] = %q, want %q", healthy[0], "healthy-one")
	}

	// Aggregated card should only include the healthy agent's skills.
	agg := mgr.GetAggregatedCard()
	if len(agg.Skills) != 1 {
		t.Errorf("aggregated skills = %d, want 1 (only from healthy agent)", len(agg.Skills))
	}
}

func TestBuildCardURL(t *testing.T) {
	tests := []struct {
		base     string
		path     string
		expected string
	}{
		{"https://example.com", "/.well-known/agent.json", "https://example.com/.well-known/agent.json"},
		{"https://example.com/", "/.well-known/agent.json", "https://example.com/.well-known/agent.json"},
		{"https://example.com", ".well-known/agent.json", "https://example.com/.well-known/agent.json"},
		{"https://example.com/api/", "/card", "https://example.com/api/card"},
	}

	for _, tt := range tests {
		t.Run(tt.base+"_"+tt.path, func(t *testing.T) {
			got := buildCardURL(tt.base, tt.path)
			if got != tt.expected {
				t.Errorf("buildCardURL(%q, %q) = %q, want %q", tt.base, tt.path, got, tt.expected)
			}
		})
	}
}

func TestManager_AllAgentStates(t *testing.T) {
	card := testCard("status-agent", 3)
	srv := newFakeAgentCardServer(card)
	defer srv.Close()

	agents := []config.AgentConfig{
		agentConfigFromServer("status-agent", srv),
	}

	mgr := NewManager(agents, config.CardSignatureConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer mgr.Stop()

	waitForCondition(t, 2*time.Second, func() bool {
		_, ok := mgr.GetCard("status-agent")
		return ok
	}, "status-agent card")

	states := mgr.AllAgentStates()
	if len(states) != 1 {
		t.Fatalf("AllAgentStates() returned %d, want 1", len(states))
	}

	s := states[0]
	if s.Name != "status-agent" {
		t.Errorf("Name = %q, want %q", s.Name, "status-agent")
	}
	if !s.Healthy {
		t.Error("expected healthy")
	}
	if s.SkillCount != 3 {
		t.Errorf("SkillCount = %d, want 3", s.SkillCount)
	}
	if s.LastPolled.IsZero() {
		t.Error("expected non-zero LastPolled")
	}
	if s.LastError != "" {
		t.Errorf("expected empty LastError, got %q", s.LastError)
	}
}

func TestManager_NonexistentAgent(t *testing.T) {
	mgr := NewManager(nil, config.CardSignatureConfig{}, testLogger())

	_, ok := mgr.GetCard("nonexistent")
	if ok {
		t.Error("expected GetCard to return false for nonexistent agent")
	}

	if mgr.IsHealthy("nonexistent") {
		t.Error("expected IsHealthy to return false for nonexistent agent")
	}

	_, ok = mgr.GetAgentState("nonexistent")
	if ok {
		t.Error("expected GetAgentState to return false for nonexistent agent")
	}
}

// TestAggregateCards_EmptyAgents covers the empty map case in AggregateCards.
func TestAggregateCards_EmptyAgents(t *testing.T) {
	result := AggregateCards(map[string]*agentState{}, "https://gateway.example.com")
	if result == nil {
		t.Fatal("AggregateCards should never return nil")
	}
	if len(result.Skills) != 0 {
		t.Errorf("expected 0 skills from empty agents, got %d", len(result.Skills))
	}
	if result.URL != "https://gateway.example.com" {
		t.Errorf("URL = %q, want %q", result.URL, "https://gateway.example.com")
	}
}

// TestAggregateCards_UnhealthyOrNilCard verifies unhealthy and nil-card agents are excluded.
func TestAggregateCards_UnhealthyOrNilCard(t *testing.T) {
	agents := map[string]*agentState{
		"unhealthy": {
			name:    "unhealthy",
			healthy: false,
			card:    &protocol.AgentCard{Skills: []protocol.AgentSkill{{ID: "s1"}}},
		},
		"no-card": {
			name:    "no-card",
			healthy: true,
			card:    nil,
		},
		"healthy": {
			name:    "healthy",
			healthy: true,
			card: &protocol.AgentCard{
				Skills: []protocol.AgentSkill{{ID: "s2"}},
				Capabilities: &protocol.AgentCapabilities{
					Streaming:             true,
					PushNotifications:     true,
					StateTransitionHistory: true,
				},
			},
		},
	}
	result := AggregateCards(agents, "")
	if len(result.Skills) != 1 {
		t.Errorf("expected 1 skill from only healthy agent, got %d", len(result.Skills))
	}
	if !result.Capabilities.Streaming {
		t.Error("expected Streaming = true")
	}
	if !result.Capabilities.PushNotifications {
		t.Error("expected PushNotifications = true")
	}
	if !result.Capabilities.StateTransitionHistory {
		t.Error("expected StateTransitionHistory = true")
	}
}

// TestDetectChanges_NilNewCard covers the nil new card path.
func TestDetectChanges_NilNewCard(t *testing.T) {
	old := &protocol.AgentCard{Name: "agent"}
	changes := DetectChanges(old, nil)
	if changes != nil {
		t.Errorf("DetectChanges(old, nil) = %v, want nil", changes)
	}
}

// TestDetectChanges_SkillsFromZero covers the "from 0 to any" critical path.
func TestDetectChanges_SkillsFromZero(t *testing.T) {
	old := &protocol.AgentCard{Name: "a", Skills: nil}
	newCard := &protocol.AgentCard{Name: "a", Skills: []protocol.AgentSkill{{ID: "s1"}}}
	changes := DetectChanges(old, newCard)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if !changes[0].Critical {
		t.Error("skill change from 0 to any should be critical")
	}
}

// TestDetectChanges_CapabilitiesChange covers the capabilities change path.
func TestDetectChanges_CapabilitiesChange(t *testing.T) {
	old := &protocol.AgentCard{
		Name:         "a",
		Capabilities: &protocol.AgentCapabilities{Streaming: true},
	}
	newCard := &protocol.AgentCard{
		Name:         "a",
		Capabilities: &protocol.AgentCapabilities{Streaming: false},
	}
	changes := DetectChanges(old, newCard)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change (capabilities), got %d", len(changes))
	}
	if changes[0].Field != "capabilities" {
		t.Errorf("field = %q, want %q", changes[0].Field, "capabilities")
	}
}

// TestHandleCardChange_ApprovePolicy tests the approve policy path.
func TestHandleCardChange_ApprovePolicy(t *testing.T) {
	mgr := NewManager(nil, config.CardSignatureConfig{}, testLogger())
	oldCard := testCard("agent", 2)
	newCard := testCard("agent", 3)
	newCard.Version = "2.0"

	state := &agentState{
		name:         "agent",
		card:         oldCard,
		changePolicy: CardChangeApprove,
	}

	changes := []Change{{Field: "version", OldValue: "1.0", NewValue: "2.0", Critical: true}}
	mgr.handleCardChange(state, newCard, changes)

	// Approve policy should NOT update the card (behaves like alert)
	if state.card != oldCard {
		t.Error("approve policy should keep old card")
	}
}

// TestHandleCardChange_UnknownPolicy tests the unknown policy fallback path.
func TestHandleCardChange_UnknownPolicy(t *testing.T) {
	mgr := NewManager(nil, config.CardSignatureConfig{}, testLogger())
	oldCard := testCard("agent", 2)
	newCard := testCard("agent", 3)

	state := &agentState{
		name:         "agent",
		card:         oldCard,
		changePolicy: CardChangePolicy("unknown-policy"),
	}

	changes := []Change{{Field: "name", Critical: false}}
	mgr.handleCardChange(state, newCard, changes)

	// Unknown policy behaves like alert — keeps old card
	if state.card != oldCard {
		t.Error("unknown policy should keep old card")
	}
}

// TestHandleCardChange_AlertNonCritical covers the non-critical branch in alert policy.
func TestHandleCardChange_AlertNonCritical(t *testing.T) {
	mgr := NewManager(nil, config.CardSignatureConfig{}, testLogger())
	oldCard := testCard("agent", 2)
	newCard := testCard("agent", 2)
	newCard.Name = "changed-name"

	state := &agentState{
		name:         "agent",
		card:         oldCard,
		changePolicy: CardChangeAlert,
	}

	// Non-critical change (name only)
	changes := []Change{{Field: "name", Critical: false}}
	mgr.handleCardChange(state, newCard, changes)

	// Alert policy always keeps old card
	if state.card != oldCard {
		t.Error("alert policy should keep old card for non-critical changes")
	}
}

// TestNewManager_NilLogger verifies nil logger defaults to slog.Default().
func TestNewManager_NilLogger(t *testing.T) {
	agents := []config.AgentConfig{
		{
			Name:             "agent-x",
			URL:              "https://example.com",
			CardPath:         "/.well-known/agent.json",
			PollInterval:     config.Duration{Duration: 60 * time.Second},
			Timeout:          config.Duration{Duration: 10 * time.Second},
			CardChangePolicy: "alert",
		},
	}
	// Pass nil logger — should not panic
	mgr := NewManager(agents, config.CardSignatureConfig{}, nil)
	if mgr == nil {
		t.Fatal("NewManager with nil logger should return non-nil manager")
	}
	if mgr.logger == nil {
		t.Error("manager logger should not be nil after nil input")
	}
}

// TestFetchCard_BadStatusCode tests that a non-200 status returns an error.
func TestFetchCard_BadStatusCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	mgr := NewManager(nil, config.CardSignatureConfig{}, testLogger())
	state := &agentState{
		name:          "test-agent",
		url:           srv.URL,
		cardPath:      "/.well-known/agent.json",
		timeout:       5 * time.Second,
		allowInsecure: true,
	}

	_, err := mgr.fetchCard(context.Background(), state)
	if err == nil {
		t.Fatal("expected error for non-200 status code")
	}
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("expected HTTP 403 error, got: %v", err)
	}
}

// TestFetchCard_InvalidJSON tests that invalid JSON body returns a parse error.
func TestFetchCard_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not valid json {{{`))
	}))
	defer srv.Close()

	mgr := NewManager(nil, config.CardSignatureConfig{}, testLogger())
	state := &agentState{
		name:          "test-agent",
		url:           srv.URL,
		cardPath:      "/.well-known/agent.json",
		timeout:       5 * time.Second,
		allowInsecure: true,
	}

	_, err := mgr.fetchCard(context.Background(), state)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing agent") {
		t.Errorf("expected JSON parse error, got: %v", err)
	}
}

// TestDetectChanges_DescriptionChange covers the description change path.
func TestDetectChanges_DescriptionChange(t *testing.T) {
	old := &protocol.AgentCard{Name: "a", Description: "old desc"}
	newCard := &protocol.AgentCard{Name: "a", Description: "new desc"}
	changes := DetectChanges(old, newCard)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Field != "description" {
		t.Errorf("field = %q, want %q", changes[0].Field, "description")
	}
	if changes[0].Critical {
		t.Error("description change should not be critical")
	}
}

// TestFetchCard_RequestCreationError tests that an invalid URL causes a request creation error.
// We use a context that is already canceled to trigger the error path indirectly,
// but a simpler approach is an invalid URL scheme.
func TestFetchCard_BadURL(t *testing.T) {
	mgr := NewManager(nil, config.CardSignatureConfig{}, testLogger())
	state := &agentState{
		name:          "bad-url-agent",
		url:           "http://invalid host with spaces",
		cardPath:      "/.well-known/agent.json",
		timeout:       5 * time.Second,
		allowInsecure: true,
	}

	_, err := mgr.fetchCard(context.Background(), state)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

// TestFetchCard_BodyReadError tests that a body read error returns the right error.
// We use Hijacker + chunked encoding to deterministically trigger io.ReadAll failure.
func TestFetchCard_BodyReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server does not support hijacking")
		}
		conn, buf, _ := hj.Hijack()
		// Write chunked response with a valid chunk, then close before terminating chunk.
		buf.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n")
		buf.WriteString("5\r\nhello\r\n") // valid chunk
		buf.Flush()
		conn.Close() // close mid-stream — missing terminating 0-length chunk
	}))
	defer srv.Close()

	mgr := NewManager(nil, config.CardSignatureConfig{}, testLogger())
	state := &agentState{
		name:          "body-error-agent",
		url:           srv.URL,
		cardPath:      "/.well-known/agent.json",
		timeout:       2 * time.Second,
		allowInsecure: true,
	}

	_, err := mgr.fetchCard(context.Background(), state)
	if err == nil {
		t.Fatal("expected error when body read fails mid-stream")
	}
	if !strings.Contains(err.Error(), "reading agent") {
		t.Errorf("expected body read error message, got: %v", err)
	}
}

// TestManager_CardChangeApprove_Integration tests approve policy via full integration.
func TestManager_CardChangeApprove_Integration(t *testing.T) {
	srv, mc := newMutableFakeServer()
	defer srv.Close()

	oldCard := testCard("approve-agent", 2)
	mc.setCard(oldCard)

	agents := []config.AgentConfig{
		agentConfigFromServer("approve-agent", srv, func(cfg *config.AgentConfig) {
			cfg.CardChangePolicy = "approve"
		}),
	}

	mgr := NewManager(agents, config.CardSignatureConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer mgr.Stop()

	// Wait for initial card.
	waitForCondition(t, 2*time.Second, func() bool {
		_, ok := mgr.GetCard("approve-agent")
		return ok
	}, "approve-agent initial card")

	// Change the card — should be pending approval (kept as old).
	newCard := testCard("approve-agent", 5)
	newCard.Version = "2.0"
	mc.setCard(newCard)

	time.Sleep(200 * time.Millisecond)

	// Approve policy should keep old card.
	got, _ := mgr.GetCard("approve-agent")
	if got.Version != "1.0" {
		t.Errorf("approve policy should keep old card, got version %q", got.Version)
	}
}
