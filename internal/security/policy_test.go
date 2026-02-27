package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
)

// nopLogger returns a logger that discards output.
func nopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestPolicyEngine_IPDeny(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-bad-ip",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				IPs: []string{"10.0.0.0/8"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	tests := []struct {
		name   string
		ip     string
		action string
	}{
		{"matching IP denied", "10.1.2.3", "deny"},
		{"non-matching IP allowed", "192.168.1.1", "allow"},
		{"exact boundary denied", "10.0.0.1", "deny"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := engine.Evaluate(context.Background(), &PolicyRequest{IP: tt.ip})
			if d.Action != tt.action {
				t.Errorf("IP %s: got action %q, want %q", tt.ip, d.Action, tt.action)
			}
		})
	}
}

func TestPolicyEngine_IPNegation(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-non-internal",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				IPs: []string{"!10.0.0.0/8"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	tests := []struct {
		name   string
		ip     string
		action string
	}{
		{"internal IP allowed", "10.1.2.3", "allow"},
		{"external IP denied", "192.168.1.1", "deny"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := engine.Evaluate(context.Background(), &PolicyRequest{IP: tt.ip})
			if d.Action != tt.action {
				t.Errorf("IP %s: got action %q, want %q", tt.ip, d.Action, tt.action)
			}
		})
	}
}

func TestPolicyEngine_AgentDeny(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-internal-agent",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				Agents: []string{"internal-bot"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	tests := []struct {
		name   string
		agent  string
		action string
	}{
		{"matching agent denied", "internal-bot", "deny"},
		{"other agent allowed", "public-agent", "allow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := engine.Evaluate(context.Background(), &PolicyRequest{Agent: tt.agent})
			if d.Action != tt.action {
				t.Errorf("agent %s: got action %q, want %q", tt.agent, d.Action, tt.action)
			}
		})
	}
}

func TestPolicyEngine_MethodDeny(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-send",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				Methods: []string{"message/send", "message/stream"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	tests := []struct {
		name   string
		method string
		action string
	}{
		{"message/send denied", "message/send", "deny"},
		{"message/stream denied", "message/stream", "deny"},
		{"tasks/get allowed", "tasks/get", "allow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := engine.Evaluate(context.Background(), &PolicyRequest{Method: tt.method})
			if d.Action != tt.action {
				t.Errorf("method %s: got action %q, want %q", tt.method, d.Action, tt.action)
			}
		})
	}
}

func TestPolicyEngine_UserDeny(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-alice",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				Users: []string{"alice@example.com"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	tests := []struct {
		name   string
		user   string
		action string
	}{
		{"alice denied", "alice@example.com", "deny"},
		{"bob allowed", "bob@example.com", "allow"},
		{"empty user allowed", "", "allow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := engine.Evaluate(context.Background(), &PolicyRequest{User: tt.user})
			if d.Action != tt.action {
				t.Errorf("user %s: got action %q, want %q", tt.user, d.Action, tt.action)
			}
		})
	}
}

func TestPolicyEngine_TimeRange(t *testing.T) {
	policies := []Policy{
		{
			Name:     "business-hours-only",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				TimeRange: &TimeRange{
					Start: "22:00",
					End:   "06:00",
					TZ:    "UTC",
				},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	tests := []struct {
		name   string
		hour   int
		min    int
		action string
	}{
		{"inside deny range (23:00)", 23, 0, "deny"},
		{"inside deny range (02:00)", 2, 0, "deny"},
		{"outside deny range (10:00)", 10, 0, "allow"},
		{"boundary start (22:00)", 22, 0, "deny"},
		{"boundary end (06:00)", 6, 0, "allow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqTime := time.Date(2025, 6, 15, tt.hour, tt.min, 0, 0, time.UTC)
			d := engine.Evaluate(context.Background(), &PolicyRequest{Time: reqTime})
			if d.Action != tt.action {
				t.Errorf("time %02d:%02d: got action %q, want %q", tt.hour, tt.min, d.Action, tt.action)
			}
		})
	}
}

func TestPolicyEngine_TimeRangeTimezone(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-after-hours-kst",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				TimeRange: &TimeRange{
					Start: "18:00",
					End:   "09:00",
					TZ:    "Asia/Seoul",
				},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())

	// 10:00 KST = 01:00 UTC → inside business hours in KST
	utcTime := time.Date(2025, 6, 15, 1, 0, 0, 0, time.UTC)
	d := engine.Evaluate(context.Background(), &PolicyRequest{Time: utcTime})
	if d.Action != "allow" {
		t.Errorf("10:00 KST (01:00 UTC): got action %q, want %q", d.Action, "allow")
	}

	// 20:00 KST = 11:00 UTC → outside business hours in KST
	utcTime = time.Date(2025, 6, 15, 11, 0, 0, 0, time.UTC)
	d = engine.Evaluate(context.Background(), &PolicyRequest{Time: utcTime})
	if d.Action != "deny" {
		t.Errorf("20:00 KST (11:00 UTC): got action %q, want %q", d.Action, "deny")
	}
}

func TestPolicyEngine_HeaderMatching(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-custom-header",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				Headers: map[string]string{
					"X-Custom-Flag": "blocked",
				},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	tests := []struct {
		name    string
		headers http.Header
		action  string
	}{
		{
			"matching header denied",
			http.Header{"X-Custom-Flag": []string{"blocked"}},
			"deny",
		},
		{
			"different value allowed",
			http.Header{"X-Custom-Flag": []string{"allowed"}},
			"allow",
		},
		{
			"missing header allowed",
			http.Header{},
			"allow",
		},
		{
			"case-insensitive key via Set",
			func() http.Header {
				h := http.Header{}
				h.Set("x-custom-flag", "blocked")
				return h
			}(),
			"deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := engine.Evaluate(context.Background(), &PolicyRequest{Headers: tt.headers})
			if d.Action != tt.action {
				t.Errorf("got action %q, want %q", d.Action, tt.action)
			}
		})
	}
}

func TestPolicyEngine_Priority(t *testing.T) {
	policies := []Policy{
		{
			Name:     "low-priority-allow",
			Action:   "allow",
			Priority: 1,
			Match: PolicyMatch{
				Users: []string{"alice@example.com"},
			},
		},
		{
			Name:     "high-priority-deny",
			Action:   "deny",
			Priority: 100,
			Match: PolicyMatch{
				Users: []string{"alice@example.com"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	d := engine.Evaluate(context.Background(), &PolicyRequest{User: "alice@example.com"})
	if d.Action != "deny" {
		t.Errorf("expected high-priority deny, got %q", d.Action)
	}
	if d.MatchedPolicy != "high-priority-deny" {
		t.Errorf("expected matched policy 'high-priority-deny', got %q", d.MatchedPolicy)
	}
}

func TestPolicyEngine_DefaultAllow(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-specific",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				Users: []string{"evil@example.com"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	d := engine.Evaluate(context.Background(), &PolicyRequest{User: "good@example.com"})
	if d.Action != "allow" {
		t.Errorf("expected default allow, got %q", d.Action)
	}
	if d.MatchedPolicy != "" {
		t.Errorf("expected empty matched policy for default, got %q", d.MatchedPolicy)
	}
}

func TestPolicyEngine_EmptyMatchMatchesAll(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-everything",
			Action:   "deny",
			Priority: 10,
			Match:    PolicyMatch{}, // empty = matches all
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	d := engine.Evaluate(context.Background(), &PolicyRequest{
		Agent:  "any-agent",
		Method: "message/send",
		User:   "anyone@example.com",
		IP:     "1.2.3.4",
	})
	if d.Action != "deny" {
		t.Errorf("empty match should match everything, got %q", d.Action)
	}
}

func TestPolicyEngine_MultipleConditionsAND(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-alice-on-agent-a",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				Users:  []string{"alice@example.com"},
				Agents: []string{"agent-a"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	tests := []struct {
		name   string
		user   string
		agent  string
		action string
	}{
		{"both match → deny", "alice@example.com", "agent-a", "deny"},
		{"user matches, agent doesn't → allow", "alice@example.com", "agent-b", "allow"},
		{"agent matches, user doesn't → allow", "bob@example.com", "agent-a", "allow"},
		{"neither matches → allow", "bob@example.com", "agent-b", "allow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := engine.Evaluate(context.Background(), &PolicyRequest{
				User:  tt.user,
				Agent: tt.agent,
			})
			if d.Action != tt.action {
				t.Errorf("got action %q, want %q", d.Action, tt.action)
			}
		})
	}
}

func TestPolicyEngine_UpdatePoliciesAtomic(t *testing.T) {
	engine := NewPolicyEngine([]Policy{
		{Name: "old", Action: "deny", Priority: 10, Match: PolicyMatch{}},
	}, nopLogger())

	// Before update: everything denied
	d := engine.Evaluate(context.Background(), &PolicyRequest{})
	if d.Action != "deny" {
		t.Fatalf("before update: expected deny, got %q", d.Action)
	}

	// Update with empty policies → default allow
	engine.UpdatePolicies([]Policy{})
	d = engine.Evaluate(context.Background(), &PolicyRequest{})
	if d.Action != "allow" {
		t.Errorf("after update: expected allow, got %q", d.Action)
	}
}

func TestPolicyEngine_ListPolicies(t *testing.T) {
	policies := []Policy{
		{Name: "p1", Priority: 5},
		{Name: "p2", Priority: 10},
		{Name: "p3", Priority: 1},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	listed := engine.ListPolicies()

	if len(listed) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(listed))
	}
	// Should be sorted by priority descending
	if listed[0].Name != "p2" || listed[1].Name != "p1" || listed[2].Name != "p3" {
		t.Errorf("unexpected order: %v, %v, %v", listed[0].Name, listed[1].Name, listed[2].Name)
	}
}

func TestPolicyEngine_ConcurrentEvaluate(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-bad",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				Users: []string{"bad@example.com"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())

	var wg sync.WaitGroup
	const goroutines = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			user := "good@example.com"
			expected := "allow"
			if idx%2 == 0 {
				user = "bad@example.com"
				expected = "deny"
			}
			d := engine.Evaluate(context.Background(), &PolicyRequest{User: user})
			if d.Action != expected {
				t.Errorf("goroutine %d: user %s got %q, want %q", idx, user, d.Action, expected)
			}
		}(i)
	}

	// Also run UpdatePolicies concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		engine.UpdatePolicies(policies)
	}()

	wg.Wait()
}

func TestPolicyGuard_DenyResponse(t *testing.T) {
	policies := []Policy{
		{
			Name:        "block-all",
			Description: "Block everything",
			Action:      "deny",
			Priority:    10,
			Match:       PolicyMatch{},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	guard := NewPolicyGuard(engine, nopLogger())

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "should not reach here")
	})

	handler := guard.Process(inner)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}

	// Verify JSON response contains SentinelError
	var resp struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Hint    string `json:"hint"`
			DocsURL string `json:"docs_url"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Error.Code != 403 {
		t.Errorf("expected error code 403, got %d", resp.Error.Code)
	}
	if resp.Error.Message != "Request blocked by policy" {
		t.Errorf("unexpected message: %s", resp.Error.Message)
	}
	if resp.Error.Hint == "" {
		t.Error("expected non-empty hint")
	}
	if resp.Error.DocsURL == "" {
		t.Error("expected non-empty docs_url")
	}
}

func TestPolicyGuard_AllowPassesThrough(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-specific",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				Users: []string{"blocked@example.com"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	guard := NewPolicyGuard(engine, nopLogger())

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	handler := guard.Process(inner)

	// Set up context with auth info for an allowed user
	ctx := ctxkeys.WithAuthInfo(context.Background(), ctxkeys.AuthInfo{
		Subject: "allowed@example.com",
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req = req.WithContext(ctx)
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !reached {
		t.Error("inner handler was not reached")
	}
}

func TestPolicyGuard_Name(t *testing.T) {
	engine := NewPolicyEngine(nil, nopLogger())
	guard := NewPolicyGuard(engine, nopLogger())
	if guard.Name() != "policy_guard" {
		t.Errorf("expected 'policy_guard', got %q", guard.Name())
	}
}

func TestPolicyGuard_ExtractsContextFields(t *testing.T) {
	// Create a policy that blocks a specific agent + user + method combination
	policies := []Policy{
		{
			Name:     "block-combo",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				Agents:  []string{"my-agent"},
				Users:   []string{"alice@example.com"},
				Methods: []string{"message/send"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())
	guard := NewPolicyGuard(engine, nopLogger())

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := guard.Process(inner)

	// Set up full context
	ctx := context.Background()
	ctx = ctxkeys.WithAuthInfo(ctx, ctxkeys.AuthInfo{Subject: "alice@example.com"})
	ctx = ctxkeys.WithRouteResult(ctx, ctxkeys.RouteResult{AgentName: "my-agent"})
	ctx = ctxkeys.WithRequestMeta(ctx, ctxkeys.RequestMeta{Method: "message/send"})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req = req.WithContext(ctx)
	req.RemoteAddr = "1.2.3.4:5678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestPolicyEngine_IPWithPort(t *testing.T) {
	policies := []Policy{
		{
			Name:     "block-ip",
			Action:   "deny",
			Priority: 10,
			Match: PolicyMatch{
				IPs: []string{"192.168.1.100"},
			},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())

	// IP with port should still match
	d := engine.Evaluate(context.Background(), &PolicyRequest{IP: "192.168.1.100:12345"})
	if d.Action != "deny" {
		t.Errorf("IP with port: got action %q, want deny", d.Action)
	}

	// IP without port should also match
	d = engine.Evaluate(context.Background(), &PolicyRequest{IP: "192.168.1.100"})
	if d.Action != "deny" {
		t.Errorf("IP without port: got action %q, want deny", d.Action)
	}
}

func TestPolicyEngine_NoPolicies(t *testing.T) {
	engine := NewPolicyEngine(nil, nopLogger())
	d := engine.Evaluate(context.Background(), &PolicyRequest{
		Agent:  "any",
		Method: "message/send",
		User:   "anyone",
		IP:     "1.2.3.4",
	})
	if d.Action != "allow" {
		t.Errorf("no policies: expected allow, got %q", d.Action)
	}
}

func TestPolicyEngine_AllowPolicy(t *testing.T) {
	// Test that an explicit allow policy works
	policies := []Policy{
		{
			Name:     "allow-vip",
			Action:   "allow",
			Priority: 100,
			Match: PolicyMatch{
				Users: []string{"vip@example.com"},
			},
		},
		{
			Name:     "deny-all",
			Action:   "deny",
			Priority: 1,
			Match:    PolicyMatch{},
		},
	}

	engine := NewPolicyEngine(policies, nopLogger())

	// VIP should be allowed (higher priority)
	d := engine.Evaluate(context.Background(), &PolicyRequest{User: "vip@example.com"})
	if d.Action != "allow" {
		t.Errorf("VIP user: expected allow, got %q", d.Action)
	}
	if d.MatchedPolicy != "allow-vip" {
		t.Errorf("VIP user: expected matched policy 'allow-vip', got %q", d.MatchedPolicy)
	}

	// Regular user should be denied (lower priority deny-all)
	d = engine.Evaluate(context.Background(), &PolicyRequest{User: "regular@example.com"})
	if d.Action != "deny" {
		t.Errorf("regular user: expected deny, got %q", d.Action)
	}
}

func TestMatchIPs_MixedPositiveNegative(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		ip       string
		want     bool
	}{
		{
			"positive only, match",
			[]string{"10.0.0.0/8"},
			"10.1.2.3",
			true,
		},
		{
			"positive only, no match",
			[]string{"10.0.0.0/8"},
			"192.168.1.1",
			false,
		},
		{
			"negative only, not in range",
			[]string{"!10.0.0.0/8"},
			"192.168.1.1",
			true,
		},
		{
			"negative only, in range",
			[]string{"!10.0.0.0/8"},
			"10.1.2.3",
			false,
		},
		{
			"empty list matches all",
			nil,
			"1.2.3.4",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchIPs(tt.patterns, tt.ip)
			if got != tt.want {
				t.Errorf("matchIPs(%v, %q) = %v, want %v", tt.patterns, tt.ip, got, tt.want)
			}
		})
	}
}

func TestMatchTimeRange_NormalRange(t *testing.T) {
	tr := &TimeRange{Start: "09:00", End: "17:00", TZ: "UTC"}

	tests := []struct {
		hour int
		min  int
		want bool
	}{
		{8, 59, false},
		{9, 0, true},
		{12, 0, true},
		{16, 59, true},
		{17, 0, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%02d:%02d", tt.hour, tt.min), func(t *testing.T) {
			tm := time.Date(2025, 1, 1, tt.hour, tt.min, 0, 0, time.UTC)
			got := matchTimeRange(tr, tm)
			if got != tt.want {
				t.Errorf("matchTimeRange at %02d:%02d = %v, want %v", tt.hour, tt.min, got, tt.want)
			}
		})
	}
}

func TestMatchTimeRange_NilRange(t *testing.T) {
	if !matchTimeRange(nil, time.Now()) {
		t.Error("nil time range should always match")
	}
}
