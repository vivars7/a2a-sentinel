package security

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/config"
)

// timeLayoutHHMM is the expected format for TimeRange.Start and TimeRange.End.
const timeLayoutHHMM = "15:04"

// defaultPolicyAction is returned when no policy matches a request.
const defaultPolicyAction = "allow"

// PolicyEngine evaluates ABAC policies against requests.
// It is safe for concurrent use; UpdatePolicies swaps the policy slice atomically
// under a write lock while Evaluate holds a read lock.
type PolicyEngine struct {
	policies []Policy
	mu       sync.RWMutex
	logger   *slog.Logger
}

// NewPolicyEngine creates a PolicyEngine with the given policies sorted by
// priority descending. A nil logger is replaced with slog.Default().
func NewPolicyEngine(policies []Policy, logger *slog.Logger) *PolicyEngine {
	if logger == nil {
		logger = slog.Default()
	}
	sorted := make([]Policy, len(policies))
	copy(sorted, policies)
	sortPolicies(sorted)
	return &PolicyEngine{
		policies: sorted,
		logger:   logger,
	}
}

// Evaluate checks the request against all policies in priority order.
// The first matching policy wins. If no policy matches, the default action is "allow".
func (e *PolicyEngine) Evaluate(_ context.Context, req *PolicyRequest) PolicyDecision {
	e.mu.RLock()
	policies := e.policies
	e.mu.RUnlock()

	for _, p := range policies {
		if matchPolicy(p, req) {
			e.logger.Debug("policy matched",
				"policy", p.Name,
				"action", p.Action,
				"user", req.User,
				"ip", req.IP,
				"agent", req.Agent,
				"method", req.Method,
			)
			return PolicyDecision{
				Action:        p.Action,
				MatchedPolicy: p.Name,
				Reason:        fmt.Sprintf("matched policy %q: %s", p.Name, p.Description),
			}
		}
	}

	return PolicyDecision{
		Action:        defaultPolicyAction,
		MatchedPolicy: "",
		Reason:        "no matching policy, default allow",
	}
}

// UpdatePolicies replaces all policies atomically. The new set is sorted by priority.
func (e *PolicyEngine) UpdatePolicies(policies []Policy) {
	sorted := make([]Policy, len(policies))
	copy(sorted, policies)
	sortPolicies(sorted)

	e.mu.Lock()
	e.policies = sorted
	e.mu.Unlock()

	e.logger.Info("policies updated", "count", len(sorted))
}

// ListPolicies returns a copy of the current policies in evaluation order.
func (e *PolicyEngine) ListPolicies() []Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make([]Policy, len(e.policies))
	copy(out, e.policies)
	return out
}

// sortPolicies sorts policies by priority descending (highest first).
func sortPolicies(policies []Policy) {
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Priority > policies[j].Priority
	})
}

// matchPolicy returns true if all non-empty conditions in the policy match the request.
// Empty conditions match everything (AND logic across dimensions).
func matchPolicy(p Policy, req *PolicyRequest) bool {
	if !matchStringList(p.Match.Agents, req.Agent) {
		return false
	}
	if !matchStringList(p.Match.Methods, req.Method) {
		return false
	}
	if !matchStringList(p.Match.Users, req.User) {
		return false
	}
	if !matchIPs(p.Match.IPs, req.IP) {
		return false
	}
	if !matchHeaders(p.Match.Headers, req.Headers) {
		return false
	}
	if !matchTimeRange(p.Match.TimeRange, req.Time) {
		return false
	}
	return true
}

// matchStringList returns true if the list is empty or contains the value.
func matchStringList(list []string, value string) bool {
	if len(list) == 0 {
		return true
	}
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// matchIPs returns true if the IP list is empty, or the request IP matches at
// least one entry (CIDR or exact). Entries prefixed with "!" are negated — if
// the request IP matches a negated entry, the match fails immediately.
func matchIPs(patterns []string, ip string) bool {
	if len(patterns) == 0 {
		return true
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		// Try stripping port
		host, _, err := net.SplitHostPort(ip)
		if err != nil {
			return false
		}
		parsedIP = net.ParseIP(host)
		if parsedIP == nil {
			return false
		}
	}

	for _, pattern := range patterns {
		negated := false
		cidr := pattern
		if strings.HasPrefix(pattern, "!") {
			negated = true
			cidr = pattern[1:]
		}

		matched := matchSingleIP(parsedIP, cidr)
		if negated && matched {
			// Negated match: IP is in a blocked range
			return false
		}
		if !negated && matched {
			return true
		}
	}

	// If all patterns were non-negated and none matched, fail.
	// If all patterns were negated and none triggered, pass.
	for _, pattern := range patterns {
		if !strings.HasPrefix(pattern, "!") {
			// Had positive patterns but none matched
			return false
		}
	}
	return true
}

// matchSingleIP checks if parsedIP is within the CIDR or matches exactly.
func matchSingleIP(parsedIP net.IP, cidr string) bool {
	// Try CIDR
	if strings.Contains(cidr, "/") {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return false
		}
		return network.Contains(parsedIP)
	}
	// Exact IP match
	target := net.ParseIP(cidr)
	if target == nil {
		return false
	}
	return parsedIP.Equal(target)
}

// matchHeaders returns true if the map is empty or all specified headers
// match (case-insensitive key lookup, exact value match).
func matchHeaders(expected map[string]string, actual http.Header) bool {
	if len(expected) == 0 {
		return true
	}
	if actual == nil {
		return false
	}
	for key, val := range expected {
		got := actual.Get(key) // case-insensitive lookup
		if got != val {
			return false
		}
	}
	return true
}

// ConvertPolicies converts config.PolicyConfig types to security.Policy types.
func ConvertPolicies(cfgs []config.PolicyConfig) []Policy {
	policies := make([]Policy, len(cfgs))
	for i, c := range cfgs {
		p := Policy{
			Name:        c.Name,
			Description: c.Description,
			Action:      c.Action,
			Priority:    c.Priority,
			Match: PolicyMatch{
				Agents:  c.Match.Agents,
				Methods: c.Match.Methods,
				Users:   c.Match.Users,
				IPs:     c.Match.IPs,
				Headers: c.Match.Headers,
			},
		}
		if c.Match.TimeRange != nil {
			p.Match.TimeRange = &TimeRange{
				Start: c.Match.TimeRange.Start,
				End:   c.Match.TimeRange.End,
				TZ:    c.Match.TimeRange.TZ,
			}
		}
		policies[i] = p
	}
	return policies
}

// matchTimeRange returns true if the range is nil or the given time falls
// within the [Start, End) window in the configured timezone.
func matchTimeRange(tr *TimeRange, t time.Time) bool {
	if tr == nil {
		return true
	}

	loc := time.UTC
	if tr.TZ != "" {
		parsed, err := time.LoadLocation(tr.TZ)
		if err == nil {
			loc = parsed
		}
	}

	localTime := t.In(loc)
	startTime, err := time.Parse(timeLayoutHHMM, tr.Start)
	if err != nil {
		return true // invalid config → don't block
	}
	endTime, err := time.Parse(timeLayoutHHMM, tr.End)
	if err != nil {
		return true
	}

	// Build start/end on the same date as localTime
	now := localTime.Hour()*60 + localTime.Minute()
	start := startTime.Hour()*60 + startTime.Minute()
	end := endTime.Hour()*60 + endTime.Minute()

	if start <= end {
		// Normal range, e.g. 09:00-18:00
		return now >= start && now < end
	}
	// Overnight range, e.g. 22:00-06:00
	return now >= start || now < end
}
