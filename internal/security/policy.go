package security

import (
	"net/http"
	"time"
)

// Policy defines an ABAC access control rule.
// Policies are evaluated in priority order (highest first); the first match wins.
type Policy struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Match       PolicyMatch `yaml:"match"`
	Action      string      `yaml:"action"`   // "allow" or "deny"
	Priority    int         `yaml:"priority"`  // higher = evaluated first
}

// PolicyMatch defines conditions that must all be true for a policy to match.
// Empty fields are treated as "match all" for that dimension.
type PolicyMatch struct {
	Agents    []string          `yaml:"agents"`     // agent name matching
	Methods   []string          `yaml:"methods"`    // A2A method matching (message/send, etc.)
	Users     []string          `yaml:"users"`      // authenticated user/subject matching
	IPs       []string          `yaml:"ips"`        // CIDR matching, prefix ! for negation
	Headers   map[string]string `yaml:"headers"`    // header value matching
	TimeRange *TimeRange        `yaml:"time_range"` // time-of-day restriction
}

// TimeRange restricts access to specific hours of the day.
type TimeRange struct {
	Start string `yaml:"start"` // "09:00" (HH:MM)
	End   string `yaml:"end"`   // "18:00" (HH:MM)
	TZ    string `yaml:"tz"`    // "Asia/Seoul", defaults to UTC
}

// PolicyRequest is the input to policy evaluation.
// It captures all attributes of a request that policies can match against.
type PolicyRequest struct {
	Agent   string
	Method  string
	User    string
	IP      string
	Headers http.Header
	Time    time.Time
}

// PolicyDecision is the output of policy evaluation.
type PolicyDecision struct {
	Action        string // "allow" or "deny"
	MatchedPolicy string // name of matching policy, empty if default
	Reason        string // human-readable reason
}
