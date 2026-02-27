// Package config handles YAML configuration parsing, defaults, and validation
// for the a2a-sentinel security gateway.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration for a2a-sentinel.
type Config struct {
	Listen         ListenConfig         `yaml:"listen"`
	ExternalURL    string               `yaml:"external_url"`
	MCP            MCPConfig            `yaml:"mcp"`
	Health         HealthConfig         `yaml:"health"`
	Agents         []AgentConfig        `yaml:"agents"`
	Routing        RoutingConfig        `yaml:"routing"`
	Card           CardConfig           `yaml:"card"`
	Security       SecurityConfig       `yaml:"security"`
	BodyInspection BodyInspectionConfig `yaml:"body_inspection"`
	Logging        LoggingConfig        `yaml:"logging"`
	Shutdown       ShutdownConfig       `yaml:"shutdown"`
	Migration      MigrationConfig      `yaml:"migration"`
	Reload         ReloadConfig         `yaml:"reload"`
}

// ListenConfig defines the listener address and connection limits.
type ListenConfig struct {
	Host           string    `yaml:"host"`
	Port           int       `yaml:"port"`
	GRPCPort       int       `yaml:"grpc_port"`
	MaxConnections int       `yaml:"max_connections"`
	GlobalRateLimit int      `yaml:"global_rate_limit"`
	TrustedProxies []string  `yaml:"trusted_proxies"`
	TLS            TLSConfig `yaml:"tls"`
}

// TLSConfig holds optional TLS certificate paths.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// MCPConfig controls the MCP management server (default OFF, local-only).
type MCPConfig struct {
	Enabled bool    `yaml:"enabled"`
	Host    string  `yaml:"host"`
	Port    int     `yaml:"port"`
	Auth    MCPAuth `yaml:"auth"`
}

// MCPAuth holds MCP server authentication settings.
type MCPAuth struct {
	Token string `yaml:"token"`
}

// HealthConfig defines health check endpoint paths and readiness behavior.
type HealthConfig struct {
	LivenessPath  string `yaml:"liveness_path"`
	ReadinessPath string `yaml:"readiness_path"`
	ReadinessMode string `yaml:"readiness_mode"`
}

// AgentConfig describes a backend A2A agent with its connection and policy settings.
type AgentConfig struct {
	Name             string            `yaml:"name"`
	URL              string            `yaml:"url"`
	GRPCURL          string            `yaml:"grpc_url"`
	CardPath         string            `yaml:"card_path"`
	PollInterval     Duration          `yaml:"poll_interval"`
	Timeout          Duration          `yaml:"timeout"`
	MaxStreams       int               `yaml:"max_streams"`
	Default          bool              `yaml:"default"`
	AllowInsecure    bool              `yaml:"allow_insecure"`
	HealthCheck      HealthCheckConfig `yaml:"health_check"`
	CardChangePolicy string            `yaml:"card_change_policy"`
}

// HealthCheckConfig controls per-agent health checking behavior.
type HealthCheckConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Interval Duration `yaml:"interval"`
}

// RoutingConfig determines how requests are routed to agents.
type RoutingConfig struct {
	Mode string `yaml:"mode"`
}

// CardConfig controls Agent Card exposure policy.
type CardConfig struct {
	Mode           string `yaml:"mode"`
	GatewayJWKFile string `yaml:"gateway_jwk_file"`
}

// SecurityConfig is the top-level security configuration (all defaults ON).
type SecurityConfig struct {
	CardSignature CardSignatureConfig `yaml:"card_signature"`
	Auth          AuthConfig          `yaml:"auth"`
	Replay        ReplayConfig        `yaml:"replay"`
	RateLimit     RateLimitConfig     `yaml:"rate_limit"`
	Push          PushConfig          `yaml:"push"`
	Policies      []PolicyConfig      `yaml:"policies"`
}

// PolicyConfig defines an ABAC access control rule in configuration.
type PolicyConfig struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Match       PolicyMatchConfig `yaml:"match"`
	Action      string            `yaml:"action"`   // "allow" or "deny"
	Priority    int               `yaml:"priority"`  // higher = evaluated first
}

// PolicyMatchConfig defines conditions that must all be true for a policy to match.
type PolicyMatchConfig struct {
	Agents    []string          `yaml:"agents"`
	Methods   []string          `yaml:"methods"`
	Users     []string          `yaml:"users"`
	IPs       []string          `yaml:"ips"`
	Headers   map[string]string `yaml:"headers"`
	TimeRange *TimeRangeConfig  `yaml:"time_range"`
}

// TimeRangeConfig restricts access to specific hours of the day.
type TimeRangeConfig struct {
	Start string `yaml:"start"` // "09:00" (HH:MM)
	End   string `yaml:"end"`   // "18:00" (HH:MM)
	TZ    string `yaml:"tz"`    // "Asia/Seoul", defaults to UTC
}

// CardSignatureConfig controls JWS signature verification for Agent Cards.
type CardSignatureConfig struct {
	Require         bool     `yaml:"require"`
	TrustedJWKSURLs []string `yaml:"trusted_jwks_urls"`
	CacheTTL        Duration `yaml:"cache_ttl"`
}

// AuthConfig defines the authentication mode and scheme configuration.
type AuthConfig struct {
	Mode                 string         `yaml:"mode"`
	Schemes              []SchemeConfig `yaml:"schemes"`
	AllowUnauthenticated bool           `yaml:"allow_unauthenticated"`
}

// SchemeConfig describes a single authentication scheme (e.g., bearer JWT).
type SchemeConfig struct {
	Type string    `yaml:"type"`
	JWT  JWTConfig `yaml:"jwt"`
}

// JWTConfig holds JWT validation parameters for a bearer auth scheme.
type JWTConfig struct {
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	JWKSURL  string `yaml:"jwks_url"`
}

// ReplayConfig controls nonce/timestamp replay attack prevention.
type ReplayConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Window          Duration `yaml:"window"`
	NoncePolicy     string   `yaml:"nonce_policy"`
	NonceSource     string   `yaml:"nonce_source"`  // "auto", "header", "jsonrpc-id"
	ClockSkew       Duration `yaml:"clock_skew"`     // tolerance for timestamp validation
	Store           string   `yaml:"store"`
	RedisURL        string   `yaml:"redis_url"`
	CleanupInterval Duration `yaml:"cleanup_interval"`
}

// RateLimitConfig defines rate limiting by IP, user, and per-agent.
type RateLimitConfig struct {
	Enabled  bool           `yaml:"enabled"`
	IP       IPRateConfig   `yaml:"ip"`
	User     UserRateConfig `yaml:"user"`
	PerAgent int            `yaml:"per_agent"`
}

// IPRateConfig defines per-IP rate limiting with burst and cleanup settings.
type IPRateConfig struct {
	PerIP           int      `yaml:"per_ip"`
	Burst           int      `yaml:"burst"`
	CleanupInterval Duration `yaml:"cleanup_interval"`
}

// UserRateConfig defines per-user rate limiting with burst and cleanup settings.
type UserRateConfig struct {
	PerUser         int      `yaml:"per_user"`
	Burst           int      `yaml:"burst"`
	CleanupInterval Duration `yaml:"cleanup_interval"`
}

// PushConfig controls push notification security (SSRF prevention).
type PushConfig struct {
	BlockPrivateNetworks bool     `yaml:"block_private_networks"`
	AllowedDomains       []string `yaml:"allowed_domains"`
	RequireHTTPS         bool     `yaml:"require_https"`
	RequireChallenge     bool     `yaml:"require_challenge"`
	HMACSecret           string   `yaml:"hmac_secret"`
}

// BodyInspectionConfig controls how request bodies are read and inspected.
type BodyInspectionConfig struct {
	MaxSize       int  `yaml:"max_size"`
	SkipStreaming bool `yaml:"skip_streaming"`
}

// LoggingConfig defines log output format and audit sampling.
type LoggingConfig struct {
	Level  string      `yaml:"level"`
	Format string      `yaml:"format"`
	Output string      `yaml:"output"`
	Audit  AuditConfig `yaml:"audit"`
}

// AuditConfig controls OTel-compatible audit log sampling rates.
type AuditConfig struct {
	SamplingRate      float64 `yaml:"sampling_rate"`
	ErrorSamplingRate float64 `yaml:"error_sampling_rate"`
	MaxBodyLogSize    int     `yaml:"max_body_log_size"`
}

// ShutdownConfig defines graceful shutdown and SSE drain timeouts.
type ShutdownConfig struct {
	Timeout      Duration `yaml:"timeout"`
	DrainTimeout Duration `yaml:"drain_timeout"`
}

// MigrationConfig holds the target agentgateway version for migration.
type MigrationConfig struct {
	AgentgatewayVersion string `yaml:"agentgateway_version"`
}

// ReloadConfig controls config hot-reload behavior (SIGHUP and file watching).
type ReloadConfig struct {
	Enabled   bool     `yaml:"enabled"`    // default true
	WatchFile bool     `yaml:"watch_file"` // default true
	Debounce  Duration `yaml:"debounce"`   // default 2s
}

// Duration is a time.Duration that supports YAML string parsing (e.g., "60s", "5m").
type Duration struct {
	time.Duration
}

// UnmarshalYAML implements yaml.Unmarshaler for Duration, parsing strings like "60s" or "5m".
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// MarshalYAML implements yaml.Marshaler for Duration.
func (d Duration) MarshalYAML() (interface{}, error) {
	return d.Duration.String(), nil
}

// Load reads, parses, applies defaults, and validates a configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	ApplyDefaults(&cfg)

	if err := Validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
