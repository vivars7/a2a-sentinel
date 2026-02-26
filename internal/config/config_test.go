package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// helper: write YAML to a temp file and return its path.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sentinel.yaml")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("writing temp yaml: %v", err)
	}
	return p
}

// minimalValidYAML is the smallest YAML that passes validation.
const minimalValidYAML = `
agents:
  - name: test-agent
    url: http://localhost:9000
`

func TestLoad_ValidYAML(t *testing.T) {
	p := writeTempYAML(t, minimalValidYAML)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(cfg.Agents))
	}
	if cfg.Agents[0].Name != "test-agent" {
		t.Errorf("agent name = %q, want %q", cfg.Agents[0].Name, "test-agent")
	}
}

func TestLoad_EmptyAgents(t *testing.T) {
	yaml := `
agents: []
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for empty agents")
	}
	if !strings.Contains(err.Error(), "agents list must not be empty") {
		t.Errorf("error should mention empty agents: %v", err)
	}
}

func TestLoad_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "port negative",
			yaml: `
listen:
  port: -1
agents:
  - name: a
    url: http://localhost:9000
`,
			want: "listen.port must be 1-65535",
		},
		{
			name: "port too high",
			yaml: `
listen:
  port: 70000
agents:
  - name: a
    url: http://localhost:9000
`,
			want: "listen.port must be 1-65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := writeTempYAML(t, tt.yaml)
			_, err := Load(p)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestLoad_InvalidAuthMode(t *testing.T) {
	yaml := `
security:
  auth:
    mode: invalid-mode
agents:
  - name: a
    url: http://localhost:9000
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for invalid auth mode")
	}
	if !strings.Contains(err.Error(), "security.auth.mode must be one of") {
		t.Errorf("error should mention auth.mode: %v", err)
	}
}

func TestLoad_DefaultsApplied(t *testing.T) {
	p := writeTempYAML(t, minimalValidYAML)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Listen defaults
	if cfg.Listen.Host != "0.0.0.0" {
		t.Errorf("listen.host = %q, want %q", cfg.Listen.Host, "0.0.0.0")
	}
	if cfg.Listen.Port != 8080 {
		t.Errorf("listen.port = %d, want %d", cfg.Listen.Port, 8080)
	}
	if cfg.Listen.MaxConnections != 1000 {
		t.Errorf("listen.max_connections = %d, want %d", cfg.Listen.MaxConnections, 1000)
	}
	if cfg.Listen.GlobalRateLimit != 5000 {
		t.Errorf("listen.global_rate_limit = %d, want %d", cfg.Listen.GlobalRateLimit, 5000)
	}

	// MCP defaults
	if cfg.MCP.Host != "127.0.0.1" {
		t.Errorf("mcp.host = %q, want %q", cfg.MCP.Host, "127.0.0.1")
	}
	if cfg.MCP.Port != 8081 {
		t.Errorf("mcp.port = %d, want %d", cfg.MCP.Port, 8081)
	}

	// Health defaults
	if cfg.Health.LivenessPath != "/healthz" {
		t.Errorf("health.liveness_path = %q, want %q", cfg.Health.LivenessPath, "/healthz")
	}
	if cfg.Health.ReadinessPath != "/readyz" {
		t.Errorf("health.readiness_path = %q, want %q", cfg.Health.ReadinessPath, "/readyz")
	}
	if cfg.Health.ReadinessMode != "any_healthy" {
		t.Errorf("health.readiness_mode = %q, want %q", cfg.Health.ReadinessMode, "any_healthy")
	}

	// Routing default
	if cfg.Routing.Mode != "path-prefix" {
		t.Errorf("routing.mode = %q, want %q", cfg.Routing.Mode, "path-prefix")
	}

	// Card default
	if cfg.Card.Mode != "gateway" {
		t.Errorf("card.mode = %q, want %q", cfg.Card.Mode, "gateway")
	}

	// Security auth default
	if cfg.Security.Auth.Mode != "passthrough-strict" {
		t.Errorf("security.auth.mode = %q, want %q", cfg.Security.Auth.Mode, "passthrough-strict")
	}

	// Replay defaults
	if cfg.Security.Replay.Window.Duration != 300*time.Second {
		t.Errorf("security.replay.window = %v, want %v", cfg.Security.Replay.Window.Duration, 300*time.Second)
	}
	if cfg.Security.Replay.NoncePolicy != "warn" {
		t.Errorf("security.replay.nonce_policy = %q, want %q", cfg.Security.Replay.NoncePolicy, "warn")
	}
	if cfg.Security.Replay.Store != "memory" {
		t.Errorf("security.replay.store = %q, want %q", cfg.Security.Replay.Store, "memory")
	}

	// Rate limit defaults
	if cfg.Security.RateLimit.IP.PerIP != 200 {
		t.Errorf("security.rate_limit.ip.per_ip = %d, want %d", cfg.Security.RateLimit.IP.PerIP, 200)
	}
	if cfg.Security.RateLimit.IP.Burst != 50 {
		t.Errorf("security.rate_limit.ip.burst = %d, want %d", cfg.Security.RateLimit.IP.Burst, 50)
	}
	if cfg.Security.RateLimit.IP.CleanupInterval.Duration != 5*time.Minute {
		t.Errorf("security.rate_limit.ip.cleanup_interval = %v, want %v", cfg.Security.RateLimit.IP.CleanupInterval.Duration, 5*time.Minute)
	}
	if cfg.Security.RateLimit.User.PerUser != 100 {
		t.Errorf("security.rate_limit.user.per_user = %d, want %d", cfg.Security.RateLimit.User.PerUser, 100)
	}
	if cfg.Security.RateLimit.User.Burst != 20 {
		t.Errorf("security.rate_limit.user.burst = %d, want %d", cfg.Security.RateLimit.User.Burst, 20)
	}
	if cfg.Security.RateLimit.User.CleanupInterval.Duration != 5*time.Minute {
		t.Errorf("security.rate_limit.user.cleanup_interval = %v, want %v", cfg.Security.RateLimit.User.CleanupInterval.Duration, 5*time.Minute)
	}
	if cfg.Security.RateLimit.PerAgent != 500 {
		t.Errorf("security.rate_limit.per_agent = %d, want %d", cfg.Security.RateLimit.PerAgent, 500)
	}

	// Body inspection defaults
	if cfg.BodyInspection.MaxSize != 1048576 {
		t.Errorf("body_inspection.max_size = %d, want %d", cfg.BodyInspection.MaxSize, 1048576)
	}

	// Logging defaults
	if cfg.Logging.Level != "info" {
		t.Errorf("logging.level = %q, want %q", cfg.Logging.Level, "info")
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("logging.format = %q, want %q", cfg.Logging.Format, "json")
	}
	if cfg.Logging.Output != "stdout" {
		t.Errorf("logging.output = %q, want %q", cfg.Logging.Output, "stdout")
	}
	if cfg.Logging.Audit.SamplingRate != 1.0 {
		t.Errorf("logging.audit.sampling_rate = %f, want %f", cfg.Logging.Audit.SamplingRate, 1.0)
	}
	if cfg.Logging.Audit.ErrorSamplingRate != 1.0 {
		t.Errorf("logging.audit.error_sampling_rate = %f, want %f", cfg.Logging.Audit.ErrorSamplingRate, 1.0)
	}
	if cfg.Logging.Audit.MaxBodyLogSize != 1024 {
		t.Errorf("logging.audit.max_body_log_size = %d, want %d", cfg.Logging.Audit.MaxBodyLogSize, 1024)
	}

	// Shutdown defaults
	if cfg.Shutdown.Timeout.Duration != 30*time.Second {
		t.Errorf("shutdown.timeout = %v, want %v", cfg.Shutdown.Timeout.Duration, 30*time.Second)
	}
	if cfg.Shutdown.DrainTimeout.Duration != 15*time.Second {
		t.Errorf("shutdown.drain_timeout = %v, want %v", cfg.Shutdown.DrainTimeout.Duration, 15*time.Second)
	}

	// Migration default
	if cfg.Migration.AgentgatewayVersion != "latest" {
		t.Errorf("migration.agentgateway_version = %q, want %q", cfg.Migration.AgentgatewayVersion, "latest")
	}

	// Agent defaults
	a := cfg.Agents[0]
	if a.CardPath != "/.well-known/agent.json" {
		t.Errorf("agent.card_path = %q, want %q", a.CardPath, "/.well-known/agent.json")
	}
	if a.PollInterval.Duration != 60*time.Second {
		t.Errorf("agent.poll_interval = %v, want %v", a.PollInterval.Duration, 60*time.Second)
	}
	if a.Timeout.Duration != 30*time.Second {
		t.Errorf("agent.timeout = %v, want %v", a.Timeout.Duration, 30*time.Second)
	}
	if a.MaxStreams != 10 {
		t.Errorf("agent.max_streams = %d, want %d", a.MaxStreams, 10)
	}
	if a.CardChangePolicy != "alert" {
		t.Errorf("agent.card_change_policy = %q, want %q", a.CardChangePolicy, "alert")
	}
	if a.HealthCheck.Interval.Duration != 30*time.Second {
		t.Errorf("agent.health_check.interval = %v, want %v", a.HealthCheck.Interval.Duration, 30*time.Second)
	}

	// Card signature defaults
	if cfg.Security.CardSignature.CacheTTL.Duration != 3600*time.Second {
		t.Errorf("security.card_signature.cache_ttl = %v, want %v", cfg.Security.CardSignature.CacheTTL.Duration, 3600*time.Second)
	}
}

func TestLoad_MultipleValidationErrors(t *testing.T) {
	yaml := `
listen:
  port: -1
security:
  auth:
    mode: bad
routing:
  mode: bad
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation errors")
	}
	msg := err.Error()
	// Should contain multiple errors
	if !strings.Contains(msg, "agents list must not be empty") {
		t.Errorf("missing agents error in: %v", msg)
	}
	if !strings.Contains(msg, "listen.port must be 1-65535") {
		t.Errorf("missing port error in: %v", msg)
	}
	if !strings.Contains(msg, "security.auth.mode must be one of") {
		t.Errorf("missing auth.mode error in: %v", msg)
	}
	if !strings.Contains(msg, "routing.mode must be one of") {
		t.Errorf("missing routing.mode error in: %v", msg)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/sentinel.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "reading config") {
		t.Errorf("error should mention reading config: %v", err)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	p := writeTempYAML(t, `{{{invalid yaml`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "parsing config") {
		t.Errorf("error should mention parsing config: %v", err)
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	p := writeTempYAML(t, "")
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for empty YAML (no agents)")
	}
	if !strings.Contains(err.Error(), "agents list must not be empty") {
		t.Errorf("error should mention empty agents: %v", err)
	}
}

func TestDurationParsing(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  time.Duration
	}{
		{"seconds", "60s", 60 * time.Second},
		{"minutes", "5m", 5 * time.Minute},
		{"hours", "1h", 1 * time.Hour},
		{"mixed", "1h30m", 90 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `
agents:
  - name: a
    url: http://localhost:9000
    poll_interval: ` + tt.input + `
`
			p := writeTempYAML(t, yaml)
			cfg, err := Load(p)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Agents[0].PollInterval.Duration != tt.want {
				t.Errorf("duration = %v, want %v", cfg.Agents[0].PollInterval.Duration, tt.want)
			}
		})
	}
}

func TestDurationParsing_Invalid(t *testing.T) {
	yaml := `
agents:
  - name: a
    url: http://localhost:9000
    poll_interval: not-a-duration
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
	if !strings.Contains(err.Error(), "invalid duration") {
		t.Errorf("error should mention invalid duration: %v", err)
	}
}

func TestLoad_SentinelYAMLExample(t *testing.T) {
	// Load the project's sentinel.yaml.example to ensure it is valid.
	examplePath := filepath.Join("..", "..", "sentinel.yaml.example")
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Skip("sentinel.yaml.example not found (skipping)")
	}
	cfg, err := Load(examplePath)
	if err != nil {
		t.Fatalf("sentinel.yaml.example should be valid: %v", err)
	}
	if len(cfg.Agents) == 0 {
		t.Error("sentinel.yaml.example should have at least one agent")
	}
}

func TestLoad_AtMostOneDefaultAgent(t *testing.T) {
	yaml := `
agents:
  - name: agent-a
    url: http://localhost:9000
    default: true
  - name: agent-b
    url: http://localhost:9001
    default: true
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for multiple default agents")
	}
	if !strings.Contains(err.Error(), "at most one agent can be default") {
		t.Errorf("error should mention default agent constraint: %v", err)
	}
}

func TestValidate_ValidAuthModes(t *testing.T) {
	modes := []string{"passthrough", "passthrough-strict", "terminate"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			yaml := `
security:
  auth:
    mode: ` + mode + `
agents:
  - name: a
    url: http://localhost:9000
`
			p := writeTempYAML(t, yaml)
			_, err := Load(p)
			if err != nil {
				t.Errorf("auth mode %q should be valid: %v", mode, err)
			}
		})
	}
}

func TestValidate_ValidRoutingModes(t *testing.T) {
	modes := []string{"path-prefix", "single"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			yaml := `
routing:
  mode: ` + mode + `
agents:
  - name: a
    url: http://localhost:9000
`
			p := writeTempYAML(t, yaml)
			_, err := Load(p)
			if err != nil {
				t.Errorf("routing mode %q should be valid: %v", mode, err)
			}
		})
	}
}

func TestValidate_ValidReadinessModes(t *testing.T) {
	modes := []string{"any_healthy", "default_healthy", "all_healthy"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			yaml := `
health:
  readiness_mode: ` + mode + `
agents:
  - name: a
    url: http://localhost:9000
`
			p := writeTempYAML(t, yaml)
			_, err := Load(p)
			if err != nil {
				t.Errorf("readiness mode %q should be valid: %v", mode, err)
			}
		})
	}
}

func TestValidate_ValidCardModes(t *testing.T) {
	modes := []string{"gateway", "passthrough"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			yaml := `
card:
  mode: ` + mode + `
agents:
  - name: a
    url: http://localhost:9000
`
			p := writeTempYAML(t, yaml)
			_, err := Load(p)
			if err != nil {
				t.Errorf("card mode %q should be valid: %v", mode, err)
			}
		})
	}
}

func TestValidate_ValidNoncePolicies(t *testing.T) {
	policies := []string{"warn", "require"}
	for _, policy := range policies {
		t.Run(policy, func(t *testing.T) {
			yaml := `
security:
  replay:
    nonce_policy: ` + policy + `
agents:
  - name: a
    url: http://localhost:9000
`
			p := writeTempYAML(t, yaml)
			_, err := Load(p)
			if err != nil {
				t.Errorf("nonce_policy %q should be valid: %v", policy, err)
			}
		})
	}
}

func TestValidate_InvalidCardChangePolicy(t *testing.T) {
	yaml := `
agents:
  - name: a
    url: http://localhost:9000
    card_change_policy: invalid
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for invalid card_change_policy")
	}
	if !strings.Contains(err.Error(), "card_change_policy must be one of") {
		t.Errorf("error should mention card_change_policy: %v", err)
	}
}

func TestValidate_InvalidNoncePolicy(t *testing.T) {
	yaml := `
security:
  replay:
    nonce_policy: invalid
agents:
  - name: a
    url: http://localhost:9000
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for invalid nonce_policy")
	}
	if !strings.Contains(err.Error(), "security.replay.nonce_policy must be one of") {
		t.Errorf("error should mention nonce_policy: %v", err)
	}
}

func TestValidate_InvalidReadinessMode(t *testing.T) {
	yaml := `
health:
  readiness_mode: invalid
agents:
  - name: a
    url: http://localhost:9000
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for invalid readiness_mode")
	}
	if !strings.Contains(err.Error(), "health.readiness_mode must be one of") {
		t.Errorf("error should mention readiness_mode: %v", err)
	}
}

func TestValidate_InvalidCardMode(t *testing.T) {
	yaml := `
card:
  mode: invalid
agents:
  - name: a
    url: http://localhost:9000
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for invalid card mode")
	}
	if !strings.Contains(err.Error(), "card.mode must be one of") {
		t.Errorf("error should mention card.mode: %v", err)
	}
}

func TestValidate_SamplingRateOutOfRange(t *testing.T) {
	yaml := `
logging:
  audit:
    sampling_rate: 1.5
    error_sampling_rate: -0.1
agents:
  - name: a
    url: http://localhost:9000
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for out-of-range sampling rates")
	}
	msg := err.Error()
	if !strings.Contains(msg, "sampling_rate must be between 0.0 and 1.0") {
		t.Errorf("error should mention sampling_rate: %v", msg)
	}
	if !strings.Contains(msg, "error_sampling_rate must be between 0.0 and 1.0") {
		t.Errorf("error should mention error_sampling_rate: %v", msg)
	}
}

func TestValidate_AgentMissingName(t *testing.T) {
	yaml := `
agents:
  - url: http://localhost:9000
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for agent without name")
	}
	if !strings.Contains(err.Error(), "name is required") {
		t.Errorf("error should mention name: %v", err)
	}
}

func TestValidate_AgentMissingURL(t *testing.T) {
	yaml := `
agents:
  - name: test
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for agent without url")
	}
	if !strings.Contains(err.Error(), "url is required") {
		t.Errorf("error should mention url: %v", err)
	}
}

func TestValidate_MCPPortInvalid(t *testing.T) {
	yaml := `
mcp:
  port: 70000
agents:
  - name: a
    url: http://localhost:9000
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for invalid mcp port")
	}
	if !strings.Contains(err.Error(), "mcp.port must be 1-65535") {
		t.Errorf("error should mention mcp.port: %v", err)
	}
}

func TestProfiles_DevLoadsSuccessfully(t *testing.T) {
	p := writeTempYAML(t, DevProfile())
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("DevProfile should produce valid config: %v", err)
	}
	if cfg.Listen.Host != "127.0.0.1" {
		t.Errorf("dev profile host = %q, want %q", cfg.Listen.Host, "127.0.0.1")
	}
	if cfg.Security.Auth.AllowUnauthenticated != true {
		t.Error("dev profile should allow unauthenticated")
	}
}

func TestProfiles_ProdLoadsSuccessfully(t *testing.T) {
	p := writeTempYAML(t, ProdProfile())
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("ProdProfile should produce valid config: %v", err)
	}
	if cfg.Listen.Host != "0.0.0.0" {
		t.Errorf("prod profile host = %q, want %q", cfg.Listen.Host, "0.0.0.0")
	}
	if cfg.Security.RateLimit.Enabled != true {
		t.Error("prod profile should enable rate limiting")
	}
	if cfg.Security.Replay.Enabled != true {
		t.Error("prod profile should enable replay protection")
	}
	if cfg.Security.CardSignature.Require != true {
		t.Error("prod profile should require card signatures")
	}
}

func TestDurationMarshalYAML(t *testing.T) {
	d := Duration{Duration: 5 * time.Minute}
	v, err := d.MarshalYAML()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("MarshalYAML returned %T, want string", v)
	}
	if s != "5m0s" {
		t.Errorf("MarshalYAML = %q, want %q", s, "5m0s")
	}
}

// TestDurationUnmarshalYAML_InvalidDuration covers time.ParseDuration error path.
func TestDurationUnmarshalYAML_InvalidDuration(t *testing.T) {
	yamlStr := `
agents:
  - name: a
    url: http://localhost:9000
    poll_interval: not-a-duration-at-all
`
	p := writeTempYAML(t, yamlStr)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for invalid duration string")
	}
	if !strings.Contains(err.Error(), "invalid duration") {
		t.Errorf("expected 'invalid duration' in error, got: %v", err)
	}
}

// TestDurationUnmarshalYAML_DecodeError covers the Decode error when value is a YAML mapping.
func TestDurationUnmarshalYAML_DecodeError(t *testing.T) {
	// A YAML mapping value cannot be decoded as a string — triggers the Decode error path.
	yamlStr := `
agents:
  - name: a
    url: http://localhost:9000
    poll_interval:
      nested: value
`
	p := writeTempYAML(t, yamlStr)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for mapping-type duration value")
	}
}

// TestValidate_NegativePollInterval covers the negative poll_interval validation path.
func TestValidate_NegativePollInterval(t *testing.T) {
	cfg := &Config{}
	cfg.Agents = []AgentConfig{
		{
			Name:             "a",
			URL:              "http://localhost:9000",
			CardChangePolicy: "alert",
			PollInterval:     Duration{Duration: -1},
		},
	}
	ApplyDefaults(cfg)
	// Manually set negative poll interval AFTER defaults (defaults won't set negative).
	cfg.Agents[0].PollInterval.Duration = -1
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for negative poll_interval")
	}
	if !strings.Contains(err.Error(), "poll_interval must be positive") {
		t.Errorf("error should mention poll_interval: %v", err)
	}
}

// TestValidate_NegativeTimeout covers the negative timeout validation path.
func TestValidate_NegativeTimeout(t *testing.T) {
	cfg := &Config{}
	cfg.Agents = []AgentConfig{
		{
			Name:             "a",
			URL:              "http://localhost:9000",
			CardChangePolicy: "alert",
			Timeout:          Duration{Duration: -1},
		},
	}
	ApplyDefaults(cfg)
	cfg.Agents[0].Timeout.Duration = -1
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for negative timeout")
	}
	if !strings.Contains(err.Error(), "timeout must be positive") {
		t.Errorf("error should mention timeout: %v", err)
	}
}

// TestValidate_NegativeMaxConnections covers the max_connections validation path.
func TestValidate_NegativeMaxConnections(t *testing.T) {
	cfg := &Config{}
	cfg.Agents = []AgentConfig{
		{Name: "a", URL: "http://localhost:9000", CardChangePolicy: "alert"},
	}
	ApplyDefaults(cfg)
	cfg.Listen.MaxConnections = -1
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for negative max_connections")
	}
	if !strings.Contains(err.Error(), "listen.max_connections must be positive") {
		t.Errorf("error should mention max_connections: %v", err)
	}
}

// TestValidate_NegativeGlobalRateLimit covers the global_rate_limit validation path.
func TestValidate_NegativeGlobalRateLimit(t *testing.T) {
	cfg := &Config{}
	cfg.Agents = []AgentConfig{
		{Name: "a", URL: "http://localhost:9000", CardChangePolicy: "alert"},
	}
	ApplyDefaults(cfg)
	cfg.Listen.GlobalRateLimit = -1
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for negative global_rate_limit")
	}
	if !strings.Contains(err.Error(), "listen.global_rate_limit must be positive") {
		t.Errorf("error should mention global_rate_limit: %v", err)
	}
}

func TestValidate_TLSFilesMissing(t *testing.T) {
	yaml := `
listen:
  tls:
    cert_file: /nonexistent/cert.pem
    key_file: /nonexistent/key.pem
agents:
  - name: a
    url: http://localhost:9000
`
	p := writeTempYAML(t, yaml)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation error for missing TLS files")
	}
	msg := err.Error()
	if !strings.Contains(msg, "listen.tls.cert_file") {
		t.Errorf("error should mention cert_file: %v", msg)
	}
	if !strings.Contains(msg, "listen.tls.key_file") {
		t.Errorf("error should mention key_file: %v", msg)
	}
}
