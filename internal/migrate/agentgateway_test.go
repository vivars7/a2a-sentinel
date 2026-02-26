package migrate

import (
	"strings"
	"testing"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/config"
)

// minimalConfig returns a Config with only agents set (the minimum for conversion).
func minimalConfig() *config.Config {
	return &config.Config{
		Agents: []config.AgentConfig{
			{Name: "agent-a", URL: "http://localhost:9000", Default: true},
		},
		Security: config.SecurityConfig{
			Auth: config.AuthConfig{Mode: "passthrough-strict"},
		},
		Listen:  config.ListenConfig{Port: 8080},
		Routing: config.RoutingConfig{Mode: "path-prefix"},
		Logging: config.LoggingConfig{Level: "info"},
	}
}

// fullConfig returns a Config with all fields populated to exercise every mapping path.
func fullConfig() *config.Config {
	cfg := minimalConfig()
	cfg.Agents = append(cfg.Agents, config.AgentConfig{
		Name: "agent-b", URL: "http://localhost:9001",
	})
	cfg.Security.Auth.Mode = "terminate"
	cfg.Security.RateLimit = config.RateLimitConfig{
		Enabled: true,
		IP:      config.IPRateConfig{PerIP: 200, Burst: 50},
		User:    config.UserRateConfig{PerUser: 100, Burst: 20},
	}
	cfg.Security.Push = config.PushConfig{BlockPrivateNetworks: true}
	cfg.Security.CardSignature = config.CardSignatureConfig{Require: true}
	cfg.Security.Replay = config.ReplayConfig{Enabled: true}
	cfg.MCP = config.MCPConfig{Enabled: true}
	cfg.BodyInspection = config.BodyInspectionConfig{MaxSize: 1048576}
	cfg.Shutdown = config.ShutdownConfig{
		Timeout:      config.Duration{Duration: 30 * time.Second},
		DrainTimeout: config.Duration{Duration: 15 * time.Second},
	}
	cfg.Logging.Audit = config.AuditConfig{SamplingRate: 1.0}
	return cfg
}

func TestConvert_MinimalConfig(t *testing.T) {
	cfg := minimalConfig()
	gw, warnings, err := Convert(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Backends
	if len(gw.Backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(gw.Backends))
	}
	b := gw.Backends[0]
	if b.Name != "agent-a" {
		t.Errorf("expected backend name agent-a, got %q", b.Name)
	}
	if b.Address != "http://localhost:9000" {
		t.Errorf("expected address http://localhost:9000, got %q", b.Address)
	}
	if !b.Default {
		t.Error("expected backend to be default")
	}

	// Auth
	if gw.Auth == nil || gw.Auth.Policy != "passthrough" {
		t.Errorf("expected auth policy passthrough, got %v", gw.Auth)
	}

	// RateLimit should be nil (not enabled)
	if gw.RateLimit != nil {
		t.Error("expected nil rateLimit for disabled rate limiting")
	}

	// Server
	if gw.Server == nil || gw.Server.Port != 8080 {
		t.Errorf("expected server port 8080, got %v", gw.Server)
	}

	// Routing
	if gw.Routing == nil || gw.Routing.Strategy != "path-prefix" {
		t.Errorf("expected routing strategy path-prefix, got %v", gw.Routing)
	}

	// No MCP, replay, or body inspection warnings for minimal config
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings for minimal config, got %d: %v", len(warnings), warnings)
	}
}

func TestConvert_FullConfig(t *testing.T) {
	cfg := fullConfig()
	gw, warnings, err := Convert(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2 backends
	if len(gw.Backends) != 2 {
		t.Fatalf("expected 2 backends, got %d", len(gw.Backends))
	}
	if gw.Backends[1].Name != "agent-b" {
		t.Errorf("expected second backend agent-b, got %q", gw.Backends[1].Name)
	}

	// Auth mode "terminate" maps to "enforce"
	if gw.Auth.Policy != "enforce" {
		t.Errorf("expected auth policy enforce, got %q", gw.Auth.Policy)
	}

	// RateLimit enabled
	if gw.RateLimit == nil {
		t.Fatal("expected rateLimit to be set")
	}
	if gw.RateLimit.PerIP != 200 {
		t.Errorf("expected perIP 200, got %d", gw.RateLimit.PerIP)
	}
	if gw.RateLimit.PerUser != 100 {
		t.Errorf("expected perUser 100, got %d", gw.RateLimit.PerUser)
	}

	// SSRF
	if gw.SSRF == nil || !gw.SSRF.BlockPrivate {
		t.Error("expected ssrf.blockPrivate to be true")
	}

	// TLS
	if gw.TLS == nil || !gw.TLS.VerifyCards {
		t.Error("expected tls.verifyCards to be true")
	}

	// Graceful shutdown
	if gw.Server.Graceful == nil {
		t.Fatal("expected graceful shutdown config")
	}
	if gw.Server.Graceful.Timeout != "30s" {
		t.Errorf("expected timeout 30s, got %q", gw.Server.Graceful.Timeout)
	}
	if gw.Server.Graceful.Drain != "15s" {
		t.Errorf("expected drain 15s, got %q", gw.Server.Graceful.Drain)
	}

	// Observability
	if gw.Observability == nil {
		t.Fatal("expected observability config")
	}
	if !gw.Observability.Audit {
		t.Error("expected audit to be true")
	}

	// Warnings: MCP + replay + body_inspection
	if len(warnings) != 3 {
		t.Errorf("expected 3 warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestConvert_NilConfig(t *testing.T) {
	_, _, err := Convert(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("expected error to mention nil, got %q", err.Error())
	}
}

func TestConvert_AuthModes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"passthrough", "passthrough"},
		{"passthrough-strict", "passthrough"},
		{"terminate", "enforce"},
		{"custom", "custom"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run("mode_"+tt.input, func(t *testing.T) {
			cfg := minimalConfig()
			cfg.Security.Auth.Mode = tt.input
			gw, _, err := Convert(cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gw.Auth.Policy != tt.expected {
				t.Errorf("mapAuthMode(%q) = %q, want %q", tt.input, gw.Auth.Policy, tt.expected)
			}
		})
	}
}

func TestConvert_Warnings(t *testing.T) {
	t.Run("mcp_warning", func(t *testing.T) {
		cfg := minimalConfig()
		cfg.MCP.Enabled = true
		_, warnings, err := Convert(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		found := false
		for _, w := range warnings {
			if w.Field == "mcp.*" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected warning for mcp.*, not found")
		}
	})

	t.Run("replay_warning", func(t *testing.T) {
		cfg := minimalConfig()
		cfg.Security.Replay.Enabled = true
		_, warnings, err := Convert(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		found := false
		for _, w := range warnings {
			if w.Field == "security.replay.*" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected warning for security.replay.*, not found")
		}
	})

	t.Run("body_inspection_warning", func(t *testing.T) {
		cfg := minimalConfig()
		cfg.BodyInspection.MaxSize = 2048
		_, warnings, err := Convert(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		found := false
		for _, w := range warnings {
			if w.Field == "body_inspection.*" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected warning for body_inspection.*, not found")
		}
	})
}

func TestMarshal_Header(t *testing.T) {
	gw := &AgentGatewayConfig{
		Backends: []GWBackend{{Name: "a", Address: "http://a:80"}},
	}
	out, err := Marshal(gw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "# Migrated from sentinel configuration\n") {
		t.Errorf("expected migration header, got:\n%s", s)
	}
	if !strings.Contains(s, "# Generated by: sentinel migrate") {
		t.Error("expected 'Generated by' line in header")
	}
	// No warnings section when warnings are empty
	if strings.Contains(s, "Warnings") {
		t.Error("expected no warnings section with empty warnings")
	}
}

func TestMarshal_Warnings(t *testing.T) {
	gw := &AgentGatewayConfig{
		Backends: []GWBackend{{Name: "a", Address: "http://a:80"}},
	}
	warnings := []Warning{
		{Field: "mcp.*", Message: "No equivalent"},
		{Field: "security.replay.*", Message: "Configure separately"},
	}
	out, err := Marshal(gw, warnings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "# Warnings (manual adjustment needed):") {
		t.Error("expected warnings header")
	}
	if !strings.Contains(s, "#   - mcp.*: No equivalent") {
		t.Error("expected mcp warning in output")
	}
	if !strings.Contains(s, "#   - security.replay.*: Configure separately") {
		t.Error("expected replay warning in output")
	}
}

func TestConvert_RateLimitDisabled(t *testing.T) {
	cfg := minimalConfig()
	cfg.Security.RateLimit = config.RateLimitConfig{
		Enabled: false,
		IP:      config.IPRateConfig{PerIP: 200},
		User:    config.UserRateConfig{PerUser: 100},
	}
	gw, _, err := Convert(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gw.RateLimit != nil {
		t.Error("expected nil rateLimit when disabled")
	}
}

func TestConvert_ShutdownConfig(t *testing.T) {
	cfg := minimalConfig()
	cfg.Shutdown = config.ShutdownConfig{
		Timeout:      config.Duration{Duration: 60 * time.Second},
		DrainTimeout: config.Duration{Duration: 30 * time.Second},
	}
	gw, _, err := Convert(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gw.Server == nil {
		t.Fatal("expected server config")
	}
	if gw.Server.Graceful == nil {
		t.Fatal("expected graceful config")
	}
	if gw.Server.Graceful.Timeout != "1m0s" {
		t.Errorf("expected timeout 1m0s, got %q", gw.Server.Graceful.Timeout)
	}
	if gw.Server.Graceful.Drain != "30s" {
		t.Errorf("expected drain 30s, got %q", gw.Server.Graceful.Drain)
	}
}

func TestConvert_NoShutdownConfig(t *testing.T) {
	cfg := minimalConfig()
	// Zero-value shutdown durations
	cfg.Shutdown = config.ShutdownConfig{}
	gw, _, err := Convert(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gw.Server.Graceful != nil {
		t.Error("expected nil graceful config when shutdown durations are zero")
	}
}

func TestConvert_CardSignatureDisabled(t *testing.T) {
	cfg := minimalConfig()
	cfg.Security.CardSignature = config.CardSignatureConfig{Require: false}
	gw, _, err := Convert(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gw.TLS != nil {
		t.Error("expected nil TLS when card signature not required")
	}
}

func TestConvert_ObservabilityNoAudit(t *testing.T) {
	cfg := minimalConfig()
	cfg.Logging = config.LoggingConfig{
		Level: "debug",
		Audit: config.AuditConfig{SamplingRate: 0},
	}
	gw, _, err := Convert(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gw.Observability == nil {
		t.Fatal("expected observability config")
	}
	if gw.Observability.LogLevel != "debug" {
		t.Errorf("expected logLevel debug, got %q", gw.Observability.LogLevel)
	}
	if gw.Observability.Audit {
		t.Error("expected audit false when sampling rate is 0")
	}
}
