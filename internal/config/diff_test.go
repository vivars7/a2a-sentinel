package config

import (
	"testing"
	"time"
)

func TestDiff_IdenticalConfigs(t *testing.T) {
	cfg := &Config{
		Listen: ListenConfig{Host: "0.0.0.0", Port: 8080},
		Agents: []AgentConfig{{Name: "a", URL: "http://localhost:9000"}},
	}
	changes := Diff(cfg, cfg)
	if len(changes) != 0 {
		t.Errorf("identical configs should produce 0 changes, got %d", len(changes))
		for _, c := range changes {
			t.Logf("  change: %s old=%v new=%v", c.Field, c.OldValue, c.NewValue)
		}
	}
}

func TestDiff_AgentAddition(t *testing.T) {
	old := &Config{
		Agents: []AgentConfig{{Name: "a", URL: "http://localhost:9000"}},
	}
	new := &Config{
		Agents: []AgentConfig{
			{Name: "a", URL: "http://localhost:9000"},
			{Name: "b", URL: "http://localhost:9001"},
		},
	}
	changes := Diff(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "agents[b]" && c.OldValue == nil && c.Reloadable {
			found = true
		}
	}
	if !found {
		t.Error("expected reloadable change for agent addition 'b'")
		for _, c := range changes {
			t.Logf("  change: %s reloadable=%v", c.Field, c.Reloadable)
		}
	}
}

func TestDiff_AgentRemoval(t *testing.T) {
	old := &Config{
		Agents: []AgentConfig{
			{Name: "a", URL: "http://localhost:9000"},
			{Name: "b", URL: "http://localhost:9001"},
		},
	}
	new := &Config{
		Agents: []AgentConfig{{Name: "a", URL: "http://localhost:9000"}},
	}
	changes := Diff(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "agents[b]" && c.NewValue == nil && c.Reloadable {
			found = true
		}
	}
	if !found {
		t.Error("expected reloadable change for agent removal 'b'")
	}
}

func TestDiff_AgentURLChange(t *testing.T) {
	old := &Config{
		Agents: []AgentConfig{{Name: "a", URL: "http://localhost:9000"}},
	}
	new := &Config{
		Agents: []AgentConfig{{Name: "a", URL: "http://localhost:9999"}},
	}
	changes := Diff(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "agents[a].url" && c.Reloadable {
			found = true
			if c.OldValue != "http://localhost:9000" {
				t.Errorf("old URL = %v, want http://localhost:9000", c.OldValue)
			}
			if c.NewValue != "http://localhost:9999" {
				t.Errorf("new URL = %v, want http://localhost:9999", c.NewValue)
			}
		}
	}
	if !found {
		t.Error("expected reloadable change for agent URL")
	}
}

func TestDiff_RateLimitChanges(t *testing.T) {
	old := &Config{
		Security: SecurityConfig{
			RateLimit: RateLimitConfig{
				Enabled: true,
				IP:      IPRateConfig{PerIP: 200, Burst: 50},
			},
		},
	}
	new := &Config{
		Security: SecurityConfig{
			RateLimit: RateLimitConfig{
				Enabled: true,
				IP:      IPRateConfig{PerIP: 500, Burst: 100},
			},
		},
	}
	changes := Diff(old, new)

	reloadableCount := 0
	for _, c := range changes {
		if c.Reloadable {
			reloadableCount++
		}
	}
	if reloadableCount < 2 {
		t.Errorf("expected at least 2 reloadable changes for rate limit, got %d", reloadableCount)
	}
}

func TestDiff_PortChangeNonReloadable(t *testing.T) {
	old := &Config{Listen: ListenConfig{Port: 8080}}
	new := &Config{Listen: ListenConfig{Port: 9090}}
	changes := Diff(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "listen.port" {
			found = true
			if c.Reloadable {
				t.Error("listen.port change should NOT be reloadable")
			}
		}
	}
	if !found {
		t.Error("expected change for listen.port")
	}
}

func TestDiff_TLSChangeNonReloadable(t *testing.T) {
	old := &Config{Listen: ListenConfig{TLS: TLSConfig{CertFile: "/old/cert.pem"}}}
	new := &Config{Listen: ListenConfig{TLS: TLSConfig{CertFile: "/new/cert.pem"}}}
	changes := Diff(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "listen.tls.cert_file" {
			found = true
			if c.Reloadable {
				t.Error("listen.tls.cert_file change should NOT be reloadable")
			}
		}
	}
	if !found {
		t.Error("expected change for listen.tls.cert_file")
	}
}

func TestDiff_LoggingLevelReloadable(t *testing.T) {
	old := &Config{Logging: LoggingConfig{Level: "info"}}
	new := &Config{Logging: LoggingConfig{Level: "debug"}}
	changes := Diff(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "logging.level" {
			found = true
			if !c.Reloadable {
				t.Error("logging.level change should be reloadable")
			}
		}
	}
	if !found {
		t.Error("expected change for logging.level")
	}
}

func TestDiff_AuthModeReloadable(t *testing.T) {
	old := &Config{Security: SecurityConfig{Auth: AuthConfig{Mode: "passthrough"}}}
	new := &Config{Security: SecurityConfig{Auth: AuthConfig{Mode: "terminate"}}}
	changes := Diff(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "security.auth.mode" {
			found = true
			if !c.Reloadable {
				t.Error("security.auth.mode change should be reloadable")
			}
		}
	}
	if !found {
		t.Error("expected change for security.auth.mode")
	}
}

func TestDiff_AuditSamplingReloadable(t *testing.T) {
	old := &Config{Logging: LoggingConfig{Audit: AuditConfig{SamplingRate: 1.0}}}
	new := &Config{Logging: LoggingConfig{Audit: AuditConfig{SamplingRate: 0.5}}}
	changes := Diff(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "logging.audit.sampling_rate" {
			found = true
			if !c.Reloadable {
				t.Error("logging.audit.sampling_rate change should be reloadable")
			}
		}
	}
	if !found {
		t.Error("expected change for logging.audit.sampling_rate")
	}
}

func TestDiff_MaxConnectionsNonReloadable(t *testing.T) {
	old := &Config{Listen: ListenConfig{MaxConnections: 1000}}
	new := &Config{Listen: ListenConfig{MaxConnections: 2000}}
	changes := Diff(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "listen.max_connections" {
			found = true
			if c.Reloadable {
				t.Error("listen.max_connections change should NOT be reloadable")
			}
		}
	}
	if !found {
		t.Error("expected change for listen.max_connections")
	}
}

func TestDiff_AgentTimeoutChange(t *testing.T) {
	old := &Config{
		Agents: []AgentConfig{{Name: "a", URL: "http://localhost:9000", Timeout: Duration{30 * time.Second}}},
	}
	new := &Config{
		Agents: []AgentConfig{{Name: "a", URL: "http://localhost:9000", Timeout: Duration{60 * time.Second}}},
	}
	changes := Diff(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "agents[a].timeout" && c.Reloadable {
			found = true
		}
	}
	if !found {
		t.Error("expected reloadable change for agent timeout")
	}
}

func TestDiff_MixedReloadableAndNon(t *testing.T) {
	old := &Config{
		Listen:  ListenConfig{Port: 8080},
		Logging: LoggingConfig{Level: "info"},
	}
	new := &Config{
		Listen:  ListenConfig{Port: 9090},
		Logging: LoggingConfig{Level: "debug"},
	}
	changes := Diff(old, new)

	var reloadable, nonReloadable int
	for _, c := range changes {
		if c.Reloadable {
			reloadable++
		} else {
			nonReloadable++
		}
	}
	if reloadable < 1 {
		t.Error("expected at least 1 reloadable change")
	}
	if nonReloadable < 1 {
		t.Error("expected at least 1 non-reloadable change")
	}
}

func TestDiff_GRPCPortNonReloadable(t *testing.T) {
	old := &Config{Listen: ListenConfig{GRPCPort: 8081}}
	new := &Config{Listen: ListenConfig{GRPCPort: 9091}}
	changes := Diff(old, new)

	found := false
	for _, c := range changes {
		if c.Field == "listen.grpc_port" {
			found = true
			if c.Reloadable {
				t.Error("listen.grpc_port change should NOT be reloadable")
			}
		}
	}
	if !found {
		t.Error("expected change for listen.grpc_port")
	}
}
