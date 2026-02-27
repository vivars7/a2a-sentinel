package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Validate checks the configuration for errors. It collects ALL errors
// rather than stopping at the first one, returning them as a joined message.
func Validate(cfg *Config) error {
	var errs []string

	// ── Agents ──
	if len(cfg.Agents) == 0 {
		errs = append(errs, "agents list must not be empty")
	}

	defaultCount := 0
	for i, a := range cfg.Agents {
		if a.Name == "" {
			errs = append(errs, fmt.Sprintf("agents[%d]: name is required", i))
		}
		if a.URL == "" {
			errs = append(errs, fmt.Sprintf("agents[%d]: url is required", i))
		}
		if a.Default {
			defaultCount++
		}
		if a.PollInterval.Duration < 0 {
			errs = append(errs, fmt.Sprintf("agents[%d]: poll_interval must be positive", i))
		}
		if a.Timeout.Duration < 0 {
			errs = append(errs, fmt.Sprintf("agents[%d]: timeout must be positive", i))
		}
		if a.GRPCURL != "" {
			if u, err := url.Parse(a.GRPCURL); err != nil || u.Host == "" {
				errs = append(errs, fmt.Sprintf("agents[%d]: grpc_url must be a valid URL (got %q)", i, a.GRPCURL))
			}
		}
		if !isValidCardChangePolicy(a.CardChangePolicy) {
			errs = append(errs, fmt.Sprintf("agents[%d]: card_change_policy must be one of: auto, alert, approve (got %q)", i, a.CardChangePolicy))
		}
	}
	if defaultCount > 1 {
		errs = append(errs, fmt.Sprintf("at most one agent can be default (found %d)", defaultCount))
	}

	// ── Ports ──
	if cfg.Listen.Port < 1 || cfg.Listen.Port > 65535 {
		errs = append(errs, fmt.Sprintf("listen.port must be 1-65535 (got %d)", cfg.Listen.Port))
	}
	if cfg.MCP.Port < 1 || cfg.MCP.Port > 65535 {
		errs = append(errs, fmt.Sprintf("mcp.port must be 1-65535 (got %d)", cfg.MCP.Port))
	}
	if cfg.Listen.GRPCPort != 0 && (cfg.Listen.GRPCPort < 1 || cfg.Listen.GRPCPort > 65535) {
		errs = append(errs, fmt.Sprintf("listen.grpc_port must be 0 (disabled) or 1-65535 (got %d)", cfg.Listen.GRPCPort))
	}
	if cfg.Listen.GRPCPort != 0 && cfg.Listen.GRPCPort == cfg.Listen.Port {
		errs = append(errs, fmt.Sprintf("listen.grpc_port must differ from listen.port (both %d)", cfg.Listen.GRPCPort))
	}

	// ── Connection limits ──
	if cfg.Listen.MaxConnections < 1 {
		errs = append(errs, fmt.Sprintf("listen.max_connections must be positive (got %d)", cfg.Listen.MaxConnections))
	}
	if cfg.Listen.GlobalRateLimit < 1 {
		errs = append(errs, fmt.Sprintf("listen.global_rate_limit must be positive (got %d)", cfg.Listen.GlobalRateLimit))
	}

	// ── Auth mode ──
	if !isValidAuthMode(cfg.Security.Auth.Mode) {
		errs = append(errs, fmt.Sprintf("security.auth.mode must be one of: passthrough, passthrough-strict, terminate (got %q)", cfg.Security.Auth.Mode))
	}

	// ── Routing mode ──
	if !isValidRoutingMode(cfg.Routing.Mode) {
		errs = append(errs, fmt.Sprintf("routing.mode must be one of: path-prefix, single (got %q)", cfg.Routing.Mode))
	}

	// ── Readiness mode ──
	if !isValidReadinessMode(cfg.Health.ReadinessMode) {
		errs = append(errs, fmt.Sprintf("health.readiness_mode must be one of: any_healthy, default_healthy, all_healthy (got %q)", cfg.Health.ReadinessMode))
	}

	// ── Card mode ──
	if !isValidCardMode(cfg.Card.Mode) {
		errs = append(errs, fmt.Sprintf("card.mode must be one of: gateway, passthrough (got %q)", cfg.Card.Mode))
	}

	// ── Nonce policy ──
	if !isValidNoncePolicy(cfg.Security.Replay.NoncePolicy) {
		errs = append(errs, fmt.Sprintf("security.replay.nonce_policy must be one of: warn, require (got %q)", cfg.Security.Replay.NoncePolicy))
	}

	// ── TLS files ──
	if cfg.Listen.TLS.CertFile != "" {
		if _, err := os.Stat(cfg.Listen.TLS.CertFile); err != nil {
			errs = append(errs, fmt.Sprintf("listen.tls.cert_file: %v", err))
		}
	}
	if cfg.Listen.TLS.KeyFile != "" {
		if _, err := os.Stat(cfg.Listen.TLS.KeyFile); err != nil {
			errs = append(errs, fmt.Sprintf("listen.tls.key_file: %v", err))
		}
	}

	// ── Sampling rates ──
	if cfg.Logging.Audit.SamplingRate < 0 || cfg.Logging.Audit.SamplingRate > 1.0 {
		errs = append(errs, fmt.Sprintf("logging.audit.sampling_rate must be between 0.0 and 1.0 (got %f)", cfg.Logging.Audit.SamplingRate))
	}
	if cfg.Logging.Audit.ErrorSamplingRate < 0 || cfg.Logging.Audit.ErrorSamplingRate > 1.0 {
		errs = append(errs, fmt.Sprintf("logging.audit.error_sampling_rate must be between 0.0 and 1.0 (got %f)", cfg.Logging.Audit.ErrorSamplingRate))
	}

	if len(errs) > 0 {
		return fmt.Errorf("configuration errors:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

func isValidAuthMode(m string) bool {
	switch m {
	case "passthrough", "passthrough-strict", "terminate":
		return true
	}
	return false
}

func isValidRoutingMode(m string) bool {
	switch m {
	case "path-prefix", "single":
		return true
	}
	return false
}

func isValidReadinessMode(m string) bool {
	switch m {
	case "any_healthy", "default_healthy", "all_healthy":
		return true
	}
	return false
}

func isValidCardMode(m string) bool {
	switch m {
	case "gateway", "passthrough":
		return true
	}
	return false
}

func isValidCardChangePolicy(p string) bool {
	switch p {
	case "auto", "alert", "approve":
		return true
	}
	return false
}

func isValidNoncePolicy(p string) bool {
	switch p {
	case "warn", "require":
		return true
	}
	return false
}
