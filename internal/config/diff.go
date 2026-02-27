package config

import (
	"fmt"
	"reflect"
)

// Change describes a single configuration field that differs between two configs.
type Change struct {
	Field      string      // dot-separated field path (e.g., "security.rate_limit.ip.per_ip")
	OldValue   interface{} // previous value
	NewValue   interface{} // new value
	Reloadable bool        // whether this change can be applied without restart
}

// Diff compares two Config values and returns a list of changes.
// Each change is annotated with whether it is reloadable at runtime.
func Diff(old, new *Config) []Change {
	var changes []Change

	// ── Non-reloadable: listen ──
	diffField(&changes, "listen.host", old.Listen.Host, new.Listen.Host, false)
	diffField(&changes, "listen.port", old.Listen.Port, new.Listen.Port, false)
	diffField(&changes, "listen.grpc_port", old.Listen.GRPCPort, new.Listen.GRPCPort, false)
	diffField(&changes, "listen.max_connections", old.Listen.MaxConnections, new.Listen.MaxConnections, false)
	diffField(&changes, "listen.global_rate_limit", old.Listen.GlobalRateLimit, new.Listen.GlobalRateLimit, false)
	diffField(&changes, "listen.tls.cert_file", old.Listen.TLS.CertFile, new.Listen.TLS.CertFile, false)
	diffField(&changes, "listen.tls.key_file", old.Listen.TLS.KeyFile, new.Listen.TLS.KeyFile, false)
	diffStringSlice(&changes, "listen.trusted_proxies", old.Listen.TrustedProxies, new.Listen.TrustedProxies, false)

	// ── Non-reloadable: external_url ──
	diffField(&changes, "external_url", old.ExternalURL, new.ExternalURL, false)

	// ── Non-reloadable: MCP ──
	diffField(&changes, "mcp.enabled", old.MCP.Enabled, new.MCP.Enabled, false)
	diffField(&changes, "mcp.host", old.MCP.Host, new.MCP.Host, false)
	diffField(&changes, "mcp.port", old.MCP.Port, new.MCP.Port, false)

	// ── Reloadable: agents ──
	diffAgents(&changes, old.Agents, new.Agents)

	// ── Reloadable: security.auth.mode ──
	diffField(&changes, "security.auth.mode", old.Security.Auth.Mode, new.Security.Auth.Mode, true)
	diffField(&changes, "security.auth.allow_unauthenticated", old.Security.Auth.AllowUnauthenticated, new.Security.Auth.AllowUnauthenticated, true)

	// ── Reloadable: security.rate_limit ──
	diffField(&changes, "security.rate_limit.enabled", old.Security.RateLimit.Enabled, new.Security.RateLimit.Enabled, true)
	diffField(&changes, "security.rate_limit.ip.per_ip", old.Security.RateLimit.IP.PerIP, new.Security.RateLimit.IP.PerIP, true)
	diffField(&changes, "security.rate_limit.ip.burst", old.Security.RateLimit.IP.Burst, new.Security.RateLimit.IP.Burst, true)
	diffField(&changes, "security.rate_limit.ip.cleanup_interval", old.Security.RateLimit.IP.CleanupInterval.Duration, new.Security.RateLimit.IP.CleanupInterval.Duration, true)
	diffField(&changes, "security.rate_limit.user.per_user", old.Security.RateLimit.User.PerUser, new.Security.RateLimit.User.PerUser, true)
	diffField(&changes, "security.rate_limit.user.burst", old.Security.RateLimit.User.Burst, new.Security.RateLimit.User.Burst, true)
	diffField(&changes, "security.rate_limit.user.cleanup_interval", old.Security.RateLimit.User.CleanupInterval.Duration, new.Security.RateLimit.User.CleanupInterval.Duration, true)
	diffField(&changes, "security.rate_limit.per_agent", old.Security.RateLimit.PerAgent, new.Security.RateLimit.PerAgent, true)

	// ── Reloadable: security.policies (card_signature, replay, push) ──
	diffField(&changes, "security.card_signature.require", old.Security.CardSignature.Require, new.Security.CardSignature.Require, true)
	diffStringSlice(&changes, "security.card_signature.trusted_jwks_urls", old.Security.CardSignature.TrustedJWKSURLs, new.Security.CardSignature.TrustedJWKSURLs, true)
	diffField(&changes, "security.card_signature.cache_ttl", old.Security.CardSignature.CacheTTL.Duration, new.Security.CardSignature.CacheTTL.Duration, true)
	diffField(&changes, "security.replay.enabled", old.Security.Replay.Enabled, new.Security.Replay.Enabled, true)
	diffField(&changes, "security.replay.window", old.Security.Replay.Window.Duration, new.Security.Replay.Window.Duration, true)
	diffField(&changes, "security.replay.nonce_policy", old.Security.Replay.NoncePolicy, new.Security.Replay.NoncePolicy, true)
	diffField(&changes, "security.push.block_private_networks", old.Security.Push.BlockPrivateNetworks, new.Security.Push.BlockPrivateNetworks, true)
	diffField(&changes, "security.push.require_https", old.Security.Push.RequireHTTPS, new.Security.Push.RequireHTTPS, true)
	diffField(&changes, "security.push.require_challenge", old.Security.Push.RequireChallenge, new.Security.Push.RequireChallenge, true)
	diffStringSlice(&changes, "security.push.allowed_domains", old.Security.Push.AllowedDomains, new.Security.Push.AllowedDomains, true)

	// ── Reloadable: logging ──
	diffField(&changes, "logging.level", old.Logging.Level, new.Logging.Level, true)
	diffField(&changes, "logging.format", old.Logging.Format, new.Logging.Format, true)
	diffField(&changes, "logging.audit.sampling_rate", old.Logging.Audit.SamplingRate, new.Logging.Audit.SamplingRate, true)
	diffField(&changes, "logging.audit.error_sampling_rate", old.Logging.Audit.ErrorSamplingRate, new.Logging.Audit.ErrorSamplingRate, true)
	diffField(&changes, "logging.audit.max_body_log_size", old.Logging.Audit.MaxBodyLogSize, new.Logging.Audit.MaxBodyLogSize, true)

	// ── Non-reloadable: routing, card, health, body_inspection, shutdown ──
	diffField(&changes, "routing.mode", old.Routing.Mode, new.Routing.Mode, false)
	diffField(&changes, "card.mode", old.Card.Mode, new.Card.Mode, false)
	diffField(&changes, "health.readiness_mode", old.Health.ReadinessMode, new.Health.ReadinessMode, false)
	diffField(&changes, "body_inspection.max_size", old.BodyInspection.MaxSize, new.BodyInspection.MaxSize, false)
	diffField(&changes, "shutdown.timeout", old.Shutdown.Timeout.Duration, new.Shutdown.Timeout.Duration, false)
	diffField(&changes, "shutdown.drain_timeout", old.Shutdown.DrainTimeout.Duration, new.Shutdown.DrainTimeout.Duration, false)

	return changes
}

// diffField appends a Change if old != new using reflect.DeepEqual for comparison.
func diffField(changes *[]Change, field string, oldVal, newVal interface{}, reloadable bool) {
	if !reflect.DeepEqual(oldVal, newVal) {
		*changes = append(*changes, Change{
			Field:      field,
			OldValue:   oldVal,
			NewValue:   newVal,
			Reloadable: reloadable,
		})
	}
}

// diffStringSlice compares two string slices and appends a Change if they differ.
func diffStringSlice(changes *[]Change, field string, oldVal, newVal []string, reloadable bool) {
	if !reflect.DeepEqual(oldVal, newVal) {
		*changes = append(*changes, Change{
			Field:      field,
			OldValue:   oldVal,
			NewValue:   newVal,
			Reloadable: reloadable,
		})
	}
}

// diffAgents compares agent lists and produces per-agent changes.
// Agent additions, removals, and URL/setting changes are all reloadable.
func diffAgents(changes *[]Change, oldAgents, newAgents []AgentConfig) {
	oldMap := make(map[string]AgentConfig, len(oldAgents))
	for _, a := range oldAgents {
		oldMap[a.Name] = a
	}
	newMap := make(map[string]AgentConfig, len(newAgents))
	for _, a := range newAgents {
		newMap[a.Name] = a
	}

	// Detect removed agents
	for name := range oldMap {
		if _, exists := newMap[name]; !exists {
			*changes = append(*changes, Change{
				Field:      fmt.Sprintf("agents[%s]", name),
				OldValue:   oldMap[name],
				NewValue:   nil,
				Reloadable: true,
			})
		}
	}

	// Detect added agents
	for name := range newMap {
		if _, exists := oldMap[name]; !exists {
			*changes = append(*changes, Change{
				Field:      fmt.Sprintf("agents[%s]", name),
				OldValue:   nil,
				NewValue:   newMap[name],
				Reloadable: true,
			})
		}
	}

	// Detect modified agents
	for name, oldAgent := range oldMap {
		newAgent, exists := newMap[name]
		if !exists {
			continue
		}
		if oldAgent.URL != newAgent.URL {
			*changes = append(*changes, Change{
				Field:      fmt.Sprintf("agents[%s].url", name),
				OldValue:   oldAgent.URL,
				NewValue:   newAgent.URL,
				Reloadable: true,
			})
		}
		if oldAgent.Timeout.Duration != newAgent.Timeout.Duration {
			*changes = append(*changes, Change{
				Field:      fmt.Sprintf("agents[%s].timeout", name),
				OldValue:   oldAgent.Timeout.Duration,
				NewValue:   newAgent.Timeout.Duration,
				Reloadable: true,
			})
		}
		if oldAgent.MaxStreams != newAgent.MaxStreams {
			*changes = append(*changes, Change{
				Field:      fmt.Sprintf("agents[%s].max_streams", name),
				OldValue:   oldAgent.MaxStreams,
				NewValue:   newAgent.MaxStreams,
				Reloadable: true,
			})
		}
		if oldAgent.Default != newAgent.Default {
			*changes = append(*changes, Change{
				Field:      fmt.Sprintf("agents[%s].default", name),
				OldValue:   oldAgent.Default,
				NewValue:   newAgent.Default,
				Reloadable: true,
			})
		}
		if oldAgent.CardChangePolicy != newAgent.CardChangePolicy {
			*changes = append(*changes, Change{
				Field:      fmt.Sprintf("agents[%s].card_change_policy", name),
				OldValue:   oldAgent.CardChangePolicy,
				NewValue:   newAgent.CardChangePolicy,
				Reloadable: true,
			})
		}
		if oldAgent.PollInterval.Duration != newAgent.PollInterval.Duration {
			*changes = append(*changes, Change{
				Field:      fmt.Sprintf("agents[%s].poll_interval", name),
				OldValue:   oldAgent.PollInterval.Duration,
				NewValue:   newAgent.PollInterval.Duration,
				Reloadable: true,
			})
		}
	}
}
