// Package migrate handles configuration migration to agentgateway format.
package migrate

import (
	"fmt"

	"github.com/vivars7/a2a-sentinel/internal/config"
	"gopkg.in/yaml.v3"
)

// AgentGatewayConfig represents the agentgateway configuration format.
type AgentGatewayConfig struct {
	Backends      []GWBackend      `yaml:"backends"`
	Auth          *GWAuth          `yaml:"auth,omitempty"`
	RateLimit     *GWRateLimit     `yaml:"rateLimit,omitempty"`
	SSRF          *GWSSRF          `yaml:"ssrf,omitempty"`
	Routing       *GWRouting       `yaml:"routing,omitempty"`
	Server        *GWServer        `yaml:"server,omitempty"`
	Observability *GWObservability `yaml:"observability,omitempty"`
	TLS           *GWTLS           `yaml:"tls,omitempty"`
}

// GWBackend represents a backend agent in agentgateway format.
type GWBackend struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
	Default bool   `yaml:"default,omitempty"`
}

// GWAuth represents the authentication policy in agentgateway format.
type GWAuth struct {
	Policy string `yaml:"policy"`
}

// GWRateLimit represents rate limiting configuration in agentgateway format.
type GWRateLimit struct {
	PerIP   int `yaml:"perIP,omitempty"`
	PerUser int `yaml:"perUser,omitempty"`
}

// GWSSRF represents SSRF protection configuration in agentgateway format.
type GWSSRF struct {
	BlockPrivate bool `yaml:"blockPrivate"`
}

// GWRouting represents routing configuration in agentgateway format.
type GWRouting struct {
	Strategy string `yaml:"strategy"`
}

// GWServer represents server configuration in agentgateway format.
type GWServer struct {
	Port     int         `yaml:"port"`
	Graceful *GWGraceful `yaml:"graceful,omitempty"`
}

// GWGraceful represents graceful shutdown configuration in agentgateway format.
type GWGraceful struct {
	Timeout string `yaml:"timeout,omitempty"`
	Drain   string `yaml:"drain,omitempty"`
}

// GWObservability represents observability configuration in agentgateway format.
type GWObservability struct {
	LogLevel string `yaml:"logLevel,omitempty"`
	Audit    bool   `yaml:"audit,omitempty"`
}

// GWTLS represents TLS configuration in agentgateway format.
type GWTLS struct {
	VerifyCards bool `yaml:"verifyCards,omitempty"`
}

// Warning represents a field that could not be automatically migrated.
type Warning struct {
	Field   string
	Message string
}

// Convert transforms a sentinel config into agentgateway format.
// Returns the converted config, a list of warnings for fields that need
// manual adjustment, and any error encountered during conversion.
func Convert(cfg *config.Config) (*AgentGatewayConfig, []Warning, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("config is nil")
	}

	var warnings []Warning
	gw := &AgentGatewayConfig{}

	// Map agents to backends.
	for _, agent := range cfg.Agents {
		gw.Backends = append(gw.Backends, GWBackend{
			Name:    agent.Name,
			Address: agent.URL,
			Default: agent.Default,
		})
	}

	// Map security.auth to auth.
	gw.Auth = &GWAuth{Policy: mapAuthMode(cfg.Security.Auth.Mode)}

	// Map security.rate_limit to rateLimit (only if enabled).
	if cfg.Security.RateLimit.Enabled {
		gw.RateLimit = &GWRateLimit{
			PerIP:   cfg.Security.RateLimit.IP.PerIP,
			PerUser: cfg.Security.RateLimit.User.PerUser,
		}
	}

	// Map security.push to ssrf.
	gw.SSRF = &GWSSRF{BlockPrivate: cfg.Security.Push.BlockPrivateNetworks}

	// Map routing to routing.
	gw.Routing = &GWRouting{Strategy: cfg.Routing.Mode}

	// Map listen to server.
	gw.Server = &GWServer{Port: cfg.Listen.Port}
	if cfg.Shutdown.Timeout.Duration > 0 || cfg.Shutdown.DrainTimeout.Duration > 0 {
		gw.Server.Graceful = &GWGraceful{
			Timeout: cfg.Shutdown.Timeout.Duration.String(),
			Drain:   cfg.Shutdown.DrainTimeout.Duration.String(),
		}
	}

	// Map logging to observability.
	gw.Observability = &GWObservability{
		LogLevel: cfg.Logging.Level,
		Audit:    cfg.Logging.Audit.SamplingRate > 0,
	}

	// Map card_signature to tls.
	if cfg.Security.CardSignature.Require {
		gw.TLS = &GWTLS{VerifyCards: true}
	}

	// Warnings for unmappable fields.
	if cfg.MCP.Enabled {
		warnings = append(warnings, Warning{
			Field:   "mcp.*",
			Message: "MCP server has no agentgateway equivalent. Remove or implement separately.",
		})
	}
	if cfg.Security.Replay.Enabled {
		warnings = append(warnings, Warning{
			Field:   "security.replay.*",
			Message: "Replay attack prevention has no agentgateway equivalent. Configure separately.",
		})
	}
	if cfg.BodyInspection.MaxSize > 0 {
		warnings = append(warnings, Warning{
			Field:   "body_inspection.*",
			Message: "Body inspection settings have no agentgateway equivalent. Review gateway defaults.",
		})
	}

	return gw, warnings, nil
}

// mapAuthMode converts sentinel auth mode names to agentgateway policy names.
func mapAuthMode(mode string) string {
	switch mode {
	case "passthrough", "passthrough-strict":
		return "passthrough"
	case "terminate":
		return "enforce"
	default:
		return mode
	}
}

// Marshal converts the AgentGatewayConfig to YAML with migration comments.
// The output includes a header comment indicating the file was auto-generated,
// plus any warnings that require manual attention.
func Marshal(gw *AgentGatewayConfig, warnings []Warning) ([]byte, error) {
	data, err := yaml.Marshal(gw)
	if err != nil {
		return nil, fmt.Errorf("marshalling agentgateway config: %w", err)
	}

	header := "# Migrated from sentinel configuration\n"
	header += "# Generated by: sentinel migrate\n"
	if len(warnings) > 0 {
		header += "#\n# Warnings (manual adjustment needed):\n"
		for _, w := range warnings {
			header += fmt.Sprintf("#   - %s: %s\n", w.Field, w.Message)
		}
	}
	header += "\n"

	return append([]byte(header), data...), nil
}
