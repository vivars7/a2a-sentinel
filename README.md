# a2a-sentinel

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/vivars7/a2a-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/vivars7/a2a-sentinel/actions/workflows/ci.yml)

**A lightweight, security-first A2A gateway in Go.**

Develop with sentinel, deploy with agentgateway. Zero agent code changes.

---

## Why sentinel?

a2a-sentinel is not trying to replace [agentgateway](https://github.com/solo-io/agentgateway) (the Kubernetes-native A2A+MCP data plane). Instead, it fills a different need: developers who want to add A2A security to their agents in 5 minutes, without waiting for Kubernetes setup.

| | agentgateway | a2a-sentinel |
|---|---|---|
| **For** | Platform/infra teams | Individual devs, small teams |
| **Deploy** | Kubernetes-native | Single binary, docker compose |
| **Scope** | Full data plane (A2A+MCP+LLM) | A2A security gateway |
| **Config** | Extensive YAML/API/CRD | Agent Card = your config |
| **Security** | Configurable | ON by default |
| **First request** | ~30 min (K8s setup) | ~5 min (docker compose up) |
| **Error messages** | Standard codes | Educational (hint + docs_url) |
| **Bindings** | gRPC + REST + JSON-RPC | JSON-RPC + REST + gRPC (v0.3) |
| **Management** | K8s tools | MCP server (15 tools, v0.3) |
| **Migration** | — | Zero-effort (same A2A protocol) |

---

## Features

- [x] Two-layer rate limiting (IP-based pre-auth + user-based post-auth)
- [x] Agent Card change detection (cache poisoning defense)
- [x] Authentication modes (JWT, API Key, passthrough-strict default)
- [x] HTTP + SSE proxy (no httputil.ReverseProxy)
- [x] Structured audit logging (OTel-compatible, configurable sampling)
- [x] Educational error messages (hint + docs_url for every block)
- [x] Aggregated Agent Card (merges skills from all backends)
- [x] Graceful shutdown with SSE stream draining
- [x] Health checks (/healthz, /readyz with configurable readiness modes)
- [x] Agent Card JWS signature verification
- [x] Push Notification SSRF protection
- [x] Replay attack prevention (nonce + timestamp)
- [x] Full MCP server (13 tools, 4 resources, read + write)
- [x] sentinel migrate command (-> agentgateway)
- [x] Card change approve mode (MCP-based)
- [x] Prometheus-compatible metrics endpoint (/metrics)
- [x] gRPC binding support with JSON-RPC protocol translation
- [x] Config hot-reload (SIGHUP + file watch with debounce)
- [x] Extended Prometheus metrics with histograms (prometheus/client_golang)
- [x] Helm chart for Kubernetes deployment
- [x] ABAC policy engine (IP, user, agent, method, time-based, header rules)

---

## Quick Start (5 minutes)

### Prerequisites

- Docker and Docker Compose (or Go 1.22+)

### Clone and Run

```bash
git clone https://github.com/vivars7/a2a-sentinel
cd a2a-sentinel
docker compose up -d --build
```

Wait for services to be healthy (check logs with `docker compose logs -f`).

Open **http://localhost:3000** for the interactive demo dashboard.

The setup includes two demo agents:
- **echo-agent**: Standard synchronous A2A agent
- **streaming-agent**: SSE streaming agent

### Verify Health

```bash
# Gateway health
curl http://localhost:8080/healthz
# {"status":"ok","version":"dev"}

# Readiness (all agents healthy)
curl http://localhost:8080/readyz
# {"status":"ready","healthy_agents":2,"total_agents":2}

# Aggregated Agent Card (merged from all backends)
curl http://localhost:8080/.well-known/agent.json | jq .
```

### Send Your First A2A Message

**JSON-RPC binding (echo agent):**

```bash
curl -X POST http://localhost:8080/agents/echo/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"text": "Hello from sentinel!"}],
        "messageId": "msg-1"
      }
    }
  }'
```

**Server-Sent Events (streaming agent):**

```bash
curl -N -X POST http://localhost:8080/agents/streaming/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "2",
    "method": "message/stream",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"text": "Stream test"}],
        "messageId": "msg-2"
      }
    }
  }'
```

Each chunk arrives as a separate SSE event. The gateway drains all outstanding streams on graceful shutdown.

**gRPC binding (requires grpcurl):**

```bash
grpcurl -plaintext -d '{
  "message": {
    "role": "user",
    "parts": [{"text": "Hello via gRPC!"}],
    "messageId": "msg-3"
  }
}' localhost:8443 a2a.v1.A2AService/SendMessage
```

The gRPC binding translates A2A protocol messages to/from JSON-RPC internally. Agents do not need gRPC support -- sentinel handles the translation.

---

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                   a2a-sentinel Gateway                    │
│                                                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Security │→ │ Policy   │→ │ Protocol │→ │  Router  │   │
│  │ Layer    │  │ Engine   │  │ Detector │  │          │   │
│  │ (2-tier) │  │ (ABAC)   │  │          │  │          │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│       │                                        │          │
│  ┌─────────┐  ┌──────────────┐        ┌──────────────┐    │
│  │  Audit  │  │ Agent Card   │        │    Proxy     │    │
│  │  Logger │  │ Manager      │        │ HTTP/SSE/gRPC│    │
│  │ (OTel)  │  │ (polling+agg)│        │              │    │
│  └─────────┘  └──────────────┘        └──────────────┘    │
│                                              │            │
│  ┌────────────────────┐  ┌───────────────────────────┐    │
│  │ gRPC Server (:8443)│  │ Config Hot-Reload         │    │
│  │ A2A gRPC binding   │  │ SIGHUP + fsnotify watch   │    │
│  │ ↔ JSON-RPC transl. │  │ Debounce + atomic swap    │    │
│  └────────────────────┘  └───────────────────────────┘    │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐  │
│  │ MCP Server (127.0.0.1:8081) — 15 tools             │   │
│  │ Read:  list_agents, get_agent_status,               │  │
│  │        get_aggregated_card, health_check,           │  │
│  │        get_config, get_audit_log, get_metrics       │  │
│  │ Write: update_rate_limit, reload_config,            │  │
│  │        toggle_agent, rotate_api_key,                │  │
│  │        flush_replay_cache, trigger_card_poll        │  │
│  │ Card:  list_pending_changes,                        │  │
│  │        approve_card_change, reject_card_change      │  │
│  │ Policy: list_policies, evaluate_policy              │  │
│  └─────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────┘
```

### Component Breakdown

**Security (2-layer pipeline):**
1. Pre-auth IP rate limiting (global_rate_limit on listen port)
2. Authentication (JWT, API Key, or passthrough modes)
3. Post-auth user rate limiting (per-user bucket)

**Protocol Detector:**
Identifies incoming request as JSON-RPC, REST, or Agent Card fetch based on method/path.

**Router:**
- `path-prefix`: `/agents/{name}/` → agent named `name`
- `single`: all traffic → one default agent

**Policy Engine (ABAC):**
Attribute-based access control with priority-ordered rules. Supports IP, user, agent, method, time-based, and header conditions. Rules are hot-reloadable via config reload.

**Proxy:**
- **HTTP**: Standard A2A JSON-RPC and REST binding forwarding
- **SSE**: Maintains goroutine per stream, demuxes chunks, gracefully drains on shutdown
- **gRPC**: Accepts A2A gRPC calls on a separate port, translates to/from JSON-RPC for backend agents

**Agent Card Manager:**
- Polls each agent's `/.well-known/agent.json` (configurable interval)
- Caches responses, detects changes
- Aggregates into merged card at `/agents/.well-known/agent.json`
- Validates JWS signatures if configured

**Audit Logger:**
- OTel-compatible structured JSON
- Records: timestamp, method, agent, user_id, decision (allow/block), reason, rate_limit_state
- Configurable sampling (default 100% for errors, 1% for allow)

**Health Checks:**
- `/healthz`: gateway status (startup/running/shutdown)
- `/readyz`: all agents health + gateway readiness (modes: `any_healthy`, `default_healthy`, `all_healthy`)

---

## Configuration

### Minimal Config (sentinel-demo.yaml)

```yaml
agents:
  - name: echo
    url: http://echo-agent:9000
    default: true
  - name: streaming
    url: http://streaming-agent:9001

security:
  auth:
    mode: passthrough-strict
  rate_limit:
    enabled: true

routing:
  mode: path-prefix

logging:
  level: info
  format: json
```

### Generate Config

```bash
# Development profile (loose security for testing)
./sentinel init --profile dev

# Production profile (strict security defaults)
./sentinel init --profile prod
```

### Validate Config

```bash
./sentinel validate --config sentinel.yaml
# Output: config valid
```

### gRPC Binding

```yaml
listen:
  grpc_port: 8443          # Separate port for gRPC connections

grpc:
  enabled: true
  max_message_size: 4MB     # Max gRPC message size
  reflection: true          # Enable gRPC server reflection
```

gRPC clients connect on the gRPC port. Sentinel translates A2A gRPC calls to JSON-RPC internally and forwards to backend agents over HTTP. No gRPC support is required from agents.

### Config Hot-Reload

```yaml
reload:
  enabled: true
  watch: true               # Enable fsnotify file watching
  debounce: 2s              # Debounce interval for file changes
```

Send `SIGHUP` to the sentinel process or rely on automatic file watching. Only reloadable fields (rate limits, policies, logging, agents) are updated. Non-reloadable fields (listen ports, TLS, auth mode) require a restart.

### Policy Engine (ABAC)

```yaml
security:
  policies:
    - name: block-internal-ips
      priority: 10
      effect: deny
      conditions:
        source_ip:
          cidr: ["192.168.0.0/16"]
    - name: business-hours-only
      priority: 20
      effect: deny
      conditions:
        time:
          outside: "09:00-17:00"
          timezone: "America/New_York"
    - name: restrict-agent-access
      priority: 30
      effect: deny
      conditions:
        agent: ["internal-agent"]
        user_not: ["admin@example.com"]
```

See [docs/SECURITY.md](docs/SECURITY.md) for full policy engine documentation.

### Full Schema

See `sentinel.yaml.example` for all available options including:
- **agents**: Health checks, polling intervals, timeouts, max concurrent streams
- **security.auth**: JWT issuer/audience/jwks_url, API key validation, passthrough modes
- **security.rate_limit**: IP limits, user limits, per-agent limits, cleanup intervals
- **security.replay**: Nonce tracking (memory or Redis), configurable window, nonce_source, clock_skew
- **security.push**: SSRF defense (block private networks), allowed domains, HMAC signing, dns_fail_policy
- **security.policies**: ABAC rules with IP, user, agent, method, time, header conditions
- **body_inspection**: Max body size, skip for streaming requests
- **card**: Aggregation mode, JWK file for signing
- **logging**: Audit sampling, max body log size, output format
- **grpc**: gRPC binding port, max message size, reflection
- **reload**: Hot-reload settings (watch, debounce)
- **mcp**: Port, auth token, enabled flag

---

## Security

### Authentication Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `passthrough` | Accept with or without auth headers | Development |
| `passthrough-strict` | **Default.** Require auth headers but don't validate | Strict development |
| `jwt` | Validate JWT (issuer, audience, JWKS) | Production with token issuers |
| `api-key` | Simple shared secret | Simple production |
| `none` | No auth (use only if behind trusted proxy) | Internal networks only |

All modes include a `hint` and `docs_url` in error responses to guide users toward fixes.

### Rate Limiting (2-layer)

**Pre-auth (per IP):**
- Global limit on listen port (early drop, no CPU spent on auth)
- Configured via `listen.global_rate_limit`

**Post-auth (per user):**
- Per-user bucket after authentication
- Configured via `security.rate_limit.user.per_user` and `.burst`

Both layers return 429 with remaining window:
```json
{
  "error": {
    "code": 429,
    "message": "Rate limit exceeded",
    "hint": "Current limit: 100 req/min. Wait 30s or contact admin.",
    "docs_url": "https://a2a-sentinel.dev/docs/rate-limit"
  }
}
```

### Audit Logging

All decisions (allow/block) are logged in OTel-compatible format:
```json
{
  "timestamp": "2025-02-26T12:34:56Z",
  "level": "info",
  "msg": "request_decision",
  "http_method": "POST",
  "http_target": "/agents/echo/",
  "agent_name": "echo",
  "user_id": "user-123",
  "decision": "allow",
  "reason": "rate_limit_ok",
  "rate_limit_state": {
    "user_remaining": 95,
    "user_reset_secs": 59
  }
}
```

Configurable sampling rates reduce noise in high-volume environments.

---

## Helm Chart (Kubernetes)

Deploy a2a-sentinel to Kubernetes using the included Helm chart:

```bash
# Install from local chart
helm install sentinel deploy/helm/a2a-sentinel/ \
  --namespace sentinel-system \
  --create-namespace \
  --set config.agents[0].name=echo \
  --set config.agents[0].url=http://echo-agent:9000

# Or with a values file
helm install sentinel deploy/helm/a2a-sentinel/ \
  --namespace sentinel-system \
  --create-namespace \
  -f my-values.yaml

# Upgrade
helm upgrade sentinel deploy/helm/a2a-sentinel/ \
  --namespace sentinel-system \
  -f my-values.yaml
```

The chart includes:
- Deployment with configurable replicas and resource limits
- Service for HTTP (8080) and gRPC (8443) ports
- ConfigMap for sentinel.yaml
- Optional ServiceMonitor for Prometheus scraping
- Optional Ingress resource
- Pod disruption budget for high availability

See `deploy/helm/a2a-sentinel/values.yaml` for all chart configuration options.

---

## Building from Source

### Requirements

- Go 1.22+
- git

### Build

```bash
go build -o sentinel ./cmd/sentinel
```

### Test (with race detector)

```bash
go test -race ./...
```

All code includes `_test.go` files covering happy path, error conditions, and concurrent scenarios.

### Commands

```bash
# Serve with config
./sentinel --config sentinel.yaml serve

# Validate before serving
./sentinel --config sentinel.yaml validate

# Generate config template
./sentinel init --profile dev

# Migrate config to agentgateway format
./sentinel migrate --to agentgateway --output agentgateway.yaml

# Show version
./sentinel --version

# Show help
./sentinel help
```

---

## Development

### Project Structure

```
a2a-sentinel/
├── cmd/sentinel/
│   ├── main.go              # CLI entrypoint (serve, validate, init, migrate)
│   └── main_test.go
├── proto/
│   └── a2a/v1/              # A2A gRPC service definitions (.proto)
├── gen/
│   └── a2a/v1/              # Generated Go code from proto definitions
├── internal/
│   ├── config/              # YAML parsing, validation, dev/prod profiles, hot-reload
│   ├── ctxkeys/             # context.Context key definitions
│   ├── errors/              # SentinelError type + HTTP/JSON-RPC/gRPC mapping
│   ├── health/              # /healthz, /readyz handlers
│   ├── server/              # HTTP server integration, graceful shutdown
│   ├── grpc/                # gRPC server, interceptors, JSON-RPC translation
│   ├── protocol/            # A2A types, Protocol Detector, body inspection
│   ├── security/            # Auth, rate limiting, SSRF defense, policy engine
│   ├── proxy/               # HTTP, SSE, and gRPC proxies (no ReverseProxy)
│   ├── router/              # path-prefix and single-agent routing
│   ├── agentcard/           # Agent Card polling, caching, aggregation
│   ├── audit/               # OTel-compatible audit logging, Prometheus metrics
│   └── mcpserver/           # MCP server (15 tools, read + write + card + policy)
├── deploy/
│   └── helm/a2a-sentinel/   # Helm chart for Kubernetes deployment
├── examples/
│   ├── echo-agent/          # Synchronous demo agent (Python)
│   ├── streaming-agent/     # SSE streaming demo agent (Python)
│   └── grafana/             # Grafana dashboard JSON
├── docs/
│   ├── ARCHITECTURE.md      # System architecture and request flow
│   ├── SECURITY.md          # Security model and threat defenses
│   ├── ERRORS.md            # Error catalog and troubleshooting
│   └── MIGRATION.md         # Migration guide to agentgateway
├── docker-compose.yaml      # Local development stack
├── sentinel.yaml.example    # Full configuration reference
├── CHANGELOG.md             # Version history
└── README.md                # This file
```

### TDD Workflow

All changes follow Test-Driven Development:

1. **Red**: Write test covering new behavior
2. **Green**: Implement minimum code to pass test
3. **Refactor**: Clean up, remove duplication
4. **Verify**: Run `go test -race ./...` for full suite

Example:
```bash
# Write test in internal/security/ratelimit_test.go
# Run tests until failure
go test -race ./internal/security/...

# Implement rate limiter
# Run until green
go test -race ./internal/security/...

# Verify full suite
go test -race ./...
```

### Contributing

1. Read [CONTRIBUTING.md](CONTRIBUTING.md) for coding standards
2. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture
3. Write tests first, then implementation
4. Ensure `go test -race ./...` passes
5. Keep error messages educational (include `hint` and `docs_url`)
6. Don't inject sentinel-specific headers into backend requests
7. Use `internal/ctxkeys/` for all context keys (no direct key definitions)

---

## Migration to agentgateway

When you're ready to move to production infrastructure, migrate to agentgateway (Solo.io):

**No agent code changes required.** Both sentinel and agentgateway use the same A2A protocol and expect the same Agent Card format. Your agents work with either gateway out of the box.

Use the `sentinel migrate` command to generate agentgateway-compatible config from your existing sentinel.yaml:

```bash
sentinel migrate --to agentgateway --output agentgateway.yaml
```

See [docs/MIGRATION.md](docs/MIGRATION.md) for the full migration guide.

---

## Roadmap

**v0.1**
- Core gateway (HTTP/SSE proxy)
- 2-layer rate limiting + authentication
- Agent Card caching with change detection
- Structured audit logging (OTel format)
- Health checks (/healthz, /readyz)
- MCP server (read-only, 3 tools)

**v0.2**
- Full MCP server (13 tools: read + write + card approval)
- JWS Agent Card signature verification
- SSRF protection for push notifications
- Replay attack prevention (nonce + timestamp)
- `sentinel migrate` command for agentgateway
- Card change approve mode (MCP-based workflow)
- Prometheus-compatible metrics endpoint (/metrics)
- Security integration test suite

**v0.3 (Current)**
- gRPC binding support with JSON-RPC protocol translation
- Config hot-reload (SIGHUP + fsnotify file watch with debounce)
- Extended Prometheus metrics with histograms (prometheus/client_golang)
- Grafana dashboard example
- Helm chart for Kubernetes deployment
- ABAC policy engine (IP, user, agent, method, time-based, header rules)
- Policy evaluation MCP tools
- Replay detection: nonce_source priority + timestamp validation with clock_skew (v0.3.1)
- SSRF checker: configurable dns_fail_policy for DNS failures (v0.3.1)
- Consistent HTTP 502 handling across all error mapping systems (v0.3.1)

**v1.0 (Planned)**
- OPA policy integration
- OTel SDK integration (Jaeger, Datadog)
- Multi-tenancy support
- A2A Technology Compatibility Kit (TCK) integration

---

## Support

### Troubleshooting

**Q: Gateway starts but agents show unhealthy?**
- Check agent URLs in config
- Verify agents are running and respond to `/.well-known/agent.json`
- Check `docker compose logs` for connection errors

**Q: Rate limit errors on every request?**
- Check `listen.global_rate_limit` is reasonable (default 5000/min)
- Check `security.rate_limit.user.per_user` (default 100/min)
- Look at audit logs to see which limit is triggering

**Q: SSE streams disconnecting unexpectedly?**
- Check `server.shutdown.drain_timeout` (default 15s)
- Verify backend agent keeps stream open
- Check proxy logs for timeout errors

**Q: MCP server won't start?**
- Ensure `mcp.enabled: true` in config
- Check if port 8081 is available
- MCP server only listens on 127.0.0.1 (not externally exposed)

### Documentation

- **Configuration reference**: [sentinel.yaml.example](sentinel.yaml.example)
- **Architecture & design**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Security**: [docs/SECURITY.md](docs/SECURITY.md)
- **Error reference**: [docs/ERRORS.md](docs/ERRORS.md)
- **Migration guide**: [docs/MIGRATION.md](docs/MIGRATION.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **A2A Protocol spec**: https://a2a-protocol.github.io/spec/

### Issues & Feedback

Open an issue on GitHub with:
- Config file (sanitize sensitive values)
- Error logs from `docker compose logs sentinel`
- Steps to reproduce
- Expected vs actual behavior

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- **A2A Protocol**: Linux Foundation (Google, Microsoft, AWS, Salesforce, SAP)
- **Built with**: [Claude Code](https://claude.ai) — AI-assisted development
- **Inspiration**: [agentgateway](https://github.com/solo-io/agentgateway) (agentgateway is the production platform; sentinel is the developer's gateway)

---

**Made with intention for developers who want security by default, not by deployment.**
