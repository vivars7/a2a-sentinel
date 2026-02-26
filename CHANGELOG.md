# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.2.0] - 2026-02-27

### Added
- Agent Card JWS signature verification with JWKS auto-refresh cache (`internal/agentcard/jws.go`)
- Push Notification SSRF protection — blocks private network URLs, domain allowlist, HTTPS enforcement (`internal/security/ssrf.go`)
- Replay attack prevention — nonce + timestamp tracking with warn/require policies (`internal/security/replay.go`)
- Full MCP server: 13 tools (7 read + 3 write + 3 card approval), 4 resources (`internal/mcpserver/`)
- `sentinel migrate` command — converts sentinel.yaml to agentgateway format (`internal/migrate/`, `cmd/sentinel/`)
- Card change approve mode — pending store with MCP-based manual approval workflow (`internal/agentcard/pending.go`)
- Security integration test suite — 8 end-to-end pipeline tests (`internal/security/security_integration_test.go`)
- Prometheus-compatible metrics endpoint at `/metrics` with zero dependencies (`internal/audit/metrics.go`)
- New MCP read tools: `get_config`, `get_audit_log`, `get_metrics`
- New MCP write tools: `update_rate_limit`, `reload_config`, `toggle_agent`, `rotate_api_key`, `flush_replay_cache`, `trigger_card_poll`
- New MCP card approval tools: `list_pending_changes`, `approve_card_change`, `reject_card_change`
- New error codes: `ErrCardSignatureInvalid`, `ErrMCPUnauthorized`, `ErrCardChangePending`
- CHANGELOG.md

### Changed
- MCP server upgraded from read-only (3 tools) to full read/write (13 tools, 4 resources)
- Security pipeline: JWSVerifier, ReplayDetector, and SSRFChecker are now fully implemented (previously stubs)
- `security.replay.enabled` now defaults to `true`
- Agent Card Manager accepts `CardSignatureConfig` for JWS verification during polling

## [0.1.0] - 2026-02-26

### Added
- Core A2A gateway with HTTP + SSE proxy (no httputil.ReverseProxy)
- 2-layer rate limiting (IP pre-auth + user post-auth)
- Authentication modes (JWT, API Key, passthrough-strict default)
- Agent Card polling, caching, change detection, aggregation
- Structured audit logging (OTel-compatible field names)
- Health checks (`/healthz`, `/readyz` with configurable readiness modes: any_healthy, default_healthy, all_healthy)
- MCP server (read-only, 3 tools: list_agents, get_agent_status, health_check)
- Interactive demo dashboard (localhost:3000)
- Educational error messages (hint + docs_url for every block)
- Graceful shutdown with SSE stream draining
- Protocol detection (JSON-RPC, REST, SSE)
- Hop-by-hop header removal for proxy correctness
- Body inspection via InspectAndRewind pattern
- Trusted proxy support for accurate client IP extraction
- Dev/prod configuration profiles (`sentinel init --profile dev|prod`)
- Configuration validation (`sentinel validate`)
- LimitedListener for connection limit enforcement
- Per-agent stream limits to prevent resource exhaustion
- Agent Card change detection with alert/auto policies
- Configurable audit sampling (separate rates for allow/block decisions)
