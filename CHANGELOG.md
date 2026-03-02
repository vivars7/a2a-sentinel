# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.3.3] - 2026-03-02

### Fixed
- Replay detection: `require` mode now blocks requests with missing nonce (returns 400)
- Replay detection: timestamp validation changed from symmetric (`|now-ts| > window+clock_skew`) to asymmetric (past checks against `window`, future checks against `clock_skew`) — aligns with industry standard (AWS Sig V4, OAuth 1.0, Stripe)
- Replay detection: body read errors in `require` mode now return 400 instead of silently passing through
- Replay detection: nonce TTL now uses `time.Now()` instead of request timestamp to prevent future-timestamp TTL inflation

### Changed
- Integration tests updated with JSON-RPC request bodies to satisfy `require` nonce policy

## [0.3.1] - 2026-02-27

### Fixed
- Replay detection: nonce source priority (X-Sentinel-Nonce header > JSON-RPC id) with `nonce_source` config (auto/header/jsonrpc-id)
- Replay detection: timestamp validation via X-Sentinel-Timestamp header (RFC3339 + Unix epoch) with `clock_skew` tolerance
- Replay detection: warn mode never blocks requests (always passes through)
- Replay detection: body inspection limit increased to 1MB
- SSRF checker: configurable `dns_fail_policy` (block/allow) for DNS resolution failures
- gRPC error mapping: added HTTP 502 → gRPC Unavailable mapping
- gRPC error messages: preserve hint and docs_url for educational errors
- JSON-RPC error mapping: added HTTP 502 → -32603 mapping
- JWS stub: removed noisy per-request log.Println from pipeline middleware

### Changed
- Dev/prod profiles updated with `nonce_source`, `clock_skew`, `dns_fail_policy`, and `grpc_port` fields
- All three error mapping systems (HTTP/JSON-RPC/gRPC) now consistently handle HTTP 502

### Added
- SSRF test suite (`internal/security/ssrf_test.go`)
- gRPC interceptor, error mapping, and context merge tests
- Config validation for `nonce_source` and `dns_fail_policy` fields

## [0.3.0] - 2026-02-27

### Added
- gRPC binding support with JSON-RPC protocol translation (`internal/grpc/`, `proto/`)
- Config hot-reload via SIGHUP signal and fsnotify file watch with debounce (`internal/config/reload.go`)
- Extended Prometheus metrics with proper histograms using prometheus/client_golang (`internal/audit/prometheus.go`)
- Grafana dashboard example (`examples/grafana/sentinel-dashboard.json`)
- Helm chart for Kubernetes deployment (`deploy/helm/a2a-sentinel/`)
- ABAC policy engine with IP, user, agent, method, time-based, and header rules (`internal/security/policy.go`)
- Policy evaluation MCP tools: `list_policies`, `evaluate_policy`
- gRPC-specific Prometheus metrics (grpc_requests_total, grpc_request_duration_seconds)
- Config reload metrics and timestamps (config_reload_total, config_last_reload_timestamp)
- Security block reason tracking metrics (security_blocks_total by reason)
- Upstream latency histogram metrics (upstream_request_duration_seconds)
- Build info metric (build_info with version, go_version, commit labels)
- gRPC health checking protocol support
- Separate gRPC listen port configuration (`listen.grpc_port`)

### Changed
- Metrics endpoint now uses prometheus/client_golang instead of hand-rolled exposition format
- Prometheus metrics expanded from 6 to 15+ metric families
- Configuration system now separates reloadable vs non-reloadable fields
- Security pipeline now includes PolicyGuard stage after authentication

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
