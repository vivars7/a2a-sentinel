# a2a-sentinel Architecture

a2a-sentinel is a lightweight, security-first A2A (Agent-to-Agent) protocol gateway written in Go. This document describes the system architecture, components, request flow, and design principles.

**Table of Contents:**
1. [High-Level Overview](#high-level-overview)
2. [Request Flow](#request-flow)
3. [Component Overview](#component-overview)
4. [Security Pipeline](#security-pipeline)
5. [Proxy Architecture](#proxy-architecture)
6. [Metrics Endpoint](#metrics-endpoint)
7. [Configuration System](#configuration-system)
8. [CLI Subcommands](#cli-subcommands)
9. [Design Principles](#design-principles)
10. [Graceful Shutdown](#graceful-shutdown)

---

## High-Level Overview

### System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                          Client Request                          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Sentinel Security Gateway                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 1. Protocol Detection                                      │ │
│  │    (JSON-RPC vs REST vs SSE)                              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                               │                                  │
│                               ▼                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 2. Security Pipeline (2-Layer)                             │ │
│  │                                                             │ │
│  │   Pre-Auth:  Global Rate Limit → IP Rate Limit            │ │
│  │   Auth:      JWT / API Key / Passthrough                  │ │
│  │   Post-Auth: User Rate Limit                              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                               │                                  │
│                               ▼                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 3. Router                                                  │ │
│  │    (Path-prefix or Single agent routing)                  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                               │                                  │
│                               ▼                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 4. Proxy                                                   │ │
│  │    HTTP Forward / SSE Streaming (no httputil.ReverseProxy)│ │
│  └────────────────────────────────────────────────────────────┘ │
│                               │                                  │
│                               ▼                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 5. Audit Logging (OTel-compatible)                         │ │
│  │    All decisions recorded with structured fields           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Backend Agent(s)                                │
│  (echo, streaming, or any A2A-compliant service)              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Request Flow

### Detailed Step-by-Step for a JSON-RPC Request

```
1. Client sends POST /agents/echo/
   Content-Type: application/json
   {
     "jsonrpc": "2.0",
     "id": "1",
     "method": "message/send",
     "params": { "message": {...} }
   }

2. LimitedListener accepts connection
   → Or rejects if at max_connections limit
   → Context injected with client IP (trusted_proxies aware)

3. Global Rate Limiter checks
   → Allows only N requests/sec across all clients
   → If exceeded: 429 error with hint + docs_url
   → Drops request before any CPU-intensive work

4. IP Rate Limiter checks (Pre-Auth)
   → Allows N requests/sec per client IP
   → If exceeded: 429 error
   → Per-IP limiter uses time.ticker for cleanup

5. Protocol Detector identifies JSON-RPC
   → Reads request body without consuming it (InspectAndRewind)
   → Sets context key: ctxkeys.ProtocolKey = "jsonrpc"

6. Authentication Middleware validates credentials
   → Checks configured auth mode:
      - "passthrough": accepts any request
      - "passthrough-strict": requires valid subject header or JWT
      - "jwt": validates JWT from Authorization header
      - "api-key": validates X-API-Key header
      - "none": blocks all requests
   → On success: injects ctxkeys.AuthInfo(subject, verified)
   → On failure: 401/403 with educational error

7. User Rate Limiter checks (Post-Auth)
   → Allows M requests/sec per authenticated subject
   → Optional per-agent rate limit override
   → If exceeded: 429 error

8. Router resolves agent target
   → Mode = "path-prefix": extracts agent name from /agents/{name}/
   → Mode = "single": uses configured default agent
   → Checks agent health via Agent Card Manager
   → If unhealthy: 503 error

9. Proxy routes to backend
   → For SSE: SSEProxy handles streaming
   → For JSON-RPC/REST: HTTPProxy handles request-response
   → Removes hop-by-hop headers (Connection, Keep-Alive, etc.)
   → Does NOT inject sentinel-specific headers (Zero Agent Dependency)
   → Sets X-Forwarded-For, X-Forwarded-Proto for client context

10. Response passes back
    → Hop-by-hop headers stripped from response
    → Status code copied to client
    → Body streamed to client

11. Audit Logger records decision
    → Subject, action, decision, timestamp, agent name, status code
    → Configurable sampling (e.g., sample 1:1000 requests)
    → JSON structured format (OTel compatible)
```

---

## Component Overview

### `config/` — Configuration Loading and Validation

Handles YAML configuration parsing, defaults, and validation.

**Key types:**
- `Config` — Root configuration struct
- `AgentConfig` — Per-agent configuration (URL, health check interval, security overrides)
- `SecurityConfig` — Authentication and rate limiting settings
- `BodyInspectionConfig` — Body inspection policies per protocol

**Key files:**
- `config.go` — Type definitions
- `defaults.go` — Applies default values
- `validate.go` — Configuration constraints checking
- `profiles.go` — Dev/Prod profiles (via `sentinel init --profile`)

**Flow:**
```
sentinel.yaml → config.Load() → YAML unmarshaling → applyDefaults()
                                                    → validate()
                                                    → Config struct
```

### `ctxkeys/` — Centralized Context Keys

All context.Context keys defined in one place to prevent accidental collisions.

**Key types:**
- `AuthInfo` — Authentication result (Subject, SubjectVerified flag, Scope)
- Keys for ProtocolType, ClientIP, RequestID, etc.

**Usage pattern:**
```go
authInfo, ok := ctxkeys.AuthInfoFrom(ctx)
newCtx := ctxkeys.WithAuthInfo(ctx, authInfo)
```

### `errors/` — Sentinel Error System

All errors returned to clients are `SentinelError` with structured fields.

**Key types:**
- `SentinelError` — Base error type with Code, Message, Hint, DocsURL
- Helper functions for JSON-RPC and HTTP mapping

**Every error includes:**
- `Code` — HTTP status or JSON-RPC error code
- `Message` — User-facing error message
- `Hint` — Actionable guidance (e.g., "Rate limit: 100 req/min per IP")
- `DocsURL` — Link to relevant documentation

**Example error response:**
```json
{
  "error": {
    "code": 429,
    "message": "Rate limit exceeded",
    "hint": "Current limit: 100 req/min. Wait 30s or configure security.rate_limit.user.per_user",
    "docs_url": "https://a2a-sentinel.dev/docs/rate-limit"
  }
}
```

### `health/` — Health Check Handlers

Implements `/healthz` (liveness) and `/readyz` (readiness) endpoints.

**Key concepts:**
- **Liveness** (`/healthz`) — Is the gateway process running? Always 200 OK.
- **Readiness** (`/readyz`) — Are backend agents healthy?
- **Readiness modes:**
  - `any_healthy` — At least one agent is healthy
  - `default_healthy` — Default agent is healthy
  - `all_healthy` — All agents are healthy

**Agent health determination:**
- Checks Agent Card Manager's cached Agent Cards
- Successful recent poll = healthy
- Failed recent poll = unhealthy

### `server/` — HTTP Server Integration

Assembles all components into a complete HTTP server.

**Key responsibilities:**
- Creates and configures `net.Listener` with `LimitedListener` (max connections)
- Initializes security middleware pipeline
- Starts Agent Card Manager (background polling)
- Sets up route handlers
- Implements graceful shutdown with context

**Key adapters:**
- `agentLookupAdapter` — Bridges Agent Card Manager to Router
- `healthCheckerAdapter` — Bridges Agent Card Manager to Health Handler

**Flow:**
```
server.New(cfg, version)
  → LimitedListener(host, port, max_connections)
  → BuildPipeline() → ApplyPipeline()
  → agentcard.Manager.Start()
  → http.Server.Shutdown(ctx)
```

### `protocol/` — A2A Protocol Types and Detection

Defines all A2A protocol types and detects request protocol.

**Key types:**
- `AgentCard` — Agent metadata (name, URL, skills, security schemes)
- `Task`, `Message`, `Part`, `Artifact` — A2A data structures
- `ProtocolType` — Enum: JSONRPC, REST, SSE, UNKNOWN

**Protocol Detection (`detector.go`):**
- Reads request body without consuming it (InspectAndRewind pattern)
- Identifies JSON-RPC (has `jsonrpc` field)
- Identifies SSE (Accept header contains `text/event-stream`)
- Falls back to REST if neither

**Body Inspection Pattern:**
```go
// Reads body, captures content, resets request.Body for handler
content, err := bodyinspect.InspectAndRewind(r)
// Now r.Body is reset and can be read again by handler
```

### `security/` — Two-Layer Security Pipeline

Implements authentication, authorization, and rate limiting.

**Architecture:**

```
Request Flow:
┌──────────────────────────────────────────────────┐
│ Layer 1: PRE-AUTH (early termination)            │
├──────────────────────────────────────────────────┤
│ 1. GlobalRateLimiter    → Max N req/sec total   │
│ 2. IPRateLimiter        → Max N req/sec per IP  │
│ 3. ClientIPExtractor    → Extract real IP       │
└──────────────────────────────────────────────────┘
                           ↓
┌──────────────────────────────────────────────────┐
│ Layer 2: AUTH & POST-AUTH                        │
├──────────────────────────────────────────────────┤
│ 4. AuthMiddleware       → JWT/API-Key validation│
│ 5. UserRateLimiter      → Max M req/sec per user│
│ 6. JWSVerifier          → Agent Card JWS check  │
│ 7. ReplayDetector       → Nonce + timestamp      │
│ 8. SSRFChecker          → Private network block  │
└──────────────────────────────────────────────────┘
```

**Key components:**

- **GlobalRateLimiter** — Single limiter across all requests
  - Fast path: atomic counter check
  - Blocks at listener level (no request processing)

- **IPRateLimiter** — Per-IP token bucket
  - Respects `trusted_proxies` config (X-Forwarded-For extraction)
  - Per-IP cleanup on configurable interval

- **AuthMiddleware** — Pluggable authentication
  - Modes: `passthrough`, `passthrough-strict`, `jwt`, `api-key`, `none`
  - Sets `ctxkeys.AuthInfo(subject, verified)` on success

- **UserRateLimiter** — Per-subject token bucket
  - Keyed by authenticated subject
  - Optional per-agent overrides

- **JWSVerifier** — Agent Card JWS signature verification
  - Verifies JWS-signed Agent Cards during polling
  - Fetches and caches JWKS from trusted endpoints
  - Configurable: `security.card_signature.require` (true/false)

- **ReplayDetector** — Nonce + timestamp replay prevention
  - Tracks request nonces in memory (or Redis)
  - Configurable policies: `warn` (log only) or `require` (reject duplicates)
  - Background cleanup of expired nonces
  - Configurable: `security.replay.window`, `security.replay.nonce_policy`

- **SSRFChecker** — Push notification SSRF protection
  - Blocks push notification URLs resolving to private networks
  - Validates against domain allowlist
  - Enforces HTTPS requirement
  - Configurable: `security.push.block_private_networks`, `security.push.allowed_domains`

### `proxy/` — HTTP and SSE Proxying

Forwards requests to backend agents without using `httputil.ReverseProxy`.

**Design:**
- Manual control over header forwarding
- Separate transports for HTTP and streaming (long-lived) connections
- No sentinel-specific headers injected (Zero Agent Dependency)

**Key components:**

**HTTPProxy** — Request-response proxying
```go
func (p *HTTPProxy) Forward(w http.ResponseWriter, r *http.Request,
                            targetURL, targetPath string) error
  1. Build backend URL
  2. Create backend request with original context
  3. Copy request headers (filter hop-by-hop)
  4. Set X-Forwarded-For, X-Forwarded-Proto
  5. Remove any X-Sentinel-* headers
  6. Execute backend request
  7. Copy response headers (filter hop-by-hop)
  8. Write response body
```

**SSEProxy** — Server-Sent Events streaming
```go
func (p *SSEProxy) ProxyStream(w http.ResponseWriter, r *http.Request,
                               agentName, targetURL, targetPath string,
                               maxStreams int) error
  1. Acquire stream slot from StreamManager
  2. Build backend URL
  3. Create backend request
  4. Set SSE response headers (Content-Type, Cache-Control)
  5. Reader goroutine reads lines from backend
  6. Channel forwards lines to main goroutine
  7. Select loop:
     - Write line to client with http.Flusher
     - Handle context timeout (idle_timeout)
     - Handle client disconnect (CloseNotify)
  8. Release stream slot on exit
```

**Stream Manager** — Tracks active SSE streams
- Per-agent stream slot limit
- Prevents resource exhaustion
- Records active streams for graceful drain

**Header Filtering (`headers.go`)**
- Removes hop-by-hop headers:
  - Connection, Keep-Alive, Transfer-Encoding
  - Proxy-Authenticate, Proxy-Authorization, TE, Trailer, Upgrade
- Preserves user-defined headers
- Sets X-Forwarded-For (appends, respects prior chain)
- Sets X-Forwarded-Proto (http or https)

**Transport Separation (`transport.go`)**
- `NewHTTPTransport()` — Standard HTTP with connection pooling
- `NewStreamTransport()` — Long-lived for SSE (no pooling, keep-alive)

### `router/` — Request Routing

Routes incoming requests to the correct backend agent.

**Key types:**
- `RouteTarget` — Contains agent name, URL, and rewritten path
- `Router` — Implements routing logic

**Routing modes:**

- **Single-agent mode** (`routing.mode: single`)
  - Uses the configured default agent
  - Useful for single-endpoint deployments
  - Path rewriting: `/anything` → `/a2a` (default path)

- **Path-prefix mode** (`routing.mode: path-prefix`)
  - Extracts agent name from URL: `/agents/{name}/path`
  - Agent name resolved to backend URL
  - Path rewritten: `/agents/{name}/a2a` → `/a2a`
  - Falls back to default agent if path doesn't match

**Agent lookup:**
- Queries Agent Card Manager for health and URL
- Returns error if agent unhealthy or not found
- Errors include actionable hints

### `agentcard/` — Agent Card Manager

Manages Agent Card lifecycle for all configured agents: polling, caching, change detection, aggregation.

**Key responsibilities:**

- **Polling** — Periodically fetches `/.well-known/agent.json` from each backend
  - Configurable `poll_interval` per agent
  - Configurable `timeout` per agent

- **Caching** — Stores most recent Agent Card
  - Enables fast lookups without backend calls
  - In-memory RWMutex-protected map

- **Change Detection** — Detects cache poisoning attempts
  - Configurable policies: `allow`, `warn`, `block`
  - Compares hash of new card against previous
  - Logs warnings for suspicious changes

- **Health Determination**
  - Successful recent poll = healthy
  - Failed recent poll = unhealthy
  - Used by Router and Health Handler

- **Aggregation** — Merges all backend cards into one
  - Returns aggregated card via `/.well-known/agent.json`
  - Combines skills from all backends
  - Useful for clients discovering available agents

**Key types:**
```go
type Manager struct {
  agents map[string]*agentState
  // agentState holds:
  //   - card: cached Agent Card
  //   - healthy: last poll result
  //   - lastPolled: timestamp
  //   - lastError: poll error if any
}
```

**Lifecycle:**
```
agentcard.NewManager(agents, logger)
  → Start() background polling goroutine
    → poll each agent on interval
    → detect changes
    → update health status
  → Stop() on graceful shutdown
  → GetAggregatedCard() for client discovery
```

### `audit/` — Structured Audit Logging

Records all requests and security decisions in OTel-compatible format.

**Key concepts:**
- **Structured logging** — JSON with predefined fields
- **Sampling** — Configurable sampling rate (e.g., 1:1000)
- **Minimal overhead** — Formatted to ring buffer, rotates periodically

**Logged fields:**
- `subject` — Authenticated user/API key
- `action` — Request method and path
- `decision` — ALLOW, BLOCK, ERROR
- `reason` — Rate limit exceeded, unauthorized, etc.
- `timestamp` — RFC3339 with nanosecond precision
- `agent_name` — Backend agent (if routed)
- `status_code` — HTTP response status
- `request_id` — Correlation ID

**Example log entry:**
```json
{
  "timestamp": "2026-02-26T10:15:30.123456789Z",
  "subject": "user@example.com",
  "action": "POST /agents/echo/",
  "decision": "ALLOW",
  "agent_name": "echo",
  "status_code": 200
}
```

### `mcpserver/` — MCP Management Server

Optional MCP (Model Context Protocol) server for gateway management.

**Key features:**
- Disabled by default (`mcp.enabled: true` to enable)
- Listens on 127.0.0.1 only (local access)
- Token-based authentication for write operations (optional)
- 13 tools (read + write + card approval), 4 resources

**Read tools** (no auth required):
- `list_agents` — List all configured agents with health status
- `get_agent_status` — Get detailed status for one agent
- `get_aggregated_card` — Fetch merged Agent Card
- `health_check` — Check gateway and agent health
- `get_config` — Get current gateway configuration
- `get_audit_log` — Query recent audit log entries
- `get_metrics` — Get current Prometheus metrics

**Write tools** (auth token required):
- `update_rate_limit` — Update rate limit settings at runtime
- `reload_config` — Reload sentinel.yaml without restart
- `toggle_agent` — Enable/disable an agent
- `rotate_api_key` — Rotate API key for authentication
- `flush_replay_cache` — Clear the replay nonce cache
- `trigger_card_poll` — Force immediate Agent Card poll for an agent

**Card approval tools** (auth token required):
- `list_pending_changes` — List pending Agent Card changes
- `approve_card_change` — Approve a pending card change
- `reject_card_change` — Reject a pending card change

**Resources** (4):
- `sentinel://config` — Current configuration
- `sentinel://agents` — Agent list with health
- `sentinel://audit` — Recent audit entries
- `sentinel://metrics` — Prometheus metrics snapshot

**Design:**
- Read tools are safe for monitoring and debugging
- Write tools require MCP auth token for safety
- Card approval tools support the `approve` change policy workflow

---

## Security Pipeline

### Architecture

The security pipeline is a two-layer middleware chain:

```
Layer 1: PRE-AUTH (fast termination paths)
  └─ GlobalRateLimiter (max requests/sec)
     └─ IPRateLimiter (max requests/sec per IP)

Layer 2: POST-AUTH
  └─ AuthMiddleware (JWT, API Key, passthrough)
     └─ UserRateLimiter (max requests/sec per user)
     └─ JWSVerifier (Agent Card signature verification)
     └─ ReplayDetector (nonce + timestamp validation)
     └─ SSRFChecker (push notification SSRF protection)
```

### Rate Limiting

**Two-level approach:**

1. **IP-based (Pre-Auth)** — Protects against volumetric attacks
   - Fast path: O(1) atomic counter check
   - Respects `trusted_proxies` for real client IP
   - Example: 1000 requests/sec per IP

2. **User-based (Post-Auth)** — Protects against authenticated abuse
   - Keyed by authenticated subject (email, API key, etc.)
   - Optional per-agent overrides
   - Example: 100 requests/sec per user

**Token Bucket Implementation:**
```go
type bucket struct {
  tokens    int64
  lastRefill time.Time
}

// Acquire(n, maxTokens, refillRate)
// Returns true if n tokens available
```

### Authentication Modes

**Configured via `security.auth.mode`:**

- **`passthrough`** — Accept any request, no validation
  - Sets `subject = "anonymous"`
  - Sets `verified = false`

- **`passthrough-strict`** (default) — Accept only if subject header present
  - Reads `X-Subject` header (or configured header)
  - Sets `verified = false` (header not cryptographically verified)
  - Blocks requests without subject header

- **`jwt`** — Validate JWT from `Authorization: Bearer` header
  - Verifies signature against JWKS endpoint
  - Extracts `sub` claim as subject
  - Sets `verified = true`
  - Blocks invalid/missing/expired tokens

- **`api-key`** — Validate `X-API-Key` header
  - Compares against configured API keys
  - Sets `verified = true`
  - Blocks invalid/missing keys

- **`none`** — Block all requests
  - Returns 403 Forbidden

### Client IP Detection

**Respects `trusted_proxies` configuration:**

```yaml
listen:
  trusted_proxies:
    - "10.0.0.0/8"      # Private network
    - "127.0.0.1"       # Localhost
```

**Algorithm:**
1. Parse X-Forwarded-For header (if present)
2. Use rightmost IP in chain (closest proxy)
3. Verify it's in trusted_proxies range
4. If trust broken, use direct connection IP

**Example:**
```
X-Forwarded-For: 203.0.113.1, 198.51.100.2
trusted_proxies: ["198.51.100.0/24"]

Result: Use 198.51.100.2 (trusted proxy)
```

---

## Proxy Architecture

### HTTP Forwarding

The HTTP proxy uses `http.Client` directly (not `httputil.ReverseProxy`) for full control:

```go
1. Build backend URL
   targetURL + targetPath + ?query

2. Create backend request
   http.NewRequestWithContext() preserves cancellation

3. Copy request headers
   - Filter hop-by-hop headers (Connection, Keep-Alive, etc.)
   - Preserve user headers

4. Set forwarding context
   - X-Forwarded-For (append client IP)
   - X-Forwarded-Proto (http or https)

5. Remove sentinel headers
   - Never inject X-Sentinel-* (Zero Agent Dependency)

6. Execute backend request
   resp, err := p.client.Do(backendReq)

7. Copy response headers
   - Filter hop-by-hop headers
   - Preserve content headers (Content-Type, Cache-Control, etc.)

8. Stream response
   io.Copy(w, resp.Body)
```

### SSE Streaming

The SSE proxy uses a goroutine+channel pattern for reliable streaming:

```
┌─────────────────────────────────────────────────┐
│ Main Goroutine                                   │
├─────────────────────────────────────────────────┤
│ 1. Acquire stream slot                          │
│ 2. Create backend request                       │
│ 3. Set SSE response headers                     │
│ 4. http.Flusher for immediate delivery          │
│ 5. Select loop:                                 │
│    - Line from channel → write to client        │
│    - Idle timeout → close stream                │
│    - Client close → exit                        │
└─────────────────────────────────────────────────┘
         ▲                           │
         │                           │
      line channel            context/flush
         │                           │
         │                           ▼
┌─────────────────────────────────────────────────┐
│ Reader Goroutine                                │
├─────────────────────────────────────────────────┤
│ 1. Connect to backend                           │
│ 2. Read lines from response body                │
│ 3. Parse SSE format (data: ..., event: ...)    │
│ 4. Send lines to channel                        │
│ 5. Validate against maxEventSize                │
│ 6. Close channel on EOF or error                │
└─────────────────────────────────────────────────┘
```

**Key features:**

- **Goroutine separation** — Reader doesn't block writer
- **Channel buffering** — Configurable (usually 100-200 events)
- **Timeout detection** — Idle timeout closes stream
- **Client disconnect** — Detects via CloseNotify or context
- **Stream limits** — StreamManager prevents resource exhaustion

**Timeline:**
```
Client connects
    ↓
SSEProxy.ProxyStream()
    ├─ Acquire stream slot
    ├─ Connect to backend
    ├─ Reader goroutine: backend → channel
    └─ Main goroutine: channel → client (with timeout/close checks)
         ↓
Client disconnects (or idle timeout)
    ├─ Release stream slot
    └─ Close both goroutines
```

---

## Metrics Endpoint

a2a-sentinel exposes a Prometheus-compatible metrics endpoint at `/metrics` with zero external dependencies. The metrics are generated from internal counters in the audit subsystem.

**Endpoint**: `GET /metrics`

**Exposed metrics**:
- `sentinel_requests_total{agent, status}` — Total requests by agent and status (allow/block)
- `sentinel_request_duration_seconds{agent}` — Request latency histogram
- `sentinel_active_streams{agent}` — Current active SSE streams per agent
- `sentinel_rate_limit_hits_total{layer}` — Rate limit rejections by layer (ip/user/global)
- `sentinel_agent_health{agent}` — Agent health status (1 = healthy, 0 = unhealthy)
- `sentinel_card_changes_total{agent, policy}` — Agent Card changes detected

**Design**:
- No external dependencies (no Prometheus client library)
- Metrics are collected in-memory via atomic counters
- `/metrics` handler formats output in Prometheus exposition format
- Compatible with Prometheus, Grafana, Datadog agent, and other scrapers

**Configuration**:
```yaml
# Metrics are available whenever the server is running
# No additional configuration needed
# Scrape at: http://localhost:8080/metrics
```

---

## CLI Subcommands

The `sentinel` binary supports the following subcommands:

| Subcommand | Description | Example |
|------------|-------------|---------|
| `serve` | Start the gateway server | `sentinel --config sentinel.yaml serve` |
| `validate` | Validate configuration file | `sentinel --config sentinel.yaml validate` |
| `init` | Generate config template | `sentinel init --profile dev` |
| `migrate` | Convert config to agentgateway format | `sentinel migrate --to agentgateway --output agentgateway.yaml` |
| `help` | Show usage information | `sentinel help` |
| `--version` | Show version | `sentinel --version` |

### migrate Subcommand

The `migrate` subcommand converts sentinel.yaml to agentgateway-compatible configuration:

```bash
sentinel migrate --to agentgateway --output agentgateway.yaml
```

**Flags**:
- `--to` — Target format (currently only `agentgateway`)
- `--input` — Input sentinel.yaml path (default: `sentinel.yaml`)
- `--output` — Output file path (required)

The output is a best-effort conversion. See [MIGRATION.md](./MIGRATION.md) for the full migration guide and field mapping table.

---

## Configuration System

### Configuration File Format

a2a-sentinel uses YAML configuration:

```yaml
listen:
  host: "127.0.0.1"
  port: 8080
  max_connections: 1000
  global_rate_limit: 10000
  trusted_proxies:
    - "127.0.0.1"
    - "10.0.0.0/8"

external_url: "http://localhost:8080"

agents:
  - name: "echo"
    url: "http://localhost:8081"
    default: true
    card_path: "/.well-known/agent.json"
    poll_interval: "30s"
    timeout: "5s"
    max_streams: 100

routing:
  mode: "path-prefix"  # or "single"

security:
  auth:
    mode: "passthrough-strict"  # or jwt, api-key, passthrough, none
    subject_header: "X-Subject"
  rate_limit:
    enabled: true
    ip:
      per_ip: 1000
      burst: 100
      cleanup_interval: "5m"
    user:
      per_user: 100
      burst: 10
      cleanup_interval: "5m"

health:
  liveness_path: "/healthz"
  readiness_path: "/readyz"
  readiness_mode: "any_healthy"  # or default_healthy, all_healthy

logging:
  audit:
    enabled: true
    sample_rate: 1      # 1 in N requests

shutdown:
  drain_timeout: "30s"  # Time to drain SSE streams before hard shutdown
```

### Configuration Loading Pipeline

```
Read sentinel.yaml
    ↓
yaml.Unmarshal() → Config struct
    ↓
applyDefaults() → Fill missing fields with sensible defaults
    ↓
validate() → Check constraints (e.g., port in range, rates > 0)
    ↓
Success: Config ready for use
Failure: Return error with helpful message
```

### Profiles

```bash
# Generate dev profile
sentinel init --profile dev

# Generate prod profile (stricter defaults)
sentinel init --profile prod
```

**Differences:**
- Dev: passthrough-strict auth, generous rate limits, debug logging
- Prod: jwt auth, stricter rate limits, sampled audit logging

---

## Design Principles

### 1. Zero Agent Dependency

**Goal:** Agents don't need to know they're behind sentinel.

**Implementation:**
- Never inject sentinel-specific headers (no `X-Sentinel-*`)
- No sentinel-specific metadata in Agent Card
- Transparent proxy — agents see standard HTTP headers only
- Agents continue to work if sentinel is removed

**Enforcement:**
```go
// In proxy/http.go
for key := range backendReq.Header {
  if strings.HasPrefix(strings.ToLower(key), "x-sentinel-") {
    backendReq.Header.Del(key)  // Always remove
  }
}
```

### 2. Security ON by Default

**Goal:** Most secure configuration is the default.

**Examples:**
- Auth mode: `passthrough-strict` (requires subject)
- Rate limiting: Enabled
- HTTPS: Supported (configurable)
- Agent Card change detection: Enabled with `warn` policy
- Audit logging: Enabled with sampling

**Philosophy:** Admins opt-out of security, not in.

### 3. Educational Errors

**Goal:** Every error message helps developers fix problems.

**Structure:**
```
{
  "code": 429,
  "message": "Rate limit exceeded",
  "hint": "Current limit: 1000 req/min per IP. Wait 60s or adjust listen.global_rate_limit",
  "docs_url": "https://a2a-sentinel.dev/docs/rate-limit"
}
```

**Benefits:**
- No cryptic error codes
- Actionable guidance
- Link to documentation

### 4. OTel-Compatible Audit Logging

**Goal:** Seamless integration with observability stacks.

**Design:**
- JSON structured logs
- Standard field names (timestamp, subject, action)
- Configurable sampling (don't log every request)
- Correlation IDs for request tracing

### 5. No httputil.ReverseProxy

**Goal:** Full control over header forwarding and streaming.

**Why:**
- `httputil.ReverseProxy` has opinionated defaults
- Difficult to customize hop-by-hop header handling
- SSE streaming requires custom logic
- Manual implementation is clearer

**Trade-off:** More code, but more control.

### 6. Hop-by-Hop Header Removal

**Goal:** Prevent protocol violations.

**Headers removed:**
- `Connection` — Hop-by-hop directive
- `Keep-Alive` — Connection management
- `Transfer-Encoding` — Encoding directive
- `Proxy-Authenticate`, `Proxy-Authorization` — Proxy auth
- `TE` (Transfer-Encoding short form)
- `Trailer` — Header trailer for chunked encoding
- `Upgrade` — Protocol upgrade (WebSocket)

**Implementation:**
```go
func CopyHeadersFiltered(dst, src http.Header) {
  for key, values := range src {
    if isHopByHopHeader(key) {
      continue
    }
    for _, val := range values {
      dst.Add(key, val)
    }
  }
}
```

### 7. Body Inspection via InspectAndRewind

**Goal:** Read body for protocol detection without consuming it.

**Pattern:**
```go
content, err := bodyinspect.InspectAndRewind(r)
if err != nil {
  // Handle error
}
// Now r.Body is reset and can be read by proxy
```

**Implementation:**
- Read entire body into memory
- Parse (identify protocol)
- Create new io.ReadCloser
- Assign back to r.Body
- Handler sees original body, can read again

**Limitation:** Never reads streaming bodies (Content-Length required).

### 8. Subject Logging Reliability

**Goal:** Accurate audit logs even without full authentication.

**Implementation:**
```go
// In passthrough-strict mode, if subject not verified:
logEntry.Subject = "unverified:" + subject
```

**Benefit:** Audit logs remain useful for security analysis.

---

## Graceful Shutdown

### Shutdown Sequence

```
1. SIGINT or SIGTERM received
   └─ main.go: signal.NotifyContext()

2. Server.Shutdown(ctx) initiated
   └─ Stops accepting new connections
   └─ context deadline = now + shutdown.drain_timeout

3. Active SSE streams drained
   └─ StreamManager notifies all readers
   └─ Readers flush buffered events
   └─ Wait for context timeout or all streams closed

4. Active HTTP requests completed
   └─ http.Server.Shutdown() waits for handlers
   └─ Handler contexts checked against deadline

5. Agent Card Manager stopped
   └─ agentcard.Manager.Stop()
   └─ Stops polling goroutine

6. Resources cleaned up
   └─ Database connections closed
   └─ File handles closed
   └─ Listeners closed

7. Process exits with status 0
```

### Configuration

```yaml
shutdown:
  drain_timeout: "30s"  # Max time to drain streams
```

**Behavior:**
- First 30s: Allow graceful stream closure
- After 30s: Force close remaining connections
- Active goroutines cleaned up
- Client connections may abruptly close (expected)

---

## See Also

- **[README.md](../README.md)** — Quick start and feature overview
- **[SECURITY.md](./SECURITY.md)** — Security policies and threat model
- **[ERRORS.md](./ERRORS.md)** — Error catalog and troubleshooting
- **[MIGRATION.md](./MIGRATION.md)** — Migration guide to agentgateway

---

## Summary

a2a-sentinel implements a layered security architecture:

1. **Protocol Detection** — Identifies JSON-RPC, REST, SSE
2. **Two-Layer Security** — IP rate limit (pre-auth) + auth + user rate limit (post-auth)
3. **Advanced Security** — JWS card verification, replay detection, SSRF protection
4. **Routing** — Path-prefix or single-agent modes
5. **Proxying** — HTTP and SSE with manual header control
6. **Agent Card Management** — Polling, caching, health tracking, aggregation, approve mode
7. **Audit Logging** — OTel-compatible structured logs
8. **Metrics** — Prometheus-compatible /metrics endpoint
9. **MCP Server** — 13 tools (read + write + card approval), 4 resources
10. **Migration** — `sentinel migrate` for agentgateway conversion
11. **Graceful Shutdown** — Stream draining with configurable timeout

The design prioritizes **zero agent dependency** (transparent to backends), **security by default** (all protections enabled), and **educational errors** (every block includes guidance).

For implementation details, see the source code in `internal/`.
