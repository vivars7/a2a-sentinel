# Security Guide — a2a-sentinel

**a2a-sentinel is built on a principle: Security ON by Default.**

Every security feature is enabled out of the box. Disabling any protection requires explicit configuration. This guide explains the threat model, authentication modes, rate limiting strategy, and how to configure sentinel for your security requirements.

---

## Table of Contents

1. [Security Philosophy](#security-philosophy)
2. [Threat Model & Defenses](#threat-model--defenses)
3. [Authentication Modes](#authentication-modes)
4. [Rate Limiting (2-Layer)](#rate-limiting-2-layer)
5. [Agent Card Security](#agent-card-security)
6. [Audit Logging](#audit-logging)
7. [Push Notification Protection](#push-notification-protection)
8. [Replay Attack Prevention](#replay-attack-prevention)
9. [Trusted Proxies](#trusted-proxies)
10. [Error Messages & Hints](#error-messages--hints)
11. [Configuration Reference](#configuration-reference)
12. [Reporting Vulnerabilities](#reporting-vulnerabilities)

---

## Security Philosophy

a2a-sentinel follows a **defense-in-depth** approach with sensible defaults:

- **Explicit over implicit**: All security decisions are explicit. Logging every decision (allow/block).
- **Educational errors**: Every security block includes a `hint` explaining what went wrong and a `docs_url` pointing to the fix.
- **Observable**: All decisions logged in OTel-compatible structured format for audit trails.
- **Gateway responsibility**: sentinel protects your agents. Agents don't need to validate sentinel-specific requirements.

### Security Levels

| Level | Use Case | Config Profile |
|-------|----------|-----------------|
| **Development** | Local testing, no auth needed | `sentinel init --profile dev` |
| **Strict Development** | Team testing, auth headers required but not validated | `sentinel init --profile strict-dev` |
| **Production** | Full JWT validation, aggressive rate limiting | `sentinel init --profile prod` |

---

## Threat Model & Defenses

This table maps real-world threats against a2a-sentinel defenses:

| # | Threat | Attack Vector | Sentinel Defense | Configuration |
|---|--------|---------------|------------------|-----------------|
| 1 | **Unauthorized access** | Missing or forged authentication tokens | 2-layer authentication (passthrough-strict default) | `security.auth.mode` |
| 2 | **DoS/DDoS** | Request flooding from single IP | Per-IP rate limiting (pre-auth) | `security.rate_limit.ip.per_ip`, `listen.global_rate_limit` |
| 3 | **User abuse** | Single authenticated user hammering the gateway | Per-user rate limiting (post-auth) | `security.rate_limit.user.per_user` |
| 4 | **Agent Card poisoning** | Attacker modifies agent card in transit | Change detection + alert logging | `agents[].card_change_policy` |
| 5 | **Cache poisoning** | Attacker injects malicious card during polling | JWS signature verification (v0.2) | `security.card_signature.require` |
| 6 | **SSRF via push notifications** | Attacker tricks gateway into accessing private network | URL validation, private IP blocking | `security.push.block_private_networks` |
| 7 | **Replay attacks** | Attacker replays old requests to trigger actions | Nonce + timestamp validation (v0.2) | `security.replay.enabled` |
| 8 | **Man-in-middle** | Unencrypted communication with agents | TLS enforcement by default | `agents[].allow_insecure: false` |
| 9 | **Resource exhaustion** | Too many concurrent SSE streams per agent | Per-agent stream limit | `agents[].max_streams` |
| 10 | **Connection exhaustion** | Too many total gateway connections | Global connection limit | `listen.max_connections` |

---

## Authentication Modes

a2a-sentinel supports four authentication modes, controlled by `security.auth.mode`. Choose one:

### 1. passthrough (Development Only)

**Behavior**: Accept requests with or without Authorization headers. No validation.

**Use case**: Local development before agents are ready.

**Config**:
```yaml
security:
  auth:
    mode: passthrough
```

**Risk**: Offers zero protection. Only safe on localhost.

---

### 2. passthrough-strict (DEFAULT)

**Behavior**: Require Authorization header, but don't validate the token. Extract and log the subject claim (with "unverified:" prefix).

**Use case**: Team development, docker-compose testing, strict header enforcement without JWT overhead.

**Config**:
```yaml
security:
  auth:
    mode: passthrough-strict
    allow_unauthenticated: false  # Require header
```

**How it works**:
1. Request arrives without Authorization header → **rejected with 401**
2. Request with Authorization header → accepted, subject extracted from token (if JWT) or truncated (if opaque)
3. Subject logged as `unverified:<subject>` (marks unvalidated origin)

**Example audit log**:
```json
{
  "timestamp": "2025-02-26T12:34:56Z",
  "a2a.auth.subject": "unverified:user-123"
}
```

---

### 3. jwt (Production)

**Behavior**: Full JWT validation — issuer, audience, expiry, JWKS signature verification.

**Use case**: Production with OAuth2/OIDC token providers.

**Config**:
```yaml
security:
  auth:
    mode: jwt
    allow_unauthenticated: false
    schemes:
      - type: bearer
        jwt:
          issuer: https://auth.example.com
          audience: sentinel-api
          jwks_url: https://auth.example.com/.well-known/jwks.json
```

**Validation**:
- Token format: `Authorization: Bearer <JWT>`
- Signature verified against JWKS endpoint
- Claims validated: `iss`, `aud`, `exp`
- Subject (`sub` claim) extracted and logged as verified

**Example JWT token**:
```
eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEifQ.
eyJzdWIiOiJ1c2VyLTEyMyIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIsImF1ZCI6InNlbnRpbmVsLWFwaSIsImV4cCI6MTcwODk5OTAwMH0.
<signature>
```

**Error cases**:
- Missing Authorization header → 401 (if not allowed)
- Invalid signature → 401
- Expired token → 401
- Wrong issuer → 401
- Wrong audience → 401

---

### 4. api-key (Simple Production)

**Behavior**: Simple shared secret in Authorization header.

**Use case**: Simple deployments, internal APIs with limited clients.

**Config**:
```yaml
security:
  auth:
    mode: api-key
    allow_unauthenticated: false
    schemes:
      - type: bearer
        api_key:
          secret: sk_abc123xyz  # Keep in environment variable!
```

**How it works**:
1. Client sends: `Authorization: Bearer sk_abc123xyz`
2. Gateway compares against configured secret
3. If match → allow, log subject as "api-key-user"
4. If mismatch → 401

**Best practice**: Store secret in environment variable:
```bash
export SENTINEL_API_KEY="sk_$(openssl rand -hex 16)"
./sentinel serve --config sentinel.yaml
```

---

## Rate Limiting (2-Layer)

a2a-sentinel enforces rate limits in two strategic places:

```
Request arrives
    ↓
Layer 1: Global rate limit (saves CPU on invalid traffic)
    ↓
Layer 2: Per-IP rate limit (defense against distributed attacks)
    ↓
Authentication & routing
    ↓
Layer 3: Per-user rate limit (defense against authenticated abuse)
    ↓
Request forwarded to agent
```

### Layer 1: Global Rate Limit

**What**: Gateway-wide token bucket. All traffic shares one limit.

**Default**: 5,000 requests/minute (83 req/sec)

**Use case**: Prevent gateway overload. First line of defense against any DDoS.

**Config**:
```yaml
listen:
  global_rate_limit: 5000  # req/min
```

**Behavior**:
- Request arrives → check global token bucket
- Token available → increment counter, allow request
- No token → reject with 503 (ErrGlobalLimitReached)

**Error response**:
```json
{
  "error": {
    "code": 503,
    "message": "Gateway capacity reached",
    "hint": "Gateway is at maximum connections. Try again shortly",
    "docs_url": "https://a2a-sentinel.dev/docs/limits"
  }
}
```

---

### Layer 2: Per-IP Rate Limit

**What**: Separate token bucket per client IP. Defense against single-IP attacks.

**Default**: 200 requests/minute per IP, burst of 50

**Use case**: Fair use across many clients. Prevent one bad actor from hogging gateway.

**Config**:
```yaml
security:
  rate_limit:
    enabled: true
    ip:
      per_ip: 200        # req/min per IP
      burst: 50          # allow burst up to 50
      cleanup_interval: 5m  # remove inactive IPs after 5min
```

**How IP extraction works**:

a2a-sentinel respects the `X-Forwarded-For` header when behind a trusted proxy:

```yaml
listen:
  trusted_proxies:
    - "10.0.0.0/8"       # Trust nginx/reverse proxy on private network
    - "203.0.113.5"      # Trust specific proxy IP
```

**Algorithm** (TrustedClientIP):
1. If trusted_proxies is empty → use RemoteAddr only (safest default)
2. If trusted_proxies set → parse X-Forwarded-For from right to left
3. Return rightmost IP that is NOT in trusted_proxies (the actual client)

**Example**:
- RemoteAddr: `10.0.0.1` (reverse proxy)
- X-Forwarded-For: `203.0.113.99, 10.0.0.1` (attacker, proxy)
- trusted_proxies: `["10.0.0.0/8"]`
- **Extracted IP**: `203.0.113.99` (the actual attacker)

**Without proper trusted_proxies**, attackers can spoof X-Forwarded-For to bypass limits.

---

### Layer 3: Per-User Rate Limit

**What**: Separate token bucket per authenticated user (subject). Defense against authenticated abuse.

**Default**: 100 requests/minute per user, burst of 20

**Applies to**: Only authenticated requests (passthrough-strict with subject, jwt, api-key)

**Config**:
```yaml
security:
  rate_limit:
    enabled: true
    user:
      per_user: 100      # req/min per user
      burst: 20          # allow burst up to 20
      cleanup_interval: 5m  # remove inactive users after 5min
```

**User identification**:
- **JWT mode**: Uses `sub` (subject) claim
- **passthrough-strict**: Uses extracted subject (prefixed with "unverified:")
- **api-key mode**: Uses "api-key-user"
- **Unauthenticated**: Skips per-user limit (falls back to per-IP only)

**Cleanup mechanism**:
To prevent unbounded memory growth, inactive user entries are removed after `cleanup_interval`. Last activity timestamp updated on every request.

---

### Rate Limit Error Response

Both IP and user limits return 429 (Too Many Requests):

```json
{
  "error": {
    "code": 429,
    "message": "Rate limit exceeded",
    "hint": "Wait before retrying. Configure security.rate_limit in sentinel.yaml",
    "docs_url": "https://a2a-sentinel.dev/docs/rate-limit"
  }
}
```

**Audit log entry** (with sampling):
```json
{
  "timestamp": "2025-02-26T12:34:56Z",
  "a2a.status": "blocked",
  "a2a.block_reason": "rate_limit_exceeded",
  "rate_limit_state": {
    "user_remaining": 0,
    "user_reset_secs": 30
  }
}
```

---

## Agent Card Security

Agent Cards describe the agent's capabilities, security schemes, and methods. a2a-sentinel periodically fetches and caches them, with multiple safeguards:

### Card Polling

**What**: Gateway fetches `/.well-known/agent.json` from each agent at regular intervals.

**Default interval**: 60 seconds per agent

**Config**:
```yaml
agents:
  - name: my-agent
    url: https://agent.example.com
    card_path: /.well-known/agent.json
    poll_interval: 60s      # Fetch every 60 seconds
    timeout: 30s            # 30s timeout on fetch
    allow_insecure: false   # Require HTTPS (default)
```

**Security measures**:
- Body size limit: 1 MB (prevents DoS via huge card)
- Timeout: Configurable (default 30s, prevents hanging)
- TLS enforcement: HTTPS required by default (set `allow_insecure: true` only for dev)

**Error handling**:
- Network error → log warning, mark agent unhealthy, keep cached card
- Invalid JSON → log warning, mark unhealthy, keep cached card
- HTTP error (non-200) → log warning, mark unhealthy

---

### Change Detection

**What**: When a new card is fetched, sentinel compares it against the cached version and detects changes.

**Critical changes** (marked for alert):
- URL changed
- Version changed
- Security schemes added/removed
- Skills count changed >50%

**Non-critical changes**:
- Name, description changed
- Capabilities changed (streaming, push, history)

**Use case**: Detect cache poisoning or unauthorized card updates.

**Example**:
```
Old card: version "1.0", 5 skills
New card: version "1.1", 10 skills

Detected: critical=true (>50% skills change) + non-critical (version change)
```

---

### Change Policies

**Default**: `alert` (prevent changes from taking effect)

#### 1. alert (DEFAULT)

**Behavior**: Keep old card, log warning. Changes are ignored.

**Audit log**:
```json
{
  "timestamp": "2025-02-26T12:34:56Z",
  "level": "warn",
  "msg": "agent_card_change_detected",
  "agent": "my-agent",
  "policy": "alert",
  "changes": 2,
  "critical": true
}
```

**Use case**: Production. Require manual review before agent updates.

**Config**:
```yaml
agents:
  - name: my-agent
    url: https://agent.example.com
    card_change_policy: alert
```

---

#### 2. auto

**Behavior**: Apply changes immediately, log info entry.

**Audit log**:
```json
{
  "timestamp": "2025-02-26T12:34:56Z",
  "level": "info",
  "msg": "agent_card_updated",
  "agent": "my-agent",
  "policy": "auto",
  "changes": 2
}
```

**Use case**: Development. Rolling updates without manual intervention.

**Config**:
```yaml
agents:
  - name: my-agent
    card_change_policy: auto
```

---

#### 3. approve (v0.2, planned)

**Behavior**: Store changes in pending queue. Manual approval via MCP API. Keeps old card until approved.

**Config**:
```yaml
agents:
  - name: my-agent
    card_change_policy: approve
```

---

### JWS Signature Verification (v0.2)

**What**: Validate Agent Card signatures using the agent's JWK (JSON Web Key).

**Default**: Not required (v0.1). v0.2 will make it optional but recommended.

**Config** (future):
```yaml
security:
  card_signature:
    require: true
    trusted_jwks_urls:
      - https://agent.example.com/.well-known/jwks.json
    cache_ttl: 1h
```

**How it works** (planned for v0.2):
1. Fetch card's JWS signature header
2. Verify signature against agent's JWKS
3. Extract `iss` (issuer) — must match agent URL
4. Cache JWK for TTL window (default 1 hour)
5. If signature invalid → mark card unhealthy, keep cached version

---

## Audit Logging

All requests are logged in OpenTelemetry-compatible structured JSON format. Enables you to track security decisions, debug issues, and audit compliance.

### Log Entry Structure

```json
{
  "timestamp": "2025-02-26T12:34:56Z",
  "level": "info",
  "msg": "audit",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "attributes": {
    "a2a.method": "POST",
    "a2a.protocol": "json-rpc",
    "a2a.target_agent": "my-agent",
    "a2a.auth.scheme": "bearer",
    "a2a.auth.subject": "user-123",
    "a2a.status": "allow",
    "a2a.block_reason": "",
    "a2a.start_time": "2025-02-26T12:34:56Z"
  },
  "stream": {
    "events": 42,
    "duration_ms": 5000
  }
}
```

### Field Reference

| Field | Meaning |
|-------|---------|
| `trace_id` | OpenTelemetry trace ID (for correlation) |
| `span_id` | OpenTelemetry span ID |
| `a2a.method` | HTTP method (POST, GET, etc.) |
| `a2a.protocol` | Protocol detected (json-rpc, rest, agent-card) |
| `a2a.target_agent` | Agent name matched by router |
| `a2a.auth.scheme` | Auth scheme (bearer, api-key, none) |
| `a2a.auth.subject` | Authenticated user ID or "unverified:..." |
| `a2a.status` | Decision: `allow`, `block` |
| `a2a.block_reason` | If blocked: `rate_limit_exceeded`, `auth_required`, `forbidden`, etc. |
| `a2a.start_time` | Request start timestamp |
| `stream.events` | For SSE: number of events sent (if streaming) |
| `stream.duration_ms` | For SSE: total stream duration in ms |

### Status Values

| Status | Reason | Example |
|--------|--------|---------|
| `allow` | Request passed all checks | Authenticated, not rate-limited |
| `block` | Request rejected by security layer | Rate limit hit, auth failed |

### Block Reasons

| Block Reason | Meaning | HTTP Code |
|---|---|---|
| `auth_required` | No auth header when required | 401 |
| `auth_invalid` | Invalid token (signature, expiry, issuer) | 401 |
| `rate_limit_exceeded` | IP or user rate limit hit | 429 |
| `global_limit_reached` | Gateway at max capacity | 503 |
| `forbidden` | Authenticated but lacks permission | 403 |
| `ssrf_blocked` | Push notification URL blocked | 403 |
| `replay_detected` | Nonce/timestamp validation failed | 409 |

### Sampling

By default, ALL log entries are recorded. Configure sampling to reduce noise in high-volume environments:

```yaml
logging:
  audit:
    sampling_rate: 0.1       # Log 10% of allowed requests (for volume reduction)
    error_sampling_rate: 1.0 # Always log errors/blocks (100%)
    max_body_log_size: 1024  # Truncate request bodies to 1KB in logs
```

**Why separate error sampling?** Blocks are security events — always log them. Normal traffic can be sampled to reduce log volume.

**Example**:
- 10,000 allowed requests → only 1,000 logged (10% sampling)
- 10 blocked requests → all 10 logged (100% error sampling)

### Audit Log Usage

**Find all blocked requests**:
```bash
cat sentinel.log | jq 'select(.attributes["a2a.status"] == "block")'
```

**Find rate limit violations**:
```bash
cat sentinel.log | jq 'select(.attributes["a2a.block_reason"] == "rate_limit_exceeded")'
```

**Find requests by user**:
```bash
cat sentinel.log | jq 'select(.attributes["a2a.auth.subject"] == "user-123")'
```

**Find high-latency SSE streams**:
```bash
cat sentinel.log | jq 'select(.stream.duration_ms > 30000)'
```

---

## Push Notification Protection

Push notifications allow agents to send updates to clients. However, they create an SSRF vector if not validated.

### SSRF Defense: Private Network Blocking

**What**: Block push notification URLs that resolve to private networks.

**Default**: Enabled (`block_private_networks: true`)

**Config**:
```yaml
security:
  push:
    block_private_networks: true  # Block 10.x, 172.16-31.x, 192.168.x, 127.x
    allowed_domains: []           # Optional: whitelist specific domains
    require_https: true           # Require HTTPS for push URLs
    hmac_secret: ""               # (v0.2) Sign webhooks
```

**Blocked IP ranges**:
- `10.0.0.0/8` (Private)
- `172.16.0.0/12` (Private)
- `192.168.0.0/16` (Private)
- `127.0.0.0/8` (Loopback)

**Error response**:
```json
{
  "error": {
    "code": 403,
    "message": "Push notification URL blocked",
    "hint": "URL resolves to private network. Use public URLs or configure security.push.allowed_domains",
    "docs_url": "https://a2a-sentinel.dev/docs/ssrf"
  }
}
```

### Domain Allowlist

If you have legitimate internal webhooks, allowlist them:

```yaml
security:
  push:
    block_private_networks: true
    allowed_domains:
      - "internal.company.com"     # Allow even if private
      - "webhook.service.internal"
```

**Algorithm**:
1. Parse push URL
2. Resolve hostname to IP
3. If IP in private range:
   - Check against allowed_domains
   - If domain matches → allow
   - Otherwise → reject

### HMAC Signing (v0.2)

Validate webhook authenticity:

```yaml
security:
  push:
    require_https: true
    hmac_secret: "sk_webhook_secret_key"
```

a2a-sentinel will sign push notifications with HMAC-SHA256. Webhook receiver verifies signature to ensure notification came from sentinel.

---

## Replay Attack Prevention

Replay attacks: attacker records a valid request and resends it later to trigger unintended actions.

### Defense: Nonce + Timestamp Validation (v0.2)

**What**: Require unique nonce and recent timestamp in request. Reject requests older than configured window.

**Default**: Enabled (v0.2 only)

**Config**:
```yaml
security:
  replay:
    enabled: true
    window: 300s            # Accept requests ≤5 minutes old
    nonce_policy: warn      # warn | require
    store: memory           # memory | redis
    redis_url: ""           # If store: redis
```

**Nonce policies**:

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `warn` | Log if nonce already seen, but still allow | Early warning |
| `require` | Reject if nonce already seen | Strict protection |

**Error response**:
```json
{
  "error": {
    "code": 409,
    "message": "Replay attack detected",
    "hint": "Include unique nonce and current timestamp in request",
    "docs_url": "https://a2a-sentinel.dev/docs/replay"
  }
}
```

### How to Use

**Client adds to request headers**:
```
X-Request-ID: abc123def456xyz789  # Unique nonce
X-Request-Time: 1708999200       # Unix timestamp (seconds)
```

**Gateway validation**:
1. Extract timestamp → check within window
2. Extract nonce → check against seen-before cache
3. If valid → forward request
4. If invalid or expired → 409 (Conflict)

**v0.2 note**: In v0.1, this is a stub that always passes. v0.2 will implement full validation.

---

## Trusted Proxies

If a2a-sentinel runs behind a reverse proxy (nginx, load balancer), configure `trusted_proxies` so rate limiting uses the real client IP, not the proxy IP.

### Problem Without trusted_proxies

```
Attacker at 203.0.113.99
    ↓
Reverse proxy at 10.0.0.1
    ↓
sentinel (RemoteAddr = 10.0.0.1)
    ↓
Rate limiter sees: 10.0.0.1, allows 200 req/min
Attacker can send 200 req/min from same real IP but always through proxy
```

### Solution: Configure trusted_proxies

```yaml
listen:
  trusted_proxies:
    - "10.0.0.0/8"     # Trust our private network
    - "203.0.113.5"    # Trust specific proxy IP
```

Now sentinel extracts real client IP from `X-Forwarded-For` header:

```
X-Forwarded-For: 203.0.113.99, 10.0.0.1
trusted_proxies: [10.0.0.0/8, 203.0.113.5]

Algorithm walks from right to left:
  10.0.0.1? → trusted (10.0.0.0/8)
  203.0.113.99? → NOT trusted → extract this as real client IP
```

Result: Rate limiter now sees 203.0.113.99 and enforces 200 req/min per real client.

### Safe Default

If `trusted_proxies` is empty → use `RemoteAddr` only (don't trust X-Forwarded-For). This is the safest default.

**Never trust X-Forwarded-For without explicitly configuring trusted_proxies.**

---

## Error Messages & Hints

Every security error includes:
- **Code**: HTTP status (401, 403, 429, etc.)
- **Message**: Brief human-readable summary
- **Hint**: Developer guidance on how to fix (EDUCATIONAL)
- **DocsURL**: Link to detailed documentation

### Reference: All Security Errors

| Error | Code | Hint | Cause |
|-------|------|------|-------|
| `ErrAuthRequired` | 401 | "Set Authorization header: 'Bearer <token>'" | No auth header in passthrough-strict or jwt mode |
| `ErrAuthInvalid` | 401 | "Check token expiry and issuer" | JWT signature invalid, expired, wrong issuer/audience |
| `ErrForbidden` | 403 | "Check agent permissions and scope configuration" | Authenticated but lacks permission for this agent |
| `ErrRateLimited` | 429 | "Wait before retrying. Configure security.rate_limit in sentinel.yaml" | IP or user rate limit exceeded |
| `ErrStreamLimitExceeded` | 429 | "Max streams per agent reached. Configure agents[].max_streams" | Too many concurrent SSE streams on this agent |
| `ErrSSRFBlocked` | 403 | "URL resolves to private network. Use public URLs or configure security.push.allowed_domains" | Push notification URL blocks |
| `ErrReplayDetected` | 409 | "Include unique nonce and current timestamp in request" | Nonce already seen or timestamp expired |
| `ErrGlobalLimitReached` | 503 | "Gateway is at maximum connections. Try again shortly" | Gateway-wide rate limit hit |
| `ErrAgentUnavailable` | 503 | "Check agent health with GET /readyz" | Agent unhealthy (failed card fetch, etc.) |

---

## Configuration Reference

### Security Block (Full Schema)

```yaml
security:
  # ── Authentication ──
  auth:
    mode: passthrough-strict        # passthrough | passthrough-strict | jwt | api-key | none
    allow_unauthenticated: false    # If false, require Authorization header
    schemes:
      - type: bearer
        jwt:
          issuer: https://auth.example.com
          audience: my-api
          jwks_url: https://auth.example.com/.well-known/jwks.json

  # ── Rate Limiting ──
  rate_limit:
    enabled: true
    ip:
      per_ip: 200           # requests/minute per IP
      burst: 50             # allow burst up to 50
      cleanup_interval: 5m  # remove inactive entries after 5min
    user:
      per_user: 100         # requests/minute per user
      burst: 20             # allow burst up to 20
      cleanup_interval: 5m  # remove inactive entries after 5min
    per_agent: 500          # per-agent limit (not yet enforced)

  # ── Agent Card Security ──
  card_signature:
    require: false          # (v0.2: require JWS signatures)
    trusted_jwks_urls: []   # URLs to trusted agent JWKS
    cache_ttl: 1h           # Cache JWKS for this long

  # ── Push Notification Protection ──
  push:
    block_private_networks: true
    allowed_domains: []
    require_https: true
    require_challenge: false
    hmac_secret: ""         # (v0.2: sign webhooks)

  # ── Replay Attack Prevention ──
  replay:
    enabled: false          # (v0.2: implement full validation)
    window: 5m
    nonce_policy: warn      # warn | require
    store: memory           # memory | redis
    redis_url: ""
```

### Listen Block (Global Settings)

```yaml
listen:
  host: 0.0.0.0
  port: 8080
  max_connections: 1000              # Max total TCP connections
  global_rate_limit: 5000            # requests/minute, all traffic
  trusted_proxies: []                # IPs/CIDRs to trust X-Forwarded-For from
  tls:
    cert_file: /path/to/cert.pem
    key_file: /path/to/key.pem
```

### Agent Block (Per-Agent Security)

```yaml
agents:
  - name: my-agent
    url: https://agent.example.com
    card_path: /.well-known/agent.json
    poll_interval: 60s
    timeout: 30s
    max_streams: 10                  # Concurrent SSE streams
    allow_insecure: false            # Require HTTPS (set true for dev only)
    card_change_policy: alert        # alert | auto | approve
    health_check:
      enabled: true
      interval: 30s
```

---

## Reporting Vulnerabilities

Found a security issue in a2a-sentinel? Please report it responsibly:

### Email Disclosure

Send details to security@a2a-sentinel.dev (to be published):
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

**Do NOT**:
- Post vulnerability details publicly
- Open GitHub issues for security flaws
- Attempt unauthorized access to systems

### GitHub Security Advisory

Alternatively, use GitHub's private security advisory:
1. Go to https://github.com/vivars7/a2a-sentinel
2. Click "Security" → "Report a vulnerability"
3. Fill in details and submit

GitHub will notify maintainers privately. You'll receive updates as the issue is resolved.

### Responsible Disclosure Timeline

- **Day 0**: You report vulnerability
- **Day 1-7**: Maintainers acknowledge and begin investigation
- **Day 7-14**: Fix is developed and tested
- **Day 14-21**: Fix is released
- **Day 21+**: Public disclosure (CVE if applicable)

We appreciate your help securing a2a-sentinel for everyone.

---

## Further Reading

- **[README.md](../README.md)** — Quick start, features, architecture
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System architecture and request flow
- **[ERRORS.md](ERRORS.md)** — Error catalog and troubleshooting
- **[Configuration Reference](../sentinel.yaml.example)** — Full sentinel.yaml schema with all options
- **[A2A Protocol Spec](https://a2a-protocol.github.io/spec/)** — Official A2A specification

---

**Security ON by Default. Built for developers who want protection without complexity.**
