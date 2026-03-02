# Security Guide — a2a-sentinel

**a2a-sentinel is built on a principle: Security ON by Default.**

Every security feature is enabled out of the box. Disabling any protection requires explicit configuration. This guide explains the threat model, authentication modes, rate limiting strategy, and how to configure sentinel for your security requirements.

---

## Table of Contents

1. [Security Philosophy](#security-philosophy)
2. [Threat Model & Defenses](#threat-model--defenses)
3. [Authentication Modes](#authentication-modes)
4. [Rate Limiting (2-Layer)](#rate-limiting-2-layer)
5. [Policy Engine (ABAC)](#policy-engine-abac)
6. [Agent Card Security](#agent-card-security)
7. [Audit Logging](#audit-logging)
8. [Push Notification Protection](#push-notification-protection)
9. [Replay Attack Prevention](#replay-attack-prevention)
10. [Trusted Proxies](#trusted-proxies)
11. [Error Messages & Hints](#error-messages--hints)
12. [Configuration Reference](#configuration-reference)
13. [Reporting Vulnerabilities](#reporting-vulnerabilities)

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
| 5 | **Cache poisoning** | Attacker injects malicious card during polling | JWS signature verification | `security.card_signature.require` |
| 6 | **SSRF via push notifications** | Attacker tricks gateway into accessing private network | URL validation, private IP blocking, HTTPS enforcement | `security.push.block_private_networks` |
| 7 | **Replay attacks** | Attacker replays old requests to trigger actions | Nonce + timestamp validation (warn/require policies) | `security.replay.enabled` |
| 8 | **Man-in-middle** | Unencrypted communication with agents | TLS enforcement by default | `agents[].allow_insecure: false` |
| 9 | **Resource exhaustion** | Too many concurrent SSE streams per agent | Per-agent stream limit | `agents[].max_streams` |
| 10 | **Connection exhaustion** | Too many total gateway connections | Global connection limit | `listen.max_connections` |
| 11 | **Unauthorized agent access** | User accesses restricted agents or methods | ABAC policy engine with attribute-based rules | `security.policies[]` |
| 12 | **Off-hours exploitation** | Attacks during unmonitored periods | Time-based policy restrictions | `security.policies[].conditions.time` |

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

## Policy Engine (ABAC)

a2a-sentinel includes an attribute-based access control (ABAC) policy engine that evaluates rules after authentication. Policies provide fine-grained control over who can access which agents, methods, and resources, and when.

### How It Works

The PolicyGuard middleware sits in the security pipeline after authentication and user rate limiting. For each request, it:

1. Collects request attributes (source IP, authenticated user, target agent, A2A method, current time, HTTP headers)
2. Evaluates all matching policy rules in priority order (lowest number = highest priority)
3. First matching rule determines the outcome (allow or deny)
4. If no rule matches, the request is allowed (default-allow)

### Policy Structure

Each policy rule has:
- **name**: Human-readable identifier
- **priority**: Evaluation order (lower = evaluated first)
- **effect**: `allow` or `deny`
- **conditions**: Attribute matchers (all conditions in a rule must match for the rule to apply)

### Examples

#### IP-Based Blocking

Block requests from specific IP ranges. Supports CIDR notation and negation.

```yaml
security:
  policies:
    # Block all traffic from a known-bad network
    - name: block-bad-network
      priority: 10
      effect: deny
      conditions:
        source_ip:
          cidr: ["203.0.113.0/24", "198.51.100.0/24"]

    # Allow only corporate network, deny everything else
    - name: allow-corporate-only
      priority: 20
      effect: deny
      conditions:
        source_ip:
          not_cidr: ["10.0.0.0/8", "172.16.0.0/12"]
```

**CIDR negation**: Use `not_cidr` to match requests that are NOT from the specified ranges. This is useful for "allow only these networks" patterns.

---

#### Time-Based Restrictions

Restrict access to specific time windows. Useful for business-hours-only policies or maintenance windows.

```yaml
security:
  policies:
    # Deny access outside business hours (Eastern Time)
    - name: business-hours-only
      priority: 20
      effect: deny
      conditions:
        time:
          outside: "09:00-17:00"
          timezone: "America/New_York"

    # Deny access during maintenance window (UTC)
    - name: maintenance-window
      priority: 5
      effect: deny
      conditions:
        time:
          within: "02:00-04:00"
          timezone: "UTC"
          days: ["Saturday"]
```

**Time conditions**:
- `within`: Match requests during this time range
- `outside`: Match requests outside this time range
- `timezone`: IANA timezone (default "UTC")
- `days`: Optional day-of-week filter (Monday, Tuesday, etc.)

---

#### Agent-Specific Access Control

Restrict which users or IPs can access specific agents.

```yaml
security:
  policies:
    # Only admins can access the internal-agent
    - name: restrict-internal-agent
      priority: 30
      effect: deny
      conditions:
        agent: ["internal-agent"]
        user_not: ["admin@example.com", "ops@example.com"]

    # Block external IPs from accessing sensitive agent
    - name: sensitive-agent-internal-only
      priority: 25
      effect: deny
      conditions:
        agent: ["sensitive-agent"]
        source_ip:
          not_cidr: ["10.0.0.0/8"]
```

---

#### User-Based Rules

Control access based on authenticated user identity.

```yaml
security:
  policies:
    # Block a specific user
    - name: block-suspended-user
      priority: 10
      effect: deny
      conditions:
        user: ["suspended-user@example.com"]

    # Allow only specific users to use expensive methods
    - name: restrict-expensive-methods
      priority: 30
      effect: deny
      conditions:
        method: ["tasks/pushNotification/set"]
        user_not: ["premium-user@example.com", "admin@example.com"]
```

---

#### Method-Based Rules

Restrict specific A2A methods.

```yaml
security:
  policies:
    # Disable push notifications entirely
    - name: disable-push
      priority: 15
      effect: deny
      conditions:
        method: ["tasks/pushNotification/set", "tasks/pushNotification/get"]

    # Read-only mode: only allow message/send, block task management
    - name: read-only-mode
      priority: 20
      effect: deny
      conditions:
        method: ["tasks/cancel", "tasks/delete"]
```

---

#### Header-Based Rules

Match requests based on HTTP header values.

```yaml
security:
  policies:
    # Block requests without a specific custom header
    - name: require-team-header
      priority: 25
      effect: deny
      conditions:
        header_missing: ["X-Team-ID"]

    # Block requests from a specific client version
    - name: block-old-client
      priority: 20
      effect: deny
      conditions:
        header:
          User-Agent: ["OldClient/1.0*"]
```

---

### Policy Evaluation Order

Rules are evaluated in priority order (lowest number first). The first matching rule determines the outcome:

```
Request arrives after authentication
    ↓
Sort policies by priority (ascending)
    ↓
For each policy:
    ↓
    Check all conditions against request attributes
    ↓
    All conditions match?
        YES → Apply effect (allow/deny), STOP evaluation
        NO  → Continue to next policy
    ↓
No policy matched → DEFAULT ALLOW
```

**Example evaluation**:
```yaml
policies:
  - name: allow-admin          # priority: 10
    priority: 10
    effect: allow
    conditions:
      user: ["admin@example.com"]

  - name: block-bad-ip         # priority: 20
    priority: 20
    effect: deny
    conditions:
      source_ip:
        cidr: ["203.0.113.0/24"]

  - name: business-hours       # priority: 30
    priority: 30
    effect: deny
    conditions:
      time:
        outside: "09:00-17:00"
```

For a request from `admin@example.com` at 2 AM from IP `203.0.113.50`:
1. Check `allow-admin` (priority 10): user matches → **ALLOW** (stops here)

For a request from `user@example.com` at 2 AM from IP `203.0.113.50`:
1. Check `allow-admin` (priority 10): user does not match → skip
2. Check `block-bad-ip` (priority 20): IP matches CIDR → **DENY** (stops here)

---

### Policy Error Response

When a request is denied by a policy rule:

```json
{
  "error": {
    "code": 403,
    "message": "Request denied by policy",
    "hint": "Policy 'business-hours-only' denied this request. Contact admin for access",
    "docs_url": "https://a2a-sentinel.dev/docs/policies"
  }
}
```

The hint includes the policy name to help administrators identify which rule triggered the block.

---

### Hot-Reload of Policies

Policy rules are hot-reloadable. When the configuration is reloaded (via SIGHUP or file watch), policy rules are atomically swapped without dropping any in-flight requests.

```bash
# Edit sentinel.yaml to update policies, then:
kill -HUP $(pidof sentinel)

# Or use MCP tool:
MCP tool: reload_config
```

Changes take effect immediately. No restart required.

---

### MCP Tools for Policies

Two MCP tools are available for policy management:

**list_policies** — List all configured policies with their priority, effect, and conditions:
```
MCP tool: list_policies
```

**evaluate_policy** — Test policies against a simulated request context:
```
MCP tool: evaluate_policy {
  "source_ip": "203.0.113.50",
  "user": "test@example.com",
  "agent": "echo",
  "method": "message/send"
}
```

Returns which policy would match and whether the request would be allowed or denied.

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

#### 3. approve

**Behavior**: Store changes in pending queue. Manual approval via MCP tools. Keeps old card until approved.

When a card change is detected and the policy is `approve`:
1. New card is stored in the pending changes queue
2. Old card remains active
3. Audit log records pending change
4. Operator reviews via MCP tools: `list_pending_changes`, `approve_card_change`, `reject_card_change`
5. On approval, new card replaces the old one
6. On rejection, pending change is discarded

**Config**:
```yaml
agents:
  - name: my-agent
    card_change_policy: approve
```

**MCP approval workflow**:
```
# List pending changes
MCP tool: list_pending_changes

# Approve a specific change
MCP tool: approve_card_change { "agent": "my-agent" }

# Reject a specific change
MCP tool: reject_card_change { "agent": "my-agent" }
```

---

### JWS Signature Verification

**What**: Validate Agent Card signatures using the agent's JWK (JSON Web Key). When an agent serves its Agent Card as a JWS (JSON Web Signature) compact serialization, sentinel verifies the signature during polling to ensure the card has not been tampered with in transit.

**Default**: Not required. Optional but recommended for production deployments.

**Config**:
```yaml
security:
  card_signature:
    require: true
    trusted_jwks_urls:
      - https://agent.example.com/.well-known/jwks.json
    cache_ttl: 1h
```

**How it works**:
1. Agent Card Manager fetches the card from the backend agent
2. If the response body is a JWS compact serialization (three base64url-encoded segments separated by dots), sentinel treats it as a signed card
3. Sentinel fetches the agent's JWKS from the configured `trusted_jwks_urls`
4. The JWS signature is verified against the JWKS keyset
5. The JWS payload is extracted and used as the Agent Card JSON
6. JWKS keys are cached for the configured `cache_ttl` (default 1 hour) to avoid repeated fetches
7. If signature verification fails:
   - `require: true` — mark card unhealthy, keep previously cached card, log error
   - `require: false` — log warning, accept unsigned cards but verify signed ones

**Trusted JWKS URLs**: You can configure multiple JWKS endpoints. Sentinel will try each in order and accept the first successful verification. This supports key rotation scenarios where agents may publish new keys before retiring old ones.

**Error on verification failure**:
```json
{
  "error": {
    "code": 401,
    "message": "Agent Card signature verification failed",
    "hint": "Ensure the agent's JWKS endpoint is reachable and keys are valid",
    "docs_url": "https://a2a-sentinel.dev/docs/card-signature"
  }
}
```

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
| `policy_violation` | ABAC policy rule denied the request | 403 |

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

Push notifications allow agents to send updates to clients. However, they create an SSRF (Server-Side Request Forgery) vector if not validated. An attacker could trick the gateway into making requests to internal services by providing a push notification URL that resolves to a private network address.

### SSRF Defense: Private Network Blocking

**What**: Block push notification URLs that resolve to private networks. Sentinel validates all push notification URLs before making outbound requests.

**Default**: Enabled (`block_private_networks: true`)

**Config**:
```yaml
security:
  push:
    block_private_networks: true  # Block 10.x, 172.16-31.x, 192.168.x, 127.x, ::1
    allowed_domains: []           # Optional: whitelist specific domains
    require_https: true           # Require HTTPS for push URLs
    hmac_secret: ""               # Sign webhooks with HMAC-SHA256
```

**How it works**:
1. Client or agent provides a push notification URL
2. Sentinel parses the URL and extracts the hostname
3. The hostname is resolved to an IP address via DNS
4. The resolved IP is checked against blocked private network ranges
5. If the URL's hostname matches an entry in `allowed_domains`, it is permitted regardless of IP range
6. If HTTPS is required (`require_https: true`), non-HTTPS URLs are rejected
7. If all checks pass, the push notification request proceeds

**Blocked IP ranges**:
- `10.0.0.0/8` (Private — RFC 1918)
- `172.16.0.0/12` (Private — RFC 1918)
- `192.168.0.0/16` (Private — RFC 1918)
- `127.0.0.0/8` (Loopback — IPv4)
- `::1/128` (Loopback — IPv6)
- `169.254.0.0/16` (Link-local — IPv4)
- `fe80::/10` (Link-local — IPv6)
- `fc00::/7` (Unique local — IPv6)

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
2. Check hostname against `allowed_domains` — if match, allow immediately
3. Resolve hostname to IP address
4. If IP in private range → reject with `ErrSSRFBlocked`
   - DNS lookup failure: controlled by `dns_fail_policy` (default: `block` = fail-closed)
5. If `require_https: true` and scheme is not HTTPS → reject
6. Otherwise → allow

### HMAC Webhook Signing

Validate webhook authenticity with HMAC-SHA256 signatures:

```yaml
security:
  push:
    require_https: true
    hmac_secret: "sk_webhook_secret_key"
```

When `hmac_secret` is configured, sentinel signs outbound push notification requests with an `X-Sentinel-Signature` header containing the HMAC-SHA256 digest of the request body. Webhook receivers verify the signature to ensure the notification originated from sentinel.

---

## Replay Attack Prevention

Replay attacks: attacker records a valid request and resends it later to trigger unintended actions.

### Defense: Nonce + Timestamp Validation

**What**: Track unique nonces and validate request timestamps. Reject or warn on requests that have been seen before or are older than the configured window.

**Default**: Enabled

**Config**:
```yaml
security:
  replay:
    enabled: true
    window: 300s              # Accept requests ≤5 minutes old
    nonce_policy: warn        # warn | require
    nonce_source: auto        # auto | header | jsonrpc-id
    clock_skew: 5s            # Timestamp clock skew tolerance
    store: memory             # memory | redis
    redis_url: ""             # If store: redis
    cleanup_interval: 60s     # Cleanup expired nonces every 60s
```

**Nonce policies**:

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `warn` | Log warning if nonce already seen, but still allow the request | Early warning, gradual rollout |
| `require` | Reject the request if nonce already seen | Strict protection for production |

**Nonce sources** (`nonce_source`):

| Source | Behavior |
|--------|----------|
| `auto` (default) | Check `X-Sentinel-Nonce` header first, fall back to JSON-RPC `id` field |
| `header` | Only use `X-Sentinel-Nonce` header (ignore body) |
| `jsonrpc-id` | Only use JSON-RPC `id` field from request body |

**Timestamp validation**:

When the `X-Sentinel-Timestamp` header is present, sentinel validates that the request is within the replay window:

- Accepts **RFC3339** format (e.g., `2026-02-27T12:00:00Z`) or **Unix epoch** (10-digit, e.g., `1740657600`)
- Rejects if the timestamp is older than `window` (past) or more than `clock_skew` into the future
- Without the header, `time.Now()` is used (no timestamp validation)

**Flow**:

1. Client includes a unique nonce in the `X-Sentinel-Nonce` header and optionally a timestamp in the `X-Sentinel-Timestamp` header
2. Sentinel extracts nonce based on `nonce_source` configuration
3. If `X-Sentinel-Timestamp` header is present, validates timestamp freshness
4. Checks the nonce against the in-memory nonce store
5. If the nonce has been seen before:
   - `warn`: Log warning, forward request anyway (never blocks)
   - `require`: Reject with 429 error
6. If the nonce is new: record it in the store with expiry timestamp
7. A background goroutine periodically cleans up expired nonces based on `cleanup_interval`

**Memory management**: The in-memory nonce store uses a map with periodic cleanup. Entries older than `window` are purged every `cleanup_interval` to prevent unbounded memory growth.

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
X-Sentinel-Nonce: abc123def456xyz789     # Unique nonce (UUID recommended)
X-Sentinel-Timestamp: 2026-02-27T12:00:00Z  # Optional: request timestamp (RFC3339)
```

**Gateway validation**:
1. Extract timestamp → check within window (reject if too old)
2. Extract nonce (header > JSON-RPC id based on nonce_source)
3. If X-Sentinel-Timestamp present → validate timestamp freshness
4. If valid and new → record nonce, forward request
5. If duplicate nonce → warn or reject based on `nonce_policy`

**Example client code**:
```bash
NONCE=$(uuidgen)
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
curl -X POST http://localhost:8080/agents/echo/ \
  -H "X-Sentinel-Nonce: $NONCE" \
  -H "X-Sentinel-Timestamp: $TIMESTAMP" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": "1", "method": "message/send", ...}'
```

**Flush the nonce cache** (via MCP):
```
MCP tool: flush_replay_cache
```

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
    require: false          # Set true to require JWS-signed Agent Cards
    trusted_jwks_urls: []   # URLs to trusted agent JWKS endpoints
    cache_ttl: 1h           # Cache JWKS keys for this long

  # ── Policy Engine (ABAC) ──
  policies:
    - name: example-policy          # Human-readable name
      priority: 10                  # Evaluation order (lower = first)
      effect: deny                  # allow | deny
      conditions:
        source_ip:                  # IP-based conditions
          cidr: []                  # Match these CIDRs
          not_cidr: []              # Match if NOT in these CIDRs
        user: []                    # Match these users
        user_not: []                # Match if user NOT in this list
        agent: []                   # Match these agent names
        method: []                  # Match these A2A methods
        header:                     # Match header values (glob patterns)
          X-Custom: ["value*"]
        header_missing: []          # Match if these headers are absent
        time:
          within: ""                # Time range "HH:MM-HH:MM"
          outside: ""               # Outside time range
          timezone: "UTC"           # IANA timezone
          days: []                  # Day-of-week filter

  # ── Push Notification Protection ──
  push:
    block_private_networks: true    # Block private network push URLs (SSRF defense)
    allowed_domains: []             # Domains allowed even if resolving to private IPs
    require_https: true             # Require HTTPS for push notification URLs
    dns_fail_policy: block          # block (fail-closed) | allow (fail-open) on DNS failures
    require_challenge: false        # Require challenge verification
    hmac_secret: ""                 # Sign outbound webhooks with HMAC-SHA256

  # ── Replay Attack Prevention ──
  replay:
    enabled: true           # Enable nonce + timestamp replay detection
    window: 5m              # Accept requests within this time window
    nonce_policy: warn      # warn (log only) | require (reject duplicates)
    nonce_source: auto      # auto (header > id) | header | jsonrpc-id
    clock_skew: 5s          # Timestamp clock skew tolerance
    store: memory           # memory | redis
    redis_url: ""           # Redis URL if store: redis
    cleanup_interval: 60s   # Cleanup expired nonces at this interval
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
