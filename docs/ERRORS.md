# a2a-sentinel Error Reference

a2a-sentinel provides **educational error messages** for every block decision. Each error includes:
- **Code**: HTTP status code
- **Message**: Human-readable error description
- **Hint**: Actionable guidance to resolve the issue
- **DocsURL**: Link to relevant documentation

This guide covers all error types, their causes, and troubleshooting steps.

---

## Error Response Format

### HTTP Response

When an error occurs in a regular HTTP request, sentinel returns a JSON error response with the HTTP status code set to the error code:

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

**Response header:**
```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
```

### JSON-RPC 2.0 Response

When the request is a JSON-RPC method call, sentinel returns a JSON-RPC error response with the error data embedded in the `data` field. HTTP status codes are mapped to JSON-RPC error codes:

```json
{
  "jsonrpc": "2.0",
  "id": "request-id",
  "error": {
    "code": -32600,
    "message": "Rate limit exceeded",
    "data": {
      "code": 429,
      "message": "Rate limit exceeded",
      "hint": "Wait before retrying. Configure security.rate_limit in sentinel.yaml",
      "docs_url": "https://a2a-sentinel.dev/docs/rate-limit"
    }
  }
}
```

The `data` field contains the full SentinelError object, including the hint and docs_url. This allows clients to display educational messages even in JSON-RPC contexts.

---

## Error Catalog

### Authentication & Authorization

#### ErrAuthRequired

| Field | Value |
|-------|-------|
| **HTTP Code** | 401 |
| **Message** | Authentication required |
| **Hint** | Set Authorization header: 'Bearer <token>' |
| **DocsURL** | https://a2a-sentinel.dev/docs/auth |

**When it occurs:**
- No `Authorization` header is present
- Security authentication is enabled and the request is not authenticated

**Example error response:**
```json
{
  "error": {
    "code": 401,
    "message": "Authentication required",
    "hint": "Set Authorization header: 'Bearer <token>'",
    "docs_url": "https://a2a-sentinel.dev/docs/auth"
  }
}
```

**How to fix:**
1. Add an `Authorization` header to your request:
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8080/agents/myagent/
   ```
2. If developing locally, you can disable authentication with `security.auth.mode: passthrough` in `sentinel.yaml`, or set `allow_unauthenticated: true` (not recommended for production)
3. Ensure your token is valid and not expired

---

#### ErrAuthInvalid

| Field | Value |
|-------|-------|
| **HTTP Code** | 401 |
| **Message** | Invalid authentication token |
| **Hint** | Check token expiry and issuer |
| **DocsURL** | https://a2a-sentinel.dev/docs/auth |

**When it occurs:**
- Token is malformed or cannot be parsed
- Token signature is invalid
- Token has expired
- Token issuer does not match configuration

**Example error response:**
```json
{
  "error": {
    "code": 401,
    "message": "Invalid authentication token",
    "hint": "Check token expiry and issuer",
    "docs_url": "https://a2a-sentinel.dev/docs/auth"
  }
}
```

**How to fix:**
1. Verify the token is still valid (not expired)
2. Check the token's `iss` (issuer) claim matches your configuration
3. Ensure the token was signed with the correct key
4. For JWT tokens, decode and inspect claims:
   ```bash
   # Decode JWT (for debugging only)
   echo $TOKEN | jq -R 'split(".") | .[1] | @base64d | fromjson'
   ```
5. See [Authentication Configuration](../docs/SECURITY.md#authentication) for setup details

---

#### ErrCardSignatureInvalid

| Field | Value |
|-------|-------|
| **HTTP Code** | 401 |
| **Message** | Agent Card signature verification failed |
| **Hint** | Ensure the agent's JWKS endpoint is reachable and keys are valid |
| **DocsURL** | https://a2a-sentinel.dev/docs/card-signature |

**When it occurs:**
- Agent Card is served as a JWS compact serialization but signature verification fails
- JWKS endpoint is unreachable or returns invalid keys
- The signing key has been rotated but the JWKS endpoint has not been updated
- `security.card_signature.require` is `true` and the card is unsigned

**Example error response:**
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

**How to fix:**
1. **Verify JWKS endpoint**: Check that the agent's JWKS URL is reachable
   ```bash
   curl https://agent.example.com/.well-known/jwks.json | jq .
   ```
2. **Check key validity**: Ensure the signing key ID (`kid`) in the JWS header matches a key in the JWKS
3. **Verify configuration**: Check `security.card_signature.trusted_jwks_urls` in sentinel.yaml:
   ```yaml
   security:
     card_signature:
       require: true
       trusted_jwks_urls:
         - https://agent.example.com/.well-known/jwks.json
       cache_ttl: 1h
   ```
4. **Disable requirement**: If JWS is not needed, set `require: false` (not recommended for production)
5. See [JWS Signature Verification](./SECURITY.md#jws-signature-verification) for details

---

#### ErrForbidden

| Field | Value |
|-------|-------|
| **HTTP Code** | 403 |
| **Message** | Access denied |
| **Hint** | Check agent permissions and scope configuration |
| **DocsURL** | https://a2a-sentinel.dev/docs/security |

**When it occurs:**
- Request is authenticated but lacks required permissions
- Token scope does not allow access to the requested agent
- Agent Card forbids the request
- Client IP is not in allowlist (if configured)

**Example error response:**
```json
{
  "error": {
    "code": 403,
    "message": "Access denied",
    "hint": "Check agent permissions and scope configuration",
    "docs_url": "https://a2a-sentinel.dev/docs/security"
  }
}
```

**How to fix:**
1. Verify the token has the required scope for the agent
2. Check the Agent Card permissions (via `GET /.well-known/agent.json`)
3. If using IP-based restrictions, verify your client IP is in the allowlist
4. Review your security configuration in `sentinel.yaml` under `security.auth`
5. See [Security Configuration](../docs/SECURITY.md) for detailed setup

---

### Rate Limiting

#### ErrRateLimited

| Field | Value |
|-------|-------|
| **HTTP Code** | 429 |
| **Message** | Rate limit exceeded |
| **Hint** | Wait before retrying. Configure security.rate_limit in sentinel.yaml |
| **DocsURL** | https://a2a-sentinel.dev/docs/rate-limit |

**When it occurs:**
- Request rate exceeds IP-based limit (pre-authentication)
- Request rate exceeds user-based limit (post-authentication)
- A burst of requests exhausts the rate limit bucket

**Example error response:**
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

**How to fix:**
1. **Wait and retry**: Implement exponential backoff in your client
   ```bash
   # Retry after 30 seconds
   sleep 30
   curl http://localhost:8080/agents/myagent/
   ```
2. **Check your limits**: Review your configuration:
   ```yaml
   security:
     rate_limit:
       ip:
         per_minute: 100      # Requests per minute per IP
       user:
         per_minute: 500      # Requests per minute per user
   ```
3. **Increase limits**: If you need higher throughput, adjust the config:
   ```yaml
   security:
     rate_limit:
       ip:
         per_minute: 1000     # Increase IP limit
       user:
         per_minute: 5000     # Increase user limit
   ```
4. **Distribute load**: If hitting limits legitimately, consider:
   - Using connection pools and batch requests
   - Scaling sentinel horizontally (run multiple instances)
   - Using separate rate limit buckets per service

See [Rate Limiting Configuration](../docs/SECURITY.md#rate-limiting) for advanced options.

---

#### ErrStreamLimitExceeded

| Field | Value |
|-------|-------|
| **HTTP Code** | 429 |
| **Message** | Too many concurrent streams |
| **Hint** | Max streams per agent reached. Configure agents[].max_streams |
| **DocsURL** | https://a2a-sentinel.dev/docs/streaming |

**When it occurs:**
- Too many concurrent SSE streams are open to the same agent
- Agent's `max_streams` limit is reached
- Stream limit is enforced per-agent to prevent resource exhaustion

**Example error response:**
```json
{
  "error": {
    "code": 429,
    "message": "Too many concurrent streams",
    "hint": "Max streams per agent reached. Configure agents[].max_streams",
    "docs_url": "https://a2a-sentinel.dev/docs/streaming"
  }
}
```

**How to fix:**
1. **Close unused streams**: Ensure previous SSE connections are properly closed
2. **Check active streams**: Monitor the number of concurrent streams to the agent
3. **Increase the limit** in `sentinel.yaml`:
   ```yaml
   agents:
     - name: myagent
       url: http://agent:8000
       max_streams: 1000     # Increase from default 100
   ```
4. **Load balance**: Distribute SSE connections across multiple agent instances
5. See [Streaming Configuration](./ARCHITECTURE.md#sse-proxy) for details

---

### Protocol & Validation

#### ErrInvalidRequest

| Field | Value |
|-------|-------|
| **HTTP Code** | 400 |
| **Message** | Invalid request format |
| **Hint** | Check A2A protocol specification for correct message format |
| **DocsURL** | https://a2a-sentinel.dev/docs/protocol |

**When it occurs:**
- Request body is malformed JSON
- Message format does not conform to A2A protocol
- Required fields are missing
- Body size exceeds configured limit

**Example error response:**
```json
{
  "error": {
    "code": 400,
    "message": "Invalid request format",
    "hint": "Check A2A protocol specification for correct message format",
    "docs_url": "https://a2a-sentinel.dev/docs/protocol"
  }
}
```

**How to fix:**
1. **Validate JSON**: Ensure your request body is valid JSON
   ```bash
   # Test JSON validity
   echo '{"jsonrpc": "2.0", "id": "1", "method": "message/send"}' | jq .
   ```
2. **Check A2A protocol**: Verify message format against [A2A Protocol Specification](https://a2a.dev)
3. **Include required fields**: Common required fields:
   - `jsonrpc`: "2.0"
   - `id`: Request identifier (string or number)
   - `method`: Method name (e.g., "message/send")
   - `params`: Method parameters
4. **Check body size**: If body is too large, increase the limit in `sentinel.yaml`:
   ```yaml
   listen:
     max_body_size: 10MB    # Increase from default 1MB
   ```
5. See [A2A Protocol](./ARCHITECTURE.md#a2a-protocol) for message format examples

---

#### ErrReplayDetected

| Field | Value |
|-------|-------|
| **HTTP Code** | 429 |
| **Message** | Replay attack detected |
| **Hint** | (varies by cause — see below) |
| **DocsURL** | https://a2a-sentinel.dev/docs/replay-protection |

**When it occurs:**
- Same request nonce is sent multiple times (duplicate nonce detected)
- Timestamp is too old — exceeds `window` (default 300s)
- Timestamp is too far in the future — exceeds `clock_skew` (default 5s)

#### ErrMissingReplayNonce

| Field | Value |
|-------|-------|
| **HTTP Code** | 400 |
| **Message** | Missing replay nonce |
| **Hint** | Include X-Sentinel-Nonce header or a JSON-RPC id field. |
| **DocsURL** | https://a2a-sentinel.dev/docs/replay-protection |

**When it occurs:**
- `nonce_policy: require` is set but the request has no nonce (no `X-Sentinel-Nonce` header and no JSON-RPC `id` field)
- Request body could not be read for nonce extraction in `require` mode

**Example error responses:**
```json
{
  "error": {
    "code": 429,
    "message": "Replay attack detected",
    "hint": "Request ID already seen within replay window. Use unique IDs for each request.",
    "docs_url": "https://a2a-sentinel.dev/docs/replay-protection"
  }
}
```

```json
{
  "error": {
    "code": 400,
    "message": "Missing replay nonce",
    "hint": "Include X-Sentinel-Nonce header or a JSON-RPC id field.",
    "docs_url": "https://a2a-sentinel.dev/docs/replay-protection"
  }
}
```

**How to fix:**
1. **Use unique nonce**: Generate a unique, non-repeating identifier for each request
   ```bash
   NONCE=$(uuidgen)
   curl -X POST http://localhost:8080/agents/myagent/ \
     -H "X-Sentinel-Nonce: $NONCE" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc": "2.0", "id": "1", ...}'
   ```
2. **Include timestamp**: Add current timestamp to the request
   ```bash
   TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   curl -X POST http://localhost:8080/agents/myagent/ \
     -H "X-Sentinel-Timestamp: $TIMESTAMP" \
     ...
   ```
3. **Verify nonce uniqueness**: Never reuse the same nonce
4. **Check timestamp freshness**: Ensure your system clock is synchronized (NTP)
5. **Timestamp rules**: Past timestamps accepted within `window` (default 300s), future timestamps within `clock_skew` (default 5s)
6. See [Replay Protection](../docs/SECURITY.md#replay-protection) for configuration

---

### Security Blocks

#### ErrSSRFBlocked

| Field | Value |
|-------|-------|
| **HTTP Code** | 403 |
| **Message** | Push notification URL blocked |
| **Hint** | URL resolves to private network. Use public URLs or configure security.push.allowed_domains |
| **DocsURL** | https://a2a-sentinel.dev/docs/ssrf |

**When it occurs:**
- Push notification URL resolves to a private IP address (10.x, 172.16-31.x, 192.168.x, 127.x, ::1)
- URL points to internal services that should not be accessible
- SSRF (Server-Side Request Forgery) protection is enabled

**Example error response:**
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

**How to fix:**
1. **Use public URLs**: Replace private IPs with public domains
   ```bash
   # Instead of: http://192.168.1.100:8080/webhook
   # Use: https://webhook.example.com/notify
   ```
2. **Configure allowlist**: If you need to allow specific private URLs, add them to the allowlist in `sentinel.yaml`:
   ```yaml
   security:
     push:
       allowed_domains:
         - "internal-webhook.example.com"
         - "10.0.0.0/8"       # Allow entire private subnet
   ```
3. **Use tunneling**: If you must reach private services, use a tunnel or reverse proxy
4. **Check DNS resolution**: Verify the URL resolves correctly:
   ```bash
   nslookup webhook.example.com
   ```
5. See [SSRF Protection](../docs/SECURITY.md#ssrf-protection) for detailed configuration

---

#### ErrMCPUnauthorized

| Field | Value |
|-------|-------|
| **HTTP Code** | 403 |
| **Message** | MCP operation unauthorized |
| **Hint** | Provide a valid MCP auth token. Configure mcp.auth_token in sentinel.yaml |
| **DocsURL** | https://a2a-sentinel.dev/docs/mcp |

**When it occurs:**
- A write operation is attempted on the MCP server without a valid auth token
- The MCP auth token does not match the configured token
- A destructive MCP tool (e.g., `reload_config`, `rotate_api_key`) is called without authorization

**Example error response:**
```json
{
  "error": {
    "code": 403,
    "message": "MCP operation unauthorized",
    "hint": "Provide a valid MCP auth token. Configure mcp.auth_token in sentinel.yaml",
    "docs_url": "https://a2a-sentinel.dev/docs/mcp"
  }
}
```

**How to fix:**
1. **Provide auth token**: Include the MCP auth token in your request
2. **Check configuration**: Verify the token matches what is configured:
   ```yaml
   mcp:
     enabled: true
     port: 8081
     auth_token: "your-mcp-token"
   ```
3. **Read-only tools**: Some MCP tools (e.g., `list_agents`, `health_check`) do not require auth tokens
4. See the MCP server section in [ARCHITECTURE.md](./ARCHITECTURE.md#mcpserver--mcp-management-server) for details

---

#### ErrCardChangePending

| Field | Value |
|-------|-------|
| **HTTP Code** | 202 |
| **Message** | Agent Card change pending approval |
| **Hint** | Card change detected and queued for approval. Use MCP tools to approve or reject |
| **DocsURL** | https://a2a-sentinel.dev/docs/card-approval |

**When it occurs:**
- An agent's card change policy is set to `approve`
- A new Agent Card is detected during polling that differs from the cached version
- The change is stored in the pending queue awaiting manual approval

**Example audit log entry:**
```json
{
  "timestamp": "2026-02-27T12:34:56Z",
  "level": "warn",
  "msg": "agent_card_change_pending",
  "agent": "my-agent",
  "policy": "approve",
  "changes": 3,
  "critical": true
}
```

**How to resolve:**
1. **List pending changes**: Use the MCP tool to see what changed
   ```
   MCP tool: list_pending_changes
   ```
2. **Review changes**: Inspect the diff between old and new Agent Card
3. **Approve or reject**: Use MCP tools to take action
   ```
   MCP tool: approve_card_change { "agent": "my-agent" }
   MCP tool: reject_card_change { "agent": "my-agent" }
   ```
4. **Change policy**: If manual approval is not needed, set `card_change_policy: auto`:
   ```yaml
   agents:
     - name: my-agent
       card_change_policy: auto
   ```
5. See [Card Change Approve Mode](./SECURITY.md#3-approve) for details

---

#### ErrPolicyViolation

| Field | Value |
|-------|-------|
| **HTTP Code** | 403 |
| **JSON-RPC Code** | -32001 |
| **Message** | Request denied by policy |
| **Hint** | Policy '{policy_name}' denied this request. Contact admin for access |
| **DocsURL** | https://a2a-sentinel.dev/docs/policies |

**When it occurs:**
- A request matches a `deny` rule in the ABAC policy engine
- The policy conditions (IP, user, agent, method, time, headers) matched the request attributes
- The matching rule has the highest priority (lowest number) among all matching rules

**Example error response:**
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

**JSON-RPC error response:**
```json
{
  "jsonrpc": "2.0",
  "id": "request-id",
  "error": {
    "code": -32001,
    "message": "Request denied by policy",
    "data": {
      "code": 403,
      "message": "Request denied by policy",
      "hint": "Policy 'business-hours-only' denied this request. Contact admin for access",
      "docs_url": "https://a2a-sentinel.dev/docs/policies"
    }
  }
}
```

**How to fix:**
1. **Identify the policy**: The hint includes the policy name that blocked the request
2. **Check policy conditions**: Review the policy in `sentinel.yaml`:
   ```yaml
   security:
     policies:
       - name: business-hours-only
         priority: 20
         effect: deny
         conditions:
           time:
             outside: "09:00-17:00"
   ```
3. **Test policies**: Use the MCP tool to evaluate policies against a simulated request:
   ```
   MCP tool: evaluate_policy {
     "source_ip": "203.0.113.50",
     "user": "test@example.com",
     "agent": "echo",
     "method": "message/send"
   }
   ```
4. **Update policies**: Modify conditions or add an allow rule with higher priority (lower number)
5. **Reload**: Send SIGHUP or use `reload_config` MCP tool to apply changes without restart
6. See [Policy Engine](./SECURITY.md#policy-engine-abac) for full documentation

---

### Agent & Routing

#### ErrNoRoute

| Field | Value |
|-------|-------|
| **HTTP Code** | 404 |
| **Message** | No matching agent found |
| **Hint** | Check routing path or set a default agent |
| **DocsURL** | https://a2a-sentinel.dev/docs/routing |

**When it occurs:**
- Request path does not match any configured agent
- Routing mode is `single` but path is not correct
- Routing mode is `path-prefix` but no agent matches the prefix
- No default agent is configured

**Example error response:**
```json
{
  "error": {
    "code": 404,
    "message": "No matching agent found",
    "hint": "Check routing path or set a default agent",
    "docs_url": "https://a2a-sentinel.dev/docs/routing"
  }
}
```

**How to fix:**
1. **Check configured agents**: List your agents in `sentinel.yaml`:
   ```yaml
   agents:
     - name: echo-agent
       url: http://localhost:8001
     - name: llm-agent
       url: http://localhost:8002
   ```
2. **Verify routing mode**: Check the routing configuration:
   ```yaml
   routing:
     mode: path-prefix    # or 'single'
   ```
3. **Use correct path**: Request the correct agent path
   ```bash
   # For path-prefix routing:
   curl http://localhost:8080/agents/echo-agent/

   # For single routing (no path needed):
   curl http://localhost:8080/
   ```
4. **Set a default agent**: Configure a fallback for unmatched routes:
   ```yaml
   routing:
     default_agent: echo-agent
   ```
5. **Check agent health**: Verify agents are running and registered:
   ```bash
   curl http://localhost:8080/readyz | jq .
   ```
6. See [Routing Configuration](./ARCHITECTURE.md#routing) for details

---

#### ErrAgentUnavailable

| Field | Value |
|-------|-------|
| **HTTP Code** | 503 |
| **Message** | Target agent unavailable |
| **Hint** | Check agent health with GET /readyz |
| **DocsURL** | https://a2a-sentinel.dev/docs/agents |

**When it occurs:**
- Agent is offline or not responding
- Agent connection cannot be established
- Agent failed health check
- Agent is overloaded or timing out

**Example error response:**
```json
{
  "error": {
    "code": 503,
    "message": "Target agent unavailable",
    "hint": "Check agent health with GET /readyz",
    "docs_url": "https://a2a-sentinel.dev/docs/agents"
  }
}
```

**How to fix:**
1. **Check agent health**: Use the readiness endpoint
   ```bash
   curl http://localhost:8080/readyz | jq .
   # Response: {"status":"ready","healthy_agents":2,"total_agents":2}
   ```
2. **Verify agent is running**: Check the agent's health endpoint directly
   ```bash
   curl http://localhost:8001/healthz
   ```
3. **Check connectivity**: Verify sentinel can reach the agent
   ```bash
   # From sentinel container
   curl http://agent-host:8001/
   ```
4. **Review logs**: Check sentinel and agent logs for errors
   ```bash
   docker compose logs sentinel
   docker compose logs echo-agent
   ```
5. **Check configuration**: Ensure agent URL is correct in `sentinel.yaml`:
   ```yaml
   agents:
     - name: echo-agent
       url: http://echo-agent:8001    # Verify hostname/port
   ```
6. **Retry with backoff**: Implement client-side retry logic for transient failures
7. See [Agent Configuration](./ARCHITECTURE.md#agent-configuration) for setup

---

### Gateway Limits

#### ErrGlobalLimitReached

| Field | Value |
|-------|-------|
| **HTTP Code** | 503 |
| **Message** | Gateway capacity reached |
| **Hint** | Gateway is at maximum connections. Try again shortly |
| **DocsURL** | https://a2a-sentinel.dev/docs/limits |

**When it occurs:**
- Total concurrent connections to sentinel exceed the configured limit
- Too many requests are queued
- System resources are exhausted

**Example error response:**
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

**How to fix:**
1. **Increase connection limit**: Adjust in `sentinel.yaml`:
   ```yaml
   listen:
     max_connections: 1000   # Increase from default 500
   ```
2. **Scale horizontally**: Run multiple sentinel instances behind a load balancer
   ```bash
   docker compose up -d --scale sentinel=3
   ```
3. **Reduce connection duration**: Ensure clients close connections promptly
   ```bash
   # Add connection timeout
   curl --max-time 30 http://localhost:8080/agents/myagent/
   ```
4. **Monitor usage**: Track active connections
   ```bash
   # Check via MCP server (read-only)
   curl http://localhost:9999/connections
   ```
5. **Optimize agent responses**: Faster agent responses free up connections sooner
6. See [Gateway Configuration](./ARCHITECTURE.md#gateway-configuration) for tuning

---

## JSON-RPC Error Code Mapping

When a SentinelError is converted to a JSON-RPC error response, the HTTP status code is mapped to a JSON-RPC error code:

| HTTP Status | JSON-RPC Code | JSON-RPC Meaning | Examples |
|---|---|---|---|
| 202 | — | (Not an error) | ErrCardChangePending (audit log only) |
| 400 | -32600 | Invalid Request | ErrInvalidRequest |
| 401 | -32600 | Invalid Request | ErrAuthRequired, ErrAuthInvalid, ErrCardSignatureInvalid |
| 403 | -32001 | Policy violation | ErrPolicyViolation |
| 403 | -32600 | Invalid Request | ErrForbidden, ErrSSRFBlocked, ErrMCPUnauthorized |
| 404 | -32601 | Method not found | ErrNoRoute |
| 409 | -32600 | Invalid Request | ErrReplayDetected |
| 429 | -32600 | Invalid Request | ErrRateLimited, ErrStreamLimitExceeded |
| 503 | -32603 | Internal error | ErrAgentUnavailable, ErrGlobalLimitReached |

**Note:** The original HTTP code is preserved in the `data.code` field of the JSON-RPC error response, allowing clients to make decisions based on the actual HTTP status.

**Policy violations** use the dedicated JSON-RPC code `-32001` (distinct from the general `-32600` used by other 403 errors) to allow clients to distinguish policy denials from other authorization failures.

---

## gRPC Error Code Mapping

When sentinel handles gRPC requests, errors are mapped between gRPC status codes, HTTP status codes, and JSON-RPC error codes. The educational `hint` and `docs_url` are included in the gRPC `Status.details` field.

### gRPC → HTTP/JSON-RPC

| gRPC Code | HTTP Status | JSON-RPC Code | When |
|-----------|-------------|---------------|------|
| `OK` (0) | 200 | — | Successful request |
| `CANCELLED` (1) | 499 | -32600 | Client cancelled the request |
| `INVALID_ARGUMENT` (3) | 400 | -32600 | Malformed request (bad proto, missing fields) |
| `NOT_FOUND` (5) | 404 | -32601 | No matching agent route |
| `ALREADY_EXISTS` (6) | 409 | -32600 | Replay attack detected |
| `PERMISSION_DENIED` (7) | 403 | -32001 | Policy violation or access denied |
| `RESOURCE_EXHAUSTED` (8) | 429 | -32600 | Rate limit exceeded |
| `UNAUTHENTICATED` (16) | 401 | -32600 | Missing or invalid credentials |
| `UNAVAILABLE` (14) | 503 | -32603 | Agent unavailable or gateway overloaded |
| `INTERNAL` (13) | 500 | -32603 | Internal server error |

### HTTP → gRPC (reverse mapping)

When sentinel translates backend HTTP responses to gRPC:

| HTTP Status | gRPC Code | Notes |
|-------------|-----------|-------|
| 200 | `OK` | Successful response |
| 400 | `INVALID_ARGUMENT` | Request validation failure |
| 401 | `UNAUTHENTICATED` | Authentication required or invalid |
| 403 | `PERMISSION_DENIED` | Policy denial or forbidden |
| 404 | `NOT_FOUND` | No route or agent not found |
| 408 | `DEADLINE_EXCEEDED` | Backend request timeout |
| 409 | `ALREADY_EXISTS` | Replay detection |
| 429 | `RESOURCE_EXHAUSTED` | Rate limit hit |
| 500 | `INTERNAL` | Backend internal error |
| 502 | `UNAVAILABLE` | Backend unreachable |
| 503 | `UNAVAILABLE` | Gateway or backend overloaded |

### gRPC Error Response Format

```
Status {
  code: PERMISSION_DENIED
  message: "Request denied by policy"
  details: [
    ErrorInfo {
      reason: "POLICY_VIOLATION"
      domain: "a2a-sentinel"
      metadata: {
        "hint": "Policy 'business-hours-only' denied this request. Contact admin for access"
        "docs_url": "https://a2a-sentinel.dev/docs/policies"
        "policy_name": "business-hours-only"
      }
    }
  ]
}
```

The `ErrorInfo.metadata` map preserves sentinel's educational error fields (hint, docs_url) across the gRPC protocol boundary.

---

## Error Handling Best Practices

### Client Implementation

**Implement exponential backoff for transient errors:**
```go
import "time"

func sendWithRetry(ctx context.Context, req *http.Request, maxRetries int) (*http.Response, error) {
    for i := 0; i < maxRetries; i++ {
        resp, err := http.DefaultClient.Do(req)
        if err != nil {
            return nil, err
        }

        // Success
        if resp.StatusCode < 400 {
            return resp, nil
        }

        // Transient errors: 429 (rate limited), 503 (unavailable)
        if resp.StatusCode == 429 || resp.StatusCode == 503 {
            backoff := time.Duration(math.Pow(2, float64(i))) * time.Second
            select {
            case <-time.After(backoff):
                continue
            case <-ctx.Done():
                return nil, ctx.Err()
            }
        }

        // Permanent errors: 400, 401, 403, 404
        return resp, fmt.Errorf("request failed: %d", resp.StatusCode)
    }
    return nil, fmt.Errorf("max retries exceeded")
}
```

### Displaying Educational Messages

**Extract and display hints to users:**
```go
type SentinelError struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
    Hint    string `json:"hint"`
    DocsURL string `json:"docs_url"`
}

func handleError(respBody []byte) {
    var errResp struct {
        Error SentinelError `json:"error"`
    }
    if err := json.Unmarshal(respBody, &errResp); err != nil {
        log.Fatalf("Failed to parse error: %v", err)
    }

    // Display user-friendly message with hint
    fmt.Printf("Error: %s\n", errResp.Error.Message)
    if errResp.Error.Hint != "" {
        fmt.Printf("Tip: %s\n", errResp.Error.Hint)
    }
    if errResp.Error.DocsURL != "" {
        fmt.Printf("Learn more: %s\n", errResp.Error.DocsURL)
    }
}
```

### Logging & Debugging

**Log errors with context:**
```go
import "log/slog"

slog.Error("request failed",
    "code", errResp.Error.Code,
    "message", errResp.Error.Message,
    "hint", errResp.Error.Hint,
    "url", errResp.Error.DocsURL,
)
```

---

## Configuration Reference

### Rate Limiting

```yaml
security:
  rate_limit:
    ip:
      per_minute: 100        # Requests per minute per IP address
    user:
      per_minute: 500        # Requests per minute per authenticated user
```

### Connection Limits

```yaml
listen:
  max_connections: 500       # Maximum concurrent connections
  max_body_size: 1MB         # Maximum request body size
```

### Agent Streaming

```yaml
agents:
  - name: myagent
    url: http://agent:8000
    max_streams: 100         # Maximum concurrent SSE streams
```

### SSRF Protection

```yaml
security:
  push:
    allowed_domains:
      - "webhook.example.com"
      - "10.0.0.0/8"
      - "fd00::/8"           # IPv6 private
```

---

## Related Documentation

- **[SECURITY.md](./SECURITY.md)** — Security configuration, authentication, rate limiting
- **[ARCHITECTURE.md](./ARCHITECTURE.md)** — Architecture, protocol details, configuration schema
- **[README.md](../README.md)** — Quick start guide and feature overview
- **[A2A Protocol](https://a2a.dev)** — Official Agent-to-Agent protocol specification
