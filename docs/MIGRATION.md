# Migration to agentgateway

When you're ready to move from a2a-sentinel to production infrastructure, agentgateway (Solo.io) is your zero-friction migration path.

**The core principle: Your agents don't change.** Both sentinel and agentgateway implement the same A2A protocol and expect the same Agent Card format. Migration is a gateway swap, not an agent rewrite.

---

## Why Migrate?

a2a-sentinel was designed as your on-ramp to A2A security. As your deployment evolves, agentgateway becomes the natural next step.

### Stay with sentinel

| Scenario | Reason |
|----------|--------|
| Single developer or small team | You own the infrastructure |
| Docker Compose or single binary | Your deployment is simple |
| Fewer than 10 agents | Single gateway handles your scale |
| Development or testing | You're not running production workloads |
| Simple authentication | API keys or passthrough modes are sufficient |
| Basic rate limiting | Per-IP and per-user limits meet your needs |

### Migrate to agentgateway

| Scenario | Reason |
|----------|--------|
| Platform or infrastructure team | You manage multiple teams' agents |
| Kubernetes native deployment | You want cloud-native patterns |
| 10+ agents across multiple services | Scale requires better resource isolation |
| Production at scale | You need 99.9%+ uptime and observability |
| Advanced authentication | mTLS, OPA policies, or custom auth flows |
| Multi-tenant workloads | You need strict isolation between organizations |

---

## What Transfers (Zero Agent Changes)

These work identically in both gateways:

### 1. A2A Protocol Messages

Your agents send JSON-RPC, REST, or SSE requests. agentgateway understands them the same way:

```bash
# Works in sentinel
curl -X POST http://localhost:8080/agents/echo/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": "1", "method": "message/send", ...}'

# Works in agentgateway (same curl command)
curl -X POST http://gateway.prod.example.com/agents/echo/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": "1", "method": "message/send", ...}'
```

### 2. Agent Card Format

Your agents' `/.well-known/agent.json` is agentgateway's source of truth. No changes needed:

```json
{
  "type": "agent",
  "name": "echo",
  "capabilities": ["message/send"],
  "instructions": "Echo back the user message",
  "tools": [...]
}
```

agentgateway fetches and caches this exactly as sentinel does.

### 3. Audit Log Field Names

Both use OpenTelemetry semantic convention:
- `http_method`, `http_target`
- `user_id`, `agent_name`
- `timestamp`, `decision`, `reason`

Your observability dashboards work unchanged.

### 4. Authentication Headers

If you use JWT or API keys in sentinel:

```bash
curl -H "Authorization: Bearer $TOKEN" http://sentinel:8080/agents/echo/
```

agentgateway accepts the same headers. The auth policy moves to a CRD, but the wire protocol is identical.

---

## Configuration Mapping

### sentinel.yaml Structure

```yaml
agents:
  - name: echo
    url: http://echo-agent:9000
    default: true

security:
  auth:
    mode: jwt
    issuer: https://auth.example.com
    audience: api.example.com
  rate_limit:
    enabled: true
    user:
      per_user: 100
      burst: 10

routing:
  mode: path-prefix

logging:
  format: json
  level: info
```

### agentgateway Equivalents

| sentinel | agentgateway | Location | Notes |
|----------|---|---|---|
| `agents[].name` | Agent name in registration | K8s Service or deployment label | Register via helm/kubectl |
| `agents[].url` | Backend service URL | K8s Service DNS | `http://echo-agent:9000` → `http://echo-agent.default.svc.cluster.local:9000` |
| `agents[].default` | Default agent routing | `RoutePolicy` CRD with catch-all | Path-based or header-based routing |
| `security.auth.mode: jwt` | `AuthPolicy` CRD | `kind: AuthPolicy` | Specify issuer, audience, JWKS URL |
| `security.auth.issuer` | `AuthPolicy.spec.issuer` | K8s CRD | Same value |
| `security.rate_limit` | `RateLimit` CRD or Envoy filter | K8s CRD | Per-user limits via Envoy config |
| `routing.mode: path-prefix` | `RoutePolicy` CRD | K8s CRD | `/agents/{name}/` → service routing |
| `logging.format: json` | Observability integration | Datadog/Prometheus scrape | Enable JSON logs in deployment |

---

## Migration Steps

### Step 1: Prepare agentgateway Environment

If you're not familiar with agentgateway, start here:
- [agentgateway GitHub](https://github.com/solo-io/agentgateway)
- [agentgateway Quickstart](https://docs.agentgateway.dev/quickstart)

Minimum prerequisites:
- Kubernetes cluster (v1.24+)
- kubectl access
- Helm 3+

### Step 2: Export Your sentinel Configuration

Today (v0.1), export is manual. The `sentinel migrate` tool is planned for v0.2.

**For now:** Keep your `sentinel.yaml` open and refer to the [Configuration Mapping](#configuration-mapping) table.

```bash
# Print your current config for reference
cat sentinel.yaml
```

### Step 3: Create agentgateway Kubernetes Resources

Create CRD manifests for your agents and policies.

**Example: Agent Registration**

```yaml
# agents.yaml
apiVersion: a2a.agentgateway.io/v1alpha1
kind: Agent
metadata:
  name: echo-agent
  namespace: default
spec:
  backend:
    url: http://echo-agent:9000
    timeout: 30s
    healthCheck:
      interval: 10s
      path: /.well-known/agent.json
```

**Example: Authentication Policy**

```yaml
# auth-policy.yaml
apiVersion: security.agentgateway.io/v1alpha1
kind: AuthPolicy
metadata:
  name: jwt-policy
  namespace: default
spec:
  selector:
    matchLabels:
      auth: required
  jwt:
    issuer: https://auth.example.com
    audience: api.example.com
    jwksUri: https://auth.example.com/.well-known/jwks.json
```

**Example: Rate Limit Policy**

```yaml
# rate-limit.yaml
apiVersion: ratelimit.agentgateway.io/v1alpha1
kind: RateLimit
metadata:
  name: user-limits
  namespace: default
spec:
  actions:
    - metadata:
        descriptor_key: user_id
      header_match:
        header_name: x-user-id
  rateLimit:
    unit: minute
    requestsPerUnit: 100
    burst: 10
```

### Step 4: Deploy agentgateway

Use Helm or apply manifests directly:

```bash
# Add agentgateway Helm repo
helm repo add agentgateway https://charts.agentgateway.dev
helm repo update

# Install with your values
helm install agentgateway agentgateway/agentgateway \
  --namespace agentgateway-system \
  --create-namespace \
  -f your-values.yaml

# Or: kubectl apply -f agents.yaml auth-policy.yaml rate-limit.yaml
```

### Step 5: Update Client Gateway URLs

Point your agents and clients to the new gateway:

```bash
# Old (sentinel)
GATEWAY_URL=http://localhost:8080

# New (agentgateway in K8s)
GATEWAY_URL=http://agentgateway.default.svc.cluster.local:8080
# Or (if external)
GATEWAY_URL=https://api.example.com
```

Your agents don't change—only the target URL.

### Step 6: Verify with Existing Commands

Run the same curl commands that worked in sentinel:

```bash
# Echo agent test
curl -X POST $GATEWAY_URL/agents/echo/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": "1", "method": "message/send", ...}'

# Streaming agent test
curl -N -X POST $GATEWAY_URL/agents/streaming/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": "2", "method": "message/stream", ...}'

# Health check
curl $GATEWAY_URL/healthz
```

All responses should match sentinel's output.

### Step 7: Migrate Audit Logging

Your sentinel logs are OTel-compatible. Migrate them to agentgateway's observability stack:

**Grafana Loki:**
```yaml
# In agentgateway values.yaml
observability:
  logging:
    enabled: true
    loki:
      enabled: true
      url: http://loki:3100
```

**Prometheus:**
```yaml
# In agentgateway values.yaml
observability:
  metrics:
    enabled: true
    prometheus:
      enabled: true
```

Your existing dashboards should work with minimal adjustment.

---

## Migration Tool (v0.2 — Coming Soon)

In v0.2, sentinel will ship a migration helper:

```bash
# Generate agentgateway-compatible config
sentinel migrate --to agentgateway \
  --input sentinel.yaml \
  --output agentgateway-values.yaml

# The output includes:
# - Helm values for agentgateway
# - K8s manifests for agents, auth, rate limits
# - Observability integration instructions
```

This is **best-effort conversion**. Review and adjust for your Kubernetes environment:
- Update service DNS names (e.g., `echo-agent:9000` → `echo-agent.default.svc.cluster.local`)
- Verify auth issuer/audience URLs are reachable from K8s
- Test rate limit policies with real traffic patterns

---

## Can You Run Both Simultaneously?

Yes. During migration, run sentinel and agentgateway side-by-side:

1. Point a portion of traffic to agentgateway
2. Monitor for issues (audit logs, response latency, errors)
3. Gradually shift traffic from sentinel to agentgateway
4. Once agentgateway is stable, decommission sentinel

Example canary routing (with agentgateway in K8s):

```yaml
apiVersion: v1
kind: Service
metadata:
  name: a2a-gateway
spec:
  selector:
    app: gateway
  ports:
    - port: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gateway-canary
spec:
  replicas: 2
  template:
    spec:
      containers:
        # 80% traffic → agentgateway
        - name: agentgateway
          weight: 80
        # 20% traffic → sentinel (for validation)
          weight: 20
```

---

## Is the Migration Reversible?

Yes. If agentgateway doesn't meet your needs:

1. Keep sentinel running alongside
2. Point clients back to sentinel's URL
3. Your agents work unchanged

This is exactly the reverse of the forward migration.

---

## What If You Outgrow sentinel but Don't Want Kubernetes?

a2a-sentinel handles moderate scale:
- Single binary handles 10+ concurrent agents
- Rate limiting scales to 1000+ requests/minute per user
- SSE stream management is efficient for 100+ concurrent streams

**Before jumping to K8s, consider:**

1. **Increase sentinel's resources** — More CPU/memory for your host
2. **Run multiple sentinel instances** — Load balance with your existing infra (nginx, HAProxy)
3. **Add caching layer** — Put a CDN or cache proxy in front for repeated Agent Card fetches

agentgateway is designed for **managed scale** (K8s handling resource allocation, rollouts, etc.). If you want **manual scale** without K8s, sentinel + simple load balancing is a valid long-term choice.

---

## FAQ

**Q: Do I need to change my agents?**
A: No. Zero Agent Dependency is a core principle. Your agents work with either gateway without code changes.

**Q: What if my agents are already deployed and serving production traffic?**
A: Run sentinel in front of them. No agent changes. When you're ready to migrate to agentgateway, the agents still don't change—only the gateway changes.

**Q: Can I migrate gradually (some agents to agentgateway, others stay in sentinel)?**
A: Yes. Use a load balancer or API gateway to route:
- `/agents/echo/` → agentgateway
- `/agents/legacy/` → sentinel

This lets you migrate agent-by-agent.

**Q: What about my audit logs? Will they be lost?**
A: No. Both sentinel and agentgateway store logs in OTel format. Export sentinel's logs to Loki, Datadog, or Elasticsearch *before* decommissioning. agentgateway will append new logs to the same sink.

**Q: Is there a rollback plan if agentgateway fails?**
A: Yes. Your sentinel instance is still running. Switch the gateway URL back. Clients reconnect within seconds. No data loss (audit logs persist in your sink).

**Q: How long does the migration typically take?**
A: For a small team with 5-10 agents:
- Configuration mapping: 30 min
- K8s resource creation: 20 min
- Testing: 30 min
- Cutover: 10 min
- **Total: ~2 hours**

Larger teams may spend more time on observability and multi-tenancy setup.

**Q: What if I find bugs in agentgateway?**
A: agentgateway is maintained by Solo.io and the Linux Foundation. Report issues on [GitHub](https://github.com/solo-io/agentgateway/issues). In the meantime, your sentinel instance is still available—route traffic back if needed.

---

## Reference

### sentinel Commands Used in Migration

```bash
# Validate your current config before migration
./sentinel validate --config sentinel.yaml

# Print your config for reference (before migration)
./sentinel --config sentinel.yaml serve --dry-run

# Health check (to verify agents are reachable)
curl http://localhost:8080/readyz
```

### agentgateway Resources

- **Documentation**: https://docs.agentgateway.dev/
- **GitHub**: https://github.com/solo-io/agentgateway
- **Community**: https://slack.agentgateway.dev/ (or Solo.io Slack)
- **API Reference**: https://docs.agentgateway.dev/api/

### A2A Protocol Resources

- **Spec**: https://a2a-protocol.github.io/spec/
- **Protocol Bindings**: JSON-RPC 2.0, gRPC, HTTP+JSON/REST
- **Agent Card Format**: https://a2a-protocol.github.io/spec/#agent-card

---

## Support

### Questions About sentinel?

- **Troubleshooting**: See [README.md](../README.md#troubleshooting)
- **Config Reference**: See [sentinel.yaml.example](../sentinel.yaml.example)
- **Architecture**: See [docs/ARCHITECTURE.md](./ARCHITECTURE.md)

### Questions About agentgateway?

- **Official Docs**: https://docs.agentgateway.dev/
- **GitHub Issues**: https://github.com/solo-io/agentgateway/issues
- **Community Slack**: https://slack.agentgateway.dev/

---

**Remember:** Both sentinel and agentgateway implement the A2A protocol faithfully. Your investment in A2A adoption is portable. Migrate confidently.
