# a2a-sentinel Helm Chart

A Helm chart for deploying [a2a-sentinel](https://github.com/vivars7/a2a-sentinel), a lightweight, security-first A2A (Agent-to-Agent) protocol gateway, to Kubernetes.

## Prerequisites

- Kubernetes 1.23+
- Helm 3.10+

## Installation

### Add the chart (local)

```bash
helm install my-sentinel ./deploy/helm/a2a-sentinel
```

### Install with custom values

```bash
helm install my-sentinel ./deploy/helm/a2a-sentinel \
  --namespace sentinel \
  --create-namespace \
  --values my-values.yaml
```

### Upgrade

```bash
helm upgrade my-sentinel ./deploy/helm/a2a-sentinel --values my-values.yaml
```

### Uninstall

```bash
helm uninstall my-sentinel
```

## Values Reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `replicaCount` | int | `1` | Number of replicas |
| `image.repository` | string | `ghcr.io/vivars7/a2a-sentinel` | Container image repository |
| `image.tag` | string | `""` | Image tag (defaults to chart `appVersion`) |
| `image.pullPolicy` | string | `IfNotPresent` | Image pull policy |
| `imagePullSecrets` | list | `[]` | Image pull secrets |
| `nameOverride` | string | `""` | Override chart name |
| `fullnameOverride` | string | `""` | Override fully qualified app name |
| `serviceAccount.create` | bool | `true` | Create a service account |
| `serviceAccount.annotations` | object | `{}` | Service account annotations |
| `serviceAccount.name` | string | `""` | Service account name (auto-generated if empty) |
| `podAnnotations` | object | `{}` | Pod annotations |
| `podSecurityContext.runAsNonRoot` | bool | `true` | Run as non-root |
| `podSecurityContext.runAsUser` | int | `65534` | UID to run as |
| `securityContext.allowPrivilegeEscalation` | bool | `false` | Allow privilege escalation |
| `securityContext.readOnlyRootFilesystem` | bool | `true` | Read-only root filesystem |
| `service.type` | string | `ClusterIP` | Service type |
| `service.httpPort` | int | `8080` | HTTP port (also serves `/metrics`) |
| `service.grpcPort` | int | `9090` | gRPC port |
| `service.mcpPort` | int | `8081` | MCP port |
| `ingress.enabled` | bool | `false` | Enable ingress |
| `ingress.className` | string | `""` | Ingress class name |
| `ingress.annotations` | object | `{}` | Ingress annotations |
| `ingress.hosts` | list | `[]` | Ingress hosts |
| `ingress.tls` | list | `[]` | Ingress TLS configuration |
| `resources.requests.cpu` | string | `100m` | CPU request |
| `resources.requests.memory` | string | `64Mi` | Memory request |
| `resources.limits.cpu` | string | `500m` | CPU limit |
| `resources.limits.memory` | string | `128Mi` | Memory limit |
| `autoscaling.enabled` | bool | `false` | Enable HPA |
| `autoscaling.minReplicas` | int | `1` | Minimum replicas |
| `autoscaling.maxReplicas` | int | `5` | Maximum replicas |
| `autoscaling.targetCPUUtilizationPercentage` | int | `80` | Target CPU utilization |
| `serviceMonitor.enabled` | bool | `false` | Enable Prometheus ServiceMonitor |
| `serviceMonitor.interval` | string | `30s` | Scrape interval |
| `serviceMonitor.scrapeTimeout` | string | `10s` | Scrape timeout |
| `serviceMonitor.labels` | object | `{}` | Additional labels for ServiceMonitor |
| `nodeSelector` | object | `{}` | Node selector |
| `tolerations` | list | `[]` | Tolerations |
| `affinity` | object | `{}` | Affinity rules |
| `config` | object | see values.yaml | Full sentinel.yaml configuration |

## Example Overrides

### Point to a real agent backend

```yaml
config:
  listen:
    host: 0.0.0.0
    port: 8080
  agents:
    - name: my-agent
      url: http://my-agent-service.default.svc.cluster.local:9000
      card_path: /.well-known/agent.json
      poll_interval: 60s
      timeout: 30s
      max_streams: 10
      default: true
      allow_insecure: false
      health_check:
        enabled: true
        interval: 30s
      card_change_policy: alert
```

### Enable JWT authentication

```yaml
config:
  security:
    auth:
      mode: passthrough-strict
      schemes:
        - type: bearer
          jwt:
            issuer: https://auth.example.com
            audience: my-service
            jwks_url: https://auth.example.com/.well-known/jwks.json
      allow_unauthenticated: false
```

### Enable ingress with TLS

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: sentinel.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: sentinel-tls
      hosts:
        - sentinel.example.com
```

### Enable autoscaling

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

### Enable rate limiting

```yaml
config:
  security:
    rate_limit:
      enabled: true
      ip:
        per_ip: 100
        burst: 25
        cleanup_interval: 5m
      user:
        per_user: 50
        burst: 10
        cleanup_interval: 5m
      per_agent: 200
```

### Production logging

```yaml
config:
  logging:
    level: info
    format: json
    output: stdout
    audit:
      sampling_rate: 0.1
      error_sampling_rate: 1.0
      max_body_log_size: 512
```

## Prometheus ServiceMonitor Setup

Metrics are exposed at `GET /metrics` on the HTTP port (8080). To enable scraping with the Prometheus Operator:

1. Ensure the Prometheus Operator is installed in your cluster.
2. Enable the ServiceMonitor:

```yaml
serviceMonitor:
  enabled: true
  interval: 15s
  scrapeTimeout: 10s
  labels:
    # Match your Prometheus Operator's serviceMonitorSelector labels
    release: prometheus
```

3. Verify the target appears in your Prometheus UI under Status > Targets.

Available metrics include:
- `sentinel_requests_total` — total requests by agent, method, and status
- `sentinel_request_duration_seconds` — request latency histogram
- `sentinel_auth_failures_total` — authentication failures by reason
- `sentinel_active_streams` — currently active SSE/streaming connections

## Running Helm Tests

After installation, run the built-in connectivity test:

```bash
helm test my-sentinel
```

This curl-tests the `/healthz` endpoint from inside the cluster.

## Configuration via ConfigMap

The entire `sentinel.yaml` is rendered from `values.config` into a ConfigMap and mounted read-only at `/etc/sentinel/sentinel.yaml`. Any change to `values.config` triggers a rolling restart via the `checksum/config` pod annotation.

To manage secrets (JWT tokens, HMAC secrets, Redis URLs) separately, override specific fields via a separate Kubernetes Secret and inject them as environment variables or use an external secrets operator — do not commit secrets into `values.yaml`.

## Production Note

For production deployments at scale, consider migrating to [agentgateway](https://agentgateway.dev), which provides enterprise-grade features. a2a-sentinel is designed for zero-code-change migration: your agent endpoints and A2A protocol usage remain identical.
