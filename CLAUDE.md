# CLAUDE.md — a2a-sentinel Project Instructions

> This file helps AI coding assistants understand the project conventions and constraints.

## Project Overview

a2a-sentinel is a lightweight, security-first A2A (Agent-to-Agent) protocol gateway written in Go.
Goal: developers add A2A security in 5 minutes and migrate to agentgateway for production with zero agent code changes.

## Core Principles

1. **Zero Agent Dependency**: Never inject sentinel-specific headers, metadata, or Agent Card fields into backend requests
2. **Security ON by Default**: All security defaults are enabled. Disabling requires explicit configuration
3. **Educational Errors**: Every error response includes `hint` and `docs_url` fields
4. **OTel-Compatible Audit Logs**: Field names follow OpenTelemetry semantic conventions
5. **No ReverseProxy**: HTTP/SSE proxies use http.Client + manual implementation (no httputil.ReverseProxy)
6. **Hop-by-Hop Header Removal**: Strip Connection, Keep-Alive, Transfer-Encoding etc. when proxying
7. **Explicit Body Inspection**: Use InspectAndRewind pattern where body parsing is needed; skip for streaming
8. **Subject Logging Reliability**: In passthrough-strict mode, unverified subjects get "unverified:" prefix

## Tech Stack

- **Language**: Go 1.22+
- **Dependencies (minimal)**:
  - `gopkg.in/yaml.v3` (config parsing)
  - `github.com/lestrrat-go/jwx/v2` (JWS/JWK/JWT)
  - `golang.org/x/time` (rate.Limiter)
- **HTTP Framework**: None (net/http standard library only)
- **Testing**: Standard testing package + httptest

## Coding Standards

### Go Style
- `gofmt` required
- GoDoc comments on all exported types/functions
- Wrap errors with `fmt.Errorf("context: %w", err)`
- context.Context as first parameter
- No magic numbers — use named constants

### Testing (TDD)
- All code must pass `go test -race`
- Test files in same package with `_test.go` suffix
- Table-driven tests preferred
- HTTP tests use `httptest.NewServer`
- Concurrency code tested with `-race` flag
- Coverage targets: security code 90%+, other 80%+

### Error Handling
- All errors use `internal/errors/SentinelError` type
- JSON-RPC binding: `errors.ToJSONRPCError()`, REST: HTTP status with SentinelError body
- Every error includes `hint` and `docs_url`

### Context Usage
- Only use keys from `internal/ctxkeys/` package (no direct context key definitions)
- Pattern: `ctxkeys.WithAuthInfo(ctx, info)` / `ctxkeys.AuthInfoFrom(ctx)`

## Project Structure

```
a2a-sentinel/
├── cmd/sentinel/main.go          # Entrypoint (serve, validate, init subcommands)
├── internal/
│   ├── config/                   # YAML parsing + validation + dev/prod profiles
│   ├── ctxkeys/                  # Centralized context keys (AuthInfo with SubjectVerified)
│   ├── errors/                   # SentinelError + JSON-RPC/HTTP mapping
│   ├── health/                   # /healthz, /readyz handlers (readiness modes)
│   ├── server/                   # HTTP server + LimitedListener + graceful shutdown
│   ├── protocol/                 # A2A types, Protocol Detector, bodyinspect.go
│   ├── security/                 # Security middleware (2-layer) + clientip.go
│   ├── proxy/                    # HTTP/SSE proxy + headers.go + transport.go
│   ├── router/                   # Routing (path-prefix, single)
│   ├── agentcard/                # Agent Card manager (polling, cache, change detection)
│   ├── audit/                    # OTel-compatible audit logging + sampling
│   └── mcpserver/                # MCP server (default OFF, 127.0.0.1, read-only v0.1)
├── examples/                     # Sample agents (Python/Flask)
└── docs/                         # Documentation
```

## Commit Convention

```
feat(package): description
test(package): description
fix(package): description
docs: description
refactor(package): description
```

## Prohibited

- `net/http/httputil.ReverseProxy`
- Sentinel-specific headers on backend requests (`X-Sentinel-*` etc.)
- Sentinel-specific fields in Agent Card
- HTTP frameworks (gin, echo, fiber, etc.)
- Direct context key definitions (use ctxkeys package only)
- Code without tests
- Proceeding with failing `go test -race`
