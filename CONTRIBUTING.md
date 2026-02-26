# Contributing to a2a-sentinel

Thank you for your interest in contributing to a2a-sentinel! This document provides guidance for developers who want to improve the project.

---

## Quick Start for Contributors

### 1. Fork and Clone

```bash
# Fork on GitHub, then clone your fork
git clone https://github.com/{your-username}/a2a-sentinel.git
cd a2a-sentinel
```

### 2. Set Up Development Environment

```bash
# Install Go 1.22+ (if not already installed)
# Verify installation
go version  # Should output Go 1.22 or higher

# Install dependencies
go mod download

# Build the sentinel binary
go build -o sentinel ./cmd/sentinel/

# Verify build
./sentinel --version
```

### 3. Run Tests

```bash
# Run all tests with race detector (required)
go test -race ./...

# Run tests for a specific package
go test -race ./internal/security/...

# Run with coverage
go test -race -cover ./...
```

### 4. Make Your Changes

```bash
# Create a feature branch
git checkout -b feat/your-feature-name

# Follow TDD: Write tests first, then implementation
# (See "Testing Standards" section below)

# Commit with conventional format
git commit -m "feat(package): description of changes"

# Push to your fork
git push origin feat/your-feature-name
```

### 5. Submit a Pull Request

Open a PR against the `develop` branch with:
- Clear description of changes
- Reference to any related issues
- Verification that `go test -race ./...` passes

---

## Development Environment

### Prerequisites

- **Go 1.22+** — Download from [go.dev](https://go.dev)
- **git** — Version control
- **Docker and Docker Compose** (optional) — For E2E tests and demo services

### Project Dependencies

Minimal external dependencies:
- `gopkg.in/yaml.v3` — YAML configuration parsing
- `github.com/lestrrat-go/jwx/v2` — JWT/JWS/JWK handling
- `golang.org/x/time` — Rate limiter implementation

No HTTP frameworks (we use `net/http` standard library only).

### Verify Installation

```bash
# Check Go version
go version

# Verify all dependencies are available
go mod verify

# Build sentinel
go build -o sentinel ./cmd/sentinel/

# Test the build
./sentinel --version
```

---

## Code Standards

### Go Style Guide

All code must adhere to Go standards:

- **Formatting**: Run `gofmt` before committing
  ```bash
  gofmt -w ./cmd ./internal
  ```

- **Linting**: Ensure `go vet` passes
  ```bash
  go vet ./...
  ```

- **Documentation**: All exported types and functions require GoDoc comments
  ```go
  // Handler processes incoming A2A requests.
  // It validates security, detects protocol, and routes to appropriate proxy.
  func Handler(w http.ResponseWriter, r *http.Request) {
      // ...
  }
  ```

- **Error Wrapping**: Always wrap errors with context
  ```go
  // Good
  return fmt.Errorf("failed to parse config: %w", err)

  // Avoid
  return err
  ```

- **Context Parameter**: Always place `context.Context` as the first parameter
  ```go
  // Good
  func Validate(ctx context.Context, config *Config) error {
      // ...
  }

  // Avoid
  func Validate(config *Config, ctx context.Context) error {
      // ...
  }
  ```

- **Named Constants**: Never use magic numbers
  ```go
  // Good
  const maxBodySize = 1024 * 1024  // 1 MB
  if len(body) > maxBodySize {
      // ...
  }

  // Avoid
  if len(body) > 1048576 {
      // ...
  }
  ```

- **No HTTP Frameworks**: Use `net/http` standard library only
  ```go
  // Good
  http.HandleFunc("/health", healthHandler)

  // Avoid — do not use gin, echo, fiber, etc.
  router := gin.Default()
  router.GET("/health", healthHandler)
  ```

- **No ReverseProxy**: Implement proxies manually (architectural principle)
  ```go
  // Good — manual proxy implementation
  req, _ := http.NewRequest(r.Method, backendURL, r.Body)
  // ... copy headers, forward ...

  // Avoid
  httputil.ReverseProxy{Target: backendURL}.ServeHTTP(w, r)
  ```

### Context Keys

Always use the centralized context key registry:

```go
// Good
import "a2a-sentinel/internal/ctxkeys"

ctx = ctxkeys.WithAuthInfo(ctx, authInfo)
authInfo, ok := ctxkeys.AuthInfoFrom(ctx)

// Avoid — never define context keys directly
const myKey = "my-key"
ctx = context.WithValue(ctx, myKey, value)
```

### Error Handling

All errors must use the `SentinelError` type from `internal/errors`:

```go
import "a2a-sentinel/internal/errors"

// Create an error with educational guidance
err := errors.New(
    errors.CodeRateLimitExceeded,
    "Rate limit exceeded",
    "Current limit: 100 req/min. Wait 30s or contact admin.",
    "https://a2a-sentinel.dev/docs/rate-limit",
)

// Convert to HTTP response
errResp := errors.ToHTTPError(err)
// or JSON-RPC
errResp := errors.ToJSONRPCError(err)
```

Example error response:
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

### Architecture Principles

Never violate these core design principles:

1. **Zero Agent Dependency** — Do not inject sentinel-specific headers, metadata, or Agent Card fields into backend requests
   ```go
   // Good — clean forwarding
   req.Header.Set("Content-Type", "application/json")

   // Avoid
   req.Header.Set("X-Sentinel-User-ID", userID)  // Pollutes backend
   ```

2. **Security ON by Default** — All security settings should default to enabled/strict
   ```go
   // Good
   if config.Security.RateLimit.Enabled {  // defaults to true
       // ...
   }

   // Avoid
   if !config.Security.RateLimit.Disabled {  // confusing double negative
   ```

3. **Educational Error Messages** — Every error should include `hint` and `docs_url`
   ```go
   // See "Error Handling" section above
   ```

---

## Testing Standards

### TDD Workflow

All code must follow Test-Driven Development:

1. **Red** — Write test case that fails
2. **Green** — Write minimum implementation to pass
3. **Refactor** — Clean up code and remove duplication
4. **Verify** — Run `go test -race ./...` across entire project

### Example Workflow

```bash
# 1. Create test file for new feature
# internal/security/ratelimit_test.go
# Write failing test first

# 2. Run to verify failure
go test -race ./internal/security/...
# FAIL: TestRateLimitEnforce

# 3. Implement minimal code to pass
# internal/security/ratelimit.go

# 4. Run to verify success
go test -race ./internal/security/...
# PASS

# 5. Run full suite to ensure no regressions
go test -race ./...
# PASS
```

### Test Coverage Requirements

- **Security-related code** (auth, rate limiting, audit): 90%+ coverage
- **Other code** (proxy, routing, health checks): 80%+ coverage
- **HTTP tests** must use `httptest.NewServer`
- **Concurrency tests** must use `-race` flag

### Test Guidelines

- **Table-driven tests preferred** for multiple scenarios
  ```go
  tests := []struct {
      name      string
      input     string
      wantErr   bool
      wantValue string
  }{
      {"valid input", "foo", false, "foo"},
      {"empty input", "", true, ""},
      {"special chars", "!@#", false, "!@#"},
  }
  for _, tt := range tests {
      t.Run(tt.name, func(t *testing.T) {
          got, err := Process(tt.input)
          if (err != nil) != tt.wantErr {
              t.Errorf("wantErr %v, got %v", tt.wantErr, err)
          }
          if got != tt.wantValue {
              t.Errorf("want %s, got %s", tt.wantValue, got)
          }
      })
  }
  ```

- **HTTP tests** use `httptest.NewServer`
  ```go
  backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      w.WriteHeader(http.StatusOK)
      w.Write([]byte(`{"status":"ok"}`))
  }))
  defer backend.Close()

  // Test proxy against backend
  proxy := NewProxy(backend.URL)
  // ...
  ```

- **Concurrency tests** explicitly use `-race`
  ```bash
  go test -race ./internal/proxy/...  # Tests for data races
  ```

- **Test files** go in the same package with `_test.go` suffix
  ```
  internal/security/auth.go          # Implementation
  internal/security/auth_test.go     # Tests
  ```

### Running Tests

```bash
# Run all tests with race detector (REQUIRED)
go test -race ./...

# Run tests for specific package
go test -race ./internal/security/...

# Run with verbose output
go test -race -v ./...

# Run with coverage report
go test -race -cover ./...

# Generate coverage profile
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out  # View in browser
```

---

## What We Need Most

### High-Impact Contributions

We prioritize contributions in these areas:

1. **Security Enhancements**
   - New threat detection middleware
   - Security audit improvements
   - Fuzzing test suite
   - Penetration testing results

2. **Protocol Support**
   - gRPC binding support (in addition to JSON-RPC/REST)
   - HTTP/3 support
   - Protocol compliance tests

3. **Ecosystem**
   - MCP write tools (beyond read-only v0.1)
   - Helm chart for Kubernetes deployment
   - Terraform provider for infrastructure as code

4. **Documentation**
   - Tutorials and guides
   - Translations (non-English)
   - Example agents in different languages
   - Architecture diagrams

5. **Testing & Quality**
   - Integration tests
   - Benchmarks
   - E2E test suite expansion

### Good Starting Points

Look for issues labeled:
- `good-first-issue` — Suitable for new contributors
- `help-wanted` — Clear scope, needs implementation
- `documentation` — Doc improvements
- `bug` — Bug fixes with clear reproduction steps

---

## Branch Strategy

We use a simplified Git Flow:

```
main ← stable releases only (tagged versions)
  └── develop ← active development (default PR target)
        ├── feature/* ← new features
        ├── fix/* ← bug fixes
        └── release/v* ← release stabilization
```

### Branches

| Branch | Purpose | Merges into |
|--------|---------|-------------|
| `main` | Stable releases. Tagged versions (v0.1.0, v0.2.0, etc.) | — |
| `develop` | Integration branch for next release | `main` (via release branch) |
| `feature/*` | New feature development | `develop` |
| `fix/*` | Bug fixes | `develop` (or `main` for hotfixes) |
| `release/v*` | Release candidate stabilization | `main` + back-merge to `develop` |

### Workflow for Contributors

1. Fork the repository
2. Create your branch from `develop`:
   ```bash
   git checkout develop
   git checkout -b feature/my-feature
   ```
3. Make changes, write tests, commit
4. Push and open a PR **targeting `develop`** (not main)
5. After review and CI pass, maintainer merges

---

## Pull Request Process

### Before You Submit

1. **Verify all tests pass**
   ```bash
   go test -race ./...
   ```

2. **Verify formatting**
   ```bash
   gofmt -w ./cmd ./internal
   go vet ./...
   ```

3. **Check for architecture violations**
   - No sentinel-specific headers in backend requests
   - No magic numbers
   - No direct context key definitions
   - All errors include `hint` and `docs_url`
   - No `httputil.ReverseProxy` usage

4. **Create a feature branch** from `develop`
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feat/your-feature
   ```

### Submitting Your PR

1. **Clear PR title** — Use conventional format
   ```
   feat(security): add JWS signature validation
   fix(proxy): handle SSE stream timeout gracefully
   docs: improve rate limiting guide
   ```

2. **Detailed description** — Explain:
   - What problem you're solving
   - How your solution works
   - Any design decisions or trade-offs

3. **Link related issues**
   ```
   Fixes #123
   Related to #456
   ```

4. **Reference documentation** if applicable
   - Link to `CLAUDE.md` principles you followed
   - Link to `docs/ARCHITECTURE.md` sections relevant to changes

### Review Process

- **Feature PRs** — Require 1 approval from maintainers
- **Security PRs** — Require maintainer review + security review
- **Documentation PRs** — Fast-tracked (usually auto-approved)
- **Test-only PRs** — Auto-approved if tests pass

---

## Commit Convention

Follow conventional commit format for clear history:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat` — New feature
- `fix` — Bug fix
- `test` — Test addition or modification
- `docs` — Documentation changes
- `refactor` — Code refactoring (no feature/fix)
- `perf` — Performance improvement
- `ci` — CI/CD changes

### Scope

Package name or component (e.g., `security`, `proxy`, `config`).

### Examples

```
feat(security): add JWT issuer validation

test(proxy): add SSE stream timeout test

fix(router): handle path-prefix with trailing slash

docs: add troubleshooting section to README

refactor(audit): extract sampling logic to separate function
```

---

## Issue Labels

Issues are labeled to help you find work:

| Label | Meaning | Best For |
|-------|---------|----------|
| `good-first-issue` | Suitable for new contributors | Getting started |
| `help-wanted` | Clear scope, needs implementation | All levels |
| `security` | Security-related work | Experienced contributors |
| `protocol` | A2A protocol binding/support | Protocol experts |
| `dx` | Developer experience | All levels |
| `bug` | Confirmed bug with reproduction | Bug fixes |
| `documentation` | Docs, guides, examples | Writers |
| `performance` | Performance optimization | Optimization experts |
| `enhancement` | Feature request or improvement | Feature work |

---

## Code of Conduct

### Principles

1. **Be Respectful** — Treat all contributors with respect and courtesy
2. **Be Inclusive** — Welcome contributors of all backgrounds and experience levels
3. **Be Constructive** — Focus feedback on code, not people
4. **Assume Good Intent** — Assume others are trying to help

### Expected Behavior

- Use professional and inclusive language
- Accept constructive criticism gracefully
- Focus on what is best for the project
- Show empathy to other community members

### Unacceptable Behavior

- Harassment or discrimination
- Trolling, insulting, or derogatory comments
- Exclusionary language or behavior
- Unwelcome sexual attention

**Report incidents** to the maintainers privately. We take all reports seriously.

---

## Questions or Need Help?

### Documentation

- **Configuration**: See `sentinel.yaml.example` for all options
- **Architecture**: See `docs/ARCHITECTURE.md` for detailed design
- **Security**: See `docs/SECURITY.md` for security details
- **Project Guidelines**: See `CLAUDE.md` for development standards

### Getting Support

1. **Check existing documentation** first
2. **Search existing issues** for similar questions
3. **Open a discussion** on GitHub for design questions
4. **Open an issue** if you find a bug

### Contacting Maintainers

For security issues, email maintainers directly (do not open public issues).

---

## Useful References

- **A2A Protocol Specification** — [a2a-protocol.github.io/spec](https://a2a-protocol.github.io/spec/)
- **Go Best Practices** — [golang.org/doc/effective_go](https://golang.org/doc/effective_go)
- **OpenTelemetry Semantics** — [opentelemetry.io/docs/specs/](https://opentelemetry.io/docs/specs/)
- **agentgateway** — [github.com/solo-io/agentgateway](https://github.com/solo-io/agentgateway) (production platform)

---

## Recognition

Contributors are recognized in:
- Commit history (your name stays in git)
- GitHub contributions graph
- Future acknowledgments section

Thank you for making a2a-sentinel better!

---

**Last Updated**: February 2026
