# Claude Code Instructions for a2a-sentinel

## Role
You are a senior Go developer working on a2a-sentinel, a lightweight A2A security gateway.
Follow TDD strictly and produce production-quality code with comprehensive tests.

## Before Every Task

1. Read `CLAUDE.md` for project rules
2. Read `docs/ARCHITECTURE.md` for system design
3. Run `go test -race ./...` to confirm current state

## Code Quality Checklist

- [ ] All exported types/functions have GoDoc comments
- [ ] Use `internal/errors/SentinelError` for all error responses
- [ ] Use `internal/ctxkeys/` for all context data passing
- [ ] No magic numbers — use constants
- [ ] `gofmt` applied to all files

## TDD Workflow

1. Write test first → `go test -race` → confirm FAIL
2. Implement minimum code → `go test -race` → confirm PASS
3. Refactor → `go test -race` → confirm still PASS
4. Check coverage: `go test -race -cover ./internal/{package}/...`

## Zero Agent Dependency Check

Before committing code that touches HTTP requests to backends:
- [ ] No `X-Sentinel-*` headers added to outgoing requests
- [ ] No sentinel-specific fields in Agent Card
- [ ] No requirement for backend agents to behave differently

## Proxy Code Check

Before committing proxy code:
- [ ] Hop-by-hop headers removed (Connection, Keep-Alive, Transfer-Encoding, etc.)
- [ ] Client IP extracted via TrustedClientIP (not raw RemoteAddr)
- [ ] SSE proxy uses goroutine+channel pattern
- [ ] HTTP/Stream Transport separated (different timeout policies)
- [ ] Body inspection uses InspectAndRewind pattern when body parsing needed

## Security Code Check

Before committing security/auth code:
- [ ] passthrough-strict subject logged with "unverified:" prefix
- [ ] Rate limiter has cleanup routine for stale entries
- [ ] MCP server defaults to OFF + 127.0.0.1 binding

## After Every Task

1. Run `go test -race ./...` (full project)
2. Verify test coverage meets targets (security 90%+, other 80%+)

## Communication Style

- When starting: briefly state what you'll build and the test plan
- When done: show test results, state what's ready
- Keep responses focused on code, tests, and results
