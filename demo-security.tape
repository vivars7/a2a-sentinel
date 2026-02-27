# a2a-sentinel Security Features Demo
# Prerequisites: docker compose -f docker-compose.yaml -f docker-compose-security-demo.yaml up -d

Output assets/demo-security.gif
Set Theme "Catppuccin Mocha"
Set Width 1000
Set Height 600
Set FontSize 15
Set Padding 20
Set TypingSpeed 35ms
Set PlaybackSpeed 1.0
Set Shell "bash"

Type "# a2a-sentinel Security Features"
Enter
Sleep 1s

# 1. Rate limiting — send 12 requests rapidly
Type "# 1. Rate Limiting (10 req/min per IP)"
Enter
Sleep 0.5s
Type "cat assets/demo-rate-test.sh"
Enter
Sleep 2s
Type "bash assets/demo-rate-test.sh"
Enter
Sleep 6s

# 2. Replay detection
Type ""
Enter
Type "# 2. Replay Detection (same nonce = blocked)"
Enter
Sleep 0.5s
Type "curl -s -X POST localhost:8080/agents/echo/ -H 'Content-Type: application/json' -H 'X-Sentinel-Nonce: unique-abc-123' -d @assets/demo-payloads/replay-first.json | jq .result.status"
Enter
Sleep 2s

Type ""
Enter
Type "# Same nonce again..."
Enter
Sleep 0.5s
Type "curl -s -X POST localhost:8080/agents/echo/ -H 'Content-Type: application/json' -H 'X-Sentinel-Nonce: unique-abc-123' -d @assets/demo-payloads/replay-second.json | jq .error"
Enter
Sleep 3s

# 3. Educational error
Type ""
Enter
Type "# 3. Educational Errors -- every block tells you why + how to fix"
Enter
Sleep 0.5s
Type "curl -s -X POST localhost:8080/agents/nonexistent/ -H 'Content-Type: application/json' -d @assets/demo-payloads/unknown-agent.json | jq ."
Enter
Sleep 3s

Type ""
Enter
Type "# Every error includes: hint + docs_url"
Enter
Sleep 2s
