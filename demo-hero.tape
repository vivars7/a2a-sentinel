# a2a-sentinel Hero Demo — "Secure A2A Gateway in 30 seconds"
# Prerequisites: docker compose up -d (using default sentinel-demo.yaml)

Output assets/demo-hero.gif
Set Theme "Catppuccin Mocha"
Set Width 1000
Set Height 550
Set FontSize 16
Set Padding 20
Set TypingSpeed 40ms
Set PlaybackSpeed 1.2
Set Shell "bash"

# Title
Type "# a2a-sentinel: Secure A2A Gateway in 30 seconds"
Enter
Sleep 1s

# Step 1: Health check
Type "curl -s localhost:8080/healthz | jq ."
Enter
Sleep 2s

# Step 2: Agent Card discovery
Type "curl -s localhost:8080/.well-known/agent.json | jq '.name, .skills[].id'"
Enter
Sleep 2s

# Step 3: Show payload then send to echo agent
Type ""
Enter
Type "# Send a message to echo agent"
Enter
Sleep 0.5s
Type "cat assets/demo-payloads/echo-send.json"
Enter
Sleep 1.5s
Type "curl -s -X POST localhost:8080/agents/echo/ -H 'Content-Type: application/json' -d @assets/demo-payloads/echo-send.json | jq .result"
Enter
Sleep 3s

# Step 4: Educational error — unknown agent
Type ""
Enter
Type "# Unknown agent -> educational error with hint + docs_url"
Enter
Sleep 0.5s
Type "curl -s -X POST localhost:8080/agents/unknown/ -H 'Content-Type: application/json' -d @assets/demo-payloads/unknown-agent.json | jq .error"
Enter
Sleep 3s

Type ""
Enter
Type "# Security by default. Zero config headaches."
Enter
Sleep 2s
