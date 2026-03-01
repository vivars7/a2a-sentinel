# a2a-sentinel MCP Management Demo
# Prerequisites: docker compose -f docker-compose.yaml -f docker-compose-security-demo.yaml up -d

Output assets/demo-mcp.gif
Set Theme "Catppuccin Mocha"
Set Width 1000
Set Height 550
Set FontSize 15
Set Padding 20
Set TypingSpeed 35ms
Set PlaybackSpeed 1.0
Set Shell "bash"

Type "# MCP: Manage sentinel from Claude Desktop / Cursor"
Enter
Sleep 1s

# MCP tool: list_agents
Type ""
Enter
Type "# MCP tool: list_agents"
Enter
Sleep 0.5s
Type "curl -s localhost:8081/ -H 'Content-Type: application/json' -d @assets/demo-payloads/mcp-list-agents.json | jq '.result.content[0].text | fromjson'"
Enter
Sleep 3s

# MCP tool: health_check
Type ""
Enter
Type "# MCP tool: health_check"
Enter
Sleep 0.5s
Type "curl -s localhost:8081/ -H 'Content-Type: application/json' -d @assets/demo-payloads/mcp-health-check.json | jq '.result.content[0].text | fromjson'"
Enter
Sleep 3s

# MCP tool: get_agent_card
Type ""
Enter
Type "# MCP tool: get_agent_card (echo)"
Enter
Sleep 0.5s
Type "curl -s localhost:8081/ -H 'Content-Type: application/json' -d @assets/demo-payloads/mcp-get-agent-card.json | jq '.result.content[0].text | fromjson | {name, description, skills}'"
Enter
Sleep 3s

Type ""
Enter
Type "# Real-time gateway management from your AI assistant"
Enter
Sleep 2s
