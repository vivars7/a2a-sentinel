#!/bin/bash
set -e

BASE_URL="${BASE_URL:-http://localhost:8080}"

echo "=== 1. Health Check ==="
curl -sf "$BASE_URL/healthz" | jq .

echo ""
echo "=== 2. Readiness ==="
curl -sf "$BASE_URL/readyz" | jq .

echo ""
echo "=== 3. Aggregated Agent Card ==="
curl -sf "$BASE_URL/.well-known/agent.json" | jq .

echo ""
echo "=== 4. Echo (JSON-RPC) ==="
curl -sf -X POST "$BASE_URL/agents/echo/" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user","parts":[{"text":"Hello!"}],"messageId":"msg-1"}}}' | jq .

echo ""
echo "=== 5. Streaming (SSE) ==="
curl -sf -N --max-time 10 -X POST "$BASE_URL/agents/streaming/" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"2","method":"message/stream","params":{"message":{"role":"user","parts":[{"text":"Stream test"}],"messageId":"msg-2"}}}' || true

echo ""
echo "=== All tests passed! ==="
