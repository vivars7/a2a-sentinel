#!/bin/bash
# Rate limiting demo: send 12 rapid requests (limit is 10/min)
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "$i: %{http_code}\n" \
    -X POST localhost:8080/agents/echo/ \
    -H 'Content-Type: application/json' \
    -H "X-Sentinel-Nonce: rate-test-$i" \
    -d @assets/demo-payloads/rate-test.json
done
