# Streaming Agent

A minimal A2A-compatible agent that returns Server-Sent Events (SSE) for streaming responses. Used for testing a2a-sentinel's SSE proxy.

## Run Standalone

```bash
pip install flask
python main.py
# Listening on http://localhost:9001
```

## Endpoints

- `GET /.well-known/agent.json` — Agent Card
- `POST /` — JSON-RPC handler (`message/stream`, `message/send`) returns SSE
- `POST /message:send` — REST binding (SSE)

## SSE Event Sequence

1. `TaskStatusUpdate` (working)
2. `TaskArtifactUpdate` (text chunk 1)
3. `TaskArtifactUpdate` (text chunk 2)
4. `TaskStatusUpdate` (completed)

## Docker

```bash
docker build -t streaming-agent .
docker run -p 9001:9001 streaming-agent
```
