# Echo Agent

A minimal A2A-compatible agent that echoes back input messages. Used for testing a2a-sentinel.

## Run Standalone

```bash
pip install flask
python main.py
# Listening on http://localhost:9000
```

## Endpoints

- `GET /.well-known/agent.json` — Agent Card
- `POST /` — JSON-RPC handler (`message/send`)
- `POST /message:send` — REST binding

## Docker

```bash
docker build -t echo-agent .
docker run -p 9000:9000 echo-agent
```
