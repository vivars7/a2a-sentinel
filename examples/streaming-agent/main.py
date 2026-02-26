"""Streaming agent for a2a-sentinel testing.

Implements a minimal A2A-compatible agent that returns SSE (Server-Sent Events)
for the message/stream method.

SSE event sequence:
  1. TaskStatusUpdate (working)
  2. TaskArtifactUpdate (text chunk 1)
  3. TaskArtifactUpdate (text chunk 2)
  4. TaskStatusUpdate (completed)
"""

import json
import uuid
import time
from flask import Flask, request, jsonify, Response, stream_with_context

app = Flask(__name__)

AGENT_CARD = {
    "name": "streaming-agent",
    "description": "Streaming demo agent for testing SSE proxying",
    "url": "http://streaming-agent:9001",
    "version": "1.0.0",
    "capabilities": {
        "streaming": True,
        "pushNotifications": False,
    },
    "skills": [
        {
            "id": "stream-demo",
            "name": "Stream Demo",
            "description": "Demonstrates SSE streaming with chunked responses",
        }
    ],
    "defaultInputModes": ["text"],
    "defaultOutputModes": ["text"],
}


def extract_text(message: dict) -> str:
    """Extract text content from an A2A message."""
    parts = message.get("parts", [])
    texts = []
    for part in parts:
        if isinstance(part, dict) and "text" in part:
            texts.append(part["text"])
    return " ".join(texts) if texts else ""


def sse_event(event_type: str, data: dict) -> str:
    """Format a single SSE event."""
    payload = json.dumps({"type": event_type, **data})
    return f"data: {payload}\n\n"


def generate_stream(task_id: str, input_text: str):
    """Yield SSE events simulating a streaming A2A task."""
    # Event 1: working status
    yield sse_event("TaskStatusUpdate", {
        "taskId": task_id,
        "status": {"state": "working"},
        "final": False,
    })
    time.sleep(0.1)

    # Event 2: first artifact chunk
    yield sse_event("TaskArtifactUpdate", {
        "taskId": task_id,
        "artifact": {
            "artifactId": str(uuid.uuid4()),
            "index": 0,
            "append": False,
            "lastChunk": False,
            "parts": [{"text": f"Streaming response to: '{input_text}'"}],
        },
    })
    time.sleep(0.1)

    # Event 3: second artifact chunk
    yield sse_event("TaskArtifactUpdate", {
        "taskId": task_id,
        "artifact": {
            "artifactId": str(uuid.uuid4()),
            "index": 1,
            "append": True,
            "lastChunk": True,
            "parts": [{"text": " — end of stream."}],
        },
    })
    time.sleep(0.1)

    # Event 4: completed status
    yield sse_event("TaskStatusUpdate", {
        "taskId": task_id,
        "status": {"state": "completed"},
        "final": True,
    })


@app.route("/.well-known/agent.json")
def agent_card():
    return jsonify(AGENT_CARD)


@app.route("/", methods=["POST"])
def jsonrpc_handler():
    """Handle JSON-RPC requests (method: message/stream) with SSE response."""
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": "Parse error"},
        }), 400

    req_id = body.get("id")
    method = body.get("method", "")

    if method not in ("message/stream", "message/send"):
        return jsonify({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}",
            },
        }), 404

    params = body.get("params", {})
    message = params.get("message", {})
    input_text = extract_text(message)
    task_id = str(uuid.uuid4())

    return Response(
        stream_with_context(generate_stream(task_id, input_text)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/message:send", methods=["POST"])
def rest_stream_handler():
    """Handle REST streaming requests (POST /message:send)."""
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error": {"code": 400, "message": "Invalid JSON"}}), 400

    message = body.get("message", {})
    input_text = extract_text(message)
    task_id = str(uuid.uuid4())

    return Response(
        stream_with_context(generate_stream(task_id, input_text)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9001, debug=False)
