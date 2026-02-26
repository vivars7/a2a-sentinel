"""Echo agent for a2a-sentinel testing.

Implements a minimal A2A-compatible agent that echoes back input.
Supports both JSON-RPC (POST /) and REST (POST /message:send) endpoints.
"""

import json
import uuid
from flask import Flask, request, jsonify

app = Flask(__name__)

AGENT_CARD = {
    "name": "echo-agent",
    "description": "Echo agent for testing",
    "url": "http://echo-agent:9000",
    "version": "1.0.0",
    "capabilities": {
        "streaming": False,
        "pushNotifications": False,
    },
    "skills": [
        {
            "id": "echo",
            "name": "Echo",
            "description": "Echoes back the input",
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


def make_echo_response(input_text: str, message_id: str) -> dict:
    """Build an A2A echo response message."""
    return {
        "role": "agent",
        "parts": [{"text": f"Echo: {input_text}"}],
        "messageId": str(uuid.uuid4()),
        "contextId": message_id,
    }


@app.route("/.well-known/agent.json")
def agent_card():
    return jsonify(AGENT_CARD)


@app.route("/", methods=["POST"])
def jsonrpc_handler():
    """Handle JSON-RPC requests (method: message/send)."""
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": "Parse error"},
        }), 400

    req_id = body.get("id")
    method = body.get("method", "")

    if method != "message/send":
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
    message_id = message.get("messageId", str(uuid.uuid4()))

    task_id = str(uuid.uuid4())
    response_message = make_echo_response(input_text, message_id)

    return jsonify({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "id": task_id,
            "status": {"state": "completed"},
            "artifacts": [
                {
                    "artifactId": str(uuid.uuid4()),
                    "parts": response_message["parts"],
                }
            ],
            "history": [message, response_message],
        },
    })


@app.route("/message:send", methods=["POST"])
def rest_handler():
    """Handle REST requests (POST /message:send)."""
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error": {"code": 400, "message": "Invalid JSON"}}), 400

    message = body.get("message", {})
    input_text = extract_text(message)
    message_id = message.get("messageId", str(uuid.uuid4()))

    task_id = str(uuid.uuid4())
    response_message = make_echo_response(input_text, message_id)

    return jsonify({
        "id": task_id,
        "status": {"state": "completed"},
        "artifacts": [
            {
                "artifactId": str(uuid.uuid4()),
                "parts": response_message["parts"],
            }
        ],
        "history": [message, response_message],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000, debug=False)
