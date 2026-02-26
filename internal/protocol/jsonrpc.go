package protocol

import (
	"encoding/json"
	"fmt"
)

// ParseJSONRPCMethod extracts the method from a JSON-RPC request body.
// Returns the method name and request ID, or an error if not a valid JSON-RPC 2.0 request.
func ParseJSONRPCMethod(body []byte) (method string, id interface{}, err error) {
	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "", nil, fmt.Errorf("unmarshal JSON-RPC request: %w", err)
	}

	if req.JSONRPC != "2.0" {
		return "", nil, fmt.Errorf("not a JSON-RPC 2.0 request: jsonrpc=%q", req.JSONRPC)
	}

	if req.Method == "" {
		return "", nil, fmt.Errorf("JSON-RPC request missing method field")
	}

	return req.Method, req.ID, nil
}
