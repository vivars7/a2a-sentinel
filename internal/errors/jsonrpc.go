package errors

// JSONRPCError represents a JSON-RPC 2.0 error response.
type JSONRPCError struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Error   JSONRPCErrorObj `json:"error"`
}

// JSONRPCErrorObj is the error object within a JSON-RPC error response.
type JSONRPCErrorObj struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    *SentinelError `json:"data,omitempty"`
}

// ToJSONRPCError converts a SentinelError to a JSON-RPC 2.0 error response.
// HTTP status codes are mapped to JSON-RPC error codes:
//   - 400 -> -32600 (Invalid Request)
//   - 401 -> -32600 (Invalid Request)
//   - 403 -> -32600 (Invalid Request)
//   - 404 -> -32601 (Method not found)
//   - 409 -> -32600 (Invalid Request)
//   - 429 -> -32600 (Invalid Request)
//   - 503 -> -32603 (Internal error)
//   - default -> -32603 (Internal error)
func ToJSONRPCError(err *SentinelError, requestID interface{}) JSONRPCError {
	rpcCode := httpToJSONRPCCode(err.Code)
	return JSONRPCError{
		JSONRPC: "2.0",
		ID:      requestID,
		Error: JSONRPCErrorObj{
			Code:    rpcCode,
			Message: err.Message,
			Data:    err,
		},
	}
}

func httpToJSONRPCCode(httpCode int) int {
	switch httpCode {
	case 400, 401, 403, 409, 429:
		return -32600 // Invalid Request
	case 404:
		return -32601 // Method not found
	case 502, 503:
		return -32603 // Internal error
	default:
		return -32603 // Internal error
	}
}
