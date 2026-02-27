package protocol

import (
	"net/http"
	"strings"
)

// ProtocolType identifies the A2A protocol binding.
type ProtocolType string

const (
	// ProtocolJSONRPC indicates a JSON-RPC 2.0 binding.
	ProtocolJSONRPC ProtocolType = "jsonrpc"
	// ProtocolREST indicates a REST binding.
	ProtocolREST ProtocolType = "rest"
	// ProtocolAgentCard indicates an Agent Card request.
	ProtocolAgentCard ProtocolType = "agentcard"
	// ProtocolGRPC indicates a gRPC binding.
	ProtocolGRPC ProtocolType = "grpc"
	// ProtocolUnknown indicates an unrecognized protocol.
	ProtocolUnknown ProtocolType = "unknown"
)

// maxBodyInspectSize is the maximum number of bytes to read from a request body
// for protocol detection purposes.
const maxBodyInspectSize = 64 * 1024 // 64 KB

// DetectResult holds the protocol detection result.
type DetectResult struct {
	Protocol ProtocolType
	Method   string // A2A method name (e.g., "message/send")
	Binding  string // "jsonrpc" or "rest"
}

// Detect analyzes an HTTP request to determine the A2A protocol binding.
// Returns the detected protocol, method name, and any error.
// The request body is read and restored (via InspectAndRewind pattern) for JSON-RPC detection.
func Detect(r *http.Request) (DetectResult, error) {
	// 1. Agent Card: GET /.well-known/agent.json
	if r.Method == http.MethodGet && r.URL.Path == "/.well-known/agent.json" {
		return DetectResult{
			Protocol: ProtocolAgentCard,
			Method:   "",
			Binding:  "",
		}, nil
	}

	// 2. REST authenticated extended card: GET /agent/authenticatedExtendedCard
	if r.Method == http.MethodGet && r.URL.Path == "/agent/authenticatedExtendedCard" {
		return DetectResult{
			Protocol: ProtocolREST,
			Method:   "agent/authenticatedExtendedCard",
			Binding:  "rest",
		}, nil
	}

	// 3. gRPC: Content-Type starts with "application/grpc"
	if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/grpc") {
		return DetectResult{
			Protocol: ProtocolGRPC,
			Method:   "", // gRPC method is determined by the gRPC server
			Binding:  "grpc",
		}, nil
	}

	// 4. JSON-RPC: POST with body containing "jsonrpc":"2.0"
	if r.Method == http.MethodPost {
		body, err := InspectAndRewind(r, maxBodyInspectSize)
		if err != nil {
			return DetectResult{Protocol: ProtocolUnknown}, err
		}

		if len(body) > 0 {
			method, _, err := ParseJSONRPCMethod(body)
			if err == nil && method != "" {
				return DetectResult{
					Protocol: ProtocolJSONRPC,
					Method:   method,
					Binding:  "jsonrpc",
				}, nil
			}
		}
	}

	// 5. REST patterns (POST/GET/DELETE with specific URL patterns)
	restMethod := MatchRESTPattern(r.Method, r.URL.Path)
	if restMethod != "" {
		return DetectResult{
			Protocol: ProtocolREST,
			Method:   restMethod,
			Binding:  "rest",
		}, nil
	}

	// 6. Unknown
	return DetectResult{
		Protocol: ProtocolUnknown,
		Method:   "",
		Binding:  "",
	}, nil
}
