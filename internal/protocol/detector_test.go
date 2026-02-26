package protocol

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Detect ──

func TestDetect(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
		wantProto   ProtocolType
		wantMethod  string
	}{
		// Agent Card
		{"AgentCard GET", "GET", "/.well-known/agent.json", "", "", ProtocolAgentCard, ""},

		// REST extended card
		{"REST extended card", "GET", "/agent/authenticatedExtendedCard", "", "", ProtocolREST, "agent/authenticatedExtendedCard"},

		// JSON-RPC
		{"JSONRPC message/send", "POST", "/", `{"jsonrpc":"2.0","method":"message/send","id":"1","params":{}}`, "application/json", ProtocolJSONRPC, "message/send"},
		{"JSONRPC message/stream", "POST", "/", `{"jsonrpc":"2.0","method":"message/stream","id":"2","params":{}}`, "application/json", ProtocolJSONRPC, "message/stream"},
		{"JSONRPC tasks/get", "POST", "/", `{"jsonrpc":"2.0","method":"tasks/get","id":"3","params":{}}`, "application/json", ProtocolJSONRPC, "tasks/get"},
		{"JSONRPC tasks/cancel", "POST", "/", `{"jsonrpc":"2.0","method":"tasks/cancel","id":"4","params":{}}`, "application/json", ProtocolJSONRPC, "tasks/cancel"},

		// REST patterns
		{"REST message send", "POST", "/message:send", `{}`, "application/json", ProtocolREST, "message/send"},
		{"REST message stream", "POST", "/message:stream", `{}`, "application/json", ProtocolREST, "message/stream"},
		{"REST tasks list", "GET", "/tasks", "", "", ProtocolREST, "tasks/list"},
		{"REST tasks get", "GET", "/tasks/task-123", "", "", ProtocolREST, "tasks/get"},
		{"REST tasks cancel", "POST", "/tasks/task-123:cancel", `{}`, "application/json", ProtocolREST, "tasks/cancel"},
		{"REST tasks subscribe", "GET", "/tasks/task-123:subscribe", "", "", ProtocolREST, "tasks/subscribe"},
		{"REST push set", "POST", "/tasks/task-123/pushNotifications", `{}`, "application/json", ProtocolREST, "tasks/pushNotificationConfig/set"},
		{"REST push get", "GET", "/tasks/task-123/pushNotifications", "", "", ProtocolREST, "tasks/pushNotificationConfig/get"},
		{"REST push delete", "DELETE", "/tasks/task-123/pushNotifications", "", "", ProtocolREST, "tasks/pushNotificationConfig/delete"},

		// Unknown
		{"Unknown GET root", "GET", "/", "", "", ProtocolUnknown, ""},
		{"Unknown POST random", "POST", "/foo/bar", `{}`, "application/json", ProtocolUnknown, ""},
		{"Unknown non-JSONRPC POST", "POST", "/", `{"foo":"bar"}`, "application/json", ProtocolUnknown, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}

			req := httptest.NewRequest(tt.method, tt.path, body)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			result, err := Detect(req)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}

			if result.Protocol != tt.wantProto {
				t.Errorf("Protocol = %q, want %q", result.Protocol, tt.wantProto)
			}
			if result.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", result.Method, tt.wantMethod)
			}
		})
	}
}

// ── Detect: JSON-RPC POST to REST path prioritizes JSON-RPC ──

func TestDetect_JSONRPCOverREST(t *testing.T) {
	// A POST to /message:send with a valid JSON-RPC body should detect as JSON-RPC
	body := `{"jsonrpc":"2.0","method":"message/send","id":"1","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/message:send", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := Detect(req)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// JSON-RPC takes priority over REST pattern matching
	if result.Protocol != ProtocolJSONRPC {
		t.Errorf("Protocol = %q, want %q", result.Protocol, ProtocolJSONRPC)
	}
}

// ── Detect: body preserved after JSON-RPC detection ──

func TestDetect_BodyPreserved(t *testing.T) {
	originalBody := `{"jsonrpc":"2.0","method":"message/send","id":"1","params":{"message":{"role":"user","parts":[{"type":"text","text":"hello"}]}}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(originalBody))
	req.Header.Set("Content-Type", "application/json")

	result, err := Detect(req)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if result.Protocol != ProtocolJSONRPC {
		t.Fatalf("Protocol = %q, want jsonrpc", result.Protocol)
	}

	// Body should still be readable by downstream handlers
	downstream, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll body after Detect: %v", err)
	}

	if string(downstream) != originalBody {
		t.Errorf("body after Detect = %q, want %q", string(downstream), originalBody)
	}
}

// ── Detect: nil body POST does not panic ──

func TestDetect_NilBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Body = nil

	result, err := Detect(req)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if result.Protocol != ProtocolUnknown {
		t.Errorf("Protocol = %q, want unknown", result.Protocol)
	}
}

// ── InspectAndRewind ──

func TestInspectAndRewind(t *testing.T) {
	original := `{"jsonrpc":"2.0","method":"test","id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(original))

	body, err := InspectAndRewind(req, 1024)
	if err != nil {
		t.Fatalf("InspectAndRewind error = %v", err)
	}

	if string(body) != original {
		t.Errorf("inspected body = %q, want %q", string(body), original)
	}

	// Body should be readable again
	rewound, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll after rewind: %v", err)
	}

	if string(rewound) != original {
		t.Errorf("rewound body = %q, want %q", string(rewound), original)
	}
}

func TestInspectAndRewind_MaxSize(t *testing.T) {
	// Body larger than maxSize
	largeBody := strings.Repeat("x", 200)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(largeBody))

	body, err := InspectAndRewind(req, 100)
	if err != nil {
		t.Fatalf("InspectAndRewind error = %v", err)
	}

	// Returned bytes should be truncated to maxSize
	if len(body) != 100 {
		t.Errorf("inspected body len = %d, want 100", len(body))
	}

	// But the full body (up to maxSize+1 read) is restored for downstream
	rewound, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll after rewind: %v", err)
	}

	// The restored body contains what was actually read (maxSize+1 = 101 bytes)
	if len(rewound) != 101 {
		t.Errorf("rewound body len = %d, want 101", len(rewound))
	}
}

func TestInspectAndRewind_NilBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Body = nil

	body, err := InspectAndRewind(req, 1024)
	if err != nil {
		t.Fatalf("InspectAndRewind error = %v", err)
	}

	if body != nil {
		t.Errorf("body = %v, want nil", body)
	}
}

// ── ParseJSONRPCMethod ──

func TestParseJSONRPCMethod(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantMethod string
		wantID     interface{}
		wantErr    bool
	}{
		{
			name:       "valid message/send",
			body:       `{"jsonrpc":"2.0","method":"message/send","id":"1","params":{}}`,
			wantMethod: "message/send",
			wantErr:    false,
		},
		{
			name:       "valid tasks/get with numeric ID",
			body:       `{"jsonrpc":"2.0","method":"tasks/get","id":42}`,
			wantMethod: "tasks/get",
			wantErr:    false,
		},
		{
			name:    "missing jsonrpc field",
			body:    `{"method":"message/send","id":"1"}`,
			wantErr: true,
		},
		{
			name:    "wrong jsonrpc version",
			body:    `{"jsonrpc":"1.0","method":"message/send","id":"1"}`,
			wantErr: true,
		},
		{
			name:    "missing method",
			body:    `{"jsonrpc":"2.0","id":"1"}`,
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			body:    `not json at all`,
			wantErr: true,
		},
		{
			name:    "empty object",
			body:    `{}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, _, err := ParseJSONRPCMethod([]byte(tt.body))
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseJSONRPCMethod() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseJSONRPCMethod() error = %v", err)
			}
			if method != tt.wantMethod {
				t.Errorf("method = %q, want %q", method, tt.wantMethod)
			}
		})
	}
}

// ── MatchRESTPattern ──

func TestMatchRESTPattern(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		wantMethod string
	}{
		// POST patterns
		{"POST message:send", "POST", "/message:send", "message/send"},
		{"POST message:stream", "POST", "/message:stream", "message/stream"},
		{"POST tasks cancel", "POST", "/tasks/task-abc:cancel", "tasks/cancel"},
		{"POST push set", "POST", "/tasks/task-abc/pushNotifications", "tasks/pushNotificationConfig/set"},

		// GET patterns
		{"GET tasks list", "GET", "/tasks", "tasks/list"},
		{"GET tasks get", "GET", "/tasks/my-task-123", "tasks/get"},
		{"GET tasks subscribe", "GET", "/tasks/my-task-123:subscribe", "tasks/subscribe"},
		{"GET push get", "GET", "/tasks/my-task-123/pushNotifications", "tasks/pushNotificationConfig/get"},

		// DELETE patterns
		{"DELETE push delete", "DELETE", "/tasks/task-1/pushNotifications", "tasks/pushNotificationConfig/delete"},

		// Non-matching
		{"no match GET root", "GET", "/", ""},
		{"no match POST random", "POST", "/random", ""},
		{"no match PUT tasks", "PUT", "/tasks/task-1", ""},
		{"no match GET tasks empty id", "GET", "/tasks/", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchRESTPattern(tt.method, tt.path)
			if got != tt.wantMethod {
				t.Errorf("MatchRESTPattern(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.wantMethod)
			}
		})
	}
}

// ── MatchRESTPattern: trailing slash normalization ──

func TestMatchRESTPattern_TrailingSlash(t *testing.T) {
	// /tasks/ with trailing slash should not match tasks/list (it's /tasks)
	// and should not match tasks/get (empty ID after /tasks/)
	got := MatchRESTPattern("GET", "/tasks/")
	if got != "" {
		t.Errorf("MatchRESTPattern(GET, /tasks/) = %q, want empty (trailing slash after /tasks/ = empty ID)", got)
	}
}

// ── MatchRESTPattern: complex task IDs ──

func TestMatchRESTPattern_ComplexTaskIDs(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		wantMethod string
	}{
		{"UUID task ID", "GET", "/tasks/550e8400-e29b-41d4-a716-446655440000", "tasks/get"},
		{"alphanumeric task ID", "GET", "/tasks/abc123def456", "tasks/get"},
		{"task ID with dots", "GET", "/tasks/task.v2.123", "tasks/get"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchRESTPattern(tt.method, tt.path)
			if got != tt.wantMethod {
				t.Errorf("MatchRESTPattern(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.wantMethod)
			}
		})
	}
}

// ── InspectAndRewind error path ──

// errReader always returns an error on Read.
type errReader struct{}

func (errReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("simulated read error")
}

func TestInspectAndRewind_ReadError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Body = io.NopCloser(errReader{})

	_, err := InspectAndRewind(req, 1024)
	if err == nil {
		t.Fatal("expected error from InspectAndRewind when body reader fails")
	}
}

// ── Detect: POST with body read error ──

func TestDetect_BodyReadError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Body = io.NopCloser(errReader{})

	result, err := Detect(req)
	if err == nil {
		t.Fatal("expected error from Detect when body reader fails")
	}
	if result.Protocol != ProtocolUnknown {
		t.Errorf("Protocol = %q, want unknown on error", result.Protocol)
	}
}

// ── matchRESTDelete edge cases ──

func TestMatchRESTDelete(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantMethod string
	}{
		{
			name:       "DELETE pushNotifications",
			path:       "/tasks/task-abc/pushNotifications",
			wantMethod: "tasks/pushNotificationConfig/delete",
		},
		{
			name:       "DELETE no id (empty segment)",
			path:       "/tasks//pushNotifications",
			wantMethod: "",
		},
		{
			name:       "DELETE wrong suffix",
			path:       "/tasks/task-abc/other",
			wantMethod: "",
		},
		{
			name:       "DELETE tasks root",
			path:       "/tasks",
			wantMethod: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchRESTPattern(http.MethodDelete, tt.path)
			if got != tt.wantMethod {
				t.Errorf("MatchRESTPattern(DELETE, %q) = %q, want %q", tt.path, got, tt.wantMethod)
			}
		})
	}
}

// ── extractTaskID edge cases ──

func TestExtractTaskID(t *testing.T) {
	tests := []struct {
		path    string
		wantID  string
	}{
		{"/tasks/task-123:cancel", "task-123"},
		{"/tasks/:cancel", ""},      // colon at index 0 = invalid
		{"/tasks/nocolon", ""},      // no colon
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractTaskID(tt.path)
			if got != tt.wantID {
				t.Errorf("extractTaskID(%q) = %q, want %q", tt.path, got, tt.wantID)
			}
		})
	}
}

// ── extractTaskIDBeforeSegment edge cases ──

func TestExtractTaskIDBeforeSegment(t *testing.T) {
	tests := []struct {
		path    string
		segment string
		wantID  string
	}{
		{"/tasks/task-abc/pushNotifications", "/pushNotifications", "task-abc"},
		{"/tasks//pushNotifications", "/pushNotifications", ""},       // empty id
		{"/tasks/a/b/pushNotifications", "/pushNotifications", ""},    // id contains slash
		{"/other/task-abc/pushNotifications", "/pushNotifications", ""}, // wrong prefix
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractTaskIDBeforeSegment(tt.path, tt.segment)
			if got != tt.wantID {
				t.Errorf("extractTaskIDBeforeSegment(%q, %q) = %q, want %q", tt.path, tt.segment, got, tt.wantID)
			}
		})
	}
}

// ── Detect: POST empty body falls through to REST ──

func TestDetect_POSTEmptyBodyFallsToREST(t *testing.T) {
	// POST /message:send with empty body — no JSON-RPC, should fall to REST
	req := httptest.NewRequest(http.MethodPost, "/message:send", strings.NewReader(""))
	result, err := Detect(req)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if result.Protocol != ProtocolREST {
		t.Errorf("Protocol = %q, want rest for POST /message:send with empty body", result.Protocol)
	}
	if result.Method != "message/send" {
		t.Errorf("Method = %q, want message/send", result.Method)
	}
}
