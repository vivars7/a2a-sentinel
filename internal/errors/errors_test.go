package errors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSentinelErrorWithHint(t *testing.T) {
	err := &SentinelError{Code: 401, Message: "Auth required", Hint: "Use Bearer token"}
	want := "[401] Auth required (hint: Use Bearer token)"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestSentinelErrorWithoutHint(t *testing.T) {
	err := &SentinelError{Code: 500, Message: "Internal error"}
	want := "[500] Internal error"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestSentinelErrorImplementsError(t *testing.T) {
	var _ error = (*SentinelError)(nil)
}

func TestPredefinedErrors(t *testing.T) {
	tests := []struct {
		name    string
		err     *SentinelError
		code    int
		wantMsg string
	}{
		{"ErrAuthRequired", ErrAuthRequired, 401, "Authentication required"},
		{"ErrAuthInvalid", ErrAuthInvalid, 401, "Invalid authentication token"},
		{"ErrForbidden", ErrForbidden, 403, "Access denied"},
		{"ErrRateLimited", ErrRateLimited, 429, "Rate limit exceeded"},
		{"ErrAgentUnavailable", ErrAgentUnavailable, 503, "Target agent unavailable"},
		{"ErrStreamLimitExceeded", ErrStreamLimitExceeded, 429, "Too many concurrent streams"},
		{"ErrReplayDetected", ErrReplayDetected, 429, "Replay attack detected"},
		{"ErrSSRFBlocked", ErrSSRFBlocked, 403, "Push notification URL blocked"},
		{"ErrInvalidRequest", ErrInvalidRequest, 400, "Invalid request format"},
		{"ErrNoRoute", ErrNoRoute, 404, "No matching agent found"},
		{"ErrGlobalLimitReached", ErrGlobalLimitReached, 503, "Gateway capacity reached"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.code {
				t.Errorf("Code = %d, want %d", tt.err.Code, tt.code)
			}
			if tt.err.Message != tt.wantMsg {
				t.Errorf("Message = %q, want %q", tt.err.Message, tt.wantMsg)
			}
			if tt.err.Hint == "" {
				t.Error("Hint should not be empty for predefined errors")
			}
			if tt.err.DocsURL == "" {
				t.Error("DocsURL should not be empty for predefined errors")
			}
		})
	}
}

func TestSentinelErrorJSONRoundTrip(t *testing.T) {
	original := &SentinelError{
		Code:    429,
		Message: "Rate limit exceeded",
		Hint:    "Wait 30s",
		DocsURL: "https://a2a-sentinel.dev/docs/rate-limit",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded SentinelError
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.Code != original.Code {
		t.Errorf("Code: got %d, want %d", decoded.Code, original.Code)
	}
	if decoded.Message != original.Message {
		t.Errorf("Message: got %q, want %q", decoded.Message, original.Message)
	}
	if decoded.Hint != original.Hint {
		t.Errorf("Hint: got %q, want %q", decoded.Hint, original.Hint)
	}
	if decoded.DocsURL != original.DocsURL {
		t.Errorf("DocsURL: got %q, want %q", decoded.DocsURL, original.DocsURL)
	}
}

func TestSentinelErrorJSONOmitsEmptyHint(t *testing.T) {
	err := &SentinelError{Code: 500, Message: "Error"}
	data, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal: %v", marshalErr)
	}

	var raw map[string]interface{}
	if unmarshalErr := json.Unmarshal(data, &raw); unmarshalErr != nil {
		t.Fatalf("Unmarshal: %v", unmarshalErr)
	}

	if _, exists := raw["hint"]; exists {
		t.Error("expected 'hint' to be omitted when empty")
	}
	if _, exists := raw["docs_url"]; exists {
		t.Error("expected 'docs_url' to be omitted when empty")
	}
}

func TestToJSONRPCErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        *SentinelError
		requestID  interface{}
		wantCode   int
	}{
		{"400 -> -32600", &SentinelError{Code: 400, Message: "bad"}, "req-1", -32600},
		{"401 -> -32600", ErrAuthRequired, "req-2", -32600},
		{"403 -> -32600", ErrForbidden, "req-3", -32600},
		{"404 -> -32601", ErrNoRoute, "req-4", -32601},
		{"429(replay) -> -32600", ErrReplayDetected, "req-5", -32600},
		{"429(ratelimit) -> -32600", ErrRateLimited, "req-6", -32600},
		{"503 -> -32603", ErrAgentUnavailable, nil, -32603},
		{"unknown -> -32603", &SentinelError{Code: 502, Message: "bad gateway"}, 42, -32603},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rpcErr := ToJSONRPCError(tt.err, tt.requestID)

			if rpcErr.JSONRPC != "2.0" {
				t.Errorf("JSONRPC = %q, want %q", rpcErr.JSONRPC, "2.0")
			}
			if rpcErr.ID != tt.requestID {
				t.Errorf("ID = %v, want %v", rpcErr.ID, tt.requestID)
			}
			if rpcErr.Error.Code != tt.wantCode {
				t.Errorf("Error.Code = %d, want %d", rpcErr.Error.Code, tt.wantCode)
			}
			if rpcErr.Error.Message != tt.err.Message {
				t.Errorf("Error.Message = %q, want %q", rpcErr.Error.Message, tt.err.Message)
			}
		})
	}
}

func TestToJSONRPCErrorDataField(t *testing.T) {
	rpcErr := ToJSONRPCError(ErrRateLimited, "req-1")

	if rpcErr.Error.Data == nil {
		t.Fatal("Error.Data should not be nil")
	}
	if rpcErr.Error.Data.Hint == "" {
		t.Error("Error.Data.Hint should not be empty")
	}
	if rpcErr.Error.Data.DocsURL == "" {
		t.Error("Error.Data.DocsURL should not be empty")
	}
	if rpcErr.Error.Data.Code != 429 {
		t.Errorf("Error.Data.Code = %d, want 429", rpcErr.Error.Data.Code)
	}
}

func TestToJSONRPCErrorJSONSerialization(t *testing.T) {
	rpcErr := ToJSONRPCError(ErrAuthRequired, "req-abc")
	data, err := json.Marshal(rpcErr)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if raw["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v, want 2.0", raw["jsonrpc"])
	}
	if raw["id"] != "req-abc" {
		t.Errorf("id = %v, want req-abc", raw["id"])
	}

	errObj, ok := raw["error"].(map[string]interface{})
	if !ok {
		t.Fatal("error field is not an object")
	}
	dataObj, ok := errObj["data"].(map[string]interface{})
	if !ok {
		t.Fatal("error.data is not an object")
	}
	if _, exists := dataObj["hint"]; !exists {
		t.Error("error.data should contain 'hint'")
	}
	if _, exists := dataObj["docs_url"]; !exists {
		t.Error("error.data should contain 'docs_url'")
	}
}

func TestWriteHTTPError(t *testing.T) {
	tests := []struct {
		name       string
		err        *SentinelError
		wantStatus int
	}{
		{"401 error", ErrAuthRequired, 401},
		{"403 error", ErrForbidden, 403},
		{"429 error", ErrRateLimited, 429},
		{"503 error", ErrAgentUnavailable, 503},
		{"400 error", ErrInvalidRequest, 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteHTTPError(rec, tt.err)

			resp := rec.Result()
			defer resp.Body.Close()

			// Check status code
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			// Check Content-Type
			ct := resp.Header.Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/json")
			}

			// Decode body
			var body HTTPErrorResponse
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("Decode: %v", err)
			}

			if body.Error.Code != tt.err.Code {
				t.Errorf("body.Error.Code = %d, want %d", body.Error.Code, tt.err.Code)
			}
			if body.Error.Message != tt.err.Message {
				t.Errorf("body.Error.Message = %q, want %q", body.Error.Message, tt.err.Message)
			}
			if body.Error.Hint != tt.err.Hint {
				t.Errorf("body.Error.Hint = %q, want %q", body.Error.Hint, tt.err.Hint)
			}
			if body.Error.DocsURL != tt.err.DocsURL {
				t.Errorf("body.Error.DocsURL = %q, want %q", body.Error.DocsURL, tt.err.DocsURL)
			}
		})
	}
}

func TestWriteHTTPErrorJSONBodyStructure(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTPError(rec, ErrRateLimited)

	var raw map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	errObj, ok := raw["error"].(map[string]interface{})
	if !ok {
		t.Fatal("response should have 'error' object at top level")
	}

	requiredFields := []string{"code", "message", "hint", "docs_url"}
	for _, field := range requiredFields {
		if _, exists := errObj[field]; !exists {
			t.Errorf("error object missing field %q", field)
		}
	}
}

func TestWriteHTTPErrorSetsHeaderBeforeBody(t *testing.T) {
	// Verify that WriteHTTPError can be used with a standard ResponseWriter
	rec := httptest.NewRecorder()
	WriteHTTPError(rec, ErrForbidden)

	// The recorder should have captured the write
	if rec.Body.Len() == 0 {
		t.Error("expected non-empty body")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("Code = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestToJSONRPCError_502Mapping(t *testing.T) {
	err := &SentinelError{Code: 502, Message: "Bad Gateway"}
	rpcErr := ToJSONRPCError(err, "req-502")
	if rpcErr.Error.Code != -32603 {
		t.Errorf("expected -32603 for HTTP 502, got %d", rpcErr.Error.Code)
	}
}
