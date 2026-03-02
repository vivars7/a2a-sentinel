package protocol

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInspectAndRewind_SmallerThanMaxSize(t *testing.T) {
	maxSize := 100
	originalBody := strings.Repeat("A", 50)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(originalBody))

	peeked, err := InspectAndRewind(r, maxSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(peeked) != originalBody {
		t.Errorf("peeked mismatch: got %q, want %q", peeked, originalBody)
	}

	restored, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("failed to read restored body: %v", err)
	}
	if string(restored) != originalBody {
		t.Errorf("restored body mismatch: got %q, want %q", restored, originalBody)
	}
}

func TestInspectAndRewind_ExactlyMaxSize(t *testing.T) {
	maxSize := 100
	originalBody := strings.Repeat("B", 100)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(originalBody))

	peeked, err := InspectAndRewind(r, maxSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(peeked) != originalBody {
		t.Errorf("peeked mismatch: got %d bytes, want %d bytes", len(peeked), len(originalBody))
	}

	restored, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("failed to read restored body: %v", err)
	}
	if string(restored) != originalBody {
		t.Errorf("restored body mismatch: got %d bytes, want %d bytes", len(restored), len(originalBody))
	}
}

func TestInspectAndRewind_OversizedBody(t *testing.T) {
	maxSize := 100
	originalBody := strings.Repeat("A", 300)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(originalBody))

	peeked, err := InspectAndRewind(r, maxSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Returned bytes should be truncated to maxSize
	if len(peeked) != maxSize {
		t.Errorf("expected %d peeked bytes, got %d", maxSize, len(peeked))
	}

	// But the restored body should contain the FULL original content
	restored, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("failed to read restored body: %v", err)
	}
	if string(restored) != originalBody {
		t.Errorf("restored body mismatch: got %d bytes, want %d bytes", len(restored), len(originalBody))
	}
}
