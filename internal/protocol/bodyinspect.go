package protocol

import (
	"bytes"
	"io"
	"net/http"
)

// InspectAndRewind reads the request body up to maxSize bytes and restores it
// so downstream handlers can read it again.
// Returns the read bytes. If the body exceeds maxSize, only maxSize bytes are returned.
func InspectAndRewind(r *http.Request, maxSize int) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	limited := io.LimitReader(r.Body, int64(maxSize+1))
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	// Restore body for downstream handlers
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Truncate to maxSize if needed
	if len(body) > maxSize {
		body = body[:maxSize]
	}

	return body, nil
}
