package protocol

import (
	"bytes"
	"io"
	"net/http"
)

// InspectAndRewind reads the request body up to maxSize bytes and restores it
// so downstream handlers can read it again.
// Returns the read bytes. If the body exceeds maxSize, only maxSize bytes are returned.
// The restored r.Body always contains the full original content regardless of maxSize.
func InspectAndRewind(r *http.Request, maxSize int) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	limited := io.LimitReader(r.Body, int64(maxSize+1))
	peeked, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	if len(peeked) > maxSize {
		// Body exceeded maxSize — restore full body (peeked + remainder)
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(peeked), r.Body))
		// Return only maxSize bytes for inspection
		return peeked[:maxSize], nil
	}

	// Body fits within maxSize — no remaining data
	r.Body = io.NopCloser(bytes.NewReader(peeked))
	return peeked, nil
}
