package errors

import (
	"encoding/json"
	"net/http"
)

// HTTPErrorResponse wraps a SentinelError for HTTP JSON responses.
type HTTPErrorResponse struct {
	Error SentinelError `json:"error"`
}

// WriteHTTPError writes a SentinelError as an HTTP JSON response.
func WriteHTTPError(w http.ResponseWriter, err *SentinelError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Code)
	json.NewEncoder(w).Encode(HTTPErrorResponse{Error: *err})
}
