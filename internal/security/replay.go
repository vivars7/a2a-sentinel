package security

import (
	"log"
	"net/http"
)

// ReplayDetector is a v0.2 stub that will detect replay attacks.
// Currently passes all requests through.
type ReplayDetector struct{}

// NewReplayDetector creates a ReplayDetector stub.
func NewReplayDetector() *ReplayDetector {
	return &ReplayDetector{}
}

// Process returns an http.Handler that passes all requests through (stub).
func (rd *ReplayDetector) Process(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("stub: replay detection check skipped")
		next.ServeHTTP(w, r)
	})
}

// Name returns the middleware name.
func (rd *ReplayDetector) Name() string {
	return "replay_detector"
}
