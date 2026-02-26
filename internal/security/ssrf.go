package security

import (
	"log"
	"net/http"
)

// SSRFChecker is a v0.2 stub that will block SSRF attempts on push notification URLs.
// Currently passes all requests through.
type SSRFChecker struct{}

// NewSSRFChecker creates an SSRFChecker stub.
func NewSSRFChecker() *SSRFChecker {
	return &SSRFChecker{}
}

// Process returns an http.Handler that passes all requests through (stub).
func (s *SSRFChecker) Process(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("stub: SSRF check skipped")
		next.ServeHTTP(w, r)
	})
}

// Name returns the middleware name.
func (s *SSRFChecker) Name() string {
	return "ssrf_checker"
}
