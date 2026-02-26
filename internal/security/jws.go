package security

import (
	"log"
	"net/http"
)

// JWSVerifier is a v0.2 stub that will verify JWS signatures on requests.
// Currently passes all requests through.
type JWSVerifier struct{}

// NewJWSVerifier creates a JWSVerifier stub.
func NewJWSVerifier() *JWSVerifier {
	return &JWSVerifier{}
}

// Process returns an http.Handler that passes all requests through (stub).
func (j *JWSVerifier) Process(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("stub: JWS verification check skipped")
		next.ServeHTTP(w, r)
	})
}

// Name returns the middleware name.
func (j *JWSVerifier) Name() string {
	return "jws_verifier"
}
