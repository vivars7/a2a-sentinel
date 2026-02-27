package security

import (
	"net/http"
)

// JWSVerifier is a security pipeline middleware placeholder.
// Actual JWS signature verification of Agent Cards happens in the agentcard
// package during the card polling flow (see agentcard.JWSVerifier).
// This middleware is kept for pipeline completeness and potential future
// per-request JWS verification needs.
type JWSVerifier struct{}

// NewJWSVerifier creates a JWSVerifier stub.
func NewJWSVerifier() *JWSVerifier {
	return &JWSVerifier{}
}

// Process passes all requests through without modification.
// Agent Card JWS verification is handled by agentcard.JWSVerifier, not this middleware.
func (j *JWSVerifier) Process(next http.Handler) http.Handler {
	return next
}

// Name returns the middleware name.
func (j *JWSVerifier) Name() string {
	return "jws_verifier"
}
