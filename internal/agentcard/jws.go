package agentcard

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// JWSVerifierConfig holds JWS verification settings for Agent Card signatures.
type JWSVerifierConfig struct {
	Require         bool
	TrustedJWKSURLs []string
	CacheTTL        time.Duration
}

// JWSVerifier verifies Agent Card JWS signatures against trusted JWKS endpoints.
// It uses the lestrrat-go/jwx/v2 JWKS auto-refresh cache for efficient key management.
type JWSVerifier struct {
	cfg   JWSVerifierConfig
	cache *jwk.Cache
}

// NewJWSVerifier creates a JWS verifier with the given configuration.
// Call StartCache before using VerifyCardSignature.
func NewJWSVerifier(cfg JWSVerifierConfig) *JWSVerifier {
	return &JWSVerifier{
		cfg: cfg,
	}
}

// StartCache initializes the JWKS auto-refresh cache and registers all trusted URLs.
// If no trusted JWKS URLs are configured, this is a no-op.
func (v *JWSVerifier) StartCache(ctx context.Context) error {
	if len(v.cfg.TrustedJWKSURLs) == 0 {
		return nil
	}

	c := jwk.NewCache(ctx)
	for _, url := range v.cfg.TrustedJWKSURLs {
		if err := c.Register(url, jwk.WithMinRefreshInterval(v.cfg.CacheTTL)); err != nil {
			return fmt.Errorf("registering JWKS URL %s: %w", url, err)
		}
	}
	v.cache = c
	return nil
}

// VerifyCardSignature verifies a JWS-signed Agent Card payload.
// If cardData is a JWS compact serialization, the signature is verified against
// the trusted JWKS. If it is plain JSON, it is accepted only when Require is false.
// Returns the verified payload (or the original data if unsigned and allowed).
func (v *JWSVerifier) VerifyCardSignature(ctx context.Context, cardData []byte) ([]byte, error) {
	// Try to parse as JWS first.
	_, err := jws.Parse(cardData)
	if err != nil {
		// Not a JWS — it's plain JSON.
		if v.cfg.Require {
			return nil, fmt.Errorf("card signature required but card is not JWS-signed")
		}
		return cardData, nil
	}

	// It is JWS — verify against trusted JWKS.
	if v.cache == nil {
		return nil, fmt.Errorf("no trusted JWKS configured for signature verification")
	}

	// Try each trusted JWKS URL until one succeeds.
	for _, url := range v.cfg.TrustedJWKSURLs {
		keyset, err := v.cache.Get(ctx, url)
		if err != nil {
			continue // Try next URL.
		}
		payload, err := jws.Verify(cardData, jws.WithKeySet(keyset))
		if err == nil {
			return payload, nil
		}
	}

	return nil, fmt.Errorf("card JWS signature verification failed against all trusted JWKS")
}

// IsConfigured returns true if JWS verification is configured with trusted JWKS URLs.
func (v *JWSVerifier) IsConfigured() bool {
	return len(v.cfg.TrustedJWKSURLs) > 0
}

// RequireSignature returns true if card signatures are mandatory.
func (v *JWSVerifier) RequireSignature() bool {
	return v.cfg.Require
}
