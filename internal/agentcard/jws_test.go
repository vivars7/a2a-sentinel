package agentcard

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// testJWKS generates an RSA key pair and returns the private JWK, public JWKS JSON,
// and an httptest.Server serving that JWKS.
func testJWKS(t *testing.T) (jwk.Key, []byte, *httptest.Server) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	privJWK, err := jwk.FromRaw(privateKey)
	if err != nil {
		t.Fatalf("failed to create JWK from private key: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, "test-card-key"); err != nil {
		t.Fatalf("failed to set key ID: %v", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("failed to set algorithm: %v", err)
	}

	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		t.Fatalf("failed to extract public JWK: %v", err)
	}

	pubKeySet := jwk.NewSet()
	if err := pubKeySet.AddKey(pubJWK); err != nil {
		t.Fatalf("failed to add public key to set: %v", err)
	}
	jwksJSON, err := json.Marshal(pubKeySet)
	if err != nil {
		t.Fatalf("failed to marshal JWKS: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jwksJSON)
	}))

	return privJWK, jwksJSON, srv
}

// signPayload creates a JWS compact serialization of payload signed with the given key.
func signPayload(t *testing.T, payload []byte, key jwk.Key) []byte {
	t.Helper()
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}
	return signed
}

func TestVerifyCardSignature_PlainJSON_NoRequire(t *testing.T) {
	v := NewJWSVerifier(JWSVerifierConfig{
		Require: false,
	})

	plainJSON := []byte(`{"name":"test-agent","version":"1.0"}`)
	got, err := v.VerifyCardSignature(context.Background(), plainJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(plainJSON) {
		t.Errorf("payload = %q, want %q", got, plainJSON)
	}
}

func TestVerifyCardSignature_PlainJSON_Require(t *testing.T) {
	v := NewJWSVerifier(JWSVerifierConfig{
		Require: true,
	})

	plainJSON := []byte(`{"name":"test-agent","version":"1.0"}`)
	_, err := v.VerifyCardSignature(context.Background(), plainJSON)
	if err == nil {
		t.Fatal("expected error when requiring signature on plain JSON")
	}
	if got := err.Error(); got != "card signature required but card is not JWS-signed" {
		t.Errorf("error = %q, want card signature required message", got)
	}
}

func TestVerifyCardSignature_ValidJWS(t *testing.T) {
	privJWK, _, jwksSrv := testJWKS(t)
	defer jwksSrv.Close()

	ctx := context.Background()

	v := NewJWSVerifier(JWSVerifierConfig{
		Require:         true,
		TrustedJWKSURLs: []string{jwksSrv.URL},
		CacheTTL:        1 * time.Minute,
	})

	if err := v.StartCache(ctx); err != nil {
		t.Fatalf("StartCache error: %v", err)
	}

	payload := []byte(`{"name":"signed-agent","version":"2.0"}`)
	signed := signPayload(t, payload, privJWK)

	got, err := v.VerifyCardSignature(ctx, signed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("verified payload = %q, want %q", got, payload)
	}
}

func TestVerifyCardSignature_InvalidJWS(t *testing.T) {
	// Generate one key pair for signing, another for the JWKS endpoint (mismatch).
	_, _, jwksSrv := testJWKS(t) // JWKS serves key pair A
	defer jwksSrv.Close()

	// Generate a different key to sign with (key pair B).
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate other RSA key: %v", err)
	}
	otherJWK, err := jwk.FromRaw(otherKey)
	if err != nil {
		t.Fatalf("failed to create JWK: %v", err)
	}
	if err := otherJWK.Set(jwk.KeyIDKey, "other-key"); err != nil {
		t.Fatalf("failed to set key ID: %v", err)
	}
	if err := otherJWK.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("failed to set algorithm: %v", err)
	}

	ctx := context.Background()

	v := NewJWSVerifier(JWSVerifierConfig{
		Require:         true,
		TrustedJWKSURLs: []string{jwksSrv.URL},
		CacheTTL:        1 * time.Minute,
	})

	if err := v.StartCache(ctx); err != nil {
		t.Fatalf("StartCache error: %v", err)
	}

	payload := []byte(`{"name":"agent","version":"1.0"}`)
	signed := signPayload(t, payload, otherJWK)

	_, err = v.VerifyCardSignature(ctx, signed)
	if err == nil {
		t.Fatal("expected error for JWS signed with untrusted key")
	}
	if got := err.Error(); got != "card JWS signature verification failed against all trusted JWKS" {
		t.Errorf("error = %q, want verification failed message", got)
	}
}

func TestVerifyCardSignature_NoJWKS(t *testing.T) {
	// Verifier with no JWKS URLs but receives a JWS payload.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	privJWK, err := jwk.FromRaw(privKey)
	if err != nil {
		t.Fatalf("failed to create JWK: %v", err)
	}
	if err := privJWK.Set(jwk.KeyIDKey, "no-jwks-key"); err != nil {
		t.Fatalf("failed to set key ID: %v", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("failed to set algorithm: %v", err)
	}

	v := NewJWSVerifier(JWSVerifierConfig{
		Require:         true,
		TrustedJWKSURLs: nil, // No JWKS configured.
	})

	payload := []byte(`{"name":"agent"}`)
	signed := signPayload(t, payload, privJWK)

	_, err = v.VerifyCardSignature(context.Background(), signed)
	if err == nil {
		t.Fatal("expected error when no JWKS configured")
	}
	if got := err.Error(); got != "no trusted JWKS configured for signature verification" {
		t.Errorf("error = %q, want no trusted JWKS message", got)
	}
}

func TestJWSVerifier_IsConfigured(t *testing.T) {
	tests := []struct {
		name string
		urls []string
		want bool
	}{
		{
			name: "no URLs",
			urls: nil,
			want: false,
		},
		{
			name: "empty URLs",
			urls: []string{},
			want: false,
		},
		{
			name: "with URLs",
			urls: []string{"https://example.com/.well-known/jwks.json"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewJWSVerifier(JWSVerifierConfig{
				TrustedJWKSURLs: tt.urls,
			})
			if got := v.IsConfigured(); got != tt.want {
				t.Errorf("IsConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWSVerifier_StartCache_NoURLs(t *testing.T) {
	v := NewJWSVerifier(JWSVerifierConfig{
		TrustedJWKSURLs: nil,
	})

	err := v.StartCache(context.Background())
	if err != nil {
		t.Fatalf("StartCache with no URLs should not error, got: %v", err)
	}

	// Cache should remain nil.
	if v.cache != nil {
		t.Error("cache should be nil when no URLs configured")
	}
}

func TestJWSVerifier_RequireSignature(t *testing.T) {
	v1 := NewJWSVerifier(JWSVerifierConfig{Require: true})
	if !v1.RequireSignature() {
		t.Error("RequireSignature() should return true")
	}

	v2 := NewJWSVerifier(JWSVerifierConfig{Require: false})
	if v2.RequireSignature() {
		t.Error("RequireSignature() should return false")
	}
}

func TestVerifyCardSignature_MultipleJWKSURLs_FirstFails(t *testing.T) {
	privJWK, _, jwksSrv := testJWKS(t)
	defer jwksSrv.Close()

	// Create a broken JWKS server that returns invalid JSON.
	brokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not-valid-json`))
	}))
	defer brokenSrv.Close()

	ctx := context.Background()

	v := NewJWSVerifier(JWSVerifierConfig{
		Require:         true,
		TrustedJWKSURLs: []string{brokenSrv.URL, jwksSrv.URL},
		CacheTTL:        1 * time.Minute,
	})

	if err := v.StartCache(ctx); err != nil {
		t.Fatalf("StartCache error: %v", err)
	}

	payload := []byte(`{"name":"agent","version":"1.0"}`)
	signed := signPayload(t, payload, privJWK)

	got, err := v.VerifyCardSignature(ctx, signed)
	if err != nil {
		t.Fatalf("expected verification to succeed with second JWKS URL, got: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

func TestVerifyCardSignature_JWS_NoRequire_StillVerifies(t *testing.T) {
	// Even when Require=false, if the card IS JWS-signed, we still verify it.
	privJWK, _, jwksSrv := testJWKS(t)
	defer jwksSrv.Close()

	ctx := context.Background()

	v := NewJWSVerifier(JWSVerifierConfig{
		Require:         false,
		TrustedJWKSURLs: []string{jwksSrv.URL},
		CacheTTL:        1 * time.Minute,
	})

	if err := v.StartCache(ctx); err != nil {
		t.Fatalf("StartCache error: %v", err)
	}

	payload := []byte(`{"name":"agent"}`)
	signed := signPayload(t, payload, privJWK)

	got, err := v.VerifyCardSignature(ctx, signed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}
