package security

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
)

// okHandler is a test handler that returns 200 and writes AuthInfo details.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	info, ok := ctxkeys.AuthInfoFrom(r.Context())
	if !ok {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "no-auth-info")
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "mode=%s subject=%s scheme=%s verified=%v",
		info.Mode, info.Subject, info.Scheme, info.SubjectVerified)
})

func TestAuthPassthroughMode(t *testing.T) {
	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode: "passthrough",
	})

	handler := mw.Process(okHandler)

	// Any request should pass through
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "mode=passthrough") {
		t.Errorf("expected mode=passthrough, got %s", body)
	}
	if !strings.Contains(body, "subject=") {
		t.Errorf("expected empty subject, got %s", body)
	}
}

func TestAuthPassthroughStrictNoHeader(t *testing.T) {
	tests := []struct {
		name                 string
		allowUnauthenticated bool
		wantCode             int
	}{
		{
			name:                 "no header, allow_unauthenticated=false returns 401",
			allowUnauthenticated: false,
			wantCode:             http.StatusUnauthorized,
		},
		{
			name:                 "no header, allow_unauthenticated=true passes",
			allowUnauthenticated: true,
			wantCode:             http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := NewAuthMiddleware(AuthPipelineConfig{
				Mode:                 "passthrough-strict",
				AllowUnauthenticated: tt.allowUnauthenticated,
			})

			handler := mw.Process(okHandler)
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("expected %d, got %d", tt.wantCode, rec.Code)
			}
		})
	}
}

func TestAuthPassthroughStrictWithHeader(t *testing.T) {
	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode: "passthrough-strict",
	})

	handler := mw.Process(okHandler)

	// Create a JWT-like token with a sub claim
	payload := `{"sub":"alice@example.com","iss":"test"}`
	fakeJWT := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(payload)) +
		".fakesig"

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+fakeJWT)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "mode=passthrough-strict") {
		t.Errorf("expected mode=passthrough-strict, got %s", body)
	}
	if !strings.Contains(body, "unverified:") {
		t.Errorf("expected subject with 'unverified:' prefix, got %s", body)
	}
	if !strings.Contains(body, "alice@example.com") {
		t.Errorf("expected alice@example.com in subject, got %s", body)
	}
	if !strings.Contains(body, "verified=false") {
		t.Errorf("expected SubjectVerified=false, got %s", body)
	}
	if !strings.Contains(body, "scheme=bearer") {
		t.Errorf("expected scheme=bearer, got %s", body)
	}
}

func TestAuthPassthroughStrictOpaqueToken(t *testing.T) {
	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode: "passthrough-strict",
	})

	handler := mw.Process(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "ApiKey my-opaque-secret-key-12345")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "unverified:") {
		t.Errorf("expected subject with 'unverified:' prefix, got %s", body)
	}
	if !strings.Contains(body, "scheme=apikey") {
		t.Errorf("expected scheme=apikey, got %s", body)
	}
}

func TestAuthTerminateModeValidJWT(t *testing.T) {
	// Create a valid unsigned JWT with claims
	tok, err := jwt.NewBuilder().
		Subject("alice@example.com").
		Issuer("test-issuer").
		Audience([]string{"test-audience"}).
		Expiration(time.Now().Add(1 * time.Hour)).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		t.Fatalf("failed to build JWT: %v", err)
	}

	// Serialize without signing (using jwa.NoSignature for unsigned)
	tokenBytes, err := jwt.Sign(tok, jwt.WithInsecureNoSignature())
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode:     "terminate",
		Issuer:   "test-issuer",
		Audience: "test-audience",
		JWKSURL:  "", // no JWKS URL — skip signature verification
	})

	handler := mw.Process(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, "mode=terminate") {
		t.Errorf("expected mode=terminate, got %s", body)
	}
	if !strings.Contains(body, "alice@example.com") {
		t.Errorf("expected subject alice@example.com, got %s", body)
	}
	if !strings.Contains(body, "verified=true") {
		t.Errorf("expected SubjectVerified=true, got %s", body)
	}

	// Suppress unused import warning
	_ = jwa.NoSignature
}

func TestAuthTerminateModeInvalidJWT(t *testing.T) {
	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode:     "terminate",
		Issuer:   "test-issuer",
		Audience: "test-audience",
	})

	handler := mw.Process(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuthTerminateModeExpiredJWT(t *testing.T) {
	tok, err := jwt.NewBuilder().
		Subject("expired-user").
		Issuer("test-issuer").
		Audience([]string{"test-audience"}).
		Expiration(time.Now().Add(-1 * time.Hour)). // expired
		IssuedAt(time.Now().Add(-2 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("failed to build JWT: %v", err)
	}

	tokenBytes, err := jwt.Sign(tok, jwt.WithInsecureNoSignature())
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode:     "terminate",
		Issuer:   "test-issuer",
		Audience: "test-audience",
	})

	handler := mw.Process(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired JWT, got %d", rec.Code)
	}
}

func TestAuthTerminateModeNonBearerScheme(t *testing.T) {
	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode: "terminate",
	})

	handler := mw.Process(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "ApiKey some-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-bearer in terminate mode, got %d", rec.Code)
	}
}

func TestAuthTerminateModeNoHeaderAllowUnauthenticated(t *testing.T) {
	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode:                 "terminate",
		AllowUnauthenticated: true,
	})

	handler := mw.Process(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestAuthPassthroughStrictBearerTokenUnverifiedPrefix(t *testing.T) {
	// passthrough-strict with a Bearer token that has a "sub" claim —
	// subject must be prefixed with "unverified:"
	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode: "passthrough-strict",
	})

	handler := mw.Process(okHandler)

	// Build a fake JWT with a sub claim
	payload := `{"sub":"charlie@example.com","iss":"some-issuer"}`
	fakeJWT := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(payload)) +
		".somesig"

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+fakeJWT)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "unverified:charlie@example.com") {
		t.Errorf("expected 'unverified:charlie@example.com' in body, got %s", body)
	}
	if !strings.Contains(body, "verified=false") {
		t.Errorf("expected SubjectVerified=false, got %s", body)
	}
}

func TestAuthTerminateModeNoHeaderNotAllowed(t *testing.T) {
	// terminate mode with no Authorization header and allowUnauthenticated=false
	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode:                 "terminate",
		AllowUnauthenticated: false,
	})

	handler := mw.Process(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing header in terminate mode, got %d", rec.Code)
	}
}

func TestAuthDefaultModeActsLikePassthroughStrict(t *testing.T) {
	// Unknown/default mode should behave like passthrough-strict
	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode:                 "unknown-mode",
		AllowUnauthenticated: false,
	})

	handler := mw.Process(okHandler)

	// No auth header → 401
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unknown mode with no header, got %d", rec.Code)
	}
}

func TestAuthDefaultModeAllowsWithHeader(t *testing.T) {
	// Unknown mode with a header should pass through (like passthrough-strict)
	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode:                 "unknown-mode",
		AllowUnauthenticated: false,
	})

	handler := mw.Process(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for unknown mode with bearer header, got %d", rec.Code)
	}
}

func TestParseAuthHeaderEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantScheme string
		wantToken  string
	}{
		{
			name:       "normal bearer",
			header:     "Bearer mytoken123",
			wantScheme: "bearer",
			wantToken:  "mytoken123",
		},
		{
			name:       "single word no space",
			header:     "justatoken",
			wantScheme: "",
			wantToken:  "justatoken",
		},
		{
			name:       "empty string",
			header:     "",
			wantScheme: "",
			wantToken:  "",
		},
		{
			name:       "scheme with token containing spaces (SplitN 2)",
			header:     "Bearer tok en with spaces",
			wantScheme: "bearer",
			wantToken:  "tok en with spaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotScheme, gotToken := parseAuthHeader(tt.header)
			if gotScheme != tt.wantScheme {
				t.Errorf("scheme: got %q, want %q", gotScheme, tt.wantScheme)
			}
			if gotToken != tt.wantToken {
				t.Errorf("token: got %q, want %q", gotToken, tt.wantToken)
			}
		})
	}
}

func TestExtractJSONFieldEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		json   string
		field  string
		want   string
	}{
		{
			name:  "field not found",
			json:  `{"iss":"test"}`,
			field: "sub",
			want:  "",
		},
		{
			name:  "field found, value is a string",
			json:  `{"sub":"alice"}`,
			field: "sub",
			want:  "alice",
		},
		{
			name:  "field found but value is not a string (number)",
			json:  `{"sub":42}`,
			field: "sub",
			want:  "",
		},
		{
			name:  "field found but no colon",
			json:  `{"sub"`,
			field: "sub",
			want:  "",
		},
		{
			name:  "field found, colon present, but no closing quote",
			json:  `{"sub":"alice`,
			field: "sub",
			want:  "",
		},
		{
			name:  "empty json",
			json:  ``,
			field: "sub",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSONField(tt.json, tt.field)
			if got != tt.want {
				t.Errorf("extractJSONField(%q, %q) = %q, want %q", tt.json, tt.field, got, tt.want)
			}
		})
	}
}

func TestExtractSubjectFromToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{
			name:  "empty token",
			token: "",
			want:  "",
		},
		{
			name: "JWT-like token with sub",
			token: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) +
				"." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"bob"}`)) +
				".sig",
			want: "bob",
		},
		{
			name:  "opaque short token",
			token: "shortkey",
			want:  "shortkey",
		},
		{
			name:  "opaque long token truncated",
			token: "abcdefghijklmnopqrstuvwxyz",
			want:  "abcdefghijklmnop...",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSubjectFromToken(tt.token)
			if got != tt.want {
				t.Errorf("extractSubjectFromToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuthTerminateModeJWKSFetchError(t *testing.T) {
	// Point jwksURL at an address that will refuse connections immediately.
	// Using a closed httptest server guarantees the port is unreachable.
	closedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedServer.Close() // close before use so any request fails

	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode:    "terminate",
		JWKSURL: closedServer.URL + "/jwks.json",
	})

	handler := mw.Process(okHandler)

	// Any valid-looking Bearer token is fine; the error should occur during JWKS fetch,
	// before JWT signature validation even begins.
	tok, err := jwt.NewBuilder().
		Subject("attacker@example.com").
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("failed to build JWT: %v", err)
	}
	tokenBytes, err := jwt.Sign(tok, jwt.WithInsecureNoSignature())
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when JWKS fetch fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthTerminateModeJWKSValidation(t *testing.T) {
	// Generate an RSA key pair.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Build a JWK from the private key so we can derive the public JWK set.
	privJWK, err := jwk.FromRaw(privateKey)
	if err != nil {
		t.Fatalf("failed to create JWK from private key: %v", err)
	}
	// kid must be set on the private JWK; jwt.Sign will embed it in the token
	// header so that jwt.WithKeySet can match the correct public key.
	if err := privJWK.Set(jwk.KeyIDKey, "test-key-id"); err != nil {
		t.Fatalf("failed to set key ID: %v", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("failed to set algorithm: %v", err)
	}

	// Extract the public key into its own JWK.
	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		t.Fatalf("failed to extract public JWK: %v", err)
	}

	// Build a public JWK set and marshal it to JSON for the test server.
	pubKeySet := jwk.NewSet()
	if err := pubKeySet.AddKey(pubJWK); err != nil {
		t.Fatalf("failed to add public key to set: %v", err)
	}
	jwksJSON, err := json.Marshal(pubKeySet)
	if err != nil {
		t.Fatalf("failed to marshal JWKS: %v", err)
	}

	// Serve the public JWKS from a test HTTP server.
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jwksJSON)
	}))
	defer jwksServer.Close()

	// Build and sign a JWT with the private RSA key.
	tok, err := jwt.NewBuilder().
		Subject("verified-user@example.com").
		Issuer("test-issuer").
		Audience([]string{"test-audience"}).
		Expiration(time.Now().Add(1 * time.Hour)).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		t.Fatalf("failed to build JWT: %v", err)
	}
	// Sign using the private JWK so the kid is embedded in the token header,
	// enabling jwt.WithKeySet to match the public key by kid during verification.
	tokenBytes, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privJWK))
	if err != nil {
		t.Fatalf("failed to sign JWT with RSA key: %v", err)
	}

	mw := NewAuthMiddleware(AuthPipelineConfig{
		Mode:     "terminate",
		Issuer:   "test-issuer",
		Audience: "test-audience",
		JWKSURL:  jwksServer.URL,
	})

	handler := mw.Process(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid JWKS-signed JWT, got %d; body: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, "mode=terminate") {
		t.Errorf("expected mode=terminate, got %s", body)
	}
	if !strings.Contains(body, "verified-user@example.com") {
		t.Errorf("expected subject verified-user@example.com, got %s", body)
	}
	if !strings.Contains(body, "verified=true") {
		t.Errorf("expected SubjectVerified=true, got %s", body)
	}
}
