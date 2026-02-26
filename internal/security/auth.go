package security

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
)

// AuthMiddleware handles authentication based on configured mode.
type AuthMiddleware struct {
	mode                 string
	allowUnauthenticated bool
	// JWT validation fields (for terminate mode)
	issuer   string
	audience string
	jwksURL  string
}

// NewAuthMiddleware creates an AuthMiddleware from configuration.
func NewAuthMiddleware(cfg AuthPipelineConfig) *AuthMiddleware {
	return &AuthMiddleware{
		mode:                 cfg.Mode,
		allowUnauthenticated: cfg.AllowUnauthenticated,
		issuer:               cfg.Issuer,
		audience:             cfg.Audience,
		jwksURL:              cfg.JWKSURL,
	}
}

// Process returns an http.Handler that performs authentication checks.
func (a *AuthMiddleware) Process(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var authInfo ctxkeys.AuthInfo

		switch a.mode {
		case "passthrough":
			authInfo = a.processPassthrough()
		case "passthrough-strict":
			var err *sentinelerrors.SentinelError
			authInfo, err = a.processPassthroughStrict(r)
			if err != nil {
				sentinelerrors.WriteHTTPError(w, err)
				return
			}
		case "terminate":
			var err *sentinelerrors.SentinelError
			authInfo, err = a.processTerminate(r)
			if err != nil {
				sentinelerrors.WriteHTTPError(w, err)
				return
			}
		default:
			// Unknown mode — treat as passthrough-strict for safety
			var err *sentinelerrors.SentinelError
			authInfo, err = a.processPassthroughStrict(r)
			if err != nil {
				sentinelerrors.WriteHTTPError(w, err)
				return
			}
		}

		ctx := ctxkeys.WithAuthInfo(r.Context(), authInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Name returns the middleware name.
func (a *AuthMiddleware) Name() string {
	return "auth"
}

// processPassthrough passes all requests without authentication checks.
func (a *AuthMiddleware) processPassthrough() ctxkeys.AuthInfo {
	return ctxkeys.AuthInfo{
		Mode:            "passthrough",
		Subject:         "",
		Scheme:          "",
		SubjectVerified: false,
	}
}

// processPassthroughStrict checks for Authorization header presence.
func (a *AuthMiddleware) processPassthroughStrict(r *http.Request) (ctxkeys.AuthInfo, *sentinelerrors.SentinelError) {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		if !a.allowUnauthenticated {
			return ctxkeys.AuthInfo{}, sentinelerrors.ErrAuthRequired
		}
		// Allow unauthenticated: pass through with empty subject
		return ctxkeys.AuthInfo{
			Mode:            "passthrough-strict",
			Subject:         "",
			Scheme:          "",
			SubjectVerified: false,
		}, nil
	}

	// Parse scheme and token from "Scheme Token" format
	scheme, token := parseAuthHeader(authHeader)

	// Extract subject from token (best effort)
	subject := extractSubjectFromToken(token)

	// v3: prefix "unverified:" for passthrough-strict
	if subject != "" {
		subject = "unverified:" + subject
	}

	return ctxkeys.AuthInfo{
		Mode:            "passthrough-strict",
		Subject:         subject,
		Scheme:          scheme,
		SubjectVerified: false,
	}, nil
}

// processTerminate performs full JWT validation.
func (a *AuthMiddleware) processTerminate(r *http.Request) (ctxkeys.AuthInfo, *sentinelerrors.SentinelError) {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		if !a.allowUnauthenticated {
			return ctxkeys.AuthInfo{}, sentinelerrors.ErrAuthRequired
		}
		return ctxkeys.AuthInfo{
			Mode:            "terminate",
			Subject:         "",
			Scheme:          "",
			SubjectVerified: false,
		}, nil
	}

	scheme, tokenStr := parseAuthHeader(authHeader)
	if !strings.EqualFold(scheme, "bearer") {
		return ctxkeys.AuthInfo{}, sentinelerrors.ErrAuthInvalid
	}

	// Parse and validate the JWT
	var parseOpts []jwt.ParseOption
	parseOpts = append(parseOpts, jwt.WithValidate(true))

	if a.issuer != "" {
		parseOpts = append(parseOpts, jwt.WithIssuer(a.issuer))
	}
	if a.audience != "" {
		parseOpts = append(parseOpts, jwt.WithAudience(a.audience))
	}

	// If JWKS URL is provided, use it for signature verification
	if a.jwksURL != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		keySet, err := jwk.Fetch(ctx, a.jwksURL)
		if err != nil {
			return ctxkeys.AuthInfo{}, sentinelerrors.ErrAuthInvalid
		}
		parseOpts = append(parseOpts, jwt.WithKeySet(keySet))
	} else {
		// No JWKS URL — skip signature verification, validate claims only
		parseOpts = append(parseOpts, jwt.WithVerify(false))
	}

	token, err := jwt.Parse([]byte(tokenStr), parseOpts...)
	if err != nil {
		return ctxkeys.AuthInfo{}, sentinelerrors.ErrAuthInvalid
	}

	subject := token.Subject()

	return ctxkeys.AuthInfo{
		Mode:            "terminate",
		Subject:         subject,
		Scheme:          scheme,
		SubjectVerified: true,
	}, nil
}

// parseAuthHeader splits "Scheme Token" into its parts.
func parseAuthHeader(header string) (scheme, token string) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 {
		return strings.ToLower(parts[0]), parts[1]
	}
	return "", header
}

// extractSubjectFromToken attempts a best-effort subject extraction.
// For JWTs, decodes the payload (second segment) and extracts "sub".
// For opaque tokens, returns the token itself (truncated).
func extractSubjectFromToken(token string) string {
	if token == "" {
		return ""
	}

	// Try JWT-style: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		// Decode the payload (second part)
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err == nil {
			// Simple extraction: look for "sub" field
			sub := extractJSONField(string(payload), "sub")
			if sub != "" {
				return sub
			}
		}
	}

	// Opaque token — use first 16 chars as identifier
	if len(token) > 16 {
		return token[:16] + "..."
	}
	return token
}

// extractJSONField does a minimal extraction of a string field from JSON.
// This avoids importing encoding/json just for this simple case.
func extractJSONField(jsonStr, field string) string {
	// Look for "field":"value" pattern
	key := `"` + field + `"`
	idx := strings.Index(jsonStr, key)
	if idx < 0 {
		return ""
	}
	// Find the colon after the key
	rest := jsonStr[idx+len(key):]
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[colonIdx+1:])
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	// Find closing quote
	rest = rest[1:]
	endIdx := strings.Index(rest, `"`)
	if endIdx < 0 {
		return ""
	}
	return rest[:endIdx]
}
