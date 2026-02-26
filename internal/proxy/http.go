package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
)

// HTTPProxy forwards HTTP requests to backend agents.
// It uses http.Client directly instead of httputil.ReverseProxy
// to maintain full control over header management and forwarding behavior.
type HTTPProxy struct {
	client *http.Client
	logger *slog.Logger
}

// NewHTTPProxy creates a new HTTP proxy with the given transport.
func NewHTTPProxy(transport http.RoundTripper, logger *slog.Logger) *HTTPProxy {
	return &HTTPProxy{
		client: &http.Client{Transport: transport},
		logger: logger,
	}
}

// Forward proxies the request to the target backend.
// targetURL is the base URL of the backend (e.g., "http://localhost:8080").
// targetPath is the path to append (e.g., "/a2a").
func (p *HTTPProxy) Forward(w http.ResponseWriter, r *http.Request, targetURL string, targetPath string) error {
	// 1. Build backend request URL
	backendURL := targetURL + targetPath
	if r.URL.RawQuery != "" {
		backendURL += "?" + r.URL.RawQuery
	}

	// 2. Create backend request with original context
	backendReq, err := http.NewRequestWithContext(r.Context(), r.Method, backendURL, r.Body)
	if err != nil {
		sentinelerrors.WriteHTTPError(w, sentinelerrors.ErrAgentUnavailable)
		return fmt.Errorf("creating backend request: %w", err)
	}

	// 3. Copy headers (filter hop-by-hop)
	CopyHeadersFiltered(backendReq.Header, r.Header)

	// 4. Set forwarding headers
	// X-Forwarded-For: append client IP
	clientIP := extractClientIP(r)
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		backendReq.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		backendReq.Header.Set("X-Forwarded-For", clientIP)
	}

	// X-Forwarded-Proto
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	backendReq.Header.Set("X-Forwarded-Proto", proto)

	// 5. DO NOT inject sentinel-specific headers (Zero Agent Dependency)
	// Remove any X-Sentinel-* headers that might have been set
	for key := range backendReq.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-sentinel-") {
			backendReq.Header.Del(key)
		}
	}

	// 6. Execute backend request
	resp, err := p.client.Do(backendReq)
	if err != nil {
		sentinelerrors.WriteHTTPError(w, sentinelerrors.ErrAgentUnavailable)
		return fmt.Errorf("backend request failed: %w", err)
	}
	defer resp.Body.Close()

	// 7. Copy response headers (filter hop-by-hop)
	CopyHeadersFiltered(w.Header(), resp.Header)

	// 8. Write status code
	w.WriteHeader(resp.StatusCode)

	// 9. Copy response body
	io.Copy(w, resp.Body)

	return nil
}

func extractClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
