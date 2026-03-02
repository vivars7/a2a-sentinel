package security

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/vivars7/a2a-sentinel/internal/config"
	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
	"github.com/vivars7/a2a-sentinel/internal/protocol"
)

// privateRanges defines the CIDR blocks considered private/internal networks.
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",    // loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fd00::/8",       // IPv6 unique local
	}
	for _, cidr := range cidrs {
		_, ipNet, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, ipNet)
	}
}

// SSRFChecker validates push notification URLs to prevent SSRF attacks.
// It inspects requests that set push notification configuration and blocks
// URLs that resolve to private/internal networks.
// Note: Sentinel validates push destination URLs at registration time only.
// It does not send push notifications — that is the backend agent's responsibility.
type SSRFChecker struct {
	blockPrivate   bool
	allowedDomains []string
	requireHTTPS   bool
	dnsFailPolicy  string // "block" or "allow"
	logger         *slog.Logger
}

// NewSSRFChecker creates an SSRF checker with the given push notification config.
func NewSSRFChecker(cfg config.PushConfig, logger *slog.Logger) *SSRFChecker {
	if logger == nil {
		logger = slog.Default()
	}
	dnsPolicy := cfg.DNSFailPolicy
	if dnsPolicy == "" {
		dnsPolicy = "block"
	}
	return &SSRFChecker{
		blockPrivate:   cfg.BlockPrivateNetworks,
		allowedDomains: cfg.AllowedDomains,
		requireHTTPS:   cfg.RequireHTTPS,
		dnsFailPolicy:  dnsPolicy,
		logger:         logger,
	}
}

// IsPrivateNetwork checks whether the given host (IP or hostname) resolves to
// a private or internal network address. It strips any port from the host string,
// resolves hostnames to IPs, and checks each IP against known private CIDR ranges.
func IsPrivateNetwork(host string) bool {
	// Strip port if present
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	// Check well-known private hostnames
	lower := strings.ToLower(hostname)
	if lower == "localhost" || strings.HasSuffix(lower, ".local") {
		return true
	}

	// Try parsing as IP directly
	if ip := net.ParseIP(hostname); ip != nil {
		return isPrivateIP(ip)
	}

	// Resolve hostname to IPs
	ips, err := net.LookupHost(hostname)
	if err != nil {
		// If DNS fails, treat as potentially private (fail-closed)
		return true
	}

	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil {
			if isPrivateIP(ip) {
				return true
			}
		}
	}

	return false
}

// isPrivateNetworkWithPolicy checks whether the host resolves to a private network.
// When DNS lookup fails, behavior depends on dnsFailPolicy:
// "block" (default) treats DNS failures as private (fail-closed).
// "allow" treats DNS failures as non-private (fail-open).
// isPrivateNetworkWithPolicy checks whether the host resolves to a private network.
// Returns (isPrivate, dnsWarning). When DNS lookup fails and dns_fail_policy is "allow",
// isPrivate is false but dnsWarning contains a warning message for operational visibility.
func (s *SSRFChecker) isPrivateNetworkWithPolicy(host string) (bool, string) {
	// Strip port if present
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	// Check well-known private hostnames
	lower := strings.ToLower(hostname)
	if lower == "localhost" || strings.HasSuffix(lower, ".local") {
		return true, ""
	}

	// Try parsing as IP directly
	if ip := net.ParseIP(hostname); ip != nil {
		return isPrivateIP(ip), ""
	}

	// Resolve hostname to IPs
	ips, err := net.LookupHost(hostname)
	if err != nil {
		// DNS failure: policy determines behavior
		if s.dnsFailPolicy == "allow" {
			s.logger.Warn("ssrf: DNS lookup failed, allowing per dns_fail_policy",
				"host", hostname,
				"error", err.Error(),
			)
			return false, "DNS resolution failed for push URL"
		}
		// Default: "block" (fail-closed)
		s.logger.Warn("ssrf: DNS lookup failed, blocking per dns_fail_policy",
			"host", hostname,
			"error", err.Error(),
		)
		return true, ""
	}

	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil {
			if isPrivateIP(ip) {
				return true, ""
			}
		}
	}

	return false, ""
}

// isPrivateIP checks if an IP address falls within any private range.
func isPrivateIP(ip net.IP) bool {
	for _, ipNet := range privateRanges {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidatePushURL performs full validation of a push notification callback URL.
// It checks the URL scheme, private network access, allowed domains, and performs
// DNS rebinding defense by resolving the hostname and verifying resolved IPs.
// Returns a warning string (non-empty when DNS failed but was allowed by policy)
// and an error if the URL should be blocked.
func (s *SSRFChecker) ValidatePushURL(rawURL string) (warning string, err error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid push notification URL: %w", err)
	}

	// Check scheme
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("push notification URL must use http or https scheme, got %q", scheme)
	}

	if s.requireHTTPS && scheme != "https" {
		return "", fmt.Errorf("push notification URL must use HTTPS (got %s://)", scheme)
	}

	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("push notification URL has empty host")
	}

	// Check allowed domains (if configured)
	if len(s.allowedDomains) > 0 {
		if !s.isDomainAllowed(host) {
			return "", fmt.Errorf("push notification URL host %q not in allowed domains", host)
		}
	}

	// Check private network (includes DNS rebinding defense via resolution)
	if s.blockPrivate {
		isPrivate, dnsWarning := s.isPrivateNetworkWithPolicy(parsed.Host)
		if isPrivate {
			return "", fmt.Errorf("push notification URL resolves to private network: %s", host)
		}
		warning = dnsWarning
	}

	return warning, nil
}

// isDomainAllowed checks if a hostname matches any of the allowed domains.
// Supports exact match and wildcard suffix match (e.g., host "sub.example.com"
// matches allowed domain "example.com").
func (s *SSRFChecker) isDomainAllowed(host string) bool {
	lower := strings.ToLower(host)
	for _, domain := range s.allowedDomains {
		d := strings.ToLower(domain)
		if lower == d {
			return true
		}
		// Allow subdomains: "sub.example.com" matches "example.com"
		if strings.HasSuffix(lower, "."+d) {
			return true
		}
	}
	return false
}

// Process returns an http.Handler that validates push notification URLs
// in A2A requests. Non-push requests pass through unchanged.
// For push notification requests, the handler extracts the callback URL
// and validates it against SSRF protections.
func (s *SSRFChecker) Process(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only inspect POST requests (push config is set via POST)
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		// Read and rewind body for inspection
		body, err := protocol.InspectAndRewind(r, 64*1024)
		if err != nil {
			s.logger.Warn("ssrf: failed to read request body", "error", err)
			next.ServeHTTP(w, r)
			return
		}

		if len(body) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Extract push notification URL from the request
		pushURL := s.extractPushURL(r, body)
		if pushURL == "" {
			// Not a push notification request — pass through
			next.ServeHTTP(w, r)
			return
		}

		// Validate the push URL
		warning, err := s.ValidatePushURL(pushURL)
		if err != nil {
			s.logger.Warn("ssrf: blocked push notification URL",
				"url", pushURL,
				"reason", err.Error(),
			)
			sentinelerrors.WriteHTTPError(w, sentinelerrors.ErrSSRFBlocked)
			return
		}

		if warning != "" {
			w.Header().Set("X-Sentinel-Warning", warning)
			s.logger.Warn("ssrf: push URL registered with warning",
				"url", pushURL,
				"warning", warning,
				"ssrf_dns_failed_but_allowed", true,
			)
		}

		next.ServeHTTP(w, r)
	})
}

// Name returns the middleware name.
func (s *SSRFChecker) Name() string {
	return "ssrf_checker"
}

// extractPushURL extracts a push notification URL from the request.
// It checks both JSON-RPC and REST push notification patterns.
func (s *SSRFChecker) extractPushURL(r *http.Request, body []byte) string {
	// Try JSON-RPC first
	method, _, err := protocol.ParseJSONRPCMethod(body)
	if err == nil {
		return s.extractPushURLFromJSONRPC(method, body)
	}

	// Try REST pattern
	restMethod := protocol.MatchRESTPattern(r.Method, r.URL.Path)
	if restMethod == "tasks/pushNotificationConfig/set" {
		return s.extractPushURLFromRESTBody(body)
	}

	return ""
}

// jsonrpcPushRequest represents the JSON-RPC params for push notification config set.
type jsonrpcPushRequest struct {
	Params struct {
		PushNotificationConfig struct {
			URL string `json:"url"`
		} `json:"pushNotificationConfig"`
	} `json:"params"`
}

// jsonrpcMessageRequest represents JSON-RPC params for message/send or message/stream
// which may contain an embedded pushNotificationConfig.
type jsonrpcMessageRequest struct {
	Params struct {
		Configuration struct {
			PushNotificationConfig *struct {
				URL string `json:"url"`
			} `json:"pushNotificationConfig"`
		} `json:"configuration"`
	} `json:"params"`
}

// extractPushURLFromJSONRPC extracts the push notification URL from a JSON-RPC request body.
func (s *SSRFChecker) extractPushURLFromJSONRPC(method string, body []byte) string {
	switch method {
	case "tasks/pushNotificationConfig/set":
		var req jsonrpcPushRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return ""
		}
		return req.Params.PushNotificationConfig.URL

	case "message/send", "message/stream":
		var req jsonrpcMessageRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return ""
		}
		if req.Params.Configuration.PushNotificationConfig != nil {
			return req.Params.Configuration.PushNotificationConfig.URL
		}
	}

	return ""
}

// extractPushURLFromRESTBody extracts the push notification URL from a REST request body.
func (s *SSRFChecker) extractPushURLFromRESTBody(body []byte) string {
	var payload struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return payload.URL
}
