package security

import (
	"net"
	"strings"
)

// TrustedClientIP extracts the real client IP based on trusted_proxies configuration.
// If trusted_proxies is empty, uses RemoteAddr only (safe default).
// If set, extracts rightmost non-trusted IP from X-Forwarded-For.
func TrustedClientIP(r_remoteAddr string, xForwardedFor string, trustedProxies []string) string {
	// Parse RemoteAddr to strip port
	remoteIP := stripPort(r_remoteAddr)

	if len(trustedProxies) == 0 {
		return remoteIP
	}

	// Parse trusted proxy CIDRs
	trustedNets := parseCIDRs(trustedProxies)

	// If no X-Forwarded-For header, use RemoteAddr
	if xForwardedFor == "" {
		return remoteIP
	}

	// Parse X-Forwarded-For: split by comma, trim whitespace
	parts := strings.Split(xForwardedFor, ",")
	ips := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			ips = append(ips, trimmed)
		}
	}

	// Walk from the rightmost IP toward the left.
	// Return the first (rightmost) IP that is NOT in trusted proxies.
	for i := len(ips) - 1; i >= 0; i-- {
		ip := net.ParseIP(ips[i])
		if ip == nil {
			continue
		}
		if !isIPTrusted(ip, trustedNets) {
			return ips[i]
		}
	}

	// All IPs in XFF are trusted — fallback to RemoteAddr
	return remoteIP
}

// stripPort removes the port from addr (handles both IPv4 and IPv6).
func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port present, return as-is
		return addr
	}
	return host
}

// parseCIDRs parses a slice of CIDR strings or plain IPs into []*net.IPNet.
func parseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		// Try parsing as CIDR first
		_, ipNet, err := net.ParseCIDR(c)
		if err == nil {
			nets = append(nets, ipNet)
			continue
		}
		// Try as plain IP — convert to /32 or /128
		ip := net.ParseIP(c)
		if ip != nil {
			mask := net.CIDRMask(128, 128)
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: mask})
		}
	}
	return nets
}

// isIPTrusted checks if an IP falls within any of the trusted CIDR ranges.
func isIPTrusted(ip net.IP, trustedNets []*net.IPNet) bool {
	for _, n := range trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
