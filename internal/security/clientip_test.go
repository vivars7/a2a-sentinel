package security

import (
	"testing"
)

func TestTrustedClientIP(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		xff            string
		trustedProxies []string
		want           string
	}{
		{
			name:           "no trusted proxies uses RemoteAddr",
			remoteAddr:     "192.168.1.100:12345",
			xff:            "10.0.0.1, 172.16.0.1",
			trustedProxies: nil,
			want:           "192.168.1.100",
		},
		{
			name:           "empty trusted proxies uses RemoteAddr",
			remoteAddr:     "192.168.1.100:12345",
			xff:            "10.0.0.1",
			trustedProxies: []string{},
			want:           "192.168.1.100",
		},
		{
			name:           "RemoteAddr without port",
			remoteAddr:     "192.168.1.100",
			xff:            "",
			trustedProxies: nil,
			want:           "192.168.1.100",
		},
		{
			name:           "trusted proxies with XFF extracts rightmost non-trusted",
			remoteAddr:     "10.0.0.1:8080",
			xff:            "203.0.113.50, 10.0.0.2, 10.0.0.1",
			trustedProxies: []string{"10.0.0.0/8"},
			want:           "203.0.113.50",
		},
		{
			name:           "trusted proxies with multiple non-trusted returns rightmost non-trusted",
			remoteAddr:     "10.0.0.1:8080",
			xff:            "1.1.1.1, 2.2.2.2, 10.0.0.5",
			trustedProxies: []string{"10.0.0.0/8"},
			want:           "2.2.2.2",
		},
		{
			name:           "all XFF IPs trusted falls back to RemoteAddr",
			remoteAddr:     "10.0.0.1:8080",
			xff:            "10.0.0.2, 10.0.0.3",
			trustedProxies: []string{"10.0.0.0/8"},
			want:           "10.0.0.1",
		},
		{
			name:           "trusted proxies but no XFF uses RemoteAddr",
			remoteAddr:     "192.168.1.1:9999",
			xff:            "",
			trustedProxies: []string{"10.0.0.0/8"},
			want:           "192.168.1.1",
		},
		{
			name:           "single IP trusted proxy",
			remoteAddr:     "10.0.0.1:8080",
			xff:            "203.0.113.50, 10.0.0.1",
			trustedProxies: []string{"10.0.0.1"},
			want:           "203.0.113.50",
		},
		{
			name:           "IPv6 RemoteAddr",
			remoteAddr:     "[::1]:8080",
			xff:            "",
			trustedProxies: nil,
			want:           "::1",
		},
		{
			name:           "XFF with spaces",
			remoteAddr:     "10.0.0.1:8080",
			xff:            " 203.0.113.50 , 10.0.0.2 ",
			trustedProxies: []string{"10.0.0.0/8"},
			want:           "203.0.113.50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TrustedClientIP(tt.remoteAddr, tt.xff, tt.trustedProxies)
			if got != tt.want {
				t.Errorf("TrustedClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStripPort(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.1:8080", "192.168.1.1"},
		{"192.168.1.1", "192.168.1.1"},
		{"[::1]:8080", "::1"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripPort(tt.input)
			if got != tt.want {
				t.Errorf("stripPort(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseCIDRs(t *testing.T) {
	nets := parseCIDRs([]string{"10.0.0.0/8", "192.168.1.1", "invalid"})
	// Should parse the CIDR and the single IP, skip invalid
	if len(nets) != 2 {
		t.Fatalf("expected 2 parsed nets, got %d", len(nets))
	}
}

func TestTrustedClientIPWithInvalidXFFEntries(t *testing.T) {
	// XFF contains invalid (non-parseable) IP entries mixed with valid ones.
	// Invalid entries should be skipped; the rightmost valid non-trusted IP is returned.
	got := TrustedClientIP(
		"10.0.0.1:8080",
		"not-an-ip, 203.0.113.10, 10.0.0.1",
		[]string{"10.0.0.0/8"},
	)
	// "not-an-ip" is skipped, "10.0.0.1" is trusted, so rightmost non-trusted is "203.0.113.10"
	if got != "203.0.113.10" {
		t.Errorf("expected '203.0.113.10', got %q", got)
	}
}

func TestTrustedClientIPAllXFFInvalid(t *testing.T) {
	// All XFF entries are invalid IPs — falls back to RemoteAddr.
	got := TrustedClientIP(
		"192.168.1.5:9999",
		"not-an-ip, also-invalid",
		[]string{"10.0.0.0/8"},
	)
	if got != "192.168.1.5" {
		t.Errorf("expected '192.168.1.5', got %q", got)
	}
}

func TestTrustedClientIPIPv6Trusted(t *testing.T) {
	// IPv6 trusted proxy range.
	got := TrustedClientIP(
		"[::1]:8080",
		"2001:db8::1, ::1",
		[]string{"::1/128"},
	)
	// ::1 is trusted, so rightmost non-trusted is 2001:db8::1
	if got != "2001:db8::1" {
		t.Errorf("expected '2001:db8::1', got %q", got)
	}
}
