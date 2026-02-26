package proxy

import "net/http"

// hopByHopHeaders lists headers that must be removed when proxying.
// These are connection-specific headers that should not be forwarded
// between hops per HTTP/1.1 specification (RFC 7230 Section 6.1).
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// CopyHeadersFiltered copies headers from src to dst, excluding hop-by-hop headers.
func CopyHeadersFiltered(dst, src http.Header) {
	for key, values := range src {
		if isHopByHop(key) {
			continue
		}
		for _, v := range values {
			dst.Add(key, v)
		}
	}
}

func isHopByHop(header string) bool {
	canonical := http.CanonicalHeaderKey(header)
	for _, h := range hopByHopHeaders {
		if canonical == http.CanonicalHeaderKey(h) {
			return true
		}
	}
	return false
}
