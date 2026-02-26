package proxy

import (
	"net"
	"net/http"
	"time"
)

// NewHTTPTransport creates an http.Transport optimized for regular HTTP proxying.
func NewHTTPTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}
}

// NewStreamTransport creates an http.Transport optimized for SSE streaming.
// No response header timeout or idle timeout — streams can be long-lived.
func NewStreamTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       0, // no idle timeout for streams
		ResponseHeaderTimeout: 0, // no response header timeout
		TLSHandshakeTimeout:   10 * time.Second,
	}
}
