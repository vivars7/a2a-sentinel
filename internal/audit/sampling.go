package audit

import "math/rand"

// SamplingConfig controls audit log sampling rates.
type SamplingConfig struct {
	Rate      float64 // Normal request sampling rate (0.0-1.0)
	ErrorRate float64 // Error/blocked request sampling rate (0.0-1.0)
	MaxBody   int     // Maximum body bytes to log
}

// ShouldLog determines if a request should be logged based on its status.
// Error/blocked requests use ErrorRate, normal requests use Rate.
func (s SamplingConfig) ShouldLog(status string) bool {
	switch status {
	case "blocked", "error":
		return s.ErrorRate >= 1.0 || rand.Float64() < s.ErrorRate
	default:
		return s.Rate >= 1.0 || rand.Float64() < s.Rate
	}
}
