package agentcard

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/protocol"
)

// maxCardBodySize limits the Agent Card response body to prevent abuse.
const maxCardBodySize = 1 << 20 // 1 MB

// pollAgent runs the polling loop for a single agent. It fetches the Agent Card
// at the configured interval until the context is canceled.
func (m *Manager) pollAgent(ctx context.Context, state *agentState) {
	// Fetch immediately on start.
	m.fetchAndUpdate(ctx, state)

	ticker := time.NewTicker(state.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.fetchAndUpdate(ctx, state)
		}
	}
}

// fetchAndUpdate fetches a card and updates state under lock.
func (m *Manager) fetchAndUpdate(ctx context.Context, state *agentState) {
	card, err := m.fetchCard(ctx, state)

	m.mu.Lock()
	defer m.mu.Unlock()

	state.lastPolled = time.Now()

	if err != nil {
		state.healthy = false
		state.lastError = err
		m.logger.Warn("failed to fetch agent card",
			"agent", state.name,
			"error", err,
		)
		return
	}

	// If we had no card before, this is the initial fetch.
	if state.card == nil {
		state.card = card
		state.healthy = true
		state.lastError = nil
		m.logger.Info("agent card fetched",
			"agent", state.name,
			"skills", len(card.Skills),
		)
		return
	}

	// Detect changes between old and new card.
	changes := DetectChanges(state.card, card)
	if len(changes) > 0 {
		m.handleCardChange(state, card, changes)
	}

	// Mark healthy regardless of change policy decision.
	state.healthy = true
	state.lastError = nil
}

// fetchCard retrieves the Agent Card from the agent's card_path endpoint.
// It uses http.Client (NOT httputil.ReverseProxy) per project rules.
func (m *Manager) fetchCard(ctx context.Context, state *agentState) (*protocol.AgentCard, error) {
	cardURL := buildCardURL(state.url, state.cardPath)

	// Enforce HTTPS unless allow_insecure is true.
	if !state.allowInsecure && strings.HasPrefix(cardURL, "http://") {
		return nil, fmt.Errorf("insecure HTTP URL not allowed for agent %q (set allow_insecure: true to permit): %s", state.name, cardURL)
	}

	client := &http.Client{
		Timeout: state.timeout,
	}

	// If allow_insecure, skip TLS verification (for dev environments only).
	if state.allowInsecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // explicit dev-only flag
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cardURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for agent %q card: %w", state.name, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching agent %q card: %w", state.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent %q card returned HTTP %d", state.name, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCardBodySize))
	if err != nil {
		return nil, fmt.Errorf("reading agent %q card body: %w", state.name, err)
	}

	// JWS signature verification: if configured, verify before parsing JSON.
	if m.jwsVerifier != nil && m.jwsVerifier.IsConfigured() {
		verified, verifyErr := m.jwsVerifier.VerifyCardSignature(ctx, body)
		if verifyErr != nil {
			if m.jwsVerifier.RequireSignature() {
				return nil, fmt.Errorf("agent %q card JWS verification: %w", state.name, verifyErr)
			}
			m.logger.Warn("JWS verification failed, using unsigned card",
				"agent", state.name,
				"error", verifyErr,
			)
		} else {
			body = verified
		}
	}

	var card protocol.AgentCard
	if err := json.Unmarshal(body, &card); err != nil {
		return nil, fmt.Errorf("parsing agent %q card JSON: %w", state.name, err)
	}

	return &card, nil
}

// buildCardURL constructs the full URL for fetching the Agent Card.
func buildCardURL(baseURL, cardPath string) string {
	base := strings.TrimRight(baseURL, "/")
	path := cardPath
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}
