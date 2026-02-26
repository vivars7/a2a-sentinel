package agentcard

import (
	"fmt"
	"math"

	"github.com/vivars7/a2a-sentinel/internal/protocol"
)

// CardChangePolicy defines how Agent Card changes are handled.
type CardChangePolicy string

const (
	// CardChangeAuto applies changes immediately with an audit log entry.
	CardChangeAuto CardChangePolicy = "auto"
	// CardChangeAlert keeps the old card and logs a warning (default).
	CardChangeAlert CardChangePolicy = "alert"
	// CardChangeApprove stores changes in a pending queue for manual approval (v0.2).
	CardChangeApprove CardChangePolicy = "approve"
)

// Change describes a single field difference between two Agent Cards.
type Change struct {
	Field    string
	OldValue string
	NewValue string
	Critical bool
}

// DetectChanges compares old and new Agent Cards and returns changes.
// "Critical" changes: URL, skills count changes >50%, securitySchemes, version.
func DetectChanges(old, newCard *protocol.AgentCard) []Change {
	if old == nil || newCard == nil {
		return nil
	}

	var changes []Change

	// URL change — critical
	if old.URL != newCard.URL {
		changes = append(changes, Change{
			Field:    "url",
			OldValue: old.URL,
			NewValue: newCard.URL,
			Critical: true,
		})
	}

	// Version change — critical
	if old.Version != newCard.Version {
		changes = append(changes, Change{
			Field:    "version",
			OldValue: old.Version,
			NewValue: newCard.Version,
			Critical: true,
		})
	}

	// Name change
	if old.Name != newCard.Name {
		changes = append(changes, Change{
			Field:    "name",
			OldValue: old.Name,
			NewValue: newCard.Name,
			Critical: false,
		})
	}

	// Description change
	if old.Description != newCard.Description {
		changes = append(changes, Change{
			Field:    "description",
			OldValue: old.Description,
			NewValue: newCard.Description,
			Critical: false,
		})
	}

	// Skills count change — critical if >50% change
	oldSkills := len(old.Skills)
	newSkills := len(newCard.Skills)
	if oldSkills != newSkills {
		critical := false
		if oldSkills > 0 {
			pctChange := math.Abs(float64(newSkills-oldSkills)) / float64(oldSkills)
			critical = pctChange > 0.5
		} else if newSkills > 0 {
			// From 0 to any is >50% change
			critical = true
		}
		changes = append(changes, Change{
			Field:    "skills",
			OldValue: fmt.Sprintf("%d skills", oldSkills),
			NewValue: fmt.Sprintf("%d skills", newSkills),
			Critical: critical,
		})
	}

	// SecuritySchemes change — critical
	oldSchemeCount := len(old.SecuritySchemes)
	newSchemeCount := len(newCard.SecuritySchemes)
	if oldSchemeCount != newSchemeCount {
		changes = append(changes, Change{
			Field:    "securitySchemes",
			OldValue: fmt.Sprintf("%d schemes", oldSchemeCount),
			NewValue: fmt.Sprintf("%d schemes", newSchemeCount),
			Critical: true,
		})
	}

	// Capabilities change
	oldCaps := capabilitiesString(old.Capabilities)
	newCaps := capabilitiesString(newCard.Capabilities)
	if oldCaps != newCaps {
		changes = append(changes, Change{
			Field:    "capabilities",
			OldValue: oldCaps,
			NewValue: newCaps,
			Critical: false,
		})
	}

	return changes
}

// hasCriticalChanges returns true if any change is marked critical.
func hasCriticalChanges(changes []Change) bool {
	for _, c := range changes {
		if c.Critical {
			return true
		}
	}
	return false
}

// handleCardChange applies the change policy when a card update is detected.
func (m *Manager) handleCardChange(state *agentState, newCard *protocol.AgentCard, changes []Change) {
	critical := hasCriticalChanges(changes)

	switch state.changePolicy {
	case CardChangeAuto:
		// Apply immediately + audit log
		state.card = newCard
		m.logger.Info("agent card updated (auto policy)",
			"agent", state.name,
			"changes", len(changes),
			"critical", critical,
		)

	case CardChangeAlert:
		// Keep old card + warning log
		if critical {
			m.logger.Warn("agent card critical change detected, keeping old card (alert policy)",
				"agent", state.name,
				"changes", len(changes),
			)
		} else {
			// Non-critical changes in alert mode: still keep old card, log info
			m.logger.Warn("agent card change detected, keeping old card (alert policy)",
				"agent", state.name,
				"changes", len(changes),
			)
		}

	case CardChangeApprove:
		// Store in pending queue — v0.2 MCP approval
		// For now, behave like alert: keep old card, log warning
		m.logger.Warn("agent card change pending approval (approve policy)",
			"agent", state.name,
			"changes", len(changes),
			"critical", critical,
		)

	default:
		// Unknown policy — treat as alert
		m.logger.Warn("agent card change detected, unknown policy — treating as alert",
			"agent", state.name,
			"policy", string(state.changePolicy),
		)
	}
}

// capabilitiesString returns a summary string for an AgentCapabilities pointer.
func capabilitiesString(caps *protocol.AgentCapabilities) string {
	if caps == nil {
		return "<nil>"
	}
	return fmt.Sprintf("streaming=%t,push=%t,history=%t",
		caps.Streaming, caps.PushNotifications, caps.StateTransitionHistory)
}
