package agentcard

import (
	"github.com/vivars7/a2a-sentinel/internal/protocol"
)

// AggregateCards creates a gateway Agent Card from all healthy agents.
// CRITICAL: No sentinel-specific fields (Zero Agent Dependency principle).
func AggregateCards(agents map[string]*agentState, gatewayURL string) *protocol.AgentCard {
	aggregated := &protocol.AgentCard{
		Name:         "a2a-sentinel-gateway",
		Description:  "Aggregated Agent Card from a2a-sentinel gateway",
		URL:          gatewayURL,
		Capabilities: &protocol.AgentCapabilities{},
	}

	var allSkills []protocol.AgentSkill

	for _, state := range agents {
		if !state.healthy || state.card == nil {
			continue
		}

		// Collect skills from each healthy agent.
		allSkills = append(allSkills, state.card.Skills...)

		// Combine capabilities: true if ANY agent supports it.
		if state.card.Capabilities != nil {
			if state.card.Capabilities.Streaming {
				aggregated.Capabilities.Streaming = true
			}
			if state.card.Capabilities.PushNotifications {
				aggregated.Capabilities.PushNotifications = true
			}
			if state.card.Capabilities.StateTransitionHistory {
				aggregated.Capabilities.StateTransitionHistory = true
			}
		}
	}

	aggregated.Skills = allSkills

	return aggregated
}
