// Package revoke implements `sikkerkey-mcp revoke [agentId]`.
//
// Local-only: removes the on-disk slot for the agent. Does NOT call
// the dashboard to revoke server-side — the operator is expected to
// have already revoked from the AI agents panel before running this
// (otherwise the agent row stays approved + enabled, just orphaned).
//
// If a single agent slot exists and no agentId is passed, that slot
// is removed. If multiple slots exist and no agentId is passed, the
// command refuses and asks the operator to specify which one.
package revoke

import (
	"fmt"

	"sikkerkey-mcp/internal/identity"
)

// Run executes the revoke. Empty agentID auto-picks when only one slot
// exists.
func Run(agentID string) error {
	if agentID == "" {
		agents, err := identity.LoadAll()
		if err != nil {
			return err
		}
		switch len(agents) {
		case 0:
			return fmt.Errorf("no AI agent slots on this machine")
		case 1:
			agentID = agents[0].AgentID
		default:
			fmt.Println("Multiple agent slots found. Specify which to revoke:")
			for _, a := range agents {
				fmt.Printf("  sikkerkey-mcp revoke %s   # %s\n", a.AgentID, a.Name)
			}
			return fmt.Errorf("ambiguous: pass an agent ID")
		}
	}

	id, err := identity.Load(agentID)
	if err != nil {
		return fmt.Errorf("agent %s not found locally: %w", agentID, err)
	}
	if err := identity.Delete(agentID); err != nil {
		return err
	}
	fmt.Printf("Removed local slot for agent %s (%s).\n", id.AgentID, id.Name)
	fmt.Println("Reminder: revoke the agent from the SikkerKey dashboard")
	fmt.Println("if you haven't already — local removal alone leaves the")
	fmt.Println("server-side row approved.")
	return nil
}
