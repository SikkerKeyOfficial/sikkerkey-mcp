// Package whoami implements `sikkerkey-mcp whoami`.
//
// Lists every AI agent slot present on this machine. Most laptops
// host one slot; power users may host several (one per AI client they
// want to provision separately). No network calls — purely local.
package whoami

import (
	"fmt"

	"sikkerkey-mcp/internal/identity"
)

// Run prints all locally-registered agents.
func Run() error {
	agents, err := identity.LoadAll()
	if err != nil {
		return err
	}
	if len(agents) == 0 {
		fmt.Println("No AI agents registered on this machine.")
		fmt.Println("Run `sikkerkey-mcp install <token>` after generating one")
		fmt.Println("from the dashboard's AI agents panel.")
		return nil
	}

	for i, a := range agents {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("  Agent ID:  %s\n", a.AgentID)
		fmt.Printf("  Name:      %s\n", a.Name)
		fmt.Printf("  Vault:     %s\n", a.VaultID)
		fmt.Printf("  API:       %s\n", a.APIURL)
		fmt.Printf("  Key path:  %s\n", a.PrivateKeyPath)
	}
	return nil
}
