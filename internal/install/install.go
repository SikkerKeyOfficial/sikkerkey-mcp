// Package install implements `sikkerkey-mcp install <token>`.
//
// Flow:
//  1. Validate token format (64 hex chars).
//  2. Generate Ed25519 keypair locally.
//  3. POST /v1/ai-bootstrap/register with token + public key.
//  4. Write the registered identity + private key to
//     ~/.sikkerkey/agents/{agentId}/.
//  5. Tell the user the agent is pending approval and how to wire up
//     their AI client.
package install

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"

	"sikkerkey-mcp/internal/api"
	"sikkerkey-mcp/internal/identity"
)

var tokenPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// Run executes the install flow with the provided token, optional name
// override, and the API base URL (resolved from SIKKERKEY_API_URL or
// the default).
func Run(token, name string) error {
	token = strings.TrimSpace(token)
	if !tokenPattern.MatchString(token) {
		return fmt.Errorf("invalid token format (expected 64 hex chars)")
	}

	apiBase := strings.TrimSpace(os.Getenv("SIKKERKEY_API_URL"))
	if apiBase == "" {
		apiBase = api.DefaultAPIBase
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	fmt.Println("SikkerKey AI Agent Bootstrap")
	fmt.Println("============================")
	fmt.Println("Registering agent...")

	resp, err := api.Register(apiBase, api.BootstrapRegisterRequest{
		Token:     token,
		PublicKey: pubB64,
		Name:      name,
	})
	if err != nil {
		return err
	}

	id := identity.Identity{
		AgentID: resp.AgentID,
		Name:    resp.Name,
		VaultID: resp.VaultID,
		APIURL:  apiBase,
	}
	if err := identity.Save(id, priv); err != nil {
		return err
	}

	slot, _ := identity.Slot(resp.AgentID)

	fmt.Println()
	fmt.Println("AI agent identity registered.")
	fmt.Printf("  Agent ID:  %s\n", resp.AgentID)
	fmt.Printf("  Name:      %s\n", resp.Name)
	fmt.Printf("  Vault:     %s\n", resp.VaultID)
	fmt.Printf("  Slot:      %s\n", slot)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Approve the agent from the SikkerKey dashboard's AI agents panel.")
	fmt.Println("  2. Generate the MCP config block for your AI client:")
	fmt.Println("       sikkerkey-mcp config claude-desktop")
	fmt.Println("       sikkerkey-mcp config claude-code")
	fmt.Println("       sikkerkey-mcp config cursor")
	fmt.Println("       sikkerkey-mcp config codex")
	fmt.Println("     and paste the output into the client's MCP config file.")
	return nil
}
