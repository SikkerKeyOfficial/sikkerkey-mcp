// Package identity manages the AI agent's on-disk identity slot.
//
// Path layout:
//
//	~/.sikkerkey/agents/{agentId}/
//	    identity.json     {agentId, name, vaultId, apiUrl, privateKeyPath}
//	    private.pem       Ed25519 private key, PKCS8 PEM
//
// One slot per registered agent. A laptop can host multiple agents
// (e.g., one per AI client) without conflict. Distinct from the
// regular SikkerKey machine identity at ~/.sikkerkey/vaults/{vaultId}/
// — agents live under ~/.sikkerkey/agents/, machines under
// ~/.sikkerkey/vaults/, no overlap.
package identity

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Identity is the on-disk record of a registered AI agent.
type Identity struct {
	AgentID        string `json:"agentId"`
	Name           string `json:"name"`
	VaultID        string `json:"vaultId"`
	APIURL         string `json:"apiUrl"`
	PrivateKeyPath string `json:"privateKeyPath"`
}

// AgentsRoot is the directory that holds every agent slot. Defaults to
// $HOME/.sikkerkey/agents, overrideable via SIKKERKEY_HOME for tests
// and ephemeral environments.
func AgentsRoot() (string, error) {
	if env := strings.TrimSpace(os.Getenv("SIKKERKEY_HOME")); env != "" {
		return filepath.Join(env, "agents"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".sikkerkey", "agents"), nil
}

// Slot returns the path to a specific agent's directory. The directory
// may not exist yet.
func Slot(agentID string) (string, error) {
	root, err := AgentsRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, agentID), nil
}

// Save writes the identity record + private key to a fresh slot. The
// directory and any parents are created with 0o700; identity.json is
// 0o600; private.pem is 0o600. Existing slot for the same agentId is
// overwritten — on re-registration the new keypair replaces the old.
func Save(id Identity, priv ed25519.PrivateKey) error {
	if id.AgentID == "" {
		return errors.New("identity: AgentID is required")
	}

	slot, err := Slot(id.AgentID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(slot, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", slot, err)
	}
	// Lock parent dirs to 0700 too. MkdirAll respects umask; explicit
	// chmod ensures the agents/ root + the slot end up identical
	// regardless of how the tree was created.
	root, _ := AgentsRoot()
	_ = os.Chmod(root, 0o700)
	_ = os.Chmod(slot, 0o700)

	pemBytes, err := encodePKCS8PEM(priv)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	privPath := filepath.Join(slot, "private.pem")
	if err := os.WriteFile(privPath, pemBytes, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", privPath, err)
	}

	id.PrivateKeyPath = privPath

	idJSON, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity: %w", err)
	}
	idPath := filepath.Join(slot, "identity.json")
	if err := os.WriteFile(idPath, idJSON, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", idPath, err)
	}
	return nil
}

// Load reads a single agent's identity by agentId.
func Load(agentID string) (*Identity, error) {
	slot, err := Slot(agentID)
	if err != nil {
		return nil, err
	}
	idPath := filepath.Join(slot, "identity.json")
	data, err := os.ReadFile(idPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", idPath, err)
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("parse %s: %w", idPath, err)
	}
	return &id, nil
}

// LoadAll lists every registered agent on this machine. Used by
// `whoami` when no agent ID is specified — most laptops have one slot,
// but a power user can host multiple AI agents and we don't want
// `whoami` to fail when there's ambiguity, just to surface the list.
func LoadAll() ([]Identity, error) {
	root, err := AgentsRoot()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", root, err)
	}
	var out []Identity
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id, err := Load(e.Name())
		if err != nil {
			// Skip malformed slots rather than aborting — a partially
			// written slot from a crashed install shouldn't block
			// listing the working ones.
			continue
		}
		out = append(out, *id)
	}
	return out, nil
}

// LoadPrivateKey reads the PEM-encoded private key for an identity.
func LoadPrivateKey(id *Identity) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(id.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", id.PrivateKeyPath, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", id.PrivateKeyPath)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 key in %s: %w", id.PrivateKeyPath, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", id.PrivateKeyPath)
	}
	return priv, nil
}

// Delete removes an agent's slot. Used by `revoke` after the operator
// has revoked the agent in the dashboard. Idempotent.
func Delete(agentID string) error {
	slot, err := Slot(agentID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(slot); err != nil {
		return fmt.Errorf("remove %s: %w", slot, err)
	}
	return nil
}

func encodePKCS8PEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
