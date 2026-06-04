// Package api is the HTTP client for the SikkerKey AI surface.
//
// Two responsibilities:
//
//  1. Calling /v1/ai-bootstrap/register during install — this is
//     token-authed, no signature.
//
//  2. Calling /v1/ai/* routes during normal operation — these are
//     Ed25519-signed using the agent's stored private key. Signature
//     format mirrors the SikkerKey machine-auth wire format:
//     "{method}:{path}:{timestamp}:{nonce}:{bodyHash}" signed with
//     Ed25519, sent in X-Signature alongside X-Machine-Id (the agent
//     ID), X-Timestamp, and X-Nonce.
package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sikkerkey-mcp/internal/identity"
)

// DefaultAPIBase is the production SikkerKey API. Override via the
// SIKKERKEY_API_URL env var for staging/dev environments.
const DefaultAPIBase = "https://api.sikkerkey.com"

// Client wraps an HTTP client, an agent identity, and the corresponding
// private key. One Client per agent; reusable across many requests.
type Client struct {
	id         *identity.Identity
	priv       ed25519.PrivateKey
	httpClient *http.Client
	apiBase    string
}

// New constructs a signing client from a loaded identity.
func New(id *identity.Identity, priv ed25519.PrivateKey) *Client {
	apiBase := strings.TrimRight(id.APIURL, "/")
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}
	return &Client{
		id:         id,
		priv:       priv,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiBase:    apiBase,
	}
}

// BootstrapRegisterRequest is the body of POST /v1/ai-bootstrap/register.
type BootstrapRegisterRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"publicKey"`
	Name      string `json:"name,omitempty"`
}

// BootstrapRegisterResponse is what the bootstrap endpoint returns on
// successful registration.
type BootstrapRegisterResponse struct {
	AgentID string `json:"agentId"`
	Name    string `json:"name"`
	VaultID string `json:"vaultId"`
}

// Register exchanges a one-time bootstrap token for an AI agent
// identity. Token-authed (no signature on this request — the token
// itself is the credential), so this is a static method that doesn't
// need a Client.
func Register(apiBase string, req BootstrapRegisterRequest) (*BootstrapRegisterResponse, error) {
	apiBase = strings.TrimRight(apiBase, "/")
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap request: %w", err)
	}
	httpReq, err := http.NewRequest("POST", apiBase+"/v1/ai-bootstrap/register", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("bootstrap request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var errResp struct{ Error string `json:"error"` }
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("bootstrap rejected: %s", errResp.Error)
		}
		return nil, fmt.Errorf("bootstrap rejected: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var out BootstrapRegisterResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse bootstrap response: %w", err)
	}
	return &out, nil
}

// Do signs and sends a request to /v1/ai/{path}. `path` should start
// with "/v1/ai/...". Body may be nil for GET requests.
//
// On non-2xx, returns an error with the server's `error` field if
// present. On 2xx, the response body is returned for the caller to
// JSON-decode into whatever response type the route uses.
func (c *Client) Do(method, path string, body any) ([]byte, error) {
	if !strings.HasPrefix(path, "/v1/ai/") {
		return nil, fmt.Errorf("Do: path must start with /v1/ai/, got %q", path)
	}

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode body: %w", err)
		}
	}

	bodyHash := sha256Hex(bodyBytes)
	// Backend's SignatureVerifier expects timestamp in SECONDS — it
	// multiplies by 1000 to compare against System.currentTimeMillis().
	// Sending UnixMilli would put us ~57000 years in the future.
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce, err := randomNonce()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Signed payload mirrors SignatureVerifier on the backend:
	//   "{method}:{path}:{timestamp}:{nonce}:{bodyHash}"
	signedPayload := fmt.Sprintf("%s:%s:%s:%s:%s", method, path, timestamp, nonce, bodyHash)
	sig := ed25519.Sign(c.priv, []byte(signedPayload))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	req, err := http.NewRequest(method, c.apiBase+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Machine-Id", c.id.AgentID)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sigB64)
	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp struct{ Error string `json:"error"` }
		if json.Unmarshal(respBytes, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBytes))
	}
	return respBytes, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func randomNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
