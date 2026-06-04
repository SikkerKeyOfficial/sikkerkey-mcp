// Package serve implements the MCP server side of the Model Context
// Protocol (https://modelcontextprotocol.io). Targets spec version
// 2025-11-25 with backwards-compatible negotiation for older clients.
//
// Wire format: JSON-RPC 2.0 over stdio. AI clients launch this binary
// as a subprocess and exchange newline-delimited JSON messages on the
// child's stdin/stdout. stderr is reserved for diagnostics — never
// emit JSON-RPC frames there.
//
// Lifecycle:
//
//	1. Client sends "initialize" with its supported protocol version.
//	2. Server replies with the agreed protocol version, capabilities,
//	   server info.
//	3. Client sends "notifications/initialized" — purely informational.
//	4. Client sends "tools/list" → server returns tool definitions.
//	5. Client sends "tools/call" → server dispatches to the tool, returns
//	   text content.
//	6. Either side may send "shutdown" before terminating.
//
// Errors map to JSON-RPC error codes. Tool failures (auth, scope,
// network) come back as a successful tool/call response with
// isError=true and an error message in the content — that's the MCP
// convention so the AI can reason about and retry tool failures
// without aborting the whole conversation.
package serve

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"sikkerkey-mcp/internal/api"
	"sikkerkey-mcp/internal/identity"
)

// Spec version we announce by default. Clients negotiate down to
// older versions if they don't know this one.
const ServerProtocolVersion = "2025-11-25"

// Versions we explicitly recognise as compatible. If the client
// requests one of these we mirror it back. If it requests something
// we don't recognise we fall back to ServerProtocolVersion (per the
// spec's negotiation guidance: server picks its preferred version,
// client decides whether to continue).
var supportedProtocolVersions = []string{
	"2025-11-25",
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
}

// JSON-RPC 2.0 error codes — standard set plus MCP-specific.
const (
	errParseError     = -32700
	errInvalidRequest = -32600
	errMethodNotFound = -32601
	errInvalidParams  = -32602
	errInternalError  = -32603
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Server is the running MCP server bound to one agent identity.
type Server struct {
	id       *identity.Identity
	api      *api.Client
	registry *toolRegistry

	mu       sync.Mutex
	out      *bufio.Writer
	clientV  string // negotiated protocol version
	clientUp bool   // received "notifications/initialized"
}

// Run loads the single registered identity, sets up an API client,
// and serves MCP over stdio until the client disconnects or sends
// "shutdown". When multiple identity slots exist this picks the one
// matching SIKKERKEY_AGENT_ID; if that's unset and there's exactly one
// slot, it auto-picks. If multiple slots exist with no env override,
// fail loudly so the operator wires the right slot to the right AI
// client explicitly.
func Run() error {
	id, err := pickIdentity()
	if err != nil {
		return err
	}
	priv, err := identity.LoadPrivateKey(id)
	if err != nil {
		return fmt.Errorf("load private key for %s: %w", id.AgentID, err)
	}

	srv := &Server{
		id:       id,
		api:      api.New(id, priv),
		registry: newToolRegistry(),
		out:      bufio.NewWriter(os.Stdout),
	}
	registerAllTools(srv.registry, srv.api)

	return srv.serveStdio(os.Stdin)
}

func pickIdentity() (*identity.Identity, error) {
	if env := os.Getenv("SIKKERKEY_AGENT_ID"); env != "" {
		id, err := identity.Load(env)
		if err != nil {
			return nil, fmt.Errorf("SIKKERKEY_AGENT_ID=%s: %w", env, err)
		}
		return id, nil
	}
	all, err := identity.LoadAll()
	if err != nil {
		return nil, err
	}
	switch len(all) {
	case 0:
		return nil, errors.New("no AI agent identity registered. Run `sikkerkey-mcp install <token>` first.")
	case 1:
		return &all[0], nil
	default:
		return nil, fmt.Errorf("multiple agent identities found (%d). Set SIKKERKEY_AGENT_ID to pick one", len(all))
	}
}

func (s *Server) serveStdio(in io.Reader) error {
	// JSON-RPC over stdio uses newline-delimited JSON in MCP's stdio
	// transport. bufio.Scanner with a generous buffer handles this.
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		s.handleFrame(line)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stdio read: %w", err)
	}
	return nil
}

func (s *Server) handleFrame(frame []byte) {
	var req rpcRequest
	if err := json.Unmarshal(frame, &req); err != nil {
		s.writeError(nil, errParseError, "parse error: "+err.Error())
		return
	}
	if req.JSONRPC != "2.0" {
		s.writeError(req.ID, errInvalidRequest, "jsonrpc must be \"2.0\"")
		return
	}

	// Notifications have no id; we don't reply.
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"

	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "notifications/initialized":
		s.clientUp = true
		// no reply
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(req)
	case "ping":
		s.writeResult(req.ID, map[string]any{})
	case "shutdown":
		s.writeResult(req.ID, map[string]any{})
		// The client is expected to close stdin after this; we just
		// keep serving until EOF rather than racing to exit.
	case "notifications/cancelled", "notifications/progress":
		// We don't track outstanding requests by id yet — every tool
		// call runs synchronously. Acknowledge and ignore.
	default:
		if isNotification {
			return
		}
		s.writeError(req.ID, errMethodNotFound, "method not found: "+req.Method)
	}
}

// initializeParams matches the spec for "initialize". We only inspect
// the version; client capabilities come along but we don't currently
// gate on them.
type initializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	ClientInfo      map[string]any `json:"clientInfo"`
	Capabilities    map[string]any `json:"capabilities"`
}

func (s *Server) handleInitialize(req rpcRequest) {
	var p initializeParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.writeError(req.ID, errInvalidParams, "invalid initialize params: "+err.Error())
		return
	}

	// Negotiate: if the client speaks a version we know, mirror it.
	// Otherwise announce our preferred version and let the client
	// decide whether to continue.
	chosen := ServerProtocolVersion
	for _, v := range supportedProtocolVersions {
		if v == p.ProtocolVersion {
			chosen = v
			break
		}
	}
	s.clientV = chosen

	s.writeResult(req.ID, map[string]any{
		"protocolVersion": chosen,
		"serverInfo": map[string]any{
			"name":    "sikkerkey-mcp",
			"version": Version,
		},
		"capabilities": map[string]any{
			"tools": map[string]any{
				// listChanged: we don't dynamically add/remove tools
				// at runtime, so this stays false.
				"listChanged": false,
			},
		},
		// Surfaced to the AI as guidance text. Helps the model
		// understand what the agent can and can't do without having
		// to read every tool description.
		"instructions": s.instructions(),
	})
}

func (s *Server) instructions() string {
	return fmt.Sprintf(
		"You are connected to SikkerKey, a secrets management platform, "+
			"as AI agent %q on vault %q.\n\n"+
			"Surface: management plane only. Tools cover machine and AI-agent "+
			"identities, projects, secret metadata, rotation schedules, access "+
			"policies, canaries, audit log, alerts, webhooks, and support.\n\n"+
			"Authentication: every call is Ed25519-signed by this agent's "+
			"private key with timestamp + nonce replay protection. This "+
			"identity is distinct from machine identities — there is no path "+
			"through these tools to authenticate as a machine or read "+
			"plaintext secrets.\n\n"+
			"Authorization: operations are gated by scopes granted at "+
			"provisioning time and revocable from the vault owner's "+
			"dashboard. Every action is recorded in the audit log attributed "+
			"to this agent.\n\n"+
			"Plaintext contract: read-blind on stored secret values. No tool "+
			"returns the plaintext of an existing secret. Write actions "+
			"(create / update_value / rotate / dynamic_create) take plaintext "+
			"as input, encrypt it server-side with envelope encryption, and "+
			"do not round-trip the value back. The one exception is "+
			"manage_temporary_secrets.create, which returns a one-time-use "+
			"share-link credential intended for a human recipient; opening "+
			"that link from this surface destroys the secret without "+
			"delivering it.\n\n"+
			"Companion SDKs: SikkerKey ships read-only runtime SDKs for "+
			"Python, Node.js, Go, .NET, and Kotlin/JVM. Applications use "+
			"these to fetch secrets at runtime under a separate machine "+
			"identity (not this AI agent). When the customer asks how to "+
			"read a secret from their application, call `manage_sdks` to "+
			"get the install command, runtime requirement, and a "+
			"quick-start snippet for their language, then hand them "+
			"working code rather than a docs link.\n\n"+
			"Each tool's `action` parameter selects the underlying operation; "+
			"per-action descriptions list scope requirements.",
		s.id.Name, s.id.VaultID,
	)
}

func (s *Server) handleToolsList(req rpcRequest) {
	tools := s.registry.list()
	s.writeResult(req.ID, map[string]any{
		"tools": tools,
	})
}

type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) handleToolsCall(req rpcRequest) {
	var p toolsCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.writeError(req.ID, errInvalidParams, "invalid tools/call params: "+err.Error())
		return
	}

	t, ok := s.registry.get(p.Name)
	if !ok {
		// Unknown tool. Per MCP convention we return tools/call with
		// isError=true rather than a JSON-RPC error, so the AI can
		// recover instead of aborting the conversation.
		s.writeResult(req.ID, errorContent(fmt.Sprintf("unknown tool: %s", p.Name)))
		return
	}

	out, err := t.invoke(p.Arguments)
	if err != nil {
		s.writeResult(req.ID, errorContent(err.Error()))
		return
	}
	s.writeResult(req.ID, successContent(out))
}

// writeResult / writeError / errorContent / successContent.

func (s *Server) writeResult(id json.RawMessage, result any) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
	s.writeFrame(resp)
}

func (s *Server) writeError(id json.RawMessage, code int, msg string) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
	s.writeFrame(resp)
}

func (s *Server) writeFrame(resp rpcResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bytes, err := json.Marshal(resp)
	if err != nil {
		// If we can't even marshal a response, log to stderr — there's
		// nothing useful to send the client.
		fmt.Fprintln(os.Stderr, "encode response:", err)
		return
	}
	s.out.Write(bytes)
	s.out.WriteByte('\n')
	s.out.Flush()
}

// MCP tools/call response shapes.

func successContent(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
		"isError": false,
	}
}

func errorContent(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
		"isError": true,
	}
}
