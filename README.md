# SikkerKey MCP

The official [Model Context Protocol](https://modelcontextprotocol.io) server for [SikkerKey](https://sikkerkey.com). Manage your vault from Claude Code, Codex, Cursor, and other MCP-compatible AI clients, without ever giving the AI access to plaintext secret values.

The server runs locally as a child process of your AI client, authenticates to SikkerKey on every call with an Ed25519 signed request, and exposes management tools for projects, secrets, policies, canaries, machines, AI agents, audit, alerts, webhooks, and support. The agent's private key never leaves the machine, and no tool returns the plaintext content of a stored secret.

## Installation

```bash
npm install -g sikkerkey-mcp
```

Or run without installing:

```bash
npx sikkerkey-mcp <subcommand>
```

## Quick start

### 1. Provision an AI agent

In the SikkerKey dashboard, go to **Machines → AI Agents** and click **Bootstrap AI agent**. Pick the scopes the agent should hold and an optional project allowlist. The dashboard issues a one-time bootstrap token. Copy it.

### 2. Register on your machine

```bash
sikkerkey-mcp install <token>
```

The binary generates an Ed25519 keypair locally, sends only the public key to SikkerKey, and stores the keypair at `~/.sikkerkey/agents/<agentId>/`. The private key never leaves your machine. The agent enters the **pending** state. Approve it from the dashboard to activate.

### 3. Wire it up to your AI client

The `config` subcommand prints a ready-to-paste config block for the supported clients:

```bash
sikkerkey-mcp config claude-code
sikkerkey-mcp config claude-desktop
sikkerkey-mcp config cursor
sikkerkey-mcp config codex
```

Paste the printed block into the client's MCP config file (the path is included in the output) and restart the client. The SikkerKey tools appear immediately.

### 4. Verify

Restart your AI client and ask it to call `whoami`. The first signed call exercises the full path: the AI client invokes the binary, the MCP server signs the request, and SikkerKey validates the signature and the agent's scope set before returning metadata.

## Subcommands

| Command | Description |
|---------|-------------|
| `install <token> [-name=<name>]` | Bootstrap an AI agent identity from a dashboard-issued token |
| `whoami` | List locally registered agents |
| `revoke [agentId]` | Remove a local agent slot (does not unregister on the server) |
| `config <client>` | Print the MCP config block for the named AI client |
| `serve` | Run as MCP server over stdio (the path AI clients invoke) |

Run with no subcommand to start the MCP server (same as `serve`).

## Plaintext contract

The MCP surface is read-blind on stored secret values. No tool returns the plaintext of an existing secret. Write actions (`create`, `update_value`, `rotate`, `dynamic_create`) accept plaintext as input, encrypt it server-side with envelope encryption, and never round-trip the value back. The single exception is `manage_temporary_secrets.create`, which returns a one-shot share-link credential intended for a human recipient.

AI agents are a separate identity class from machines. The MCP server's signed requests cannot authenticate as a machine, and the runtime SDK and CLI surface that machines use to read secret values is not reachable through any tool. See the [security model](https://docs.sikkerkey.com/docs/mcp/security-model) for the full contract.

## Supported AI clients

| Client | Config target |
|--------|--------------|
| Claude Code | `~/.claude.json` (user-scoped) or `.mcp.json` (project-scoped) |
| Claude Desktop | `claude_desktop_config.json` (OS-specific path) |
| Cursor | `~/.cursor/mcp.json` (user) or `.cursor/mcp.json` (project) |
| Codex | `~/.codex/config.toml` |

Any other MCP-over-stdio client also works. Point it at `sikkerkey-mcp serve` and set `SIKKERKEY_AGENT_ID` in the environment.

## Supported platforms

| OS | Architecture |
|----|-------------|
| Linux | x64, arm64 |
| macOS | x64, arm64 (Apple Silicon) |
| Windows | x64 |

## Environment variables

| Variable | Purpose |
|----------|---------|
| `SIKKERKEY_AGENT_ID` | Selects which local agent identity the server runs as. Required when more than one agent is registered on this host. |
| `SIKKERKEY_HOME` | Override the identity root. Defaults to `~/.sikkerkey`. |

### Repository layout

```
main.go            CLI entry: install / whoami / revoke / config / serve
internal/
  serve/           MCP server over stdio + the tool registry (one file per tool group)
  install/         agent bootstrap (keypair generation, public-key registration)
  whoami/ revoke/  local agent-slot management
  identity/        on-disk keypair storage + request signing
  api/ config/     SikkerKey API client and per-client config blocks
```

## Documentation

Full documentation: [docs.sikkerkey.com](https://docs.sikkerkey.com)

- [MCP overview](https://docs.sikkerkey.com/docs/mcp/overview)
- [Setup](https://docs.sikkerkey.com/docs/mcp/setup)
- [Tools reference](https://docs.sikkerkey.com/docs/mcp/tools)
- [Security model](https://docs.sikkerkey.com/docs/mcp/security-model)
