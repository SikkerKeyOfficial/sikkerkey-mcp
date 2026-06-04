// sikkerkey-mcp is the SikkerKey AI agent MCP server.
//
// One binary, several modes:
//
//	sikkerkey-mcp install <token>   bootstrap an AI agent identity from
//	                                a dashboard-issued token
//	sikkerkey-mcp whoami            list locally-registered agents
//	sikkerkey-mcp revoke [id]       remove a local agent slot
//	sikkerkey-mcp config <client>   print MCP config for an AI client
//	sikkerkey-mcp serve             run as MCP server over stdio
//	                                (default — what AI clients invoke)
//
// The MCP server exposes management tools backed by the SikkerKey AI
// surface (/v1/ai/*). It NEVER reads plaintext secret values — those
// routes are not on this surface, by design.
package main

import (
	"flag"
	"fmt"
	"os"

	"sikkerkey-mcp/internal/config"
	"sikkerkey-mcp/internal/install"
	"sikkerkey-mcp/internal/revoke"
	"sikkerkey-mcp/internal/serve"
	"sikkerkey-mcp/internal/whoami"
)

const usage = `sikkerkey-mcp — SikkerKey AI agent MCP server

Usage:
  sikkerkey-mcp install <token> [-name=<name>]   bootstrap an AI agent
  sikkerkey-mcp whoami                           list local agents
  sikkerkey-mcp revoke [agentId]                 remove a local agent slot
  sikkerkey-mcp config <client>                  print MCP config block
  sikkerkey-mcp serve                            run as MCP server (stdio)
  sikkerkey-mcp                                  same as 'serve'

Environment:
  SIKKERKEY_API_URL    override the default API base (https://api.sikkerkey.com)
  SIKKERKEY_HOME       override the default identity root ($HOME/.sikkerkey)
`

func main() {
	if len(os.Args) < 2 {
		// No subcommand → run as MCP server. This is the path AI
		// clients hit when they exec the binary via stdio.
		runServe()
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "install":
		runInstall(args)
	case "whoami":
		runWhoami(args)
	case "revoke":
		runRevoke(args)
	case "config":
		runConfig(args)
	case "serve":
		runServe()
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n\n", cmd)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	name := fs.String("name", "", "optional name for this agent (defaults to server-assigned)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: sikkerkey-mcp install <token>")
		os.Exit(2)
	}
	if err := install.Run(rest[0], *name); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func runWhoami(args []string) {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: sikkerkey-mcp whoami")
		os.Exit(2)
	}
	if err := whoami.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func runRevoke(args []string) {
	var id string
	if len(args) == 1 {
		id = args[0]
	} else if len(args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: sikkerkey-mcp revoke [agentId]")
		os.Exit(2)
	}
	if err := revoke.Run(id); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func runConfig(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: sikkerkey-mcp config <claude-desktop|claude-code|cursor|codex>")
		os.Exit(2)
	}
	if err := config.Run(args[0]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func runServe() {
	if err := serve.Run(); err != nil {
		// Errors during serve are reported on stderr — stdout is
		// reserved for JSON-RPC frames.
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
