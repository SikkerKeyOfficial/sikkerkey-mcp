// Package config implements `sikkerkey-mcp config <client>`.
//
// Prints a config block the user pastes into their AI client's MCP
// configuration. Each AI client has a different config file format
// and location — this command emits the right shape for the named
// client and tells the operator where to put it.
//
// Supported clients (matches Anthropic's official MCP client list as
// of 2025):
//
//   - claude-desktop  ~/Library/Application Support/Claude/claude_desktop_config.json (mac)
//                     %APPDATA%\Claude\claude_desktop_config.json (windows)
//                     ~/.config/Claude/claude_desktop_config.json (linux)
//   - claude-code     ~/.claude.json or project .mcp.json (project-scoped)
//   - cursor          ~/.cursor/mcp.json or .cursor/mcp.json (project-scoped)
//   - codex           ~/.codex/config.toml
package config

import (
	"fmt"
	"os"
	"strings"

	"sikkerkey-mcp/internal/identity"
)

// Run prints the config block for the named client.
func Run(client string) error {
	binary := resolveBinaryRef()

	// Pick which agent the config block should target. If multiple
	// slots exist, surface them all rather than guessing — the
	// operator wires SIKKERKEY_AGENT_ID into the config for the
	// specific agent they want this client to use.
	agents, err := identity.LoadAll()
	if err != nil {
		return err
	}
	if len(agents) == 0 {
		return fmt.Errorf("no AI agent identity registered. Run `sikkerkey-mcp install <token>` first")
	}

	switch client {
	case "claude-desktop":
		return printClaudeDesktop(binary, agents)
	case "claude-code":
		return printClaudeCode(binary, agents)
	case "cursor":
		return printCursor(binary, agents)
	case "codex":
		return printCodex(binary, agents)
	default:
		return fmt.Errorf("unknown client %q. Supported: claude-desktop, claude-code, cursor, codex", client)
	}
}

func printClaudeDesktop(binary string, agents []identity.Identity) error {
	fmt.Println("# Claude Desktop MCP config")
	fmt.Println("#")
	fmt.Println("# Paste the block under the \"mcpServers\" key in your Claude Desktop")
	fmt.Println("# config file:")
	fmt.Println("#   macOS:    ~/Library/Application Support/Claude/claude_desktop_config.json")
	fmt.Println("#   Linux:    ~/.config/Claude/claude_desktop_config.json")
	fmt.Println("#   Windows:  %APPDATA%\\Claude\\claude_desktop_config.json")
	fmt.Println("#")
	fmt.Println("# Restart Claude Desktop after editing.")
	fmt.Println()
	fmt.Println(`{`)
	fmt.Println(`  "mcpServers": {`)
	for i, a := range agents {
		key := "sikkerkey"
		if len(agents) > 1 {
			// Disambiguate when multiple agents exist on this machine.
			key = "sikkerkey-" + sanitizeName(a.Name)
		}
		comma := ","
		if i == len(agents)-1 {
			comma = ""
		}
		fmt.Printf(`    "%s": {`+"\n", key)
		fmt.Printf(`      "command": "%s",`+"\n", binary)
		fmt.Printf(`      "args": ["serve"],`+"\n")
		fmt.Printf(`      "env": {`+"\n")
		fmt.Printf(`        "SIKKERKEY_AGENT_ID": "%s"`+"\n", a.AgentID)
		fmt.Printf(`      }`+"\n")
		fmt.Printf(`    }%s`+"\n", comma)
	}
	fmt.Println(`  }`)
	fmt.Println(`}`)
	return nil
}

func printClaudeCode(binary string, agents []identity.Identity) error {
	fmt.Println("# Claude Code MCP config")
	fmt.Println("#")
	fmt.Println("# Add to ~/.claude.json (user-scoped) or .mcp.json in your project root")
	fmt.Println("# (project-scoped, checked into the repo).")
	fmt.Println("#")
	fmt.Println("# Or run: claude mcp add sikkerkey", binary, "serve")
	fmt.Println()
	fmt.Println(`{`)
	fmt.Println(`  "mcpServers": {`)
	for i, a := range agents {
		key := "sikkerkey"
		if len(agents) > 1 {
			key = "sikkerkey-" + sanitizeName(a.Name)
		}
		comma := ","
		if i == len(agents)-1 {
			comma = ""
		}
		fmt.Printf(`    "%s": {`+"\n", key)
		fmt.Printf(`      "command": "%s",`+"\n", binary)
		fmt.Printf(`      "args": ["serve"],`+"\n")
		fmt.Printf(`      "env": {`+"\n")
		fmt.Printf(`        "SIKKERKEY_AGENT_ID": "%s"`+"\n", a.AgentID)
		fmt.Printf(`      }`+"\n")
		fmt.Printf(`    }%s`+"\n", comma)
	}
	fmt.Println(`  }`)
	fmt.Println(`}`)
	return nil
}

func printCursor(binary string, agents []identity.Identity) error {
	fmt.Println("# Cursor MCP config")
	fmt.Println("#")
	fmt.Println("# Paste under \"mcpServers\" in:")
	fmt.Println("#   user-scoped:    ~/.cursor/mcp.json")
	fmt.Println("#   project-scoped: .cursor/mcp.json (checked into the repo)")
	fmt.Println()
	fmt.Println(`{`)
	fmt.Println(`  "mcpServers": {`)
	for i, a := range agents {
		key := "sikkerkey"
		if len(agents) > 1 {
			key = "sikkerkey-" + sanitizeName(a.Name)
		}
		comma := ","
		if i == len(agents)-1 {
			comma = ""
		}
		fmt.Printf(`    "%s": {`+"\n", key)
		fmt.Printf(`      "command": "%s",`+"\n", binary)
		fmt.Printf(`      "args": ["serve"],`+"\n")
		fmt.Printf(`      "env": {`+"\n")
		fmt.Printf(`        "SIKKERKEY_AGENT_ID": "%s"`+"\n", a.AgentID)
		fmt.Printf(`      }`+"\n")
		fmt.Printf(`    }%s`+"\n", comma)
	}
	fmt.Println(`  }`)
	fmt.Println(`}`)
	return nil
}

func printCodex(binary string, agents []identity.Identity) error {
	fmt.Println("# Codex MCP config")
	fmt.Println("#")
	fmt.Println("# Append to ~/.codex/config.toml.")
	fmt.Println()
	for _, a := range agents {
		key := "sikkerkey"
		if len(agents) > 1 {
			key = "sikkerkey-" + sanitizeName(a.Name)
		}
		fmt.Printf("[mcp_servers.%s]\n", key)
		fmt.Printf("command = %q\n", binary)
		fmt.Printf("args = [\"serve\"]\n")
		fmt.Printf("\n")
		fmt.Printf("[mcp_servers.%s.env]\n", key)
		fmt.Printf("SIKKERKEY_AGENT_ID = %q\n", a.AgentID)
		fmt.Println()
	}
	return nil
}

// resolveBinaryRef returns the value to use as `command` in the
// printed config block.
//
// The choice between an absolute path and the bare PATH name matters
// for portability:
//
//   - For npm-installed users (`npm install -g sikkerkey-mcp`,
//     `npm install` in a project, or `npx sikkerkey-mcp`), the Go
//     binary lives deep inside `node_modules`. `os.Executable()`
//     returns that absolute path. Hard-coding it into the config
//     breaks when the user upgrades the package, moves their
//     `node_modules`, or shares the config across machines.
//
//   - For source-built users who put the binary at a custom path
//     that may not be on PATH, the absolute path is the right
//     thing to print.
//
// Detection heuristic: if the binary is running from inside a
// `node_modules` directory, we know it was launched by the npm
// shim, which is itself on PATH. Use the PATH-resolvable name so
// the AI client looks it up dynamically.
func resolveBinaryRef() string {
	binary, err := os.Executable()
	if err != nil {
		// os.Executable failed — fall back to the bare name and
		// let the operator fix the path if needed.
		return "sikkerkey-mcp"
	}
	sep := string(os.PathSeparator)
	if strings.Contains(binary, sep+"node_modules"+sep) {
		return "sikkerkey-mcp"
	}
	return binary
}

// sanitizeName turns an agent name into a config-key-safe slug. AI
// clients accept arbitrary keys but readability suffers if names
// include spaces or special characters.
func sanitizeName(s string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32 // lowercase
		case r == '_', r == ' ':
			return '-'
		}
		return -1 // drop
	}, s)
	if out == "" {
		out = "agent"
	}
	return out
}
