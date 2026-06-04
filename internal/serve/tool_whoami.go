package serve

import (
	"encoding/json"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newWhoamiTool) }

// whoami is a single-call tool with no args. It's not built via
// actionTool because there's no action selector — self-introspection
// is one operation. Always callable: the backend route requires only
// signature validity, no scope.
func newWhoamiTool(c *api.Client) *tool {
	schema := map[string]any{
		"type":                 "object",
		"properties":           map[string]any{},
		"additionalProperties": false,
	}

	return &tool{
		name:        "whoami",
		description: "Describe the calling AI agent: id, name, approval / enabled state, full scope set, project allowlist, and the last 20 audit entries attributed to this agent. Use this at the start of a session to confirm what you can and cannot do, or after the vault owner edits your scopes from the dashboard. Always callable, no scope required.",
		inputSchema: schema,
		invoke: func(_ json.RawMessage) (string, error) {
			raw, err := c.Do("GET", "/v1/ai/whoami", nil)
			if err != nil {
				return "", err
			}
			return pretty(raw), nil
		},
	}
}
