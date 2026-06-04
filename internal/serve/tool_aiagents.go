package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageAiAgentsTool) }

func newManageAiAgentsTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_ai_agents",
		summary: "Manage AI agent identities on the vault — list, inspect, approve / deny pending agents, enable / disable, rename, view rename history, and revoke. Bootstrap-token issuance, scope-set mutation, and project-allowlist mutation are NOT exposed here (privilege-escalation paths) and remain dashboard-only.",
		actions: []toolAction{
			{
				action:  "list",
				summary: "List every AI agent owned by the vault, with scope and allowlist counts. Authoritative current-state — preferred over inferring from audit history.",
				scopes:  []string{"aiagents.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/ai-agents", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "get",
				summary:  "Detail for one AI agent including the full scope set and project allowlist.",
				scopes:   []string{"aiagents.read"},
				required: []string{"agentId"},
				argSchema: map[string]any{
					"agentId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "agentId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/ai-agents/%s", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "name_history",
				summary:  "Return the rename history for an AI agent.",
				scopes:   []string{"aiagents.read"},
				required: []string{"agentId"},
				argSchema: map[string]any{
					"agentId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "agentId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/ai-agents/%s/name-history", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "approve",
				summary:  "Approve a pending AI agent so it can authenticate against the vault.",
				scopes:   []string{"aiagents.write"},
				required: []string{"agentId"},
				argSchema: map[string]any{
					"agentId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "agentId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/ai-agents/%s/approve", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "deny",
				summary:  "Deny and remove a pending AI agent. Cascades through scopes, allowlist, and name history. An agent cannot deny itself.",
				scopes:   []string{"aiagents.write"},
				required: []string{"agentId"},
				argSchema: map[string]any{
					"agentId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "agentId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/ai-agents/%s/deny", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "disable",
				summary:  "Disable an AI agent. Signed requests by the agent are denied with 403 'Agent is disabled' until enabled. Scopes and allowlist preserved. An agent cannot disable itself.",
				scopes:   []string{"aiagents.write"},
				required: []string{"agentId"},
				argSchema: map[string]any{
					"agentId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "agentId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/ai-agents/%s/disable", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "enable",
				summary:  "Re-enable a disabled AI agent.",
				scopes:   []string{"aiagents.write"},
				required: []string{"agentId"},
				argSchema: map[string]any{
					"agentId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "agentId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/ai-agents/%s/enable", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "rename",
				summary:  "Rename an AI agent. Recorded in the agent's name history.",
				scopes:   []string{"aiagents.write"},
				required: []string{"agentId", "name"},
				argSchema: map[string]any{
					"agentId": map[string]any{"type": "string"},
					"name":    map[string]any{"type": "string", "description": "New name (1-255 chars)."},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "agentId")
					if err != nil {
						return "", err
					}
					name, err := argStringRequired(args, "name")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/ai-agents/%s/rename", url.PathEscape(id)), map[string]any{"name": name})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "revoke",
				summary:  "Revoke an approved AI agent. Cascades through scopes, allowlist, and name history. Distinguished from deny by audit action ('revoke' vs 'deny'). An agent cannot revoke itself.",
				scopes:   []string{"aiagents.write"},
				required: []string{"agentId"},
				argSchema: map[string]any{
					"agentId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "agentId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/ai-agents/%s/revoke", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
