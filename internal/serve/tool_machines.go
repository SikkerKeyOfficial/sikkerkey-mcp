package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageMachinesTool) }

func newManageMachinesTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_machines",
		summary: "Manage signed machine identities for the vault. Used to list machines, approve pending ones, rename, revoke, and view rename history. Note: machines are secret CONSUMERS — for the AI agent's own management surface use the project-machines tool instead.",
		actions: []toolAction{
			{
				action:  "list",
				summary: "List every machine in the vault. Each row's `kind` is one of: standard (long-lived), ephemeral (enrollment-token fleet machine), or temp (time-bounded single machine).",
				scopes:  []string{"machines.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/machines", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "get",
				summary:  "Single-machine detail. Returns list-row fields plus `kind` (standard | ephemeral | temp), lifecycle fields (expiresAt, enrollmentTokenId), project memberships (projectId + projectName + addedAt), and the count of per-secret grants. Use when you have a machineId from another tool and want full state without paging the list.",
				scopes:   []string{"machines.read"},
				required: []string{"machineId"},
				argSchema: map[string]any{
					"machineId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "machineId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/machines/%s", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "approve",
				summary:  "Approve a pending machine so it can read its granted secrets.",
				scopes:   []string{"machines.write"},
				required: []string{"machineId"},
				argSchema: map[string]any{
					"machineId": map[string]any{"type": "string", "description": "UUID of the machine to approve."},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "machineId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/machines/%s/approve", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "deny",
				summary:  "Deny and remove a pending machine.",
				scopes:   []string{"machines.write"},
				required: []string{"machineId"},
				argSchema: map[string]any{
					"machineId": map[string]any{"type": "string", "description": "UUID of the pending machine to deny."},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "machineId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/machines/%s/deny", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "revoke",
				summary:  "Revoke an approved machine. Drops all secret grants and project memberships. Pass preview=true to get the cascade summary (grant + membership counts) without revoking.",
				scopes:   []string{"machines.write"},
				required: []string{"machineId"},
				argSchema: map[string]any{
					"machineId": map[string]any{"type": "string"},
					"preview":   map[string]any{"type": "boolean", "description": "If true, returns a cascade summary without revoking. Use this before asking the human to confirm."},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "machineId")
					if err != nil {
						return "", err
					}
					var body any
					if preview, ok := argBool(args, "preview"); ok && preview {
						body = map[string]any{"preview": true}
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/machines/%s/revoke", url.PathEscape(id)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "rename",
				summary:  "Rename a machine. Recorded in the machine's name history.",
				scopes:   []string{"machines.write"},
				required: []string{"machineId", "name"},
				argSchema: map[string]any{
					"machineId": map[string]any{"type": "string"},
					"name":      map[string]any{"type": "string", "description": "New name (1-255 chars)."},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "machineId")
					if err != nil {
						return "", err
					}
					name, err := argStringRequired(args, "name")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/machines/%s/rename", url.PathEscape(id)), map[string]any{"name": name})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "name_history",
				summary:  "Return the rename history for a machine.",
				scopes:   []string{"machines.read"},
				required: []string{"machineId"},
				argSchema: map[string]any{
					"machineId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "machineId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/machines/%s/name-history", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
