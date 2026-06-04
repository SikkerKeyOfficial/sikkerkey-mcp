package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageProjectsTool) }

func newManageProjectsTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_projects",
		summary: "Manage projects (the unit of secret isolation in the vault). When the agent has a project allowlist, create auto-adds the new project to that allowlist so the agent can act on what it just made.",
		actions: []toolAction{
			{
				action:  "list",
				summary: "List every project in the vault.",
				scopes:  []string{"projects.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/projects", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "create",
				summary:  "Create a new project. Auto-added to the agent's allowlist if the agent is restricted.",
				scopes:   []string{"projects.write"},
				required: []string{"name"},
				argSchema: map[string]any{
					"name":        map[string]any{"type": "string", "description": "1-100 characters."},
					"description": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					name, err := argStringRequired(args, "name")
					if err != nil {
						return "", err
					}
					body := map[string]any{"name": name}
					if d := argString(args, "description"); d != "" {
						body["description"] = d
					}
					raw, err := c.Do("POST", "/v1/ai/projects", body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "update",
				summary:  "Update a project's name and/or description.",
				scopes:   []string{"projects.write"},
				required: []string{"projectId"},
				argSchema: map[string]any{
					"projectId":   map[string]any{"type": "string"},
					"name":        map[string]any{"type": "string"},
					"description": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					body := map[string]any{}
					if n := argString(args, "name"); n != "" {
						body["name"] = n
					}
					if d := argString(args, "description"); d != "" {
						body["description"] = d
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/update", url.PathEscape(id)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "delete",
				summary:  "Delete a project. Cascades through every secret, version, grant, policy, canary, temporary secret, and team permission in the project. Pass preview=true to get the cascade summary without writing — confirmName is not required for preview, only for the real delete.",
				scopes:   []string{"projects.write"},
				required: []string{"projectId"},
				argSchema: map[string]any{
					"projectId":   map[string]any{"type": "string"},
					"confirmName": map[string]any{"type": "string", "description": "Must equal the project's current name. Required when preview=false (default)."},
					"preview":     map[string]any{"type": "boolean", "description": "If true, returns a per-resource cascade count without deleting. Use this before asking the human to confirm."},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					body := map[string]any{}
					if preview, ok := argBool(args, "preview"); ok && preview {
						body["preview"] = true
					} else {
						name, err := argStringRequired(args, "confirmName")
						if err != nil {
							return "", err
						}
						body["confirmName"] = name
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/delete", url.PathEscape(id)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
