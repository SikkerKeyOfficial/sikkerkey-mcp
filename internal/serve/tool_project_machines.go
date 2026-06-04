package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageProjectMachinesTool) }

func newManageProjectMachinesTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_project_machines",
		summary: "Manage which machines are attached to a project and which secrets they can read. The vault's six-requirement gate: a machine reads a secret only if it's approved, in the project, and explicitly granted that secret. This tool is how those grants get set.",
		actions: []toolAction{
			{
				action:   "query",
				summary:  "List machines attached to a project, with filters/sort/pagination via body. Each row includes `kind` (standard | ephemeral | temp).",
				scopes:   []string{"projects.machines.read"},
				required: []string{"projectId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"search":    map[string]any{"type": "string"},
					"sortBy":    map[string]any{"type": "string", "description": "name | added | secretCount"},
					"sortDir":   map[string]any{"type": "string", "enum": []any{"asc", "desc"}},
					"page":      map[string]any{"type": "integer"},
					"pageSize":  map[string]any{"type": "integer"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					body := map[string]any{}
					if s := argString(args, "search"); s != "" {
						body["search"] = s
					}
					if s := argString(args, "sortBy"); s != "" {
						body["sortBy"] = s
					}
					if s := argString(args, "sortDir"); s != "" {
						body["sortDir"] = s
					}
					if n, ok := argInt(args, "page"); ok {
						body["page"] = n
					}
					if n, ok := argInt(args, "pageSize"); ok {
						body["pageSize"] = n
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/machines/query", url.PathEscape(pid)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "attach",
				summary:  "Add a machine to a project. The machine must be owned by the vault owner.",
				scopes:   []string{"projects.machines.write"},
				required: []string{"projectId", "machineId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"machineId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					mid, err := argStringRequired(args, "machineId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/machines", url.PathEscape(pid)), map[string]any{"machineId": mid})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "detach",
				summary:  "Remove a machine from a project. Cascades through every secret grant for that machine within this project.",
				scopes:   []string{"projects.machines.write"},
				required: []string{"projectId", "machineId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"machineId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					mid, err := argStringRequired(args, "machineId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/machines/%s/detach", url.PathEscape(pid), url.PathEscape(mid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "grants_get",
				summary:  "List secret IDs in this project that the machine has access to.",
				scopes:   []string{"projects.machines.read"},
				required: []string{"projectId", "machineId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"machineId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					mid, err := argStringRequired(args, "machineId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/projects/%s/machines/%s/secrets", url.PathEscape(pid), url.PathEscape(mid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "grants_set",
				summary:  "Replace the set of secrets a machine can read within a project. Only secrets in this project are valid; ids from other projects are ignored.",
				scopes:   []string{"projects.machines.write"},
				required: []string{"projectId", "machineId", "secretIds"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"machineId": map[string]any{"type": "string"},
					"secretIds": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Secret IDs the machine should be able to read. Replaces existing grants. Empty array clears all grants."},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					mid, err := argStringRequired(args, "machineId")
					if err != nil {
						return "", err
					}
					ids := argStringSlice(args, "secretIds")
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/machines/%s/grants", url.PathEscape(pid), url.PathEscape(mid)), map[string]any{"secretIds": ids})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
