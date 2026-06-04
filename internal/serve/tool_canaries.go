package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageCanariesTool) }

func newManageCanariesTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_canaries",
		summary: "Manage canary secrets — defensive trip-wires that freeze the project (and optionally related projects) when read by an unexpected machine. Also handles project unfreeze recovery.",
		actions: []toolAction{
			{
				action:   "list",
				summary:  "List every canary in a project — arming state, trigger configuration, last trip timestamp, fire count. Use this before answering 'is this project canary-protected?' rather than scanning every secret for type=='canary'.",
				scopes:   []string{"projects.policies.read"},
				required: []string{"projectId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/projects/%s/canaries", url.PathEscape(pid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "create",
				summary:  "Plant a new canary in a project. The value is server-generated (64-char symbols) so attackers have nothing meaningful to exfil.",
				scopes:   []string{"projects.policies.write"},
				required: []string{"projectId", "name"},
				argSchema: map[string]any{
					"projectId":                    map[string]any{"type": "string"},
					"name":                         map[string]any{"type": "string"},
					"enabled":                      map[string]any{"type": "boolean", "description": "Whether the canary is armed at creation. Default true."},
					"triggerFreezeProject":         map[string]any{"type": "boolean", "description": "Freeze this project on trip. Default true."},
					"triggerFreezeRelatedProjects": map[string]any{"type": "boolean", "description": "Also freeze projects that share machines with this one. Default false."},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					name, err := argStringRequired(args, "name")
					if err != nil {
						return "", err
					}
					body := map[string]any{"projectId": pid, "name": name}
					if v, ok := argBool(args, "enabled"); ok {
						body["enabled"] = v
					}
					if v, ok := argBool(args, "triggerFreezeProject"); ok {
						body["triggerFreezeProject"] = v
					}
					if v, ok := argBool(args, "triggerFreezeRelatedProjects"); ok {
						body["triggerFreezeRelatedProjects"] = v
					}
					raw, err := c.Do("POST", "/v1/ai/canaries", body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "get",
				summary:  "Return a canary's trigger configuration and trip history.",
				scopes:   []string{"projects.policies.read"},
				required: []string{"canaryId"},
				argSchema: map[string]any{
					"canaryId": map[string]any{"type": "string", "description": "Secret ID of the canary."},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "canaryId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/canaries/%s", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "config",
				summary:  "Update trigger toggles on an existing canary. Use enable/disable for arming.",
				scopes:   []string{"projects.policies.write"},
				required: []string{"canaryId"},
				argSchema: map[string]any{
					"canaryId":                     map[string]any{"type": "string"},
					"triggerFreezeProject":         map[string]any{"type": "boolean"},
					"triggerFreezeRelatedProjects": map[string]any{"type": "boolean"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "canaryId")
					if err != nil {
						return "", err
					}
					body := map[string]any{}
					if v, ok := argBool(args, "triggerFreezeProject"); ok {
						body["triggerFreezeProject"] = v
					}
					if v, ok := argBool(args, "triggerFreezeRelatedProjects"); ok {
						body["triggerFreezeRelatedProjects"] = v
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/canaries/%s/config", url.PathEscape(id)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "enable",
				summary:  "Arm a canary. Idempotent.",
				scopes:   []string{"projects.policies.write"},
				required: []string{"canaryId"},
				argSchema: map[string]any{
					"canaryId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "canaryId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/canaries/%s/enable", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "disable",
				summary:  "Disarm a canary without deleting it. Useful when investigating a suspected false positive.",
				scopes:   []string{"projects.policies.write"},
				required: []string{"canaryId"},
				argSchema: map[string]any{
					"canaryId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "canaryId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/canaries/%s/disable", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "unfreeze_project",
				summary:  "Clear a canary-triggered freeze on a project. Does NOT disarm the canary — another read against the same trip-wire will fire it again.",
				scopes:   []string{"projects.policies.write"},
				required: []string{"projectId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/unfreeze", url.PathEscape(pid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
