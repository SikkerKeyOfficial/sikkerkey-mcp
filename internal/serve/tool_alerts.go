package serve

import (
	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageAlertsTool) }

func newManageAlertsTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_alerts",
		summary: "Manage which audit actions trigger alerts (email + webhook dispatch). The vault owner picks which actions are noisy enough to wake them up.",
		actions: []toolAction{
			{
				action:  "list",
				summary: "List currently enabled alert actions for this vault.",
				scopes:  []string{"alerts.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/alerts", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:  "actions",
				summary: "List every action name available to subscribe to. Surfaces severity per action so the AI can recommend a sensible default.",
				scopes:  []string{"alerts.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/alerts/actions", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "set",
				summary:  "Replace the set of enabled alert actions wholesale. Pass the complete desired set; missing actions are deactivated.",
				scopes:   []string{"alerts.write"},
				required: []string{"enabledActions"},
				argSchema: map[string]any{
					"enabledActions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Action names to enable. Empty array disables all alerts."},
				},
				handler: func(args map[string]any) (string, error) {
					ids := argStringSlice(args, "enabledActions")
					raw, err := c.Do("POST", "/v1/ai/alerts", map[string]any{"enabledActions": ids})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
