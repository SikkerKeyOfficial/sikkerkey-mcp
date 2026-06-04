package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageWebhooksTool) }

func newManageWebhooksTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_webhooks",
		summary: "Manage outbound alert-delivery webhooks. Each webhook subscribes to a subset of audit actions; SikkerKey signs and POSTs the payload via HMAC-SHA256 when a matching event fires. The signing secret is shown ONLY in the create response — list/get/update never return it. Pair with manage_alerts to set which actions get delivered.",
		actions: []toolAction{
			{
				action:  "list",
				summary: "List all webhooks for the vault. Returns metadata + delivery health (consecutive failures, last delivered/failed timestamps, last error). Does NOT return signing secrets.",
				scopes:  []string{"alerts.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/webhooks", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "get",
				summary:  "Detail for one webhook. Same fields as list.",
				scopes:   []string{"alerts.read"},
				required: []string{"webhookId"},
				argSchema: map[string]any{
					"webhookId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "webhookId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/webhooks/%s", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "create",
				summary:  "Create a new webhook. URL must be HTTPS and pass the SSRF guard. Response includes the signing secret in plaintext — capture it now, it cannot be retrieved later.",
				scopes:   []string{"alerts.write"},
				required: []string{"url", "actions"},
				argSchema: map[string]any{
					"url":     map[string]any{"type": "string", "description": "HTTPS endpoint that will receive POST deliveries. ≤ 2048 chars."},
					"actions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Audit action names to subscribe to. Use read_audit.actions to list valid values."},
				},
				handler: func(args map[string]any) (string, error) {
					webhookUrl, err := argStringRequired(args, "url")
					if err != nil {
						return "", err
					}
					actions := argStringSlice(args, "actions")
					if len(actions) == 0 {
						return "", fmt.Errorf("`actions` must contain at least one event name")
					}
					raw, err := c.Do("POST", "/v1/ai/webhooks", map[string]any{
						"url":     webhookUrl,
						"actions": actions,
					})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "update",
				summary:  "Update a webhook's URL, subscribed actions, or enabled state. Re-enabling resets health (consecutiveFailures, lastError). Signing secret is unchanged and never returned.",
				scopes:   []string{"alerts.write"},
				required: []string{"webhookId"},
				argSchema: map[string]any{
					"webhookId": map[string]any{"type": "string"},
					"url":       map[string]any{"type": "string", "description": "New HTTPS endpoint."},
					"actions":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Replacement subscribed-actions list."},
					"enabled":   map[string]any{"type": "boolean", "description": "Pause / resume delivery."},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "webhookId")
					if err != nil {
						return "", err
					}
					body := map[string]any{}
					if v := argString(args, "url"); v != "" {
						body["url"] = v
					}
					if v := argStringSlice(args, "actions"); len(v) > 0 {
						body["actions"] = v
					}
					if v, ok := argBool(args, "enabled"); ok {
						body["enabled"] = v
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/webhooks/%s/update", url.PathEscape(id)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "delete",
				summary:  "Permanently delete a webhook.",
				scopes:   []string{"alerts.write"},
				required: []string{"webhookId"},
				argSchema: map[string]any{
					"webhookId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "webhookId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/webhooks/%s/delete", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "test",
				summary:  "Send a test payload to a webhook to verify delivery + signature handling.",
				scopes:   []string{"alerts.write"},
				required: []string{"webhookId"},
				argSchema: map[string]any{
					"webhookId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "webhookId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/webhooks/%s/test", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
