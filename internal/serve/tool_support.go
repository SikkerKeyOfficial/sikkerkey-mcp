package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newSupportTool) }

func newSupportTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "support",
		summary: "Open and manage support tickets on behalf of the vault owner.",
		actions: []toolAction{
			{
				action:  "categories",
				summary: "List ticket categories visible to this vault's plan.",
				scopes:  []string{"support.write"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/ticket-categories", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:  "list",
				summary: "Filtered ticket query with pagination.",
				scopes:  []string{"support.write"},
				argSchema: map[string]any{
					"page":     map[string]any{"type": "integer"},
					"pageSize": map[string]any{"type": "integer"},
					"status":   map[string]any{"type": "string", "description": "open | waiting_on_customer | waiting_on_staff | resolved | closed"},
				},
				handler: func(args map[string]any) (string, error) {
					body := map[string]any{}
					if v, ok := argInt(args, "page"); ok {
						body["page"] = v
					}
					if v, ok := argInt(args, "pageSize"); ok {
						body["pageSize"] = v
					}
					if v := argString(args, "status"); v != "" {
						body["status"] = v
					}
					raw, err := c.Do("POST", "/v1/ai/tickets/query", body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "get",
				summary:  "Ticket detail with the full message thread (excluding internal staff notes).",
				scopes:   []string{"support.write"},
				required: []string{"ticketId"},
				argSchema: map[string]any{
					"ticketId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "ticketId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/tickets/%s", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "create",
				summary:  "Open a new support ticket.",
				scopes:   []string{"support.write"},
				required: []string{"categoryId", "priority", "title", "body"},
				argSchema: map[string]any{
					"categoryId": map[string]any{"type": "string"},
					"priority":   map[string]any{"type": "string", "enum": []any{"low", "normal", "high", "urgent"}},
					"title":      map[string]any{"type": "string"},
					"body":       map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					cat, err := argStringRequired(args, "categoryId")
					if err != nil {
						return "", err
					}
					prio, err := argStringRequired(args, "priority")
					if err != nil {
						return "", err
					}
					title, err := argStringRequired(args, "title")
					if err != nil {
						return "", err
					}
					body, err := argStringRequired(args, "body")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", "/v1/ai/tickets", map[string]any{
						"categoryId": cat,
						"priority":   prio,
						"title":      title,
						"body":       body,
					})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "reply",
				summary:  "Add a reply to an existing ticket. JSON body only — file attachments aren't supported on the AI surface (use the dashboard if attachments are needed).",
				scopes:   []string{"support.write"},
				required: []string{"ticketId", "body"},
				argSchema: map[string]any{
					"ticketId": map[string]any{"type": "string"},
					"body":     map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "ticketId")
					if err != nil {
						return "", err
					}
					body, err := argStringRequired(args, "body")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/tickets/%s/reply", url.PathEscape(id)), map[string]any{"body": body})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "rate",
				summary:  "Rate a resolved ticket (1-5). Once-only; second submission returns 409.",
				scopes:   []string{"support.write"},
				required: []string{"ticketId", "rating"},
				argSchema: map[string]any{
					"ticketId": map[string]any{"type": "string"},
					"rating":   map[string]any{"type": "integer", "minimum": 1, "maximum": 5},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "ticketId")
					if err != nil {
						return "", err
					}
					rating, ok := argInt(args, "rating")
					if !ok {
						return "", fmt.Errorf("missing or non-integer `rating`")
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/tickets/%s/rate", url.PathEscape(id)), map[string]any{"rating": rating})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "attachment",
				summary:  "Download a ticket attachment (returns binary data, base64-encoded). Internal staff notes are filtered out.",
				scopes:   []string{"support.write"},
				required: []string{"attachmentId"},
				argSchema: map[string]any{
					"attachmentId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "attachmentId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/tickets/attachments/%s", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					// Attachment route returns raw bytes. Hand them
					// back as-is; AI clients can interpret as needed.
					return string(raw), nil
				},
			},
		},
	}).build()
}
