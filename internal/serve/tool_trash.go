package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageTrashTool) }

func newManageTrashTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_trash",
		summary: "View and act on soft-deleted secrets. Secrets sit in trash for 30 days before automatic hard-delete; restore returns them, purge hard-deletes immediately.",
		actions: []toolAction{
			{
				action:  "list",
				summary: "List every soft-deleted secret in the vault.",
				scopes:  []string{"trash.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/trash", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "restore",
				summary:  "Restore a soft-deleted secret to its previous project. Subject to plan limits — if you've hit your secret cap, restore will fail until you delete or upgrade.",
				scopes:   []string{"trash.write"},
				required: []string{"secretId"},
				argSchema: map[string]any{
					"secretId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/trash/%s/restore", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "purge",
				summary:  "Hard-delete a soft-deleted secret immediately. Irreversible — version history goes too.",
				scopes:   []string{"trash.write"},
				required: []string{"secretId"},
				argSchema: map[string]any{
					"secretId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/trash/%s/purge", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
