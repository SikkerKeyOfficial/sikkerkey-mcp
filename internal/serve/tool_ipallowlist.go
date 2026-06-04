package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageIpAllowlistTool) }

func newManageIpAllowlistTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_ipallowlist",
		summary: "Manage the IP allowlist that gates machine authentication for the vault. Note: only applies to MACHINE Ed25519 auth and enrollment — dashboard JWT sessions are intentionally not gated by this. Disabling drops the gate entirely; configure carefully.",
		actions: []toolAction{
			{
				action:  "list",
				summary: "Return current allowlist entries and the enabled/disabled state.",
				scopes:  []string{"ipallowlist.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/ipallowlist", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "add",
				summary:  "Add a CIDR to the allowlist.",
				scopes:   []string{"ipallowlist.write"},
				required: []string{"cidr"},
				argSchema: map[string]any{
					"cidr":  map[string]any{"type": "string", "description": "IPv4 or IPv6 CIDR. Single host = /32 or /128."},
					"label": map[string]any{"type": "string", "description": "Human-readable note for this entry."},
				},
				handler: func(args map[string]any) (string, error) {
					cidr, err := argStringRequired(args, "cidr")
					if err != nil {
						return "", err
					}
					body := map[string]any{"cidr": cidr}
					if l := argString(args, "label"); l != "" {
						body["label"] = l
					}
					raw, err := c.Do("POST", "/v1/ai/ipallowlist", body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "update",
				summary:  "Update the label on an entry. The CIDR itself is immutable — use delete+add for that.",
				scopes:   []string{"ipallowlist.write"},
				required: []string{"entryId"},
				argSchema: map[string]any{
					"entryId": map[string]any{"type": "string"},
					"label":   map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "entryId")
					if err != nil {
						return "", err
					}
					body := map[string]any{}
					if l := argString(args, "label"); l != "" {
						body["label"] = l
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/ipallowlist/%s/update", url.PathEscape(id)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "delete",
				summary:  "Remove an entry from the allowlist.",
				scopes:   []string{"ipallowlist.write"},
				required: []string{"entryId"},
				argSchema: map[string]any{
					"entryId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "entryId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/ipallowlist/%s/delete", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:  "enable",
				summary: "Turn allowlist enforcement on for the vault.",
				scopes:  []string{"ipallowlist.write"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("POST", "/v1/ai/ipallowlist/enable", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:  "disable",
				summary: "Turn allowlist enforcement off. Machines from any IP can then authenticate.",
				scopes:  []string{"ipallowlist.write"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("POST", "/v1/ai/ipallowlist/disable", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "bulk_delete",
				summary:  "Delete multiple allowlist entries by id in one call.",
				scopes:   []string{"ipallowlist.write"},
				required: []string{"entryIds"},
				argSchema: map[string]any{
					"entryIds": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
				handler: func(args map[string]any) (string, error) {
					ids := argStringSlice(args, "entryIds")
					raw, err := c.Do("POST", "/v1/ai/ipallowlist/bulk-delete", map[string]any{"entryIds": ids})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
