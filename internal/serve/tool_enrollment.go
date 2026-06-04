package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageEnrollmentTool) }

func newManageEnrollmentTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_enrollment",
		summary: "Manage enrollment tokens — multi-use credentials that ephemeral machines (CI runners, autoscaling pods) use to bootstrap themselves into specific projects + secret grants.",
		actions: []toolAction{
			{
				action:  "list",
				summary: "List enrollment tokens, including revoked ones.",
				scopes:  []string{"enrollment.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/enrollment-tokens", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "get",
				summary:  "Detail for one enrollment token (config, redemption count, revocation state).",
				scopes:   []string{"enrollment.read"},
				required: []string{"tokenId"},
				argSchema: map[string]any{
					"tokenId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "tokenId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/enrollment-tokens/%s", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "create",
				summary:  "Issue a new enrollment token. Bootstrap-time scopes (projects, secrets, lifetime) are baked into the token at issue and can't be widened later — to grant more, issue a new token.",
				scopes:   []string{"enrollment.write"},
				required: []string{"name", "projectIds", "secretIds", "tokenLifetimeSeconds", "machineLifetimeSeconds", "maxUses"},
				argSchema: map[string]any{
					"name":                   map[string]any{"type": "string"},
					"description":            map[string]any{"type": "string"},
					"projectIds":             map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Projects machines enrolled by this token are added to. Empty array allowed if granting only secret access."},
					"secretIds":              map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Secrets machines enrolled by this token are granted access to. Empty array allowed."},
					"tokenLifetimeSeconds":   map[string]any{"type": "integer", "description": "How long the token itself remains valid for redemption (seconds from now)."},
					"machineLifetimeSeconds": map[string]any{"type": "integer", "description": "Lifetime for each machine enrolled via this token (seconds)."},
					"maxUses":                map[string]any{"type": "integer", "description": "How many times the token can be redeemed."},
					"sourceCidr":             map[string]any{"type": "string", "description": "Optional. Restrict redemption to a CIDR range."},
					"hostnamePattern":        map[string]any{"type": "string", "description": "Optional regex; only hostnames matching can redeem."},
					"namePattern":            map[string]any{"type": "string", "description": "Optional regex; only machine names matching can redeem."},
				},
				handler: func(args map[string]any) (string, error) {
					name, err := argStringRequired(args, "name")
					if err != nil {
						return "", err
					}
					tokenLifetime, ok := argInt(args, "tokenLifetimeSeconds")
					if !ok {
						return "", fmt.Errorf("missing or non-integer `tokenLifetimeSeconds`")
					}
					machineLifetime, ok := argInt(args, "machineLifetimeSeconds")
					if !ok {
						return "", fmt.Errorf("missing or non-integer `machineLifetimeSeconds`")
					}
					maxUses, ok := argInt(args, "maxUses")
					if !ok {
						return "", fmt.Errorf("missing or non-integer `maxUses`")
					}
					// projectIds and secretIds are required by the
					// backend DTO but may be empty arrays; pass through
					// directly without filtering on length.
					body := map[string]any{
						"name":                   name,
						"projectIds":             argStringSlice(args, "projectIds"),
						"secretIds":              argStringSlice(args, "secretIds"),
						"tokenLifetimeSeconds":   tokenLifetime,
						"machineLifetimeSeconds": machineLifetime,
						"maxUses":                maxUses,
					}
					if v := argString(args, "description"); v != "" {
						body["description"] = v
					}
					if v := argString(args, "sourceCidr"); v != "" {
						body["sourceCidr"] = v
					}
					if v := argString(args, "hostnamePattern"); v != "" {
						body["hostnamePattern"] = v
					}
					if v := argString(args, "namePattern"); v != "" {
						body["namePattern"] = v
					}
					raw, err := c.Do("POST", "/v1/ai/enrollment-tokens", body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "revoke",
				summary:  "Revoke an enrollment token. Stops new redemptions; existing machines enrolled via this token continue to operate with their existing identities.",
				scopes:   []string{"enrollment.write"},
				required: []string{"tokenId"},
				argSchema: map[string]any{
					"tokenId": map[string]any{"type": "string"},
					"reason":  map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "tokenId")
					if err != nil {
						return "", err
					}
					body := map[string]any{}
					if r := argString(args, "reason"); r != "" {
						body["reason"] = r
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/enrollment-tokens/%s/revoke", url.PathEscape(id)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
