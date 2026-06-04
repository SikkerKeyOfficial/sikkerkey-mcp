package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageTemporarySecretsTool) }

func newManageTemporarySecretsTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_temporary_secrets",
		summary: "One-shot self-destructing secrets shared via signed URL + passphrase. Server encrypts with AES-256-GCM, hashes passphrase with Argon2id, destroys on first reveal (right or wrong passphrase) or expiry. The create response carries the URL + token + passphrase — those are the only way to ever read the value, so deliver them to the recipient through your normal channel.",
		actions: []toolAction{
			{
				action:   "list",
				summary:  "List all temporary secrets in a project. Shows status (pending/viewed/destroyed/expired), expiry, and creation time. Never shows values, tokens, or passphrases.",
				scopes:   []string{"projects.secrets.read"},
				required: []string{"projectId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/projects/%s/temporary-secrets", url.PathEscape(pid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "create",
				summary:  "Create a one-shot temporary secret. Provide either a value directly or set generateRandom=true. Response includes id, token, passphrase, expiresAt, and the shareable URL.",
				scopes:   []string{"projects.secrets.write"},
				required: []string{"projectId", "name", "expiresInSeconds"},
				argSchema: map[string]any{
					"projectId":        map[string]any{"type": "string"},
					"name":             map[string]any{"type": "string", "description": "Display name for the temporary secret. 1-256 characters."},
					"value":            map[string]any{"type": "string", "description": "Plaintext value to share. Required unless generateRandom=true. ≤ 100KB."},
					"generateRandom":   map[string]any{"type": "boolean", "description": "If true, server generates the value using length + charset. Default false."},
					"length":           map[string]any{"type": "integer", "description": "Length when generateRandom=true. 1-1024. Default 32."},
					"charset":          map[string]any{"type": "string", "enum": []any{"symbols", "alphanumeric", "numbers", "uuid"}, "description": "Charset when generateRandom=true. Default symbols."},
					"expiresInSeconds": map[string]any{"type": "integer", "description": "Time until the link expires. 60 to 86400 (24h)."},
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
					expires, ok := argInt(args, "expiresInSeconds")
					if !ok {
						return "", fmt.Errorf("missing or non-integer `expiresInSeconds`")
					}
					body := map[string]any{"name": name, "expiresInSeconds": expires}
					if gen, ok := argBool(args, "generateRandom"); ok && gen {
						body["generateRandom"] = true
						if v, ok := argInt(args, "length"); ok {
							body["length"] = v
						}
						if v := argString(args, "charset"); v != "" {
							body["charset"] = v
						}
					} else {
						v, err := argStringRequired(args, "value")
						if err != nil {
							return "", fmt.Errorf("`value` is required when `generateRandom` is not true")
						}
						body["value"] = v
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/temporary-secrets", url.PathEscape(pid)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
