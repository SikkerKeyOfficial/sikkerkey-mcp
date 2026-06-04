package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageSecretsTool) }

func newManageSecretsTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_secrets",
		summary: "Manage secrets within a project. The agent NEVER sees plaintext secret values — even rotate operations return only metadata (id, version). Plaintext stays inside the vault.",
		actions: []toolAction{
			{
				action:   "list",
				summary:  "List secrets in a project (metadata only — no plaintext). Returns id, name, type, fieldNames, note, version, createdAt, updatedAt.",
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
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/projects/%s/secrets", url.PathEscape(pid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "get",
				summary:  "Single-secret metadata (same fields as one list row). Use when you already have a secretId and don't want to page the whole project. Plaintext is never returned.",
				scopes:   []string{"projects.secrets.read"},
				required: []string{"projectId", "secretId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"secretId":  map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					sid, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/projects/%s/secrets/%s", url.PathEscape(pid), url.PathEscape(sid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "create",
				summary:  "Create a new secret in the project. The value you supply is encrypted server-side with envelope encryption (per-secret AES-256 data key wrapped by the project master key) and never returned by any read endpoint. Response contains only id and name.",
				scopes:   []string{"projects.secrets.write"},
				required: []string{"projectId", "name", "value"},
				argSchema: map[string]any{
					"projectId":  map[string]any{"type": "string"},
					"name":       map[string]any{"type": "string", "description": "1-255 characters."},
					"value":      map[string]any{"type": "string", "description": "Plaintext secret value. ≤ 12KB."},
					"note":       map[string]any{"type": "string"},
					"fieldNames": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional. If set, value must be a JSON object string keyed by these field names (creates a structured secret)."},
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
					value, err := argStringRequired(args, "value")
					if err != nil {
						return "", err
					}
					body := map[string]any{"name": name, "value": value, "projectId": pid}
					if n := argString(args, "note"); n != "" {
						body["note"] = n
					}
					if fn := argStringSlice(args, "fieldNames"); len(fn) > 0 {
						body["fieldNames"] = fn
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/secrets", url.PathEscape(pid)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "update_value",
				summary:  "Replace a secret's value. Input is plaintext; the new value is encrypted server-side and never echoed back. Response contains only id and new version. Bumps version. Blocked on secrets with active rotation or canaries.",
				scopes:   []string{"projects.secrets.write"},
				required: []string{"projectId", "secretId", "value"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"secretId":  map[string]any{"type": "string"},
					"value":     map[string]any{"type": "string", "description": "New plaintext value. ≤ 12KB."},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					sid, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					value, err := argStringRequired(args, "value")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/secrets/%s/update", url.PathEscape(pid), url.PathEscape(sid)), map[string]any{"value": value})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "delete",
				summary:  "Soft-delete a secret (moves to trash, recoverable for 30 days).",
				scopes:   []string{"projects.secrets.write"},
				required: []string{"projectId", "secretId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"secretId":  map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					sid, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/secrets/%s/delete", url.PathEscape(pid), url.PathEscape(sid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "rename",
				summary:  "Change a secret's display name. Does not affect machine grants (those are by id, not name).",
				scopes:   []string{"projects.secrets.write"},
				required: []string{"projectId", "secretId", "name"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"secretId":  map[string]any{"type": "string"},
					"name":      map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					sid, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					name, err := argStringRequired(args, "name")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/secrets/%s/name", url.PathEscape(pid), url.PathEscape(sid)), map[string]any{"name": name})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "update_note",
				summary:  "Update the human-readable note attached to a secret.",
				scopes:   []string{"projects.secrets.write"},
				required: []string{"projectId", "secretId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"secretId":  map[string]any{"type": "string"},
					"note":      map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					sid, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					note := argString(args, "note")
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/secrets/%s/note", url.PathEscape(pid), url.PathEscape(sid)), map[string]any{"note": note})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "rotate",
				summary:  "Server-side rotation: generates a new random value (or rotates specific fields on a structured secret). Plaintext never returned to the agent.",
				scopes:   []string{"projects.secrets.write"},
				required: []string{"projectId", "secretId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"secretId":  map[string]any{"type": "string"},
					"length":    map[string]any{"type": "integer", "description": "Generated value length. 1-1024. Default 32."},
					"charset":   map[string]any{"type": "string", "enum": []any{"symbols", "alphanumeric", "numbers", "uuid"}, "description": "Default symbols."},
					"fields":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "For structured secrets: field names to rotate (others preserved). Omit to rotate all."},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					sid, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					body := map[string]any{}
					if n, ok := argInt(args, "length"); ok {
						body["length"] = n
					}
					if cs := argString(args, "charset"); cs != "" {
						body["charset"] = cs
					}
					if fs := argStringSlice(args, "fields"); len(fs) > 0 {
						body["fields"] = fs
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/secrets/%s/rotate", url.PathEscape(pid), url.PathEscape(sid)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "rollback",
				summary:  "Restore a previous version's encrypted value as the current version (writes a new version pointing at the old data).",
				scopes:   []string{"projects.secrets.write"},
				required: []string{"projectId", "secretId", "version"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"secretId":  map[string]any{"type": "string"},
					"version":   map[string]any{"type": "integer", "description": "Version number to restore."},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					sid, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					version, ok := argInt(args, "version")
					if !ok {
						return "", fmt.Errorf("missing or non-integer `version`")
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/secrets/%s/rollback", url.PathEscape(pid), url.PathEscape(sid)), map[string]any{"version": version})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "versions",
				summary:  "List version history for a secret (numbers + timestamps; no values).",
				scopes:   []string{"projects.secrets.read"},
				required: []string{"projectId", "secretId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"secretId":  map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					sid, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/projects/%s/secrets/%s/versions", url.PathEscape(pid), url.PathEscape(sid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:  "dynamic_list",
				summary: "List every secret with a server-side rotation schedule (across all allowed projects).",
				scopes:  []string{"projects.secrets.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/dynamic-secrets", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "dynamic_get",
				summary:  "Detail for one dynamic secret (rotation interval, charset, last/next rotation).",
				scopes:   []string{"projects.secrets.read"},
				required: []string{"secretId"},
				argSchema: map[string]any{
					"secretId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/dynamic-secrets/%s", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "dynamic_create",
				summary:  "Create a secret with a server-side rotation schedule. Two modes: provide projectId+name to create a new secret, or provide existingSecretId to attach a schedule to one that already exists. Initial value is generated server-side; plaintext is never returned.",
				scopes:   []string{"projects.secrets.write"},
				required: []string{"intervalSeconds"},
				argSchema: map[string]any{
					"projectId":        map[string]any{"type": "string", "description": "Required when creating a new secret."},
					"name":             map[string]any{"type": "string", "description": "Required when creating a new secret. 1-255 characters."},
					"existingSecretId": map[string]any{"type": "string", "description": "Provide instead of projectId+name to attach a schedule to an already-existing secret."},
					"note":             map[string]any{"type": "string"},
					"intervalSeconds":  map[string]any{"type": "integer", "description": "Rotation cadence. 300 (5 min) to 30 days."},
					"length":           map[string]any{"type": "integer", "description": "Generated value length. 1-1024. Default 32."},
					"charset":          map[string]any{"type": "string", "enum": []any{"symbols", "alphanumeric", "numbers", "uuid"}, "description": "Default symbols."},
					"fieldNames":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "For structured secrets: schema field names. Required if creating a structured secret."},
					"fields":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "For structured secrets: which fieldNames to rotate (others use staticFields). Defaults to all."},
					"staticFields":     map[string]any{"type": "object", "description": "For structured secrets: per-field static values for non-rotated fields."},
				},
				handler: func(args map[string]any) (string, error) {
					interval, ok := argInt(args, "intervalSeconds")
					if !ok {
						return "", fmt.Errorf("missing or non-integer `intervalSeconds`")
					}
					body := map[string]any{"intervalSeconds": interval}
					if v := argString(args, "existingSecretId"); v != "" {
						body["secretId"] = v
					} else {
						pid := argString(args, "projectId")
						name := argString(args, "name")
						if pid == "" || name == "" {
							return "", fmt.Errorf("must provide either `existingSecretId`, or both `projectId` and `name`")
						}
						body["projectId"] = pid
						body["name"] = name
					}
					if v := argString(args, "note"); v != "" {
						body["note"] = v
					}
					if v, ok := argInt(args, "length"); ok {
						body["length"] = v
					}
					if v := argString(args, "charset"); v != "" {
						body["charset"] = v
					}
					if v := argStringSlice(args, "fieldNames"); len(v) > 0 {
						body["fieldNames"] = v
					}
					if v := argStringSlice(args, "fields"); len(v) > 0 {
						body["fields"] = v
					}
					if v, ok := args["staticFields"].(map[string]any); ok && len(v) > 0 {
						body["staticFields"] = v
					}
					raw, err := c.Do("POST", "/v1/ai/dynamic-secrets", body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "dynamic_update",
				summary:  "Update rotation parameters on an existing dynamic secret (interval, length, charset, fields, enabled).",
				scopes:   []string{"projects.secrets.write"},
				required: []string{"secretId"},
				argSchema: map[string]any{
					"secretId":        map[string]any{"type": "string"},
					"intervalSeconds": map[string]any{"type": "integer"},
					"length":          map[string]any{"type": "integer"},
					"charset":         map[string]any{"type": "string", "enum": []any{"symbols", "alphanumeric", "numbers", "uuid"}},
					"fields":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "For structured secrets: which field names to rotate."},
					"enabled":         map[string]any{"type": "boolean", "description": "Pause / resume rotation."},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					body := map[string]any{}
					if v, ok := argInt(args, "intervalSeconds"); ok {
						body["intervalSeconds"] = v
					}
					if v, ok := argInt(args, "length"); ok {
						body["length"] = v
					}
					if v := argString(args, "charset"); v != "" {
						body["charset"] = v
					}
					if v := argStringSlice(args, "fields"); len(v) > 0 {
						body["fields"] = v
					}
					if v, ok := argBool(args, "enabled"); ok {
						body["enabled"] = v
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/dynamic-secrets/%s/update", url.PathEscape(id)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "dynamic_delete",
				summary:  "Remove a rotation schedule. The secret itself is NOT deleted — only the schedule.",
				scopes:   []string{"projects.secrets.write"},
				required: []string{"secretId"},
				argSchema: map[string]any{
					"secretId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/dynamic-secrets/%s/delete", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
