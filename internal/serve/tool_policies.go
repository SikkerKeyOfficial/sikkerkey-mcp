package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManagePoliciesTool) }

func newManagePoliciesTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_policies",
		summary: "Manage access policies and their bindings to secrets. A policy is a layered set of constraints (time window, IP allowlist, rate cap, co-sign, TTL, rotate-after-N) that applies on top of the base six-requirement gate.",
		actions: []toolAction{
			{
				action:   "list",
				summary:  "List every policy in a project.",
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
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/projects/%s/policies", url.PathEscape(pid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "get",
				summary:  "Fetch one policy with its bound-secrets list.",
				scopes:   []string{"projects.policies.read"},
				required: []string{"projectId", "policyId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"policyId":  map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					polid, err := argStringRequired(args, "policyId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/projects/%s/policies/%s", url.PathEscape(pid), url.PathEscape(polid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "create",
				summary:  "Create a new policy. Validation is strict — every enabled axis must be fully specified.",
				scopes:   []string{"projects.policies.write"},
				required: []string{"projectId", "name"},
				argSchema: map[string]any{
					"projectId":             map[string]any{"type": "string"},
					"name":                  map[string]any{"type": "string"},
					"description":           map[string]any{"type": "string"},
					"timeWindowEnabled":     map[string]any{"type": "boolean"},
					"timeWindowStart":       map[string]any{"type": "string", "description": "HH:mm"},
					"timeWindowEnd":         map[string]any{"type": "string", "description": "HH:mm"},
					"timeWindowTimezone":    map[string]any{"type": "string", "description": "IANA tz like Europe/Copenhagen."},
					"timeWindowDays":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Subset of mon..sun."},
					"ipAllowlistEnabled":    map[string]any{"type": "boolean"},
					"ipAllowlistCidrs":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"rateCapEnabled":        map[string]any{"type": "boolean"},
					"maxReadsPerDay":        map[string]any{"type": "integer"},
					"maxReadsPerMinute":     map[string]any{"type": "integer"},
					"coSignEnabled":         map[string]any{"type": "boolean"},
					"coSignMachineId":       map[string]any{"type": "string"},
					"coSignWindowSeconds":   map[string]any{"type": "integer"},
					"ttlExpiresAt":          map[string]any{"type": "integer", "description": "Epoch millis."},
					"ttlMaxReads":           map[string]any{"type": "integer"},
					"rotateAfterReads":      map[string]any{"type": "integer"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					body := buildPolicyBody(args)
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/policies", url.PathEscape(pid)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "update",
				summary:  "Update an existing policy. Every bound secret immediately sees the new constraints on its next fetch.",
				scopes:   []string{"projects.policies.write"},
				required: []string{"projectId", "policyId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"policyId":  map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					polid, err := argStringRequired(args, "policyId")
					if err != nil {
						return "", err
					}
					body := buildPolicyBody(args)
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/policies/%s/update", url.PathEscape(pid), url.PathEscape(polid)), body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "delete",
				summary:  "Delete a policy. Refused with 409 if any secrets are still bound — detach them first.",
				scopes:   []string{"projects.policies.write"},
				required: []string{"projectId", "policyId"},
				argSchema: map[string]any{
					"projectId": map[string]any{"type": "string"},
					"policyId":  map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					pid, err := argStringRequired(args, "projectId")
					if err != nil {
						return "", err
					}
					polid, err := argStringRequired(args, "policyId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/projects/%s/policies/%s/delete", url.PathEscape(pid), url.PathEscape(polid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "binding_get",
				summary:  "Return the current policy bound to a secret (or unbound).",
				scopes:   []string{"projects.policies.read"},
				required: []string{"secretId"},
				argSchema: map[string]any{
					"secretId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					sid, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/secrets/%s/binding", url.PathEscape(sid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "binding_bind",
				summary:  "Bind a secret to a policy. Replaces any existing binding. Policy must live in the same project as the secret.",
				scopes:   []string{"projects.policies.write"},
				required: []string{"secretId", "policyId"},
				argSchema: map[string]any{
					"secretId": map[string]any{"type": "string"},
					"policyId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					sid, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					polid, err := argStringRequired(args, "policyId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/secrets/%s/binding", url.PathEscape(sid)), map[string]any{"policyId": polid})
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "binding_unbind",
				summary:  "Detach a secret from its policy. Reverts to the base six-requirement gate only.",
				scopes:   []string{"projects.policies.write"},
				required: []string{"secretId"},
				argSchema: map[string]any{
					"secretId": map[string]any{"type": "string"},
				},
				handler: func(args map[string]any) (string, error) {
					sid, err := argStringRequired(args, "secretId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("POST", fmt.Sprintf("/v1/ai/secrets/%s/binding/delete", url.PathEscape(sid)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}

// buildPolicyBody assembles the policy create/update body from the
// shared argSchema keys. Every field is optional; absent fields are
// omitted from the body so the backend uses defaults.
func buildPolicyBody(args map[string]any) map[string]any {
	body := map[string]any{}
	if v := argString(args, "name"); v != "" {
		body["name"] = v
	}
	if v := argString(args, "description"); v != "" {
		body["description"] = v
	}
	if v, ok := argBool(args, "timeWindowEnabled"); ok {
		body["timeWindowEnabled"] = v
	}
	if v := argString(args, "timeWindowStart"); v != "" {
		body["timeWindowStart"] = v
	}
	if v := argString(args, "timeWindowEnd"); v != "" {
		body["timeWindowEnd"] = v
	}
	if v := argString(args, "timeWindowTimezone"); v != "" {
		body["timeWindowTimezone"] = v
	}
	if v := argStringSlice(args, "timeWindowDays"); len(v) > 0 {
		body["timeWindowDays"] = v
	}
	if v, ok := argBool(args, "ipAllowlistEnabled"); ok {
		body["ipAllowlistEnabled"] = v
	}
	if v := argStringSlice(args, "ipAllowlistCidrs"); len(v) > 0 {
		body["ipAllowlistCidrs"] = v
	}
	if v, ok := argBool(args, "rateCapEnabled"); ok {
		body["rateCapEnabled"] = v
	}
	if v, ok := argInt(args, "maxReadsPerDay"); ok {
		body["maxReadsPerDay"] = v
	}
	if v, ok := argInt(args, "maxReadsPerMinute"); ok {
		body["maxReadsPerMinute"] = v
	}
	if v, ok := argBool(args, "coSignEnabled"); ok {
		body["coSignEnabled"] = v
	}
	if v := argString(args, "coSignMachineId"); v != "" {
		body["coSignMachineId"] = v
	}
	if v, ok := argInt(args, "coSignWindowSeconds"); ok {
		body["coSignWindowSeconds"] = v
	}
	if v, ok := argInt(args, "ttlExpiresAt"); ok {
		body["ttlExpiresAt"] = v
	}
	if v, ok := argInt(args, "ttlMaxReads"); ok {
		body["ttlMaxReads"] = v
	}
	if v, ok := argInt(args, "rotateAfterReads"); ok {
		body["rotateAfterReads"] = v
	}
	return body
}
