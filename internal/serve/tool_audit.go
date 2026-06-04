package serve

import (
	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newReadAuditTool) }

func newReadAuditTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "read_audit",
		summary: "Read the vault's audit log, activity feed, and usage stats. Useful for investigating who did what when, exporting compliance evidence, and surfacing usage trends.",
		actions: []toolAction{
			{
				action:  "query",
				summary: "Filtered audit query with full pagination. Returns rich entries with actor names resolved.",
				scopes:  []string{"audit.read"},
				argSchema: map[string]any{
					"actions":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"severities": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "info | low | medium | high | critical"},
					"sourceIp":   map[string]any{"type": "string"},
					"search":     map[string]any{"type": "string", "description": "Substring match on detail field."},
					"from":       map[string]any{"type": "integer", "description": "Epoch millis."},
					"to":         map[string]any{"type": "integer", "description": "Epoch millis."},
					"sortBy":     map[string]any{"type": "string", "description": "timestamp | action | severity | sourceIp"},
					"sortDir":    map[string]any{"type": "string", "enum": []any{"asc", "desc"}},
					"page":       map[string]any{"type": "integer"},
					"pageSize":   map[string]any{"type": "integer", "description": "1-200."},
				},
				handler: func(args map[string]any) (string, error) {
					body := map[string]any{}
					if v := argStringSlice(args, "actions"); len(v) > 0 {
						body["actions"] = v
					}
					if v := argStringSlice(args, "severities"); len(v) > 0 {
						body["severities"] = v
					}
					if v := argString(args, "sourceIp"); v != "" {
						body["sourceIp"] = v
					}
					if v := argString(args, "search"); v != "" {
						body["search"] = v
					}
					if v, ok := argInt(args, "from"); ok {
						body["from"] = v
					}
					if v, ok := argInt(args, "to"); ok {
						body["to"] = v
					}
					if v := argString(args, "sortBy"); v != "" {
						body["sortBy"] = v
					}
					if v := argString(args, "sortDir"); v != "" {
						body["sortDir"] = v
					}
					if v, ok := argInt(args, "page"); ok {
						body["page"] = v
					}
					if v, ok := argInt(args, "pageSize"); ok {
						body["pageSize"] = v
					}
					raw, err := c.Do("POST", "/v1/ai/audit/query", body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:  "list",
				summary: "Default audit listing — recent entries, no filters. Honors page/pageSize so you can ask for the most recent N entries (default pageSize 50, max 200). For filtered queries use `query`.",
				scopes:  []string{"audit.read"},
				argSchema: map[string]any{
					"page":     map[string]any{"type": "integer", "description": "1-indexed. Default 1."},
					"pageSize": map[string]any{"type": "integer", "description": "1-200. Default 50."},
				},
				handler: func(args map[string]any) (string, error) {
					body := map[string]any{"sortDir": "desc"}
					if v, ok := argInt(args, "page"); ok {
						body["page"] = v
					}
					if v, ok := argInt(args, "pageSize"); ok {
						body["pageSize"] = v
					}
					raw, err := c.Do("POST", "/v1/ai/audit/query", body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:  "actions",
				summary: "List every audit action name with its severity. Used to populate filter pickers / explain log entries.",
				scopes:  []string{"audit.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/audit/actions", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:  "activity",
				summary: "Lightweight recent-activity feed (last 20 events). Lighter than the full audit log.",
				scopes:  []string{"audit.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/activity", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:  "export",
				summary: "Export the audit log as CSV. Same filter shape as query, capped at 10,000 rows.",
				scopes:  []string{"audit.read"},
				argSchema: map[string]any{
					"actions":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"severities": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"sourceIp":   map[string]any{"type": "string"},
					"search":     map[string]any{"type": "string"},
					"from":       map[string]any{"type": "integer"},
					"to":         map[string]any{"type": "integer"},
				},
				handler: func(args map[string]any) (string, error) {
					body := map[string]any{}
					if v := argStringSlice(args, "actions"); len(v) > 0 {
						body["actions"] = v
					}
					if v := argStringSlice(args, "severities"); len(v) > 0 {
						body["severities"] = v
					}
					if v := argString(args, "sourceIp"); v != "" {
						body["sourceIp"] = v
					}
					if v := argString(args, "search"); v != "" {
						body["search"] = v
					}
					if v, ok := argInt(args, "from"); ok {
						body["from"] = v
					}
					if v, ok := argInt(args, "to"); ok {
						body["to"] = v
					}
					raw, err := c.Do("POST", "/v1/ai/audit/export", body)
					if err != nil {
						return "", err
					}
					// Returned as CSV text.
					return string(raw), nil
				},
			},
			{
				action:  "stats",
				summary: "Vault-level usage stats (machines, projects, secrets, reads, etc.).",
				scopes:  []string{"audit.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/stats", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:  "reads_over_time",
				summary: "Time-bucketed secret-read counts over a window.",
				scopes:  []string{"audit.read"},
				argSchema: map[string]any{
					"from":   map[string]any{"type": "integer", "description": "Epoch millis."},
					"to":     map[string]any{"type": "integer", "description": "Epoch millis."},
					"bucket": map[string]any{"type": "string", "description": "e.g. hour, day."},
				},
				handler: func(args map[string]any) (string, error) {
					body := map[string]any{}
					if v, ok := argInt(args, "from"); ok {
						body["from"] = v
					}
					if v, ok := argInt(args, "to"); ok {
						body["to"] = v
					}
					if v := argString(args, "bucket"); v != "" {
						body["bucket"] = v
					}
					raw, err := c.Do("POST", "/v1/ai/stats/reads-over-time", body)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:  "usage",
				summary: "Subscription usage / plan-limit snapshot.",
				scopes:  []string{"audit.read"},
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/usage", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
