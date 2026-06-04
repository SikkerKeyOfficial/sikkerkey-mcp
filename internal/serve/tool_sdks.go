package serve

import (
	"fmt"
	"net/url"

	"sikkerkey-mcp/internal/api"
)

func init() { allBuilders = append(allBuilders, newManageSdksTool) }

func newManageSdksTool(c *api.Client) *tool {
	return (&actionTool{
		name:    "manage_sdks",
		summary: "Look up SikkerKey's official runtime SDKs — install commands, runtime requirements, docs links, and quick-start code snippets. Use this when the customer asks how to read a secret from their application (Python, Node.js, Go, .NET, or Kotlin/JVM) so you can hand them working code instead of a doc link. No scope required — vendor reference data.",
		actions: []toolAction{
			{
				action:  "list",
				summary: "List every official SikkerKey SDK with install command, runtime requirement, and a short quick-start snippet for each.",
				handler: func(args map[string]any) (string, error) {
					raw, err := c.Do("GET", "/v1/ai/sdks", nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
			{
				action:   "get",
				summary:  "Detail for one SDK by short id (python | node | go | dotnet | kotlin). Same fields as a list entry.",
				required: []string{"sdkId"},
				argSchema: map[string]any{
					"sdkId": map[string]any{"type": "string", "enum": []any{"python", "node", "go", "dotnet", "kotlin"}},
				},
				handler: func(args map[string]any) (string, error) {
					id, err := argStringRequired(args, "sdkId")
					if err != nil {
						return "", err
					}
					raw, err := c.Do("GET", fmt.Sprintf("/v1/ai/sdks/%s", url.PathEscape(id)), nil)
					if err != nil {
						return "", err
					}
					return pretty(raw), nil
				},
			},
		},
	}).build()
}
