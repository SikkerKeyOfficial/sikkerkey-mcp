package serve

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"sikkerkey-mcp/internal/api"
)

// tool is the runtime form a registered tool exposes to the protocol
// layer. Each domain (machines, projects, …) builds one of these.
type tool struct {
	name        string
	description string
	// inputSchema is the JSON Schema for the tool's arguments,
	// rendered to clients via tools/list. We keep it as a parsed map
	// so it can be marshaled directly into the spec response.
	inputSchema map[string]any
	invoke      func(args json.RawMessage) (string, error)
}

// toolRegistry holds the registered tools. Read-only after init.
type toolRegistry struct {
	mu    sync.RWMutex
	tools map[string]*tool
}

func newToolRegistry() *toolRegistry {
	return &toolRegistry{tools: make(map[string]*tool)}
}

func (r *toolRegistry) register(t *tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tools[t.name]; exists {
		// Programming error — refuse silently to overwrite.
		panic(fmt.Sprintf("tool registered twice: %s", t.name))
	}
	r.tools[t.name] = t
}

func (r *toolRegistry) get(name string) (*tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// list returns every registered tool in stable order, shaped for
// tools/list response.
func (r *toolRegistry) list() []map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for k := range r.tools {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		t := r.tools[n]
		out = append(out, map[string]any{
			"name":        t.name,
			"description": t.description,
			"inputSchema": t.inputSchema,
		})
	}
	return out
}

// registerAllTools is the integration point — implemented in tools.go,
// pulls in every tool builder.
func registerAllTools(r *toolRegistry, c *api.Client) {
	for _, builder := range allBuilders {
		r.register(builder(c))
	}
}

// builder constructs a single tool given the API client. Domain files
// append their builder to allBuilders during init.
type builder func(c *api.Client) *tool

var allBuilders []builder
