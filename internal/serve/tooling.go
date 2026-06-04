package serve

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// actionTool builds a tool that dispatches on an `action` string in
// the arguments to one of several handlers. This is the shared shape
// for every domain tool (manage_machines, manage_projects, …).
//
// Each action declares its own argument shape via a JSON Schema. The
// outer schema is a single object whose properties are the union of
// all per-action args plus an `action` enum that selects the handler.
// Per-action required-field guidance is rendered into the tool's
// description text rather than into the schema, because Anthropic's
// tool API rejects oneOf/allOf/anyOf at the top level of input_schema.
type actionTool struct {
	name        string
	description string
	// summary is rendered at the top of the tool description; the
	// per-action summary follows so the AI can see all actions at a
	// glance.
	summary string
	actions []toolAction
}

type toolAction struct {
	// action is the literal value of the `action` arg that selects
	// this handler.
	action string
	// summary is one-line guidance for the AI.
	summary string
	// scopes lists the AI agent scopes this action requires. Surfaced
	// in the tool description so the AI can reason about whether it'll
	// succeed before calling.
	scopes []string
	// argSchema is the JSON Schema for *the rest* of the arguments
	// (everything except `action`). May be nil for actions with no
	// extra args.
	argSchema map[string]any
	// required lists the arg names that this specific action requires.
	// `action` is always implicitly required; don't include it here.
	// Surfaced in the rendered tool description as `[required: ...]`
	// next to the action's summary; runtime handlers also validate via
	// argStringRequired and return clear errors for missing fields.
	required []string
	// handler runs the action. args is the entire arguments object,
	// caller is responsible for extracting fields.
	handler func(args map[string]any) (string, error)
}

// build assembles the registered tool from the action set.
func (a *actionTool) build() *tool {
	// Stable action order in the rendered description.
	sort.Slice(a.actions, func(i, j int) bool { return a.actions[i].action < a.actions[j].action })

	// Description: top-level summary, then a per-action listing.
	// Per-action required args are surfaced here (rather than in the
	// schema as a discriminated oneOf) because the Anthropic tool API
	// rejects oneOf/allOf/anyOf at the top level of input_schema.
	var b strings.Builder
	b.WriteString(a.summary)
	b.WriteString("\n\nActions:\n")
	for _, act := range a.actions {
		b.WriteString(fmt.Sprintf("  • %-22s %s", act.action, act.summary))
		if len(act.scopes) > 0 {
			b.WriteString(fmt.Sprintf("  [scopes: %s]", strings.Join(act.scopes, ", ")))
		}
		if len(act.required) > 0 {
			b.WriteString(fmt.Sprintf("  [required: %s]", strings.Join(act.required, ", ")))
		}
		b.WriteString("\n")
	}

	// Build the input schema. We expose `action` as a required enum,
	// then accept any of the per-action arg shapes via the union of
	// all action property maps. The `action` enum plus the per-action
	// guidance in the description is enough for the AI to pick the
	// right shape; runtime handlers do final validation.
	enum := make([]any, 0, len(a.actions))
	for _, act := range a.actions {
		enum = append(enum, act.action)
	}
	properties := map[string]any{
		"action": map[string]any{
			"type":        "string",
			"description": "Which underlying operation to perform.",
			"enum":        enum,
		},
	}
	// Merge each action's extra args into the top-level properties.
	// Names that collide across actions just use the union schema —
	// the runtime handler is the source of truth for validation.
	for _, act := range a.actions {
		for k, v := range act.argSchema {
			if _, exists := properties[k]; !exists {
				properties[k] = v
			}
		}
	}

	// Per-action required args used to be expressed as a discriminated
	// `oneOf` at the top level of the schema. Anthropic's tool API
	// rejects oneOf/allOf/anyOf at the top level of input_schema, so
	// the conditional requireds are surfaced in the rendered
	// description text above instead. Server-side handlers still
	// validate via argStringRequired etc. and return clear errors for
	// missing args, so the schema-level guard isn't load-bearing.
	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"required":             []any{"action"},
		"additionalProperties": false,
	}

	// Map action → handler for fast dispatch at call time.
	handlers := make(map[string]func(map[string]any) (string, error), len(a.actions))
	for _, act := range a.actions {
		handlers[act.action] = act.handler
	}

	invoke := func(raw json.RawMessage) (string, error) {
		var args map[string]any
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &args); err != nil {
				return "", fmt.Errorf("invalid arguments: %w", err)
			}
		} else {
			args = map[string]any{}
		}
		actionVal, ok := args["action"].(string)
		if !ok {
			return "", fmt.Errorf("missing or non-string `action` argument")
		}
		h, ok := handlers[actionVal]
		if !ok {
			return "", fmt.Errorf("unknown action %q. Valid: %s", actionVal, strings.Join(actionList(a.actions), ", "))
		}
		return h(args)
	}

	return &tool{
		name:        a.name,
		description: b.String(),
		inputSchema: schema,
		invoke:      invoke,
	}
}

func actionList(acts []toolAction) []string {
	out := make([]string, 0, len(acts))
	for _, a := range acts {
		out = append(out, a.action)
	}
	return out
}

// argString pulls a string from args by key. Empty if missing.
func argString(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

// argStringRequired returns the string for key, or an error if absent
// or wrong type.
func argStringRequired(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok {
		return "", fmt.Errorf("missing required argument %q", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("argument %q must be a string", key)
	}
	return s, nil
}

// argInt returns an int from args by key. Numeric JSON values come
// across as float64.
func argInt(args map[string]any, key string) (int, bool) {
	v, ok := args[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}

// argBool returns a bool from args by key.
func argBool(args map[string]any, key string) (bool, bool) {
	if v, ok := args[key].(bool); ok {
		return v, true
	}
	return false, false
}

// argStringSlice returns a []string from args by key.
func argStringSlice(args map[string]any, key string) []string {
	v, ok := args[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, x := range v {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// formatJSON pretty-prints any value as JSON for tool output. Used by
// every tool to send structured responses back to the AI as text.
func formatJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("(failed to encode: %v)", err)
	}
	return string(b)
}

// pretty turns a raw API response into pretty-printed JSON. If the
// response isn't JSON for some reason, falls back to the raw string
// so the AI still gets *something*.
func pretty(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	return formatJSON(v)
}
