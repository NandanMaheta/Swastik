package main

// S18 - 009 OpenAPI nullability (BR-IPO-04; contracts/http-api.md). current_gmp and subscription are
// null when nothing was recorded, so the generated TS client must type them `| null`.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIPOMarketContract_BR_IPO_04_NullableFields(t *testing.T) {
	api := buildAPI(deps{})
	raw, err := json.Marshal(api.OpenAPI().Components.Schemas)
	if err != nil {
		t.Fatal(err)
	}
	var schemas map[string]map[string]any
	if err := json.Unmarshal(raw, &schemas); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"ClientMarketView": {"current_gmp", "subscription"},
		"MarketSummary":    {"current_gmp"},
	}
	for name, fields := range want {
		s, ok := schemas[name]
		if !ok {
			t.Errorf("schema %s not in OpenAPI components", name)
			continue
		}
		props, _ := s["properties"].(map[string]any)
		for _, f := range fields {
			p, ok := props[f]
			if !ok {
				t.Errorf("%s.%s missing", name, f)
				continue
			}
			if !nullableSchema(p) {
				b, _ := json.Marshal(p)
				t.Errorf("%s.%s is not nullable in OpenAPI (got %s); the TS client would type it non-null", name, f, b)
			}
		}
	}
}

// nullableSchema accepts OpenAPI 3.1 forms: type array with "null", or anyOf/oneOf containing a null type.
func nullableSchema(p any) bool {
	m, ok := p.(map[string]any)
	if !ok {
		return false
	}
	if n, _ := m["nullable"].(bool); n {
		return true
	}
	if ts, ok := m["type"].([]any); ok {
		for _, x := range ts {
			if x == "null" {
				return true
			}
		}
	}
	for _, k := range []string{"anyOf", "oneOf"} {
		if arr, ok := m[k].([]any); ok {
			for _, e := range arr {
				if em, ok := e.(map[string]any); ok && strings.EqualFold(toStr(em["type"]), "null") {
					return true
				}
			}
		}
	}
	return false
}

func toStr(v any) string { s, _ := v.(string); return s }
