package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/scan"
)

// This file validates emitted SARIF against the vendored official schema
// (testdata/sarif-schema-2.1.0.json, provenance in testdata/README.md).
//
// The validator below is a deliberately small JSON Schema draft-04 subset —
// $ref, type, properties, additionalProperties, required, items, enum, anyOf,
// minItems, minimum, uniqueItems, pattern — which is the entire keyword set the
// SARIF schema actually uses (no allOf, oneOf, or not appear in it). Writing it
// costs ~150 test-only lines and keeps the module at its two production
// dependencies; pulling in a general-purpose validator to check one output
// format would be a poor trade, and skill-guard's dependency thinness is a
// stated selling point.

type schemaValidator struct {
	root map[string]any
}

func loadSchema(t *testing.T) *schemaValidator {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "sarif-schema-2.1.0.json"))
	if err != nil {
		t.Fatalf("vendored schema: %v (see testdata/README.md)", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("vendored schema is not valid JSON: %v", err)
	}
	return &schemaValidator{root: root}
}

// validate returns every constraint violation it finds, deepest path first.
func (v *schemaValidator) validate(doc any) []string {
	return v.check(doc, v.root, "$")
}

func (v *schemaValidator) resolve(schema map[string]any) map[string]any {
	ref, ok := schema["$ref"].(string)
	if !ok {
		return schema
	}
	// Only local pointers appear in the SARIF schema: "#/definitions/name".
	parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
	cur := any(v.root)
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return schema
		}
		cur = m[p]
	}
	if m, ok := cur.(map[string]any); ok {
		return v.resolve(m)
	}
	return schema
}

func (v *schemaValidator) check(doc any, schema map[string]any, path string) []string {
	schema = v.resolve(schema)
	var errs []string

	if alts, ok := schema["anyOf"].([]any); ok {
		for _, alt := range alts {
			if m, ok := alt.(map[string]any); ok && len(v.check(doc, m, path)) == 0 {
				return nil
			}
		}
		return []string{fmt.Sprintf("%s: matches none of the anyOf alternatives", path)}
	}

	// "type" is either a name or a list of accepted names ("type": ["array",
	// "null"] is common in this schema).
	if want, ok := schema["type"]; ok && !anyTypeMatches(doc, want) {
		return []string{fmt.Sprintf("%s: want type %v, got %T", path, want, doc)}
	}

	if enum, ok := schema["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if fmt.Sprint(e) == fmt.Sprint(doc) {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Sprintf("%s: %v is not one of %v", path, doc, enum))
		}
	}

	switch val := doc.(type) {
	case map[string]any:
		errs = append(errs, v.checkObject(val, schema, path)...)
	case []any:
		errs = append(errs, v.checkArray(val, schema, path)...)
	case string:
		if pat, ok := schema["pattern"].(string); ok {
			// Go's RE2 rejects a few ECMA constructs; an unsupported pattern is
			// skipped rather than reported as a document error.
			if re, err := regexp.Compile(pat); err == nil && !re.MatchString(val) {
				errs = append(errs, fmt.Sprintf("%s: %q does not match /%s/", path, val, pat))
			}
		}
	case float64:
		if min, ok := schema["minimum"].(float64); ok && val < min {
			errs = append(errs, fmt.Sprintf("%s: %v is below minimum %v", path, val, min))
		}
	}
	return errs
}

func (v *schemaValidator) checkObject(obj map[string]any, schema map[string]any, path string) []string {
	var errs []string
	props, _ := schema["properties"].(map[string]any)

	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			name := fmt.Sprint(r)
			if _, present := obj[name]; !present {
				errs = append(errs, fmt.Sprintf("%s: missing required property %q", path, name))
			}
		}
	}

	if extra, ok := schema["additionalProperties"].(bool); ok && !extra {
		var unknown []string
		for name := range obj {
			if _, defined := props[name]; !defined {
				unknown = append(unknown, name)
			}
		}
		sort.Strings(unknown)
		for _, name := range unknown {
			errs = append(errs, fmt.Sprintf("%s: property %q is not allowed here", path, name))
		}
	}

	names := make([]string, 0, len(obj))
	for name := range obj {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sub, ok := props[name].(map[string]any)
		if !ok {
			continue
		}
		errs = append(errs, v.check(obj[name], sub, path+"."+name)...)
	}
	return errs
}

func (v *schemaValidator) checkArray(arr []any, schema map[string]any, path string) []string {
	var errs []string
	if min, ok := schema["minItems"].(float64); ok && float64(len(arr)) < min {
		errs = append(errs, fmt.Sprintf("%s: %d items, minimum %v", path, len(arr), min))
	}
	if unique, ok := schema["uniqueItems"].(bool); ok && unique {
		seen := map[string]bool{}
		for _, item := range arr {
			key, _ := json.Marshal(item)
			if seen[string(key)] {
				errs = append(errs, fmt.Sprintf("%s: contains duplicate items", path))
				break
			}
			seen[string(key)] = true
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		for i, item := range arr {
			errs = append(errs, v.check(item, items, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return errs
}

// anyTypeMatches accepts a single type name or a list of them.
func anyTypeMatches(doc any, want any) bool {
	switch w := want.(type) {
	case string:
		return typeMatches(doc, w)
	case []any:
		for _, alt := range w {
			if name, ok := alt.(string); ok && typeMatches(doc, name) {
				return true
			}
		}
		return false
	}
	return true
}

func typeMatches(doc any, want string) bool {
	switch want {
	case "object":
		_, ok := doc.(map[string]any)
		return ok
	case "array":
		_, ok := doc.([]any)
		return ok
	case "string":
		_, ok := doc.(string)
		return ok
	case "boolean":
		_, ok := doc.(bool)
		return ok
	case "number", "integer":
		_, ok := doc.(float64)
		return ok
	case "null":
		return doc == nil
	}
	return true
}

// TestSARIFValidatesAgainstVendoredSchema is the M3-05 acceptance check: every
// log we emit — clean, dirty, and policy-waived — conforms to the official
// schema, with no network involved.
func TestSARIFValidatesAgainstVendoredSchema(t *testing.T) {
	v := loadSchema(t)

	cases := []struct {
		name string
		rep  *scan.Report
	}{
		{"benign", scanFixture(t, "benign")},
		{"malicious", scanFixture(t, "malicious")},
		{"malicious-waived", scanFixtureWithPolicy(t, "malicious", policyWithWaiver("SG-NET-002", "reviewed"))},
		{"synthetic", syntheticReport()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := decodeSARIF(t, c.rep, Options{Source: "testdata/" + c.name, Version: "test"})
			if errs := v.validate(doc); len(errs) > 0 {
				t.Errorf("%d schema violations:\n  %s", len(errs), strings.Join(errs, "\n  "))
			}
		})
	}
}

// TestSchemaValidatorCatchesViolations guards the guard: a validator that
// silently passes everything would make the test above worthless.
func TestSchemaValidatorCatchesViolations(t *testing.T) {
	v := loadSchema(t)
	cases := []struct {
		name string
		doc  string
	}{
		{"missing required", `{"version":"2.1.0"}`},
		{"wrong type", `{"version":"2.1.0","runs":{}}`},
		{"bad enum", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"level":"catastrophic","message":{"text":"x"}}]}]}`},
		{"unknown property", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"nonsense":1}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var doc any
			if err := json.Unmarshal([]byte(c.doc), &doc); err != nil {
				t.Fatalf("bad test input: %v", err)
			}
			if errs := v.validate(doc); len(errs) == 0 {
				t.Error("validator accepted an invalid document")
			}
		})
	}
}
