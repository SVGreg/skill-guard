package rules

import (
	"strings"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/model"
)

const ctxPack = `
apiVersion: skillguard.net/rulepack.v1
name: t
version: 1.0.0
rules:
  - id: CTX-T
    kind: context
    title: t
    scope: line
    effect:
      max_severity: low
    targets: [body]
    match:
      any:
        - regex: 'BOILERPLATE'
`

func TestContextRuleLoads(t *testing.T) {
	p, err := LoadPack([]byte(ctxPack))
	if err != nil {
		t.Fatalf("LoadPack: %v", err)
	}
	if len(p.Rules) != 0 {
		t.Errorf("context rule leaked into Rules: %d", len(p.Rules))
	}
	if len(p.Contexts) != 1 {
		t.Fatalf("want 1 context, got %d", len(p.Contexts))
	}
	c := p.Contexts[0]
	if c.MaxSeverity != model.SevLow || c.Scope != "line" {
		t.Errorf("got max=%v scope=%q", c.MaxSeverity, c.Scope)
	}
	lines, whole := c.Spans("body", "clean\nBOILERPLATE here\nclean\n")
	if whole {
		t.Error("line-scoped rule reported wholeFile")
	}
	if !lines[2] || len(lines) != 1 {
		t.Errorf("want only line 2 marked, got %v", lines)
	}
}

// TestContextScopeFileMarksWholeTarget: one match anywhere covers the file, and
// the caller is told so rather than being handed every line.
func TestContextScopeFileMarksWholeTarget(t *testing.T) {
	p, err := LoadPack([]byte(strings.Replace(ctxPack, "scope: line", "scope: file", 1)))
	if err != nil {
		t.Fatalf("LoadPack: %v", err)
	}
	lines, whole := p.Contexts[0].Spans("body", "a\nb\nBOILERPLATE\n")
	if !whole || lines != nil {
		t.Errorf("want wholeFile with no line set, got whole=%v lines=%v", whole, lines)
	}
}

// TestContextRuleRejectsInertFields: a context rule emits nothing, so severity,
// confidence and suppress would be silently ignored. An inert field that looks
// meaningful is the failure mode PR #125 fixed for the `scoring:` key — fail
// the load instead.
func TestContextRuleRejectsInertFields(t *testing.T) {
	cases := map[string]string{
		"missing effect":      strings.Replace(ctxPack, "    effect:\n      max_severity: low\n", "", 1),
		"unknown kind":        strings.Replace(ctxPack, "kind: context", "kind: hint", 1),
		"unknown scope":       strings.Replace(ctxPack, "scope: line", "scope: paragraph", 1),
		"severity on context": strings.Replace(ctxPack, "    title: t\n", "    title: t\n    severity: high\n", 1),
		"suppress on context": strings.Replace(ctxPack, "    title: t\n", "    title: t\n    suppress: ['x']\n", 1),
		"effect on detection": strings.Replace(ctxPack, "kind: context", "severity: high", 1),
		"bad max_severity":    strings.Replace(ctxPack, "max_severity: low", "max_severity: mild", 1),
	}
	for name, src := range cases {
		if _, err := LoadPack([]byte(src)); err == nil {
			t.Errorf("%s: expected a load error, got none", name)
		}
	}
}

// TestBuiltinContextPackLoads keeps the shipped catalog honest: every entry must
// be a context rule (an SG- detection in this pack would be a mistake) and the
// bar for entry is boilerplate with a canonical form.
func TestBuiltinContextPackLoads(t *testing.T) {
	packs, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	total := 0
	for _, p := range packs {
		total += len(p.Contexts)
		if p.Name != "context" && len(p.Contexts) > 0 {
			t.Errorf("pack %s ships context rules; keep them in the context pack", p.Name)
		}
		for _, c := range p.Contexts {
			if strings.HasPrefix(c.ID, "SG-") {
				t.Errorf("%s: a context rule produces no finding and must not take an SG- id", c.ID)
			}
			if c.MaxSeverity >= model.SevHigh {
				t.Errorf("%s: a ceiling of %v demotes nothing worth demoting", c.ID, c.MaxSeverity)
			}
		}
	}
	if total == 0 {
		t.Fatal("no context rules loaded — the context pack is not being embedded")
	}
}
