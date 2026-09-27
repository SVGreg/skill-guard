package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SVGreg/surfaceguard/pkg/model"
	"github.com/SVGreg/surfaceguard/pkg/scan"
)

func sampleMulti() *scan.MultiReport {
	failing := &scan.Report{
		Verdict: model.Fail, RiskScore: 40, RiskTier: "L2", MaxSeverity: model.SevCritical,
		Findings: []model.Finding{{RuleID: "SG-INJ-001", Title: "prompt injection", Severity: model.SevCritical,
			Confidence: 1, File: "SKILL.md", StartLine: 3, AST: []string{"AST01"}}},
	}
	failing.Counts.Add(model.SevCritical)
	return scan.Aggregate([]scan.BundleResult{
		{Path: "skills/ok", Name: "ok", Report: &scan.Report{Verdict: model.Pass, RiskTier: "L0"}},
		{Path: "skills/bad\x1b[2J", Name: "bad", Report: failing},
		{Path: "skills/broken", Error: "bundle contains symlink (rejected)"},
	})
}

func TestMultiTextSummaryAndOrder(t *testing.T) {
	var buf bytes.Buffer
	MultiText(&buf, sampleMulti(), Options{NoColor: true})
	out := buf.String()

	if !strings.HasPrefix(out, "verdict: fail   3 skills: 1 fail, 0 warn, 1 pass, 1 error   max risk: 40/100") {
		t.Errorf("summary line wrong:\n%s", out)
	}
	iErr, iFail, iPass := strings.Index(out, "error   -"), strings.Index(out, "fail    40 L2"), strings.Index(out, "pass    0 L0")
	if iErr < 0 || iFail < 0 || iPass < 0 || !(iErr < iFail && iFail < iPass) {
		t.Errorf("rows not worst-first (error, fail, pass):\n%s", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("attacker-controlled path reached the terminal unescaped:\n%q", out)
	}
	if !strings.Contains(out, "SG-INJ-001") || strings.Count(out, "OWASP Agentic Skills Top 10 references") != 1 {
		t.Errorf("want the failing bundle's findings and exactly one legend:\n%s", out)
	}
	if strings.Contains(out, "── skills/ok") {
		t.Errorf("a passing bundle's section is shown without --verbose:\n%s", out)
	}

	buf.Reset()
	MultiText(&buf, sampleMulti(), Options{NoColor: true, Verbose: true})
	if !strings.Contains(buf.String(), "── skills/ok") {
		t.Errorf("--verbose must show every bundle")
	}
}

func TestMultiJSONShape(t *testing.T) {
	var buf bytes.Buffer
	if err := MultiJSON(&buf, sampleMulti(), Options{}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Mode    string `json:"mode"`
		Verdict string `json:"verdict"`
		Errors  int    `json:"errors"`
		Bundles []struct {
			Path     string            `json:"path"`
			Verdict  string            `json:"verdict"`
			Error    string            `json:"error"`
			Findings []json.RawMessage `json:"findings"`
		} `json:"bundles"`
		ASTReferences map[string]json.RawMessage `json:"ast_references"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	if got.Mode != "multi" || got.Verdict != "fail" || got.Errors != 1 || len(got.Bundles) != 3 {
		t.Fatalf("envelope = %+v", got)
	}
	if got.Bundles[1].Verdict != "fail" || len(got.Bundles[1].Findings) != 1 {
		t.Errorf("bundle element must carry the single-report fields inline: %+v", got.Bundles[1])
	}
	if got.Bundles[2].Error == "" || got.Bundles[2].Verdict != "" {
		t.Errorf("errored bundle: want error and no report fields: %+v", got.Bundles[2])
	}
	if _, ok := got.ASTReferences["AST01"]; !ok {
		t.Errorf("ast_references not hoisted to the envelope")
	}
}

// TestMultiTextGroupsByAgent: an installed-skills scan lists each agent's
// skills under it, and a shared skill under every agent that loads it.
func TestMultiTextGroupsByAgent(t *testing.T) {
	ok := &scan.Report{Verdict: model.Pass, RiskTier: "L0"}
	m := scan.Aggregate([]scan.BundleResult{
		{Path: "/h/.agents/skills/shared", Agents: []string{"codex", "cursor"}, Report: ok},
		{Path: "/h/.claude/skills/mine", Agents: []string{"claude-code"}, Report: ok},
		{Path: "./extra", Report: ok},
	})
	var buf bytes.Buffer
	MultiText(&buf, m, Options{NoColor: true})
	out := buf.String()
	if strings.Count(out, "/h/.agents/skills/shared") != 2 {
		t.Errorf("shared skill must be listed under both agents:\n%s", out)
	}
	ic, ix, iu, io := strings.Index(out, "  claude-code\n"), strings.Index(out, "  codex\n"), strings.Index(out, "  cursor\n"), strings.Index(out, "  other paths\n")
	if ic < 0 || ix < 0 || iu < 0 || io < 0 || !(ic < ix && ix < iu && iu < io) {
		t.Errorf("groups missing or out of order:\n%s", out)
	}
}
