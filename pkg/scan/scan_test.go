package scan

import (
	"testing"

	"github.com/skillguard/skill-guard/pkg/model"
	"github.com/skillguard/skill-guard/pkg/policy"
	"github.com/skillguard/skill-guard/pkg/rules"
	"github.com/skillguard/skill-guard/pkg/skill"
)

func scanFixture(t *testing.T, path string) *Report {
	t.Helper()
	b, err := skill.LoadBundle(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	packs, err := rules.Builtin()
	if err != nil {
		t.Fatalf("builtin: %v", err)
	}
	return New(rules.AllRules(packs), policy.Default()).Scan(b)
}

func TestBenignPasses(t *testing.T) {
	rep := scanFixture(t, "../../testdata/benign")
	if rep.Verdict == model.Fail {
		t.Fatalf("benign skill failed with findings: %+v", rep.Findings)
	}
}

func TestMaliciousFails(t *testing.T) {
	rep := scanFixture(t, "../../testdata/malicious")
	if rep.Verdict != model.Fail {
		t.Fatalf("malicious skill did not fail; verdict=%s findings=%d", rep.Verdict, len(rep.Findings))
	}
	// Must catch the headline attacks.
	want := map[string]bool{"SG-INJ-001": false, "SG-NET-002": false, "SG-SEC-001": false}
	for _, f := range rep.Findings {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected malicious fixture to trigger %s", id)
		}
	}
}

// TestSkillMDLineNumbersAreFileAbsolute guards against the front-matter/body
// blobs being reported at blob-local line numbers instead of true file lines.
// In testdata/malicious/SKILL.md the description injection is on file line 3 and
// the body's system-prompt exfiltration is on file line 12.
func TestSkillMDLineNumbersAreFileAbsolute(t *testing.T) {
	rep := scanFixture(t, "../../testdata/malicious")
	line := func(rule string) int {
		for _, f := range rep.Findings {
			if f.RuleID == rule && f.File == "SKILL.md" {
				return f.StartLine
			}
		}
		return -1
	}
	if got := line("SG-INJ-001"); got != 3 {
		t.Errorf("SG-INJ-001 (front-matter description) reported at line %d, want file line 3", got)
	}
	if got := line("SG-INJ-006"); got != 12 {
		t.Errorf("SG-INJ-006 (body) reported at line %d, want file line 12", got)
	}
}
