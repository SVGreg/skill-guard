// Package scan orchestrates rule evaluation over a bundle: it runs the enabled
// rules against each target, applies waivers, dedups, and computes the verdict,
// risk score, and skill-card (design §6.2, §9).
package scan

import (
	"sort"

	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/rules"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// Report is the result of scanning a bundle.
type Report struct {
	Findings    []model.Finding `json:"findings"`
	Waived      []model.Finding `json:"waived,omitempty"`
	Verdict     model.Verdict   `json:"verdict"`
	RiskScore   int             `json:"risk_score"`
	RiskTier    string          `json:"risk_tier"`
	MaxSeverity model.Severity  `json:"max_severity"`
	Counts      model.Counts    `json:"counts"`
	Card        *Card           `json:"-"`
}

// Scanner evaluates a rule set under a policy.
type Scanner struct {
	rules  []*rules.Rule
	policy policy.Policy
}

// New builds a scanner from rules and policy.
func New(rs []*rules.Rule, p policy.Policy) *Scanner {
	return &Scanner{rules: rs, policy: p}
}

// Scan runs all applicable rules over the bundle.
func (s *Scanner) Scan(b *skill.Bundle) *Report {
	var findings []model.Finding

	// Assemble target texts: manifest front-matter, body, each script, each config.
	// lineOffset maps a target-local line number back to the true file line: the
	// manifest and body are sub-spans of SKILL.md, so their local line 1 is not
	// file line 1 (see skill.parseSkillMD).
	type tgt struct {
		name, lang, file, text string
		lineOffset             int
	}
	var targets []tgt
	if b.Manifest.Present {
		targets = append(targets, tgt{"manifest", "", "SKILL.md", string(b.Manifest.Raw), b.Manifest.LineOffset})
	}
	targets = append(targets, tgt{"body", "", "SKILL.md", b.Body, b.BodyLineOffset})
	for _, sc := range b.Scripts {
		targets = append(targets, tgt{"scripts", sc.Language, sc.Path, string(sc.Content), 0})
	}
	for _, cf := range b.Configs {
		targets = append(targets, tgt{"configs", "", cf.Path, string(cf.Content), 0})
	}

	for _, r := range s.rules {
		for _, t := range targets {
			if !r.AppliesTo(t.name, t.lang) {
				continue
			}
			for _, f := range r.Evaluate(t.name, t.text) {
				f.File = t.file
				f.StartLine += t.lineOffset
				if f.EndLine > 0 {
					f.EndLine += t.lineOffset
				}
				findings = append(findings, f)
			}
		}
	}

	findings = dedup(findings)
	rep := &Report{}
	for i := range findings {
		if reason := s.policy.WaiverFor(findings[i].RuleID, findings[i].File); reason != "" {
			findings[i].Waived = true
			rep.Waived = append(rep.Waived, findings[i])
			continue
		}
		rep.Findings = append(rep.Findings, findings[i])
		rep.Counts.Add(findings[i].Severity)
		if findings[i].Severity > rep.MaxSeverity {
			rep.MaxSeverity = findings[i].Severity
		}
	}
	sortFindings(rep.Findings)
	rep.RiskScore = riskScore(rep.Findings, s.policy)
	rep.RiskTier = tier(rep.RiskScore)
	rep.Verdict = s.verdict(rep, b)
	rep.Card = buildCard(b, rep)
	return rep
}

// verdict maps findings + attestation posture to pass/warn/fail (design §10.3).
func (s *Scanner) verdict(rep *Report, b *skill.Bundle) model.Verdict {
	failOn := s.policy.FailOnSeverity()
	warnOn := s.policy.WarnOnSeverity()
	for _, f := range rep.Findings {
		if f.Severity >= failOn {
			return model.Fail
		}
	}
	for _, f := range rep.Findings {
		if f.Severity >= warnOn {
			return model.Warn
		}
	}
	// Attestation posture is folded in by the caller (verify) when available;
	// scan alone warns if a signature is required-but-absent per policy handled upstream.
	return model.Pass
}

// riskScore: base points per severity × confidence, capped at 100 (design §9).
func riskScore(findings []model.Finding, p policy.Policy) int {
	base := map[model.Severity]float64{
		model.SevCritical: 40, model.SevHigh: 15, model.SevMedium: 5, model.SevLow: 1, model.SevInfo: 0,
	}
	var sum float64
	for _, f := range findings {
		sum += base[f.Severity] * f.Confidence
	}
	if sum > 100 {
		sum = 100
	}
	return int(sum + 0.5)
}

func tier(score int) string {
	switch {
	case score >= 60:
		return "L3"
	case score >= 30:
		return "L2"
	case score >= 10:
		return "L1"
	default:
		return "L0"
	}
}

func dedup(findings []model.Finding) []model.Finding {
	best := map[string]model.Finding{}
	var order []string
	for _, f := range findings {
		key := f.File + "|" + itoa(f.StartLine) + "|" + f.RuleID
		if ex, ok := best[key]; !ok || f.Confidence > ex.Confidence {
			if !ok {
				order = append(order, key)
			}
			best[key] = f
		}
	}
	out := make([]model.Finding, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}

func sortFindings(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].StartLine < fs[j].StartLine
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
