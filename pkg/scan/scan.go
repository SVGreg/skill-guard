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
	rules    []*rules.Rule
	contexts []*rules.ContextRule
	policy   policy.Policy
}

// New builds a scanner from rules and policy.
func New(rs []*rules.Rule, p policy.Policy) *Scanner {
	return &Scanner{rules: rs, policy: p}
}

// WithContexts attaches severity-capping context rules and returns the scanner,
// so it chains onto New. Kept separate from New rather than added as a third
// parameter because New is part of the published library API.
func (s *Scanner) WithContexts(cs []*rules.ContextRule) *Scanner {
	s.contexts = cs
	return s
}

// Scan runs all applicable rules over the bundle.
func (s *Scanner) Scan(b *skill.Bundle) *Report {
	var findings []model.Finding

	// Assemble target texts: manifest front-matter, body, each script, each
	// config, each bundled reference doc.
	// lineOffset maps a target-local line number back to the true file line: the
	// manifest and body are sub-spans of SKILL.md, so their local line 1 is not
	// file line 1 (see skill.parseSkillMD). Scripts, configs and docs are whole
	// files, so their offset is 0.
	var targets []scanTarget
	if b.Manifest.Present {
		targets = append(targets, scanTarget{"manifest", "", "SKILL.md", string(b.Manifest.Raw), b.Manifest.LineOffset})
	}
	targets = append(targets, scanTarget{"body", "", "SKILL.md", b.Body, b.BodyLineOffset})
	for _, sc := range b.Scripts {
		targets = append(targets, scanTarget{"scripts", sc.Language, sc.Path, string(sc.Content), 0})
	}
	for _, cf := range b.Configs {
		targets = append(targets, scanTarget{"configs", "", cf.Path, string(cf.Content), 0})
	}
	// Reference docs are instruction surface, not inert assets: progressive
	// disclosure means SKILL.md stays short and tells the agent to read and
	// follow `references/*.md`, so those files reach the model exactly like the
	// body. Leaving them unscanned made the surface skill-guard checks a strict
	// subset of the real one — a payload in references/guide.md scanned clean
	// (issue #13). Rules that declare `body` apply here too; see rules.AppliesTo.
	for _, dc := range b.Docs {
		targets = append(targets, scanTarget{"refs", "", dc.Path, string(dc.Content), 0})
	}

	// Context rules are evaluated once per target, up front, so the caps are
	// known before any finding is built. Their spans use the same lineOffset
	// correction as findings do, or a context match in the body would cap the
	// wrong line of SKILL.md.
	caps := s.contextCaps(targets)

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
				caps.apply(&f)
				findings = append(findings, f)
			}
		}
	}

	// Capping runs *before* dedup on purpose: dedup keeps one finding per
	// (file, line, rule), so demoting afterwards would let a high that is about
	// to be capped shadow nothing while still being compared at its original
	// severity along the way. Capping first means every downstream step —
	// dedup, waivers, counts, max severity, risk, verdict — sees the severity
	// the report will actually show.
	findings = dedup(findings)
	rep := &Report{}
	for i := range findings {
		if reason := s.policy.WaiverFor(findings[i].RuleID, findings[i].File); reason != "" {
			findings[i].Waived = true
			findings[i].WaiverReason = reason
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
	// Waived findings are sorted too: they are reported (JSON, SARIF
	// suppressions), so their order is part of the output and must not depend
	// on rule-evaluation order.
	sortFindings(rep.Waived)
	rep.RiskScore = riskScore(rep.Findings, s.policy)
	rep.RiskTier = tier(rep.RiskScore)
	rep.Verdict = s.verdict(rep, b)
	rep.Card = buildCard(b, rep)
	return rep
}

// scanTarget is one unit of text a rule runs against. lineOffset maps a
// target-local line back to the true file line — the manifest and body are
// sub-spans of SKILL.md, so their local line 1 is not file line 1.
type scanTarget struct {
	name, lang, file, text string
	lineOffset             int
}

// severityCaps holds the ceilings the active context rules impose, resolved to
// true file lines. A finding is capped by the *strongest* applicable ceiling
// when several context rules cover it.
type severityCaps struct {
	byLine map[fileLine]capBy
	byFile map[string]capBy
}

type fileLine struct {
	file string
	line int
}

type capBy struct {
	rule string
	max  model.Severity
}

// contextCaps evaluates every context rule against every target it applies to.
func (s *Scanner) contextCaps(targets []scanTarget) severityCaps {
	caps := severityCaps{}
	for _, c := range s.contexts {
		for _, t := range targets {
			if !c.AppliesTo(t.name, t.lang) {
				continue
			}
			lines, wholeFile := c.Spans(t.name, t.text)
			if wholeFile {
				caps.addFile(t.file, capBy{c.ID, c.MaxSeverity})
				continue
			}
			for ln := range lines {
				caps.addLine(fileLine{t.file, ln + t.lineOffset}, capBy{c.ID, c.MaxSeverity})
			}
		}
	}
	return caps
}

// stronger reports whether a is a lower ceiling than b — the one that wins.
func stronger(a, b capBy) bool { return a.max < b.max }

func (s *severityCaps) addLine(k fileLine, v capBy) {
	if s.byLine == nil {
		s.byLine = map[fileLine]capBy{}
	}
	if ex, ok := s.byLine[k]; !ok || stronger(v, ex) {
		s.byLine[k] = v
	}
}

func (s *severityCaps) addFile(file string, v capBy) {
	if s.byFile == nil {
		s.byFile = map[string]capBy{}
	}
	if ex, ok := s.byFile[file]; !ok || stronger(v, ex) {
		s.byFile[file] = v
	}
}

// apply caps one finding in place. A ceiling at or above the finding's own
// severity is a no-op and is not recorded — reporting "demoted" for a finding
// whose severity did not change would be a lie in the JSON.
func (s severityCaps) apply(f *model.Finding) {
	best, found := capBy{}, false
	if v, ok := s.byFile[f.File]; ok {
		best, found = v, true
	}
	if v, ok := s.byLine[fileLine{f.File, f.StartLine}]; ok && (!found || stronger(v, best)) {
		best, found = v, true
	}
	if !found || f.Severity <= best.max {
		return
	}
	f.OriginalSeverity = f.Severity
	f.Severity = best.max
	f.DemotedBy = best.rule
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

// dedupKey identifies a finding by its (file, line, rule) triple. It is a struct
// rather than a concatenated string because both File (a bundle path) and RuleID
// (an external rulepack may pick any id) can legally contain the delimiter — a
// filename like "x|1" would otherwise collide with a distinct triple and silently
// drop one of the two findings.
type dedupKey struct {
	file string
	line int
	rule string
}

func dedup(findings []model.Finding) []model.Finding {
	best := map[dedupKey]model.Finding{}
	var order []dedupKey
	for _, f := range findings {
		key := dedupKey{f.File, f.StartLine, f.RuleID}
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
