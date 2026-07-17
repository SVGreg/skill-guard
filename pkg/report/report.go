// Package report renders scan results as human text, JSON, or a skill-card
// (design §10.6). SARIF is deferred to M3 (PROGRESS.md).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/scan"
)

// ANSI colors (disabled when NoColor).
const (
	cReset  = "\033[0m"
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cGreen  = "\033[32m"
	cGray   = "\033[90m"
	cBold   = "\033[1m"
)

// Options controls rendering.
type Options struct {
	NoColor bool
	Verbose bool
	Source  string
	Version string
}

// Text writes a human-readable report.
func Text(w io.Writer, rep *scan.Report, opt Options) {
	col := colorer(opt.NoColor)
	verdictLine(w, rep, col)
	all := append([]model.Finding{}, rep.Findings...)
	if len(all) == 0 {
		fmt.Fprintf(w, "  %sno findings%s\n", col(cGray), col(cReset))
	}
	used := map[string]bool{}
	for _, f := range all {
		sevC := severityColor(f.Severity, col)
		var astTag string
		if ids := strings.Join(f.AST, ", "); ids != "" {
			astTag = fmt.Sprintf("  %s%s%s", col(cGray), ids, col(cReset))
		}
		fmt.Fprintf(w, "  %s:%d  %s%s%s  %s%s%s  %s%s\n",
			f.File, f.StartLine,
			col(cBold), f.RuleID, col(cReset),
			sevC, f.Severity.String(), col(cReset),
			f.Title, astTag)
		for _, id := range f.AST {
			used[id] = true
		}
		if opt.Verbose {
			if f.Excerpt != "" {
				fmt.Fprintf(w, "      match: %q  (confidence %.2f)\n", f.Excerpt, f.Confidence)
			}
			if f.Rationale != "" {
				fmt.Fprintf(w, "      why:   %s\n", f.Rationale)
			}
			if f.Fix != "" {
				fmt.Fprintf(w, "      fix:   %s\n", f.Fix)
			}
			for _, id := range f.AST {
				if ref, ok := model.ASTInfo(id); ok {
					fmt.Fprintf(w, "      owasp: %s %s — %s\n", ref.ID, ref.Title, ref.URL)
				}
			}
		}
	}
	if len(rep.Waived) > 0 {
		fmt.Fprintf(w, "  %s%d waived%s\n", col(cGray), len(rep.Waived), col(cReset))
	}
	astLegend(w, used, col)
}

// astLegend prints the OWASP Agentic Skills Top 10 references cited above, once,
// with each risk's title and canonical page.
func astLegend(w io.Writer, used map[string]bool, col func(string) string) {
	if len(used) == 0 {
		return
	}
	ids := make([]string, 0, len(used))
	width := 0
	for id := range used {
		ids = append(ids, id)
		if ref, ok := model.ASTInfo(id); ok && len(ref.Title) > width {
			width = len(ref.Title)
		}
	}
	sort.Strings(ids)
	fmt.Fprintf(w, "\n%sOWASP Agentic Skills Top 10 references:%s\n", col(cBold), col(cReset))
	for _, id := range ids {
		ref, ok := model.ASTInfo(id)
		if !ok {
			fmt.Fprintf(w, "  %s  (unknown risk id)\n", id)
			continue
		}
		fmt.Fprintf(w, "  %s  %-*s  %s%s%s\n", ref.ID, width, ref.Title, col(cGray), ref.URL, col(cReset))
	}
}

func verdictLine(w io.Writer, rep *scan.Report, col func(string) string) {
	var vc string
	switch rep.Verdict {
	case model.Fail:
		vc = cRed
	case model.Warn:
		vc = cYellow
	default:
		vc = cGreen
	}
	fmt.Fprintf(w, "%sverdict: %s%s%s   risk score: %d/100 (%s)   %s\n",
		col(cBold), col(vc), rep.Verdict, col(cReset),
		rep.RiskScore, rep.RiskTier,
		countsLine(rep.Counts))
}

func countsLine(c model.Counts) string {
	return fmt.Sprintf("[crit %d, high %d, med %d, low %d, info %d]",
		c.Critical, c.High, c.Medium, c.Low, c.Info)
}

// JSON writes the full report as JSON. Alongside the existing per-finding "ast"
// ids, it emits an "ast_references" map resolving each cited AST id to its OWASP
// title and page, so consumers do not need to hard-code the taxonomy.
func JSON(w io.Writer, rep *scan.Report, opt Options) error {
	// Anonymous embedding promotes the Report's fields inline, so the top-level
	// shape (findings, verdict, …) is unchanged and ast_references is a sibling.
	out := struct {
		*scan.Report
		ASTReferences map[string]model.ASTRef `json:"ast_references,omitempty"`
	}{Report: rep, ASTReferences: astRefs(rep)}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// astRefs collects the OWASP references for every AST id cited by a finding.
func astRefs(rep *scan.Report) map[string]model.ASTRef {
	refs := map[string]model.ASTRef{}
	add := func(fs []model.Finding) {
		for _, f := range fs {
			for _, id := range f.AST {
				if _, seen := refs[id]; seen {
					continue
				}
				if ref, ok := model.ASTInfo(id); ok {
					refs[id] = ref
				}
			}
		}
	}
	add(rep.Findings)
	add(rep.Waived)
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// SkillCard writes the skill-card with an emission envelope (design §9).
func SkillCard(w io.Writer, rep *scan.Report, opt Options) error {
	out := map[string]any{
		"card": rep.Card,
		"envelope": map[string]any{
			"scanned_at":         time.Now().UTC().Format(time.RFC3339),
			"source":             opt.Source,
			"skillguard_version": opt.Version,
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func colorer(noColor bool) func(string) string {
	if noColor {
		return func(string) string { return "" }
	}
	return func(s string) string { return s }
}

func severityColor(s model.Severity, col func(string) string) string {
	switch s {
	case model.SevCritical, model.SevHigh:
		return col(cRed)
	case model.SevMedium:
		return col(cYellow)
	default:
		return col(cGray)
	}
}
