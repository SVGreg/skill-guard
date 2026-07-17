// Package report renders scan results as human text, JSON, or a skill-card
// (design §10.6). SARIF is deferred to M3 (PROGRESS.md).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/skillguard/skill-guard/pkg/model"
	"github.com/skillguard/skill-guard/pkg/scan"
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
	for _, f := range all {
		sevC := severityColor(f.Severity, col)
		fmt.Fprintf(w, "  %s:%d  %s%s%s  %s%s%s  %s\n",
			f.File, f.StartLine,
			col(cBold), f.RuleID, col(cReset),
			sevC, f.Severity.String(), col(cReset),
			f.Title)
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
		}
	}
	if len(rep.Waived) > 0 {
		fmt.Fprintf(w, "  %s%d waived%s\n", col(cGray), len(rep.Waived), col(cReset))
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

// JSON writes the full report as JSON.
func JSON(w io.Writer, rep *scan.Report, opt Options) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
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
