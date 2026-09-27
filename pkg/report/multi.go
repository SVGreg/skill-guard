package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/SVGreg/surfaceguard/pkg/model"
	"github.com/SVGreg/surfaceguard/pkg/scan"
)

// MultiText writes a multi-bundle report: a summary line, one row per bundle
// (worst first), then the findings of every bundle that did not pass — or of
// every bundle with --verbose — and one OWASP legend for the whole set.
//
// Paths and names come from the scanned filesystem and manifests, so they are
// attacker-controlled and go through sanitize like any finding text.
func MultiText(w io.Writer, m *scan.MultiReport, opt Options) {
	col := colorer(opt.NoColor)
	rows := m.WorstFirst()
	tally := map[string]int{}
	for _, r := range rows {
		tally[r.Status()]++
	}
	noun := "skills"
	if len(rows) == 1 {
		noun = "skill"
	}
	fmt.Fprintf(w, "%sverdict: %s%s%s   %d %s: %d fail, %d warn, %d pass, %d error   max risk: %d/100   %s\n",
		col(cBold), col(verdictColor(m.Verdict)), m.Verdict, col(cReset),
		len(rows), noun, tally["fail"], tally["warn"], tally["pass"], tally["error"],
		m.RiskScoreMax, countsLine(m.Counts))
	if len(rows) > 0 {
		fmt.Fprintf(w, "\n  %s%-7s %-8s %-8s %s%s\n", col(cGray), "VERDICT", "RISK", "FINDINGS", "PATH", col(cReset))
	}
	row := func(r scan.BundleResult, indent string) {
		status := r.Status()
		risk, found := "-", "-"
		if r.Report != nil {
			risk = fmt.Sprintf("%d %s", r.RiskScore, r.RiskTier)
			found = fmt.Sprint(len(r.Findings))
		}
		fmt.Fprintf(w, "%s%s%-7s%s %-8s %-8s %s\n", indent, col(statusColor(status)), status, col(cReset), risk, found, sanitize(r.Path))
	}
	if groups := agentGroups(rows); groups == nil {
		for _, r := range rows {
			row(r, "  ")
		}
	} else {
		// An installed-skills scan: one block per agent, so a reader sees
		// what each agent can load. A skill several agents share is listed
		// under each, though it was scanned once.
		for _, g := range groups {
			fmt.Fprintf(w, "  %s%s%s\n", col(cCyan), sanitize(g.agent), col(cReset))
			for _, r := range g.rows {
				row(r, "    ")
			}
		}
	}
	for _, n := range m.Notes {
		fmt.Fprintf(w, "  %snote: %s%s\n", col(cGray), sanitize(n), col(cReset))
	}

	used := map[string]bool{}
	for _, r := range rows {
		if r.Report == nil {
			fmt.Fprintf(w, "\n%s── %s%s\n", col(cBold), sanitize(r.Path), col(cReset))
			fmt.Fprintf(w, "  %serror:%s %s\n", col(cRed), col(cReset), sanitize(r.Error))
			continue
		}
		if r.Verdict == model.Pass && !opt.Verbose {
			continue
		}
		header := sanitize(r.Path)
		if r.Name != "" {
			header += "  (" + sanitize(r.Name) + ")"
		}
		fmt.Fprintf(w, "\n%s── %s%s\n", col(cBold), header, col(cReset))
		textBody(w, r.Report, opt, col, used)
	}
	if !opt.Verbose {
		astLegend(w, used, col)
	}
}

// MultiJSON writes a multi-bundle report. The envelope is marked
// "mode": "multi" so a consumer can tell it from the single-bundle object
// (which has no "mode"); each element of "bundles" is that single-bundle
// object plus its path, and ast_references is hoisted to the envelope once.
func MultiJSON(w io.Writer, m *scan.MultiReport, opt Options) error {
	refs := map[string]model.ASTRef{}
	for _, b := range m.Bundles {
		if b.Report == nil {
			continue
		}
		for id, ref := range astRefs(b.Report) {
			refs[id] = ref
		}
	}
	if len(refs) == 0 {
		refs = nil
	}
	out := struct {
		Mode string `json:"mode"`
		*scan.MultiReport
		ASTReferences map[string]model.ASTRef `json:"ast_references,omitempty"`
	}{Mode: "multi", MultiReport: m, ASTReferences: refs}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func verdictColor(v model.Verdict) string {
	switch v {
	case model.Fail:
		return cRed
	case model.Warn:
		return cYellow
	}
	return cGreen
}

func statusColor(s string) string {
	if s == "error" {
		return cRed
	}
	return verdictColor(model.Verdict(s))
}

type agentGroup struct {
	agent string
	rows  []scan.BundleResult
}

// agentGroups splits worst-first rows by agent, agents sorted, keeping each
// group's rows worst first. It returns nil when no row names an agent (any
// scan but --installed). Rows no agent claims — explicit paths given
// alongside --installed — form a trailing "other paths" group.
func agentGroups(rows []scan.BundleResult) []agentGroup {
	by := map[string][]scan.BundleResult{}
	var other []scan.BundleResult
	for _, r := range rows {
		if len(r.Agents) == 0 {
			other = append(other, r)
			continue
		}
		for _, a := range r.Agents {
			by[a] = append(by[a], r)
		}
	}
	if len(by) == 0 {
		return nil
	}
	agents := make([]string, 0, len(by))
	for a := range by {
		agents = append(agents, a)
	}
	sort.Strings(agents)
	out := make([]agentGroup, 0, len(agents)+1)
	for _, a := range agents {
		out = append(out, agentGroup{a, by[a]})
	}
	if len(other) > 0 {
		out = append(out, agentGroup{"other paths", other})
	}
	return out
}
