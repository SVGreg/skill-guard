// Package report renders scan results as human text, JSON, or a skill-card
// (design §10.6). SARIF is deferred to M3 (PROGRESS.md).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

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
	if len(rep.Findings) == 0 {
		fmt.Fprintf(w, "  %sno findings%s\n", col(cGray), col(cReset))
	}
	used := map[string]bool{}
	for _, f := range rep.Findings {
		sevC := severityColor(f.Severity, col)
		var astTag string
		if ids := strings.Join(f.AST, ", "); ids != "" {
			astTag = fmt.Sprintf("  %s%s%s", col(cGray), sanitize(ids), col(cReset))
		}
		fmt.Fprintf(w, "  %s:%d  %s%s%s  %s%s%s  %s%s\n",
			sanitize(f.File), f.StartLine,
			col(cBold), sanitize(f.RuleID), col(cReset),
			sevC, f.Severity.String(), col(cReset),
			sanitize(f.Title), astTag)
		for _, id := range f.AST {
			used[id] = true
		}
		if opt.Verbose {
			if f.Excerpt != "" {
				fmt.Fprintf(w, "      match: %q  (confidence %.2f)\n", f.Excerpt, f.Confidence)
			}
			if f.Rationale != "" {
				fmt.Fprintf(w, "      why:   %s\n", sanitize(f.Rationale))
			}
			if f.Fix != "" {
				fmt.Fprintf(w, "      fix:   %s\n", sanitize(f.Fix))
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
			// Unresolved ids come from the rule pack, so an external --rulepack
			// reaches the terminal here; the resolved branch below prints only
			// model-owned strings.
			fmt.Fprintf(w, "  %s  (unknown risk id)\n", sanitize(id))
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

// sanitize renders control characters visibly instead of letting them reach the
// terminal. Everything the text report prints with %s is either pack-supplied
// (trusted for built-in packs, attacker-chosen for an external --rulepack) or,
// in the case of Finding.File, taken straight from a scanned bundle's directory
// entry — and a POSIX filename may contain any byte except '/' and NUL. A
// hostile bundle can therefore ship a file whose *name* is an escape sequence:
//
//	helper\x1b[2K\x1b[1;32m  verdict: pass\x1b[0m\x1b[8m.sh
//
// erases the finding line as it is drawn, paints a forged green "pass", and
// turns on conceal so the real critical finding is invisible. A bare newline is
// enough on its own to inject whole fabricated report lines. The exit code is
// unaffected, so CI gating still holds — this forges the *human*-review half of
// the output, which is the same threat class as the backlogged SG-INJ-007.
//
// Escaping rather than stripping is deliberate: a reviewer should see that the
// name carries something odd, which is also how Excerpt is already handled (%q).
// The JSON and skill-card renderers need no equivalent — encoding/json escapes
// control characters itself.
//
// cmd/skill-guard has a `safeText` that wraps strconv.Quote for the attestation
// publisher label. That one is right for a standalone field; it is not usable
// here because it also adds surrounding quotes, and File is printed in a
// `path:line` position that must stay copy-pasteable.
func sanitize(s string) string {
	// Fast path. ValidString is part of the test, not an extra: a lone 0x9b is
	// invalid UTF-8, decodes to RuneError, and would otherwise slip past
	// needsEscape and reach the terminal as a raw C1 CSI byte.
	if utf8.ValidString(s) && !strings.ContainsFunc(s, needsEscape) {
		return s // nothing to rewrite, no allocation
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	// Byte-indexed rather than `for range` so an invalid byte can be told apart
	// from a genuine U+FFFD and escaped individually. Runs of clean bytes are
	// copied verbatim.
	last := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		invalid := r == utf8.RuneError && size == 1
		if !invalid && !needsEscape(r) {
			i += size
			continue
		}
		b.WriteString(s[last:i])
		switch {
		case invalid:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
		i += size
		last = i
	}
	b.WriteString(s[last:])
	return b.String()
}

// needsEscape reports whether a rune can forge or reorder terminal output:
// the C0 controls and DEL, the C1 controls, and the bidi formatting characters
// (which can visually reverse an entire line without emitting any escape).
//
// The bidi arm is Unicode's Bidi_Control property in full — ALM, LRM, RLM, the
// LRE/RLE/PDF/LRO/RLO embeddings, and the LRI/RLI/FSI/PDI isolates. U+061C ALM
// was the one member missing: the set was written as "LRM/RLM plus the
// embeddings and isolates", which reads complete but silently omits the Arabic
// mark, and a filename may contain it as readily as any other. It is escaped
// for the same reason LRM and RLM already are — it is a formatting control that
// changes how neighbouring characters are ordered on screen, not a glyph.
func needsEscape(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e || r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// ColorDisabled reports whether ANSI color must be suppressed when writing to w.
// Callers combine it with any explicit --no-color flag; Options.NoColor stays
// the single authority inside this package, so Text remains a pure function of
// its inputs and tests never depend on the environment.
//
// This exists because the package took considerable trouble to keep *foreign*
// escape sequences off the terminal (see sanitize) while unconditionally writing
// its *own* into every redirected file: `scan x > report.txt` and, worse,
// `scan x --format text --out report.txt` — where the user explicitly asked for
// a file artifact — both produced 66 raw ESC bytes. CI logs got the same soup.
//
// Two rules only: NO_COLOR (no-color.org — set and non-empty disables, whatever
// its value) wins, then the writer itself must be a character device. Anything
// that is not an *os.File — a bytes.Buffer, a network conn — cannot be shown to
// be a terminal, so it is treated as not one.
//
// FORCE_COLOR is deliberately NOT honoured, and this was measured rather than
// assumed. It was in the first cut of this function as the escape hatch for a
// deliberate `| less -R`; the environment this was developed in exports
// FORCE_COLOR=3, so the redirect that motivated the whole fix still produced 66
// ESC bytes. Agent harnesses and CI runners set it routinely, which means
// honouring it silently reverses the fix in exactly the environments where a
// text report is most likely to be redirected into a file or a log. NO_COLOR is
// a documented cross-language convention; FORCE_COLOR is a Node/chalk one that
// few Go CLIs implement. If the `| less -R` case needs an escape hatch it should
// be an explicit --color=always flag, which is a UX decision, not an env var
// that can be set three layers up the process tree.
//
// Known limitation: os.ModeCharDevice is true for /dev/null, which isatty(3)
// would reject. Writing color to /dev/null is harmless, and the two cases that
// actually matter — regular files and pipes — are both classified correctly
// without taking golang.org/x/term as a dependency (the project is cobra +
// yaml.v3 and stdlib, deliberately).
func ColorDisabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	f, ok := w.(interface{ Stat() (os.FileInfo, error) })
	if !ok {
		return true
	}
	fi, err := f.Stat()
	if err != nil {
		return true
	}
	return fi.Mode()&os.ModeCharDevice == 0
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
