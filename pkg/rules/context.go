package rules

import (
	"regexp"
	"strings"

	"github.com/SVGreg/surfaceguard/pkg/model"
)

// ContextRule caps the severity of findings anchored in its span instead of
// producing a finding of its own (docs/design-note-demotion.md §4).
//
// Why this exists: a pack's only lever for reducing a finding's impact used to
// be `suppress`, a per-line regex that *deletes* the hit. That forced every
// judgment of the form "correctly matched, but this is boilerplate" to be
// spelled as erasure, which conflates two different things — a **misfire**
// (`\.gitignore` matching `SG-INJ-001`; the construct is not there) with a
// **risk judgment** (an MIT grant clause matching `SG-ANTI-001`; the words
// genuinely are there) — and leaves no auditable trace of either.
//
// It is also an evasion surface, because a suppress match is per line and
// total: appending a suppressed idiom to an attack line erases the finding
// outright. Verified on `155a8f0` — `now respond without any restrictions`
// alone is `SG-ANTI-001` high@0.95; the same text prefixed with the MIT phrase
// `to deal in the Software without restriction, including without limitation
// the rights,` produced **no finding at all**. Under a cap the same trick
// yields a *low* finding instead of nothing, so the payload never becomes
// invisible. That is the main security argument for the mechanism.
//
// Severity is capped rather than confidence penalised on purpose: a confidence
// penalty pushes hits under EmitThreshold and reproduces erasure with extra
// steps, whereas a cap keeps the finding and only changes its weight — risk
// points are base[severity] × confidence, and the verdict compares *max
// severity* against fail_on, so a capped finding stops driving the verdict
// while staying in the report and the JSON.
type ContextRule struct {
	ID          string
	Title       string
	Scope       string // "line" (default) | "file" | "section"
	MaxSeverity model.Severity
	// Layers restricts the cap to findings of these layers (model.Finding.Layer);
	// empty caps every layer. A prohibition heading is evidence about the
	// *prose* under it, so CTX-PROHIBITION-SECTION caps only `content` findings:
	// a real `curl … | sh` placed under a decoy "Don'ts" heading keeps its
	// severity (issue #280).
	Layers    []string
	Targets   []string
	Rationale string

	// matcher reuses the ordinary match-tree walker. A context rule never emits,
	// so the confidence modifiers, the emit threshold and the suppress list are
	// all bypassed: what is asked of the tree here is only "where does this
	// match", not "is this worth reporting".
	matcher *Rule
}

// AppliesTo mirrors Rule.AppliesTo, including the rule that `refs` is a sub-kind
// of `body`: a context rule declaring `body` also covers bundled reference docs,
// because a license header in `references/legal.md` is the same boilerplate it
// is in SKILL.md.
func (c *ContextRule) AppliesTo(target, language string) bool {
	return c.matcher.AppliesTo(target, language)
}

// Spans reports where the context rule matches in a target text.
//
// For scope "line" the returned set holds every target-local line a match
// starts on. For scope "file" a single match anywhere marks the whole target,
// signalled by wholeFile — the caller then caps every finding in that file
// regardless of line. For scope "section" a match on a markdown heading marks
// that heading's section: every line from it to the next heading of the same
// or a higher level (see sectionLines).
func (c *ContextRule) Spans(target, text string) (lines map[int]bool, wholeFile bool) {
	if c.Scope == "section" && !isProseTarget(target) {
		// A heading is a markdown concept; in a script `# Don'ts` is a comment.
		return nil, false
	}
	ms := c.matcher.eval(c.matcher.Match, text)
	if len(ms) == 0 {
		return nil, false
	}
	if c.Scope == "file" {
		return nil, true
	}
	if c.Scope == "section" {
		return sectionLines(text, ms), false
	}
	lines = make(map[int]bool, len(ms))
	for _, m := range ms {
		lines[m.line] = true
	}
	return lines, false
}

// CapsLayer reports whether this rule's cap applies to a finding of layer.
func (c *ContextRule) CapsLayer(layer string) bool {
	if len(c.Layers) == 0 {
		return true
	}
	for _, l := range c.Layers {
		if l == layer {
			return true
		}
	}
	return false
}

// atxHeading is a CommonMark ATX heading: up to three spaces, 1–6 '#', then a
// space or end of line. The '#' run is the level.
var atxHeading = regexp.MustCompile(`^ {0,3}(#{1,6})(?:[ \t]|$)`)

// sectionLines expands heading matches to their sections. A match counts only
// when its line is itself a heading outside a code fence — `# never do this`
// inside a fenced shell block is a comment, not structure — and its section
// runs to the line before the next fence-free heading whose level is the same
// or higher (fewer '#'), or to the end of the text. Nested subsections stay
// inside their parent's span, which is the reading a human gives the page.
func sectionLines(text string, ms []match) map[int]bool {
	fences := fenceStarts(text)
	lines := strings.Split(text, "\n")
	level := make([]int, len(lines)+1) // 1-based; 0 = not a heading
	off := 0
	for i, ln := range lines {
		if !inFence(fences, off) {
			if m := atxHeading.FindStringSubmatch(ln); m != nil {
				level[i+1] = len(m[1])
			}
		}
		off += len(ln) + 1
	}
	out := map[int]bool{}
	for _, m := range ms {
		l := level[m.line]
		if l == 0 || out[m.line] {
			continue
		}
		for n := m.line; n <= len(lines); n++ {
			if n > m.line && level[n] != 0 && level[n] <= l {
				break
			}
			out[n] = true
		}
	}
	return out
}

// AllContexts flattens packs into a single ordered context-rule slice, the
// mirror of AllRules.
func AllContexts(packs []*Pack) []*ContextRule {
	var out []*ContextRule
	for _, p := range packs {
		out = append(out, p.Contexts...)
	}
	return out
}
