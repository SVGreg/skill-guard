// Package rules defines the rule-pack schema, the matcher primitives, and the
// confidence/context-modifier math that turns raw pattern hits into findings.
// Rules are data (YAML), not code — see design §8 and rule-verification.md.
package rules

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/SVGreg/skill-guard/pkg/model"
)

// EmitThreshold is the minimum confidence (after context modifiers) for a
// candidate to become a finding (rule-verification.md §1.2).
const EmitThreshold = 0.5

// Context modifier deltas (rule-verification.md §1.2).
const (
	modCodeExample = -0.4 // text match inside a fenced/indented code block
	modDocumentary = -0.4 // text match near "example"/"e.g."/"do not"/"detect"…
	modInstruction = 0.15 // match in SKILL.md front-matter or body
	modDescription = 0.2  // match inside a tool/parameter description field
)

// Condition is one node of a rule's match tree. Exactly one shape is set:
// a boolean composite (any/all/not) or a leaf primitive.
type Condition struct {
	Any []Condition
	All []Condition
	Not []Condition

	// Leaf primitives.
	regex           *regexp.Regexp
	substring       string
	unicodeCategory []string
	bidiControl     bool
	tagBlock        bool
	urlHost         []string

	confidence *float64 // per-pattern override
}

func (c Condition) isLeaf() bool {
	return len(c.Any) == 0 && len(c.All) == 0 && len(c.Not) == 0
}

// structural leaves must not receive the documentary/code-example penalty
// (an invisible char in "documentation" is still an invisible char).
func (c Condition) structural() bool {
	return c.unicodeCategory != nil || c.bidiControl || c.tagBlock || c.urlHost != nil
}

// Rule is a compiled rule ready to evaluate.
type Rule struct {
	ID         string
	Title      string
	AST        []string
	Severity   model.Severity
	Engine     string
	Layer      string
	Confidence float64
	Languages  []string
	Targets    []string
	Match      Condition
	Suppress   []*regexp.Regexp
	Rationale  string
	Fix        string
}

// AppliesTo reports whether the rule should run against a target of the given
// name ("body","scripts","configs","manifest","refs") and language.
func (r *Rule) AppliesTo(target, language string) bool {
	if len(r.Targets) > 0 && !contains(r.Targets, target) {
		return false
	}
	if len(r.Languages) > 0 && !contains(r.Languages, "*") && language != "" && !contains(r.Languages, language) {
		return false
	}
	return true
}

// match is a raw hit before it becomes a finding.
type match struct {
	start, end int
	line       int
	text       string
	confidence float64
	structural bool
}

// Evaluate runs the rule against a target text and returns emitted findings
// (File is left blank for the caller to fill). Confidence modifiers, the
// suppress list, and the emit threshold are all applied here.
func (r *Rule) Evaluate(target, text string) []model.Finding {
	matches := r.eval(r.Match, text)
	var out []model.Finding
	// Dedup per line within this rule+target, keeping the highest-confidence
	// match (rule-verification.md §1.2). idxByLine maps a line to its slot in
	// out so a later, stronger signal on the same line replaces a weaker one
	// that happened to be evaluated first — otherwise the reported confidence
	// and excerpt would reflect whichever leaf is listed first in the match
	// tree, not the strongest evidence.
	idxByLine := map[int]int{}
	for _, m := range matches {
		conf := m.confidence
		if !m.structural {
			conf += contextModifier(target, text, m.start)
		} else if target == "manifest" || target == "body" {
			conf += modInstruction
		}
		if conf < 0 {
			conf = 0
		} else if conf > 1 {
			conf = 1
		}
		if conf < EmitThreshold {
			continue
		}
		if r.suppressed(lineText(text, m.start)) {
			continue
		}
		f := model.Finding{
			RuleID:     r.ID,
			AST:        r.AST,
			Severity:   r.Severity,
			Engine:     r.Engine,
			Layer:      r.Layer,
			Title:      r.Title,
			StartLine:  m.line,
			Excerpt:    truncate(m.text, 200),
			Rationale:  r.Rationale,
			Fix:        r.Fix,
			Confidence: round2(conf),
		}
		if i, ok := idxByLine[m.line]; ok {
			if f.Confidence > out[i].Confidence {
				out[i] = f // stronger signal on the same line wins
			}
			continue
		}
		idxByLine[m.line] = len(out)
		out = append(out, f)
	}
	return out
}

func (r *Rule) suppressed(line string) bool {
	for _, s := range r.Suppress {
		if s.MatchString(line) {
			return true
		}
	}
	return false
}

// eval walks the match tree.
func (r *Rule) eval(c Condition, text string) []match {
	if c.isLeaf() {
		return r.evalLeaf(c, text)
	}
	if len(c.Any) > 0 {
		var all []match
		for _, sub := range c.Any {
			all = append(all, r.eval(sub, text)...)
		}
		return all
	}
	if len(c.All) > 0 {
		var first []match
		for i, sub := range c.All {
			ms := r.eval(sub, text)
			if len(ms) == 0 {
				return nil // one branch missing ⇒ whole AND fails
			}
			if i == 0 {
				first = ms[:1]
			}
		}
		return first
	}
	if len(c.Not) > 0 {
		for _, sub := range c.Not {
			if len(r.eval(sub, text)) > 0 {
				return nil // negated branch present ⇒ fail
			}
		}
		return []match{{start: 0, line: 1, confidence: r.Confidence}}
	}
	return nil
}

func (r *Rule) evalLeaf(c Condition, text string) []match {
	conf := r.Confidence
	if c.confidence != nil {
		conf = *c.confidence
	}
	if conf == 0 {
		conf = EmitThreshold
	}
	switch {
	case c.regex != nil:
		var ms []match
		for _, loc := range c.regex.FindAllStringIndex(text, -1) {
			ms = append(ms, match{loc[0], loc[1], lineNum(text, loc[0]), text[loc[0]:loc[1]], conf, false})
		}
		return ms
	case c.substring != "":
		var ms []match
		for off := 0; ; {
			i := strings.Index(text[off:], c.substring)
			if i < 0 {
				break
			}
			p := off + i
			ms = append(ms, match{p, p + len(c.substring), lineNum(text, p), c.substring, conf, false})
			off = p + len(c.substring)
		}
		return ms
	case c.unicodeCategory != nil:
		return scanUnicodeCategory(text, c.unicodeCategory, conf)
	case c.bidiControl:
		return scanRunes(text, isBidiControl, conf)
	case c.tagBlock:
		return scanTagBlock(text, conf)
	case c.urlHost != nil:
		return scanURLHost(text, c.urlHost, conf)
	}
	return nil
}

// --- unicode / structural scanners ---

func scanUnicodeCategory(text string, cats []string, conf float64) []match {
	tables := map[string]*unicode.RangeTable{
		"Cf": unicode.Cf, "Cc": unicode.Cc, "Co": unicode.Co,
	}
	var ms []match
	for i, r := range text {
		if i == 0 && r == '\uFEFF' {
			continue // leading BOM is not smuggling
		}
		for _, cat := range cats {
			if t := tables[cat]; t != nil && unicode.Is(t, r) {
				if r == '\u200D' && isEmojiZWJ(text, i) {
					break // legitimate emoji ZWJ
				}
				ms = append(ms, match{i, i + len(string(r)), lineNum(text, i), "U+" + fmtHex(r), conf, true})
				break
			}
		}
	}
	return ms
}

func scanRunes(text string, pred func(rune) bool, conf float64) []match {
	var ms []match
	for i, r := range text {
		if pred(r) {
			ms = append(ms, match{i, i + len(string(r)), lineNum(text, i), "U+" + fmtHex(r), conf, true})
		}
	}
	return ms
}

func isBidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// scanTagBlock finds Unicode Tag chars (U+E0000–E007F) used for ASCII
// smuggling, carving out well-formed emoji tag sequences (flags).
func scanTagBlock(text string, conf float64) []match {
	runes := []rune(text)
	safe := emojiTagSpans(runes)
	byteOff := 0
	var ms []match
	for idx, r := range runes {
		if r >= 0xE0000 && r <= 0xE007F && !inSpans(safe, idx) {
			ms = append(ms, match{byteOff, byteOff + len(string(r)), lineNum(text, byteOff), "U+" + fmtHex(r), conf, true})
		}
		byteOff += len(string(r))
	}
	return ms
}

// emojiTagSpans returns rune-index spans of well-formed emoji tag sequences:
// emoji base + 2..6 tag chars in [a-z0-9] + CANCEL TAG (U+E007F).
func emojiTagSpans(runes []rune) [][2]int {
	var spans [][2]int
	for i := 0; i < len(runes); i++ {
		if !isEmojiBase(runes[i]) {
			continue
		}
		j := i + 1
		n := 0
		for j < len(runes) && ((runes[j] >= 0xE0061 && runes[j] <= 0xE007A) || (runes[j] >= 0xE0030 && runes[j] <= 0xE0039)) {
			j++
			n++
		}
		if n >= 2 && n <= 6 && j < len(runes) && runes[j] == 0xE007F {
			spans = append(spans, [2]int{i, j})
		}
	}
	return spans
}

func inSpans(spans [][2]int, idx int) bool {
	for _, s := range spans {
		if idx >= s[0] && idx <= s[1] {
			return true
		}
	}
	return false
}

func isEmojiBase(r rune) bool {
	return (r >= 0x1F000 && r <= 0x1FAFF) || (r >= 0x2600 && r <= 0x27BF)
}

func isEmojiZWJ(text string, off int) bool {
	// crude but safe: ZWJ flanked by emoji bases.
	prev, next := prevRune(text, off), nextRune(text, off+len("\u200D"))
	return isEmojiBase(prev) && isEmojiBase(next)
}

var urlHostRe = regexp.MustCompile(`https?://([^/\s"'` + "`" + `)\]<>:]+)`)

func scanURLHost(text string, hosts []string, conf float64) []match {
	var ms []match
	for _, loc := range urlHostRe.FindAllStringSubmatchIndex(text, -1) {
		host := strings.ToLower(text[loc[2]:loc[3]])
		for _, h := range hosts {
			h = strings.ToLower(h)
			if host == h || strings.HasSuffix(host, "."+h) {
				ms = append(ms, match{loc[0], loc[1], lineNum(text, loc[0]), host, conf, true})
				break
			}
		}
	}
	return ms
}

// --- context modifiers ---

var docKeywords = regexp.MustCompile(`(?i)\b(example|e\.g\.|for instance|do not|don't|never|detect|flag|insecure|avoid)\b`)

func contextModifier(target, text string, pos int) float64 {
	var delta float64
	if target == "manifest" || target == "body" {
		delta += modInstruction
	}
	if inCodeFence(text, pos) {
		delta += modCodeExample
	} else if nearDocKeyword(text, pos) {
		delta += modDocumentary
	}
	return delta
}

func inCodeFence(text string, pos int) bool {
	fences := 0
	for i := 0; i+3 <= len(text) && i < pos; {
		if text[i] == '`' && i+3 <= len(text) && text[i:i+3] == "```" {
			fences++
			i += 3
			continue
		}
		i++
	}
	return fences%2 == 1
}

func nearDocKeyword(text string, pos int) bool {
	start := pos - 80
	if start < 0 {
		start = 0
	}
	end := pos + 40
	if end > len(text) {
		end = len(text)
	}
	return docKeywords.MatchString(text[start:end])
}

// --- helpers ---

func lineNum(text string, off int) int {
	if off > len(text) {
		off = len(text)
	}
	return strings.Count(text[:off], "\n") + 1
}

func lineText(text string, off int) string {
	start := strings.LastIndexByte(text[:min(off, len(text))], '\n') + 1
	end := off
	if i := strings.IndexByte(text[off:], '\n'); i >= 0 {
		end = off + i
	} else {
		end = len(text)
	}
	if start > end {
		return ""
	}
	return text[start:end]
}

func prevRune(text string, off int) rune {
	for i := off - 1; i >= 0; i-- {
		if r := rune(text[i]); r < 0x80 || (text[i]&0xC0) != 0x80 {
			rs := []rune(text[i:off])
			if len(rs) > 0 {
				return rs[0]
			}
		}
	}
	return 0
}

func nextRune(text string, off int) rune {
	for _, r := range text[min(off, len(text)):] {
		return r
	}
	return 0
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }

func fmtHex(r rune) string { return fmt.Sprintf("%04X", r) }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
