package rules

import (
	"strings"
	"unicode"
)

// homoglyphCond configures the homoglyph_ratio primitive (design §8,
// rule-verification §2 signal (d)). SkillCloak's "Reify" operator substitutes
// Cyrillic/Greek lookalikes for Latin letters so that every regex leaf in every
// pack stops matching while the model still reads the intended word — `ignоre
// previous instructions` with one Cyrillic о is, to RE2, a different string
// entirely. That makes this the one primitive whose job is to notice that the
// *other* primitives have been disarmed.
//
// **The spec's `{gt: 0.15}` is unusable as the sole knob, and this is measured
// rather than argued.** The attack needs exactly one poisoned word, and the
// primitive runs over a whole target — a SKILL.md body, a script. Across 9938
// corpus files the four that carry a homoglyph word produce ratios of 0.00060,
// 0.00110, 0.00204 and 0.00481; the most homoglyph-dense real file in the
// corpus is **31× below** the specified threshold. A leaf written as the design
// note specifies would compile, pass a unit test built from a short string, and
// never fire on a real document — the same failure mode as the `\b` bugs in
// #159, reached by a different route. `MinCount` is therefore the operative
// knob and `Gt` is retained for callers that genuinely want a density gate.
type homoglyphCond struct {
	Gt       float64 // minimum ratio of carrier words to Latin-bearing words
	MinCount int     // minimum absolute number of carrier words (default 1)
}

// latinConfusables are the Cyrillic and Greek letters that render as a Latin
// letter in the fonts a reviewer and a terminal actually use. It is deliberately
// a curated list rather than "any Cyrillic or Greek": the point of the carrier
// test below is to separate a *disguised Latin word* from ordinary non-English
// text, and a character that does not resemble a Latin letter cannot disguise
// one. Δ, λ and Σ are absent for exactly that reason.
var latinConfusables = map[rune]bool{}

func init() {
	for _, r := range "авеѕіјкмнорстухԁԛԝАВЕЅІЈКМНОРСТУХԀԚԜ" + "αβεηικνορτυχγμΑΒΕΖΗΙΚΜΝΟΡΤΥΧ" {
		latinConfusables[r] = true
	}
}

func isLatinLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= 0x00C0 && r <= 0x024F)
}

// homoglyphCarrier reports whether a word is a Latin word wearing a disguise.
// All three clauses are false-positive work, each one measured against the
// 9938-file corpus:
//
//   - **At least three Latin letters.** Without it, `μs` (microseconds) and
//     `Δx`/`λt` in performance comments and AMM formulas are carriers, and so is
//     every two-character fragment of mojibake in the two corpus bundles that
//     ship a compressed blob named `SKILL.md`. Three is the lowest bound that
//     keeps the real payloads: `shοw` and `uрlоаd` both have exactly three.
//   - **At least one non-Latin letter** — otherwise every ordinary word matches.
//   - **Every non-Latin letter is a Latin confusable.** This is the clause that
//     lets a Russian, Greek or Chinese skill through untouched: genuine
//     non-English text is *wholly* non-Latin per word, and `报告β值与p值` mixes
//     scripts but carries CJK, which disguises nothing. Without this clause the
//     corpus produces 131 hits across 14 files; with it, 9.
func homoglyphCarrier(word string) bool {
	latin, foreign, confusable := 0, 0, 0
	for _, r := range word {
		switch {
		case isLatinLetter(r):
			latin++
		default:
			foreign++
			if latinConfusables[r] {
				confusable++
			}
		}
	}
	return latin >= 3 && foreign > 0 && foreign == confusable
}

// scanHomoglyph walks the target's words once and reports each carrier. It
// returns per-word matches rather than one whole-text verdict so the finding
// carries a real line number and the offending word as its excerpt — a reviewer
// needs to be told *which* word is disguised, since by construction it looks
// exactly like an ordinary one.
func scanHomoglyph(text string, hc *homoglyphCond, conf float64) []match {
	var carriers []match
	latinWords := 0
	start := -1
	hasLatin, isWord := false, false
	flush := func(end int) {
		if start < 0 {
			return
		}
		w := text[start:end]
		if hasLatin {
			latinWords++
		}
		if homoglyphCarrier(w) {
			carriers = append(carriers, match{start, end, lineNum(text, start), homoglyphExcerpt(w), conf, true})
		}
		start, hasLatin, isWord = -1, false, false
	}
	for i, r := range text {
		if unicode.IsLetter(r) || unicode.IsMark(r) {
			if !isWord {
				start, isWord = i, true
			}
			if isLatinLetter(r) {
				hasLatin = true
			}
			continue
		}
		flush(i)
	}
	flush(len(text))

	minCount := hc.MinCount
	if minCount < 1 {
		minCount = 1
	}
	if len(carriers) < minCount {
		return nil
	}
	if hc.Gt > 0 {
		if latinWords == 0 {
			return nil
		}
		if float64(len(carriers))/float64(latinWords) <= hc.Gt {
			return nil
		}
	}
	return carriers
}

// homoglyphExcerpt keeps the reported word printable in a terminal that may not
// have the font to distinguish the scripts — the whole point is that the two
// look identical, so the excerpt names the code points.
func homoglyphExcerpt(word string) string {
	var b strings.Builder
	b.WriteString(word)
	b.WriteString(" (")
	first := true
	for _, r := range word {
		if isLatinLetter(r) || !latinConfusables[r] {
			continue
		}
		if !first {
			b.WriteString(", ")
		}
		first = false
		b.WriteString("U+" + fmtHex(r))
	}
	b.WriteString(")")
	return b.String()
}
