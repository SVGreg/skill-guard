package rules

import (
	"fmt"
	"strings"
	"testing"
)

// texts used by both equivalence tests: newline-dense, newline-free, CRLF,
// multi-byte, and fence-heavy shapes.
func equivalenceCorpus() []string {
	return []string{
		"",
		"no newlines at all",
		"a\nb\nc\n",
		strings.Repeat("line of text\n", 500),
		strings.Repeat("no newline here ", 2000),
		"crlf\r\nlines\r\nhere\r\n",
		"emoji 🙂 and accents éàü\nsecond line\n",
		"```\nfenced\n```\nafter\n```\nsecond fence\n",
		strings.Repeat("```\ncode\n```\nprose\n", 200),
		"\n\n\n\n\n",
	}
}

// TestLineTrackerMatchesLineNum is the regression guard for the O(M×N) fix: the
// forward-pass tracker must agree with the original full-count lineNum at every
// offset, or findings would silently report wrong line numbers — the kind of
// break that no rule test would notice because every rule still fires.
func TestLineTrackerMatchesLineNum(t *testing.T) {
	for ti, text := range equivalenceCorpus() {
		t.Run(fmt.Sprintf("text%d", ti), func(t *testing.T) {
			lt := newLineTracker(text)
			// Non-decreasing offsets: the order every caller actually produces.
			for off := 0; off <= len(text); off += 7 {
				if got, want := lt.at(off), lineNum(text, off); got != want {
					t.Fatalf("at(%d) = %d, want %d", off, got, want)
				}
			}
			// Past the end must clamp exactly as lineNum does.
			if got, want := lt.at(len(text)+50), lineNum(text, len(text)+50); got != want {
				t.Errorf("at(past end) = %d, want %d", got, want)
			}
		})
	}
}

// TestLineTrackerHandlesOutOfOrderOffsets pins the safety property: a caller
// that violates the non-decreasing contract must still get the CORRECT line,
// just computed the slow way. A stale-line answer would be a silent data bug.
func TestLineTrackerHandlesOutOfOrderOffsets(t *testing.T) {
	text := "one\ntwo\nthree\nfour\nfive\n"
	lt := newLineTracker(text)
	if got := lt.at(20); got != lineNum(text, 20) {
		t.Fatalf("forward at(20) = %d, want %d", got, lineNum(text, 20))
	}
	// Now go backwards.
	for _, off := range []int{0, 4, 8, 14, 19} {
		if got, want := lt.at(off), lineNum(text, off); got != want {
			t.Errorf("backward at(%d) = %d, want %d", off, got, want)
		}
	}
}

// oldInCodeFence is the pre-fix implementation, kept here as the reference the
// indexed version must agree with.
func oldInCodeFence(text string, pos int) bool {
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

// TestFenceIndexMatchesCountingLoop proves the precomputed fence index answers
// exactly what the per-match counting loop did, so the confidence math — and
// therefore which findings clear EmitThreshold — is unchanged.
func TestFenceIndexMatchesCountingLoop(t *testing.T) {
	for ti, text := range equivalenceCorpus() {
		t.Run(fmt.Sprintf("text%d", ti), func(t *testing.T) {
			offs := fenceStarts(text)
			for pos := 0; pos <= len(text); pos++ {
				if got, want := inFence(offs, pos), oldInCodeFence(text, pos); got != want {
					t.Fatalf("inFence(pos=%d) = %v, want %v", pos, got, want)
				}
			}
		})
	}
}

// BenchmarkEvaluateScaling documents the complexity of the evaluation hot path.
// Doubling the input should roughly double the time; before the lineTracker /
// fence-index fix it more than tripled (256 KiB 152 ms → 2 MiB 4.57 s), because
// every match re-counted newlines and fences from offset 0.
func BenchmarkEvaluateScaling(b *testing.B) {
	packs, _ := Builtin()
	var r *Rule
	for _, p := range packs {
		for _, rr := range p.Rules {
			if rr.ID == "SG-NET-001" {
				r = rr
			}
		}
	}
	if r == nil {
		b.Fatal("SG-NET-001 not found")
	}
	for _, kb := range []int{256, 512, 1024, 2048} {
		var sb strings.Builder
		for sb.Len() < kb*1024 {
			sb.WriteString("see https://pastebin.com/raw/abc for details\n")
		}
		text := sb.String()
		b.Run(fmt.Sprintf("%dKiB", kb), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				r.Evaluate("body", text)
			}
		})
	}
}
