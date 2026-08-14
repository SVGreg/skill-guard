package skill

import (
	"bytes"
	"fmt"
	"testing"
)

// TestGatherRefsLineNumbers guards the single-pass line counter. gatherRefs used
// to call lineAt(content, off) per match, which counts newlines from offset 0
// every time — correct, but O(matches × size). The rewrite carries a running
// count forward instead, and a running count is exactly where an off-by-one
// hides: this pins several URLs across several lines, two on one line, and a
// duplicate that is skipped *after* the counter advances.
func TestGatherRefsLineNumbers(t *testing.T) {
	content := []byte(
		"line one\n" + // 1
			"see http://a.example/1 here\n" + // 2
			"\n" + // 3
			"two on one line http://b.example/2 and http://c.example/3\n" + // 4
			"a repeat of http://a.example/1 which is deduped\n" + // 5
			"last http://d.example/4\n") // 6
	b := &Bundle{Files: []File{{Path: "references/r.md", Role: "doc", Content: content}}}
	got := gatherRefs(b)
	want := []struct {
		url  string
		line int
	}{
		{"http://a.example/1", 2},
		{"http://b.example/2", 4},
		{"http://c.example/3", 4},
		{"http://d.example/4", 6},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d refs, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].URL != w.url || got[i].Line != w.line {
			t.Errorf("ref %d: got %s@%d, want %s@%d", i, got[i].URL, got[i].Line, w.url, w.line)
		}
	}
}

// TestGatherRefsDistinguishesDelimiterInKey: the dedup key was
// `path + "|" + url`, and both operands can legally contain the delimiter — so a
// file named "a|b" referencing "http://c" collided with file "a" referencing
// "b|http://c" and one of the two entries was silently dropped. Same bug class
// pkg/scan.dedupKey was fixed for.
func TestGatherRefsDistinguishesDelimiterInKey(t *testing.T) {
	// `|` is not excluded from urlRe, and a bundle controls its own filenames, so
	// both halves are attacker-constructible: file "a|http://x" referencing
	// "http://y" and file "a" referencing the single URL "http://x|http://y"
	// produced the identical key "a|http://x|http://y". One inventory entry
	// vanished — a way to hide an external reference from the skill-card.
	b := &Bundle{Files: []File{
		{Path: "a|http://x", Role: "doc", Content: []byte("see http://y\n")},
		{Path: "a", Role: "doc", Content: []byte("see http://x|http://y\n")},
	}}
	got := gatherRefs(b)
	if len(got) != 2 {
		t.Fatalf("delimiter collision dropped an entry: got %d refs %+v", len(got), got)
	}
}

// TestAllowedToolsSplitsOnCommas: `allowed-tools: Read, Write` is a plain YAML
// scalar, and strings.Fields alone left the comma welded on — "Read," reached
// the skill-card's permissions list verbatim.
func TestAllowedToolsSplitsOnCommas(t *testing.T) {
	for _, in := range []string{"Read, Write, Bash", "Read,Write,Bash", "Read , Write ,Bash"} {
		got := toStringSlice(in)
		want := []string{"Read", "Write", "Bash"}
		if len(got) != len(want) {
			t.Fatalf("%q: got %q, want %q", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%q: got %q, want %q", in, got, want)
			}
		}
	}
	// A YAML sequence is unaffected.
	if got := toStringSlice([]any{"Read", "Write"}); len(got) != 2 || got[0] != "Read" {
		t.Errorf("sequence form broke: %q", got)
	}
}

// BenchmarkGatherRefs documents the cost this function used to have on
// attacker-controlled input. With the per-match lineAt it ran 2.1 s / 8.3 s /
// 37.4 s at 1 / 2 / 4 MiB — quadratic, so the 16 MiB per-file cap allowed
// minutes of CPU for one file and the 256 MiB bundle cap allowed hours.
func BenchmarkGatherRefs(b *testing.B) {
	for _, mb := range []int{1, 2, 4} {
		var buf bytes.Buffer
		for i := 0; buf.Len() < mb*1024*1024; i++ {
			fmt.Fprintf(&buf, "See http://a.co/%d See http://b.co/%d\n", i, i)
		}
		bnd := &Bundle{Files: []File{{Path: "references/many.md", Role: "doc", Content: buf.Bytes()}}}
		b.Run(fmt.Sprintf("%dMiB", mb), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = gatherRefs(bnd)
			}
		})
	}
}
