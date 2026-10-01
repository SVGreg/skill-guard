package rules

import (
	"strings"
	"testing"
)

const sectionPack = `
apiVersion: surfaceguard.svgreg.net/rulepack.v1
name: t
version: 1.0.0
rules:
  - id: CTX-S
    kind: context
    title: t
    scope: section
    effect:
      max_severity: low
      layers: [content]
    targets: [body]
    match:
      any:
        - regex: '(?im)^ {0,3}#{1,6}[ \t]+[^\n]*\banti-patterns\b'
`

// TestSectionScopeSpansToNextPeerHeading pins the section walk (issue #280):
// the span starts at the matching heading, keeps nested subsections, stops at
// the next heading of the same or a higher level, and does not treat a `#`
// line inside a code fence as a heading.
func TestSectionScopeSpansToNextPeerHeading(t *testing.T) {
	p, err := LoadPack([]byte(sectionPack))
	if err != nil {
		t.Fatalf("LoadPack: %v", err)
	}
	c := p.Contexts[0]
	text := strings.Join([]string{
		"# Guide",                     // 1
		"Intro.",                      // 2
		"## Anti-Patterns",            // 3  section starts
		"- bullet one",                // 4
		"```sh",                       // 5
		"## Anti-Patterns in a fence", // 6  inside a fence: not a heading
		"# a shell comment",           // 7  inside a fence: must not end the section
		"```",                         // 8
		"### Nested detail",           // 9  deeper level: still inside
		"- bullet two",                // 10
		"## Usage",                    // 11 peer heading: section ends
		"- outside",                   // 12
		"   ## Anti-Patterns",         // 13 up to three spaces is still a heading
		"- capped again",              // 14
	}, "\n")
	lines, whole := c.Spans("body", text)
	if whole {
		t.Fatal("section scope reported a whole-file span")
	}
	want := map[int]bool{3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true, 10: true, 13: true, 14: true}
	for n := 1; n <= 14; n++ {
		if lines[n] != want[n] {
			t.Errorf("line %d: in span = %v, want %v", n, lines[n], want[n])
		}
	}
}

// TestSectionScopeIsMarkdownOnly: in a script, `# Anti-Patterns` is a comment.
func TestSectionScopeIsMarkdownOnly(t *testing.T) {
	p, err := LoadPack([]byte(sectionPack))
	if err != nil {
		t.Fatal(err)
	}
	if lines, _ := p.Contexts[0].Spans("scripts", "# Anti-Patterns\nrm -rf /\n"); len(lines) != 0 {
		t.Errorf("section scope fired on a script: %v", lines)
	}
	if !p.Contexts[0].CapsLayer("content") || p.Contexts[0].CapsLayer("code") {
		t.Error("layers: [content] must cap content findings and only those")
	}
}

// TestSectionScopeLoadErrors: a section scope on a non-markdown target and an
// unknown layer are load errors, not inert fields that look meaningful.
func TestSectionScopeLoadErrors(t *testing.T) {
	for name, pack := range map[string]string{
		"scripts target": strings.Replace(sectionPack, "targets: [body]", "targets: [body, scripts]", 1),
		"unknown layer":  strings.Replace(sectionPack, "layers: [content]", "layers: [prose]", 1),
	} {
		if _, err := LoadPack([]byte(pack)); err == nil {
			t.Errorf("%s: loaded, want an error", name)
		}
	}
}
