package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/scan"
)

// TestTextEscapesControlCharsFromBundle is the regression test for terminal
// forgery through a scanned bundle. Finding.File is a filename taken verbatim
// from the bundle's directory entry, and a POSIX filename may contain any byte
// except '/' and NUL — so before the fix, a bundle could ship a file whose name
// erased the finding line, painted a forged green "verdict: pass", and enabled
// conceal so the real critical finding never appeared on screen. Exit codes were
// never affected; this forges the human-review half of the output.
func TestTextEscapesControlCharsFromBundle(t *testing.T) {
	cases := []struct {
		name string
		file string
	}{
		{"ansi erase + forged verdict + conceal",
			"helper\x1b[2K\x1b[1;32m  verdict: pass\x1b[0m\x1b[8m.sh"},
		{"bare newline injects whole report lines",
			"a\nverdict: pass   no findings\nb.sh"},
		{"carriage return overwrites the line", "notes.sh\rclean.sh"},
		{"C1 CSI byte", "notes\x9b2Kx.sh"},
		{"bidi override reverses the line", "notes\u202egnp.sh"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := &scan.Report{
				Verdict: model.Fail,
				Findings: []model.Finding{{
					RuleID: "SG-NET-002", AST: []string{"AST01"},
					Severity: model.SevCritical, Title: "Pipe-to-shell execution",
					File: c.file, StartLine: 1,
				}},
			}
			var buf bytes.Buffer
			Text(&buf, rep, Options{NoColor: true})
			out := buf.String()

			// No raw control rune may reach the terminal (report newlines aside).
			for _, r := range out {
				if r != '\n' && needsEscape(r) {
					t.Fatalf("raw control rune %#U reached the terminal:\n%q", r, out)
				}
			}
			// The finding must still be exactly one line, still carrying its title.
			var findingLines int
			for _, ln := range strings.Split(out, "\n") {
				if strings.Contains(ln, "SG-NET-002") {
					findingLines++
					if !strings.Contains(ln, "Pipe-to-shell execution") {
						t.Errorf("finding line lost its title: %q", ln)
					}
				}
			}
			if findingLines != 1 {
				t.Errorf("got %d lines mentioning the rule id, want exactly 1:\n%q", findingLines, out)
			}
		})
	}
}

// TestTextLeavesOrdinaryTextUnchanged pins the fast path: sanitize must not
// rewrite normal report content, including non-ASCII filenames.
func TestTextLeavesOrdinaryTextUnchanged(t *testing.T) {
	rep := &scan.Report{
		Verdict: model.Pass,
		Findings: []model.Finding{{
			RuleID: "SG-NET-002", AST: []string{"AST01"},
			Severity: model.SevCritical, Title: "Pipe-to-shell execution",
			File: "scripts/résumé-器.sh", StartLine: 7,
		}},
	}
	var buf bytes.Buffer
	Text(&buf, rep, Options{NoColor: true})
	if !strings.Contains(buf.String(), "scripts/résumé-器.sh:7") {
		t.Errorf("ordinary UTF-8 path was rewritten:\n%s", buf.String())
	}
}

func TestSanitize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain/path.sh", "plain/path.sh"},
		{"résumé 器", "résumé 器"},
		{"a\x1bb", `a\x1bb`},
		{"a\nb", `a\x0ab`},
		{"a\x7fb", `a\x7fb`},
		{"a\u202eb", `a\u202eb`},
		{"\x1b\x1b", `\x1b\x1b`},
		// Invalid UTF-8 is escaped byte-wise rather than passed through or
		// collapsed to U+FFFD, so the report is always well-formed UTF-8 and a
		// lone C1 byte can never reach a terminal in a legacy 8-bit mode.
		{"a\xffb\x1b", `a\xffb\x1b`},
		{"a\x9bb", `a\x9bb`},     // bare C1 byte: invalid UTF-8
		{"a\u009bb", `a\x9bb`},   // the same C1 as valid UTF-8
		{"\xe4\xb8", `\xe4\xb8`}, // truncated multi-byte sequence
	}
	for _, c := range cases {
		if got := sanitize(c.in); got != c.want {
			t.Errorf("sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestJSONEscapesControlChars documents why the JSON renderer needs no
// sanitize call of its own: encoding/json escapes control characters, and the
// value round-trips back to the original bytes for a consuming tool.
func TestJSONEscapesControlChars(t *testing.T) {
	const name = "a\x1b[2Kb.sh"
	rep := &scan.Report{
		Verdict:  model.Fail,
		Findings: []model.Finding{{RuleID: "SG-NET-002", File: name, StartLine: 1}},
	}
	var buf bytes.Buffer
	if err := JSON(&buf, rep, Options{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if strings.ContainsRune(buf.String(), 0x1b) {
		t.Errorf("raw ESC survived JSON encoding:\n%s", buf.String())
	}
	var back struct {
		Findings []model.Finding `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Findings) != 1 || back.Findings[0].File != name {
		t.Errorf("filename did not round-trip: %+v", back.Findings)
	}
}
