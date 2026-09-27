package main

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// runScan executes the scan command against the malicious fixture, writing the
// text report to a temp file so stdout stays out of the test.
func runScan(t *testing.T, extra ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.txt")
	cmd := scanCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(append([]string{filepath.Join("..", "..", "testdata", "malicious"),
		"--out", out, "--quiet", "--no-color"}, extra...))
	// The fixture fails the gate by design, so a non-nil exitErr is expected.
	_ = cmd.Execute()
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	return string(b)
}

// TestScanSnippetFlagRendersTheSourceFrame covers the wiring: presence of the
// flag (not its value) turns the frame on, and the frame reaches the file the
// user named with --out.
func TestScanSnippetFlagRendersTheSourceFrame(t *testing.T) {
	plain := runScan(t)
	if strings.Contains(plain, "╵") {
		t.Errorf("source frame rendered without --snippet:\n%s", firstLines(plain, 6))
	}

	framed := runScan(t, "--snippet")
	if !strings.Contains(framed, "╵") || !strings.Contains(framed, "│") {
		t.Fatalf("--snippet produced no source frame:\n%s", firstLines(framed, 12))
	}
	// The header gains the column, so a reviewer can jump straight to it.
	if !strings.Contains(framed, "SKILL.md:29:8") {
		t.Errorf("header lost file:line:column:\n%s", firstLines(framed, 12))
	}
	// Bare --snippet means two context lines either side.
	if !strings.Contains(framed, " 27 │") || !strings.Contains(framed, " 31 │") {
		t.Errorf("bare --snippet did not default to 2 context lines:\n%s", firstLines(framed, 20))
	}
}

func TestScanSnippetZeroDropsContextLines(t *testing.T) {
	out := runScan(t, "--snippet=0")
	if !strings.Contains(out, "╵") {
		t.Fatalf("--snippet=0 dropped the frame entirely:\n%s", firstLines(out, 10))
	}
	// With no context, every frame is exactly one source line — so the source
	// rows must equal the finding count. That, not "one marker per source row",
	// is what "no context leaked" means.
	//
	// The two were the same number until SG-INJ-013 arrived: it is the pack's
	// first rule whose match spans *multiple lines* (a run of blank lines), and
	// writeFrame's fallback branch prints such a line plain, with no marker row,
	// because the highlight span does not fit the single line it renders. So
	// markers are a subset of source rows, and pinning them equal would make any
	// future multi-line rule look like a context leak.
	src, marks := strings.Count(out, "│"), strings.Count(out, "╵")
	// One "[n/total] file:line:col" header per finding, whatever the file.
	headers := regexp.MustCompile(`(?m)^\[\d+/\d+\] `).FindAllString(out, -1)
	if want := len(headers); src != want {
		t.Errorf("--snippet=0 printed %d source lines for %d findings (context leaked):\n%s",
			src, want, firstLines(out, 10))
	}
	if marks > src {
		t.Errorf("--snippet=0 printed %d markers for %d source lines:\n%s",
			marks, src, firstLines(out, 10))
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
