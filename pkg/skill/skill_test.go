package skill

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const miniSkill = "---\nname: mini\ndescription: A tiny fixture.\n---\n\n# Mini\n\nBody line.\n"

func writeBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(miniSkill), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// mkSymlink creates a symlink or skips the test where the platform/user cannot.
func mkSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
}

// TestLoadBundleRejectsSymlinkedFile guards the §7.1 invariant for single-file
// mode. The guard used os.Stat, which resolves the link, so ModeSymlink was
// never set and the symlink was silently followed — while directory mode
// rejected it. Both paths must reject.
func TestLoadBundleRejectsSymlinkedFile(t *testing.T) {
	dir := writeBundle(t)
	link := filepath.Join(t.TempDir(), "linked.md")
	mkSymlink(t, filepath.Join(dir, "SKILL.md"), link)

	if _, err := LoadBundle(link); err == nil {
		t.Fatal("symlinked SKILL.md was accepted; want rejection")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error %q does not mention symlink (cmd/ux.go matches on it)", err)
	}
}

// TestLoadBundleRejectsSymlinkedDir is the directory-mode half of the same
// invariant.
func TestLoadBundleRejectsSymlinkedDir(t *testing.T) {
	dir := writeBundle(t)
	link := filepath.Join(t.TempDir(), "linkdir")
	mkSymlink(t, dir, link)

	if _, err := LoadBundle(link); err == nil {
		t.Fatal("symlinked bundle dir was accepted; want rejection")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error %q does not mention symlink", err)
	}
}

// TestSingleFileEnforcesSizeCap: loadDir caps every file it reads, so the
// single-file path must too — otherwise the DoS guard is bypassed by pointing
// the scanner straight at an oversized SKILL.md.
func TestSingleFileEnforcesSizeCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "SKILL.md")
	big := make([]byte, maxFileSize+1)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(path, big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(path); err == nil {
		t.Fatal("oversized single file was accepted; want size-cap rejection")
	} else if !strings.Contains(err.Error(), "size cap") {
		t.Errorf("error %q does not mention the size cap", err)
	}
}

// TestLineOffsets pins the invariant that scan.Scan relies on to report true
// SKILL.md line numbers (f.StartLine += t.lineOffset). In miniSkill the
// front-matter body starts on file line 2 and the markdown body on file line 5.
func TestLineOffsets(t *testing.T) {
	b, err := LoadBundle(writeBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	if !b.Manifest.Present {
		t.Fatal("front-matter not detected")
	}
	if got := b.Manifest.LineOffset; got != 1 {
		t.Errorf("Manifest.LineOffset = %d, want 1 (raw starts at file line 2)", got)
	}
	if got := b.BodyLineOffset; got != 4 {
		t.Errorf("BodyLineOffset = %d, want 4 (body starts at file line 5)", got)
	}
	if !strings.HasPrefix(b.Body, "\n# Mini") {
		t.Errorf("body = %q, want it to start after the closing ---", b.Body)
	}
}

// TestCRLFFrontMatter: bundles authored on Windows must parse, and their line
// offsets must stay correct.
func TestCRLFFrontMatter(t *testing.T) {
	dir := t.TempDir()
	crlf := strings.ReplaceAll(miniSkill, "\n", "\r\n")
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(crlf), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Manifest.Present {
		t.Fatal("CRLF front-matter not detected")
	}
	if b.Manifest.Name != "mini" {
		t.Errorf("Name = %q, want mini", b.Manifest.Name)
	}
	if got := b.BodyLineOffset; got != 4 {
		t.Errorf("BodyLineOffset = %d, want 4", got)
	}
}

// TestNoFrontMatter: a SKILL.md with no front-matter is still loadable, with
// the whole file as body and a zero offset.
func TestNoFrontMatter(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Just a doc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if b.Manifest.Present {
		t.Error("Manifest.Present = true, want false")
	}
	if b.BodyLineOffset != 0 {
		t.Errorf("BodyLineOffset = %d, want 0", b.BodyLineOffset)
	}
	if b.Body != "# Just a doc\n" {
		t.Errorf("Body = %q, want the whole file", b.Body)
	}
}
