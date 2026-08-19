package skill

import (
	"fmt"
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

// TestShebangClassifiesExtensionlessScripts pins the classify() fix: an
// executable shipped without a script extension must be recognized as a `script`
// (so it reaches the code-layer rules) and labeled with its real interpreter, not
// a blanket "bash". Before the fix, `#!/usr/bin/perl` and `#!/usr/bin/php`
// classified as `asset` (never scanned as scripts) and a python shebang was
// mislabeled bash, hiding it from language-gated rules.
func TestShebangClassifiesExtensionlessScripts(t *testing.T) {
	cases := []struct {
		name         string
		content      string
		wantRole     string
		wantLanguage string
	}{
		{"perl-shebang", "#!/usr/bin/perl\nprint 1;\n", "script", "perl"},
		{"php-shebang", "#!/usr/bin/php\n<?php echo 1;\n", "script", "php"},
		{"env-python", "#!/usr/bin/env python3\nprint(1)\n", "script", "python"},
		{"posix-sh", "#!/bin/sh\necho hi\n", "script", "bash"},
		{"env-node", "#!/usr/bin/env node\nconsole.log(1)\n", "script", "javascript"},
		{"ruby", "#!/usr/bin/ruby\nputs 1\n", "script", "ruby"},
		{"no-shebang-text", "just a plain readme, no shebang\n", "asset", ""},
		{"hash-but-not-shebang", "# a comment, not a shebang\n", "asset", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := File{Path: "helper", Content: []byte(c.content)}
			classify(&f)
			if f.Role != c.wantRole {
				t.Errorf("Role = %q, want %q", f.Role, c.wantRole)
			}
			if f.Language != c.wantLanguage {
				t.Errorf("Language = %q, want %q", f.Language, c.wantLanguage)
			}
		})
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

// TestClassifyReferenceDocs pins the `doc` role: bundled prose is instruction
// surface under progressive disclosure, so it must be classified separately
// from inert assets (issue #13). The config check runs first, which is why
// requirements.txt keeps its `config` role despite the .txt extension.
func TestClassifyReferenceDocs(t *testing.T) {
	cases := []struct {
		name, path, content, wantRole string
	}{
		{"markdown-reference", "references/guide.md", "# Guide\n", "doc"},
		{"nested-markdown", "docs/deep/nested/notes.markdown", "notes\n", "doc"},
		{"mdx", "references/page.mdx", "# Page\n", "doc"},
		{"plain-text", "reference.txt", "some prose\n", "doc"},
		{"restructured-text", "README.rst", "Title\n=====\n", "doc"},
		{"readme-is-a-doc", "README.md", "# Readme\n", "doc"},
		// requirements.txt is a config name and must win over the .txt doc ext.
		{"requirements-stays-config", "requirements.txt", "requests==2.0\n", "config"},
		// Not prose: data formats and binaries stay assets.
		{"json-stays-asset", "data.json", "{}\n", "asset"},
		{"csv-stays-asset", "rows.csv", "a,b\n", "asset"},
		{"binary-md-stays-asset", "weird.md", "PK\x03\x04\x00\x00binary", "asset"},
		// Extension-less files are deliberately excluded (see docExt).
		{"extensionless-license", "LICENSE", "MIT License\n", "asset"},
		// A script extension still wins over prose.
		{"script-wins", "run.py", "print(1)\n", "script"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := File{Path: c.path, Content: []byte(c.content)}
			classify(&f)
			if f.Role != c.wantRole {
				t.Errorf("classify(%q).Role = %q, want %q", c.path, f.Role, c.wantRole)
			}
		})
	}
}

// TestClassifyExecutableExtensions pins the extensions added for issue #187.
// Role is what matters — an extension missing from scriptExt classifies as an
// inert `asset`, and scan.Scan builds no target from assets, so no rule in any
// pack can ever see the file. Each row fails against the pre-fix map.
func TestClassifyExecutableExtensions(t *testing.T) {
	cases := []struct {
		path, wantRole, wantLang string
	}{
		// Directly executable on Windows, and previously absent altogether.
		{"install.bat", "script", "batch"},
		{"scripts/setup.cmd", "script", "batch"},
		// Family completions: the other spellings were already mapped.
		{"hook.cjs", "script", "javascript"},
		{"loader.mts", "script", "typescript"},
		{"helper.cts", "script", "typescript"},
		{"tool.pyw", "script", "python"},
		{"module.psm1", "script", "powershell"},
		// Already-mapped spellings must not regress.
		{"run.sh", "script", "bash"},
		{"run.mjs", "script", "javascript"},
		{"run.ps1", "script", "powershell"},
		// Deliberately still assets — these need their own measured change,
		// so a future widening has to update this test on purpose.
		{"component.tsx", "asset", ""},
		{"widget.jsx", "asset", ""},
		{"lib.rs", "asset", ""},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			f := File{Path: c.path, Content: []byte("echo hi\n")}
			classify(&f)
			if f.Role != c.wantRole {
				t.Errorf("classify(%q).Role = %q, want %q", c.path, f.Role, c.wantRole)
			}
			if f.Language != c.wantLang {
				t.Errorf("classify(%q).Language = %q, want %q", c.path, f.Language, c.wantLang)
			}
		})
	}
}

// TestBundleCollectsDocsAndTheirURLs covers the two halves of issue #13 that
// live in this package: reference docs must be grouped into Bundle.Docs so the
// scanner can target them, and gatherRefs must inventory their URLs — it used
// to skip them along with every other `asset`.
func TestBundleCollectsDocsAndTheirURLs(t *testing.T) {
	dir := writeBundle(t)
	if err := os.MkdirAll(filepath.Join(dir, "references"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "references", "guide.md"),
		[]byte("# Guide\n\nSee https://example.com/spec for details.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "logo.png"), []byte("\x89PNG\r\n\x1a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Docs) != 1 || b.Docs[0].Path != "references/guide.md" {
		t.Fatalf("Docs = %+v, want exactly references/guide.md", b.Docs)
	}
	var found bool
	for _, r := range b.Refs {
		if r.File == "references/guide.md" && r.URL == "https://example.com/spec" {
			found = true
			if r.Line != 3 {
				t.Errorf("ref line = %d, want 3", r.Line)
			}
		}
	}
	if !found {
		t.Errorf("URL inside a reference doc not inventoried; refs = %+v", b.Refs)
	}
}

// TestBundleEnforcesTotalSizeCap covers issue #14: maxFileSize bounds each file
// but nothing bounded their sum, so a bundle of N files just under the per-file
// cap consumed ~N × 16 MiB with no ceiling — every File.Content is retained for
// the life of the scan, and scanning untrusted bundles is the whole point.
func TestBundleEnforcesTotalSizeCap(t *testing.T) {
	orig := maxBundleSize
	defer func() { maxBundleSize = orig }()
	maxBundleSize = 4096

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(miniSkill), 0o644); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1024)
	for i := range chunk {
		chunk[i] = 'a'
	}
	// Individually every file is far below maxFileSize; only the sum trips.
	for i := 0; i < 8; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("pad%02d.bin", i)), chunk, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, err := LoadBundle(dir)
	if err == nil {
		t.Fatal("bundle over the total cap was accepted; want rejection")
	}
	if !strings.Contains(err.Error(), "total size cap") {
		t.Errorf("error %q does not mention the total size cap", err)
	}
}

// TestBundleUnderTotalSizeCapLoads is the other half: the cap must not reject a
// bundle that fits, and must be a sum rather than a count.
func TestBundleUnderTotalSizeCapLoads(t *testing.T) {
	orig := maxBundleSize
	defer func() { maxBundleSize = orig }()
	maxBundleSize = 4096

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(miniSkill), 0o644); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 512)
	for i := range chunk {
		chunk[i] = 'a'
	}
	for i := 0; i < 4; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("pad%02d.bin", i)), chunk, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadBundle(dir); err != nil {
		t.Fatalf("bundle under the total cap was rejected: %v", err)
	}
}

// TestRealCorpusBundlesFitTheCap pins the sizing argument behind maxBundleSize:
// the default must sit far above any plausible real skill. The largest bundle in
// the evaluation corpus is 23.3 MiB, so a 256 MiB ceiling leaves ~11x headroom.
func TestRealCorpusBundlesFitTheCap(t *testing.T) {
	const largestObservedBundle = 24 << 20 // 23.3 MiB, evaluation corpus (n=777)
	if maxBundleSize < 4*largestObservedBundle {
		t.Errorf("maxBundleSize = %d MiB, too close to the largest real bundle (%d MiB); "+
			"legitimate skills would start failing to load", maxBundleSize>>20, largestObservedBundle>>20)
	}
}

// TestNestedSkillMDIsNotTheManifest pins the root-only manifest role. The role
// used to be claimed by basename, which gave every nested SKILL.md a role that
// led to no scan target at all: scan.Scan builds manifest/body from the ROOT
// file, and loadDir's grouping switch collects only script/config/doc.
func TestNestedSkillMDIsNotTheManifest(t *testing.T) {
	cases := []struct{ path, wantRole string }{
		{"SKILL.md", "manifest"},
		{"skills/sub/SKILL.md", "doc"},
		{"plugins/a/skills/b/SKILL.md", "doc"},
		// Anything under .claude/ is a config first — that branch precedes docs
		// and is deliberately left alone.
		{".claude/skills/x/SKILL.md", "config"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			f := File{Path: c.path, Content: []byte("---\nname: x\ndescription: y\n---\n\n# X\n")}
			classify(&f)
			if f.Role != c.wantRole {
				t.Errorf("classify(%q).Role = %q, want %q", c.path, f.Role, c.wantRole)
			}
		})
	}
}

// TestNestedSkillMDIsCollectedAsDoc is the bundle-level half: the nested file
// must actually reach Bundle.Docs, which is what scan.Scan turns into a target.
func TestNestedSkillMDIsCollectedAsDoc(t *testing.T) {
	dir := writeBundle(t)
	if err := os.MkdirAll(filepath.Join(dir, "skills", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(dir, "skills", "sub", "SKILL.md")
	if err := os.WriteFile(nested, []byte("---\nname: sub\n---\n\n# Sub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, d := range b.Docs {
		if d.Path == "skills/sub/SKILL.md" {
			found = true
		}
	}
	if !found {
		t.Errorf("nested SKILL.md not in Bundle.Docs; docs=%v", docPaths(b))
	}
	// The root manifest must still be the manifest, and must not leak into Docs.
	if !b.Manifest.Present || b.Manifest.Name != "mini" {
		t.Errorf("root manifest not parsed: present=%v name=%q", b.Manifest.Present, b.Manifest.Name)
	}
	for _, d := range b.Docs {
		if d.Path == "SKILL.md" {
			t.Error("root SKILL.md must not be collected as a doc")
		}
	}
}

func docPaths(b *Bundle) []string {
	out := make([]string, 0, len(b.Docs))
	for _, d := range b.Docs {
		out = append(out, d.Path)
	}
	return out
}
