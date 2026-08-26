package oms

import (
	"errors"
	"strings"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/skill"
)

// TestCanonicalPath walks every rule in OMS §6.1.2, including the ones that
// must reject rather than repair.
func TestCanonicalPath(t *testing.T) {
	ok := []struct{ in, want string }{
		{"SKILL.md", "SKILL.md"},
		{"./config.json", "config.json"},               // rule 3: leading ./
		{"subdir/./weights.bin", "subdir/weights.bin"}, // rule 3: interior .
		{"subdir//file", "subdir/file"},                // rule 3: repeated separators
		{"scripts/setup.sh/", "scripts/setup.sh"},      // rule 4: trailing slash
		{"a/b/c/d.txt", "a/b/c/d.txt"},                 // nested paths are untouched
		{"Model.bin", "Model.bin"},                     // rule 6: no case folding
		{"ünïcode/文件.md", "ünïcode/文件.md"},             // rule 7: valid UTF-8 is fine
	}
	for _, c := range ok {
		got, err := CanonicalPath(c.in)
		if err != nil {
			t.Errorf("CanonicalPath(%q) = error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("CanonicalPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	bad := []struct {
		in      string
		wantErr error
	}{
		{"/etc/passwd", ErrAbsolutePath},       // rule 2
		{"../outside.txt", ErrParentTraversal}, // rule 2
		{"a/../../escape.txt", ErrParentTraversal},
		// Rule 2 forbids a ".." component outright — it is not something to
		// resolve quietly, even when it would stay inside the root.
		{"a/b/../c.txt", ErrParentTraversal},
		{"..", ErrParentTraversal},
		{".", ErrEmptyPath},
		{"", ErrEmptyPath},
		{"bad\xffname.md", ErrNotUTF8}, // rule 7
	}
	for _, c := range bad {
		got, err := CanonicalPath(c.in)
		if err == nil {
			t.Errorf("CanonicalPath(%q) = %q, want error %v", c.in, got, c.wantErr)
			continue
		}
		if !errors.Is(err, c.wantErr) {
			t.Errorf("CanonicalPath(%q) error = %v, want %v", c.in, err, c.wantErr)
		}
	}
}

// TestCanonicalPathKeepsCaseDistinct pins rule 6 specifically: two names that
// differ only in case are two resources. Folding them would put our manifest
// out of step with every other implementation.
func TestCanonicalPathKeepsCaseDistinct(t *testing.T) {
	a, err1 := CanonicalPath("Model.bin")
	b, err2 := CanonicalPath("model.bin")
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: %v %v", err1, err2)
	}
	if a == b {
		t.Errorf("case-differing paths collapsed to %q", a)
	}
}

func bundleWith(paths ...string) *skill.Bundle {
	b := &skill.Bundle{Root: "/tmp/bundle"}
	for _, p := range paths {
		b.Files = append(b.Files, skill.File{Path: p, Content: []byte("content of " + p)})
	}
	return b
}

// TestEnumerateExcludesAndSorts covers §6.1 enumeration plus the §6.2.1
// matching semantics — top-level-only defaults, exact-path user entries.
func TestEnumerateExcludesAndSorts(t *testing.T) {
	b := bundleWith(
		"SKILL.md",
		"scripts/setup.sh",
		".github/workflows/ci.yml", // default exclusion, subtree
		".gitignore",               // default exclusion, file
		"docs/.git/config",         // NOT excluded: .git is not top-level here
		"skill.oms.sig",            // our own signature file
		"SKILL.md.skillsig",        // the SGMT-1 signature
		"cache/big.bin",            // excluded by the user entry below
		"subdir/cache/keep.bin",    // NOT excluded: user entries are exact paths
		"assets/logo.png",
	)

	files, ser, err := Enumerate(b, EnumOptions{ExtraIgnorePaths: []string{"cache"}})
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	var got []string
	for _, f := range files {
		got = append(got, f.Name)
	}
	want := []string{
		"SKILL.md",
		"assets/logo.png",
		"docs/.git/config",
		"scripts/setup.sh",
		"subdir/cache/keep.bin",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("enumerated %v, want %v", got, want)
	}

	if ser.Method != MethodFiles || ser.HashType != AlgoSHA256 || ser.AllowSymlinks {
		t.Errorf("serialization = %+v, want files/sha256/allow_symlinks=false", ser)
	}
	for _, must := range append(append([]string{}, DefaultIgnorePaths...), "cache", "skill.oms.sig") {
		if !contains(ser.IgnorePaths, must) {
			t.Errorf("ignore_paths %v is missing %q", ser.IgnorePaths, must)
		}
	}
}

func TestEnumerateSingleFileUsesBasename(t *testing.T) {
	b := bundleWith("some/nested/SKILL.md")
	files, _, err := Enumerate(b, EnumOptions{SingleFile: true})
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(files) != 1 || files[0].Name != "SKILL.md" {
		t.Errorf("single-file enumeration = %+v, want one entry named SKILL.md", files)
	}
}

func TestEnumerateRejects(t *testing.T) {
	cases := []struct {
		name    string
		bundle  *skill.Bundle
		opt     EnumOptions
		wantErr error
	}{
		{"empty after exclusions", bundleWith(".gitignore"), EnumOptions{}, ErrNoFiles},
		{"no files at all", bundleWith(), EnumOptions{}, ErrNoFiles},
		{"traversal", bundleWith("../escape.sh"), EnumOptions{}, ErrParentTraversal},
		{"absolute", bundleWith("/etc/passwd"), EnumOptions{}, ErrAbsolutePath},
		{"non-utf8", bundleWith("bad\xffname"), EnumOptions{}, ErrNotUTF8},
		{"glob ignore", bundleWith("SKILL.md"), EnumOptions{ExtraIgnorePaths: []string{"*.bin"}}, ErrIgnoreGlob},
		{"duplicate names", bundleWith("a/SKILL.md", "b/SKILL.md"), EnumOptions{SingleFile: true}, ErrDuplicatePath},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := Enumerate(c.bundle, c.opt); !errors.Is(err, c.wantErr) {
				t.Errorf("Enumerate error = %v, want %v", err, c.wantErr)
			}
		})
	}
}

// TestEnumerateIsDeterministic: the same bundle in a different file order must
// produce the same manifest, or the root digest is not reproducible.
func TestEnumerateIsDeterministic(t *testing.T) {
	forward := bundleWith("SKILL.md", "a.txt", "z/b.txt", "m.txt")
	reversed := bundleWith("m.txt", "z/b.txt", "a.txt", "SKILL.md")

	f1, s1, err := Enumerate(forward, EnumOptions{})
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	f2, s2, err := Enumerate(reversed, EnumOptions{})
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(f1) != len(f2) {
		t.Fatalf("different lengths: %d vs %d", len(f1), len(f2))
	}
	for i := range f1 {
		if f1[i].Name != f2[i].Name {
			t.Errorf("entry %d: %q vs %q", i, f1[i].Name, f2[i].Name)
		}
	}
	if strings.Join(s1.IgnorePaths, ",") != strings.Join(s2.IgnorePaths, ",") {
		t.Errorf("ignore_paths differ: %v vs %v", s1.IgnorePaths, s2.IgnorePaths)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
