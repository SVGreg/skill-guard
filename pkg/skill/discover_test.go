package skill

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// mkSkill writes a minimal bundle at dir (creating parents) and returns dir.
func mkSkill(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(miniSkill), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func paths(cs []Candidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Path
	}
	return out
}

func errsMatching(errs []DiscoverError, target error) []DiscoverError {
	var out []DiscoverError
	for _, e := range errs {
		if errors.Is(e, target) {
			out = append(out, e)
		}
	}
	return out
}

func TestDiscoverTree(t *testing.T) {
	// Resolved, so RealPath == Path holds where TMPDIR is itself a link (macOS).
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mkSkill(t, filepath.Join(root, "skills", "alpha"))
	mkSkill(t, filepath.Join(root, "plugins", "p", "skills", "beta"))
	// A bundle inside a bundle is part of the outer one: one candidate.
	outer := mkSkill(t, filepath.Join(root, "outer"))
	mkSkill(t, filepath.Join(outer, "examples", "inner"))
	// Vendored trees are never searched.
	mkSkill(t, filepath.Join(root, "node_modules", "pkg"))
	mkSkill(t, filepath.Join(root, "skills", "alpha2", ".venv", "x"))
	mkSkill(t, filepath.Join(root, ".git", "hooks", "y"))
	// A directory named SKILL.md is not a manifest.
	if err := os.MkdirAll(filepath.Join(root, "odd", "SKILL.md"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, errs, err := Discover([]string{root}, DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(root, "outer"),
		filepath.Join(root, "plugins", "p", "skills", "beta"),
		filepath.Join(root, "skills", "alpha"),
	}
	if !reflect.DeepEqual(paths(got), want) {
		t.Fatalf("paths = %v\nwant    %v", paths(got), want)
	}
	if len(errs) != 0 {
		t.Fatalf("unexpected discover errors: %v", errs)
	}
	for _, c := range got {
		if c.Root != root || c.RealPath != c.Path || c.Via != "" {
			t.Errorf("candidate %+v: want Root=%s, RealPath=Path, no Via", c, root)
		}
	}
}

func TestDiscoverRootIsBundle(t *testing.T) {
	root := mkSkill(t, t.TempDir())
	mkSkill(t, filepath.Join(root, "nested"))
	got, _, err := Discover([]string{root}, DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != root {
		t.Fatalf("got %v, want exactly the root bundle", paths(got))
	}
}

func TestDiscoverRootIsFile(t *testing.T) {
	root := mkSkill(t, t.TempDir())
	f := filepath.Join(root, "SKILL.md")
	got, _, err := Discover([]string{f}, DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != f || !got[0].File {
		t.Fatalf("got %+v, want one single-file candidate", got)
	}
}

func TestDiscoverMissingRoot(t *testing.T) {
	if _, _, err := Discover([]string{filepath.Join(t.TempDir(), "nope")}, DiscoverOptions{}); err == nil {
		t.Fatal("missing root: want error")
	}
}

// TestDiscoverSymlinks covers the M9 symlink contract: a link is a candidate
// only when its target directly is a bundle, it is reported once per real
// path, and it is never followed for descent (so a loop cannot be walked).
func TestDiscoverSymlinks(t *testing.T) {
	shared := mkSkill(t, filepath.Join(t.TempDir(), "agents", "skills", "shared"))
	elsewhere := t.TempDir()
	mkSkill(t, filepath.Join(elsewhere, "deep", "hidden"))

	root := t.TempDir()
	skills := filepath.Join(root, "skills")
	mkSkill(t, filepath.Join(skills, "local"))
	mkSymlink(t, shared, filepath.Join(skills, "shared-link"))
	mkSymlink(t, shared, filepath.Join(skills, "zz-second-link"))
	mkSymlink(t, elsewhere, filepath.Join(skills, "not-a-bundle")) // descent refused
	mkSymlink(t, root, filepath.Join(skills, "loop"))              // cycle
	mkSymlink(t, filepath.Join(root, "gone"), filepath.Join(skills, "dangling"))

	got, errs, err := Discover([]string{root}, DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(skills, "local"), filepath.Join(skills, "shared-link")}
	if !reflect.DeepEqual(paths(got), want) {
		t.Fatalf("paths = %v\nwant    %v", paths(got), want)
	}
	link := got[1]
	realShared, _ := filepath.EvalSymlinks(shared)
	if link.RealPath != realShared || link.Via != link.Path {
		t.Errorf("link candidate = %+v; want RealPath=%s and Via=Path", link, realShared)
	}
	if !reflect.DeepEqual(link.Also, []string{filepath.Join(skills, "zz-second-link")}) {
		t.Errorf("Also = %v; want the second link", link.Also)
	}
	skipped := errsMatching(errs, ErrSymlinkNotFollowed)
	if len(skipped) != 2 { // not-a-bundle and loop
		t.Errorf("symlink-not-followed errors = %v; want 2", skipped)
	}
}

// TestDiscoverOverlappingRoots: naming a directory and its child finds each
// bundle once, whichever root is walked first.
func TestDiscoverOverlappingRoots(t *testing.T) {
	root := t.TempDir()
	mkSkill(t, filepath.Join(root, "a", "one"))
	for _, roots := range [][]string{{root, filepath.Join(root, "a")}, {filepath.Join(root, "a"), root}} {
		got, _, err := Discover(roots, DiscoverOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("roots %v: got %v, want one bundle", roots, paths(got))
		}
	}
}

func TestDiscoverLimitsReported(t *testing.T) {
	root := t.TempDir()
	mkSkill(t, filepath.Join(root, "a", "b", "c", "deep"))
	for _, n := range []string{"s1", "s2", "s3"} {
		mkSkill(t, filepath.Join(root, n))
	}

	got, errs, err := Discover([]string{root}, DiscoverOptions{MaxDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("depth 2: got %v, want the three shallow bundles", paths(got))
	}
	if len(errsMatching(errs, ErrMaxDepth)) != 1 {
		t.Errorf("depth limit not reported: %v", errs)
	}

	got, errs, err = Discover([]string{root}, DiscoverOptions{MaxBundles: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("cap 2: got %d bundles", len(got))
	}
	if len(errsMatching(errs, ErrMaxBundles)) != 1 {
		t.Errorf("bundle cap not reported: %v", errs)
	}
}

func TestDiscoverUnreadableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything")
	}
	root := t.TempDir()
	mkSkill(t, filepath.Join(root, "ok"))
	locked := filepath.Join(root, "locked")
	mkSkill(t, filepath.Join(locked, "inside"))
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	got, errs, err := Discover([]string{root}, DiscoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(errs) != 1 || errs[0].Path != locked {
		t.Fatalf("got %v, errs %v; want one bundle and one error for %s", paths(got), errs, locked)
	}
}

func TestDiscoverDeterministic(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"z", "a", "m/x", "m/b"} {
		mkSkill(t, filepath.Join(root, n))
	}
	first, _, _ := Discover([]string{root}, DiscoverOptions{})
	for i := 0; i < 5; i++ {
		again, _, _ := Discover([]string{root}, DiscoverOptions{})
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs: %v vs %v", i, paths(first), paths(again))
		}
	}
}
