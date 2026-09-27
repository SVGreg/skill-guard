package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// execScan runs `scan args...` writing the report to a file and returns it
// with the exit code the command would produce (0 when it returned nil).
func execScan(t *testing.T, args ...string) (string, int) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report")
	cmd := scanCmd()
	cmd.SetOut(os.NewFile(0, os.DevNull))
	cmd.SetErr(os.NewFile(0, os.DevNull))
	cmd.SetArgs(append(args, "--out", out, "--quiet", "--no-color"))
	code := 0
	if err := cmd.Execute(); err != nil {
		var ee exitErr
		if !errors.As(err, &ee) {
			t.Fatalf("scan %v: non-exit error %v", args, err)
		}
		code = ee.code
	}
	b, _ := os.ReadFile(out)
	return string(b), code
}

func writeSkill(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const cleanSkill = "---\nname: clean\ndescription: Formats dates.\n---\n\n# Clean\n\nFormats a date string.\n"

var fixtures = filepath.Join("..", "..", "testdata")

func TestScanFolderDiscoversBothFixtures(t *testing.T) {
	out, code := execScan(t, fixtures, "--format", "json")
	if code != 1 {
		t.Fatalf("exit = %d; want 1 (malicious fails the set)", code)
	}
	var got struct {
		Mode    string `json:"mode"`
		Bundles []struct {
			Path    string `json:"path"`
			Verdict string `json:"verdict"`
		} `json:"bundles"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if got.Mode != "multi" || len(got.Bundles) != 2 {
		t.Fatalf("got %+v; want multi mode with benign + malicious", got)
	}
}

func TestScanSameBundleTwiceScansOnce(t *testing.T) {
	b := filepath.Join(fixtures, "benign")
	out, code := execScan(t, b, b)
	if code != 0 || !strings.Contains(out, "1 skill: 0 fail, 0 warn, 1 pass") {
		t.Fatalf("exit %d, report:\n%s", code, out)
	}
}

func TestScanEmptyFolderIsUsageError(t *testing.T) {
	if _, code := execScan(t, t.TempDir()); code != 3 {
		t.Fatalf("exit = %d; want 3", code)
	}
}

func TestScanMissingRootIsUsageError(t *testing.T) {
	if _, code := execScan(t, fixtures, filepath.Join(t.TempDir(), "nope")); code != 3 {
		t.Fatalf("exit = %d; want 3", code)
	}
}

// TestScanUnloadableBundleFailsClosed: a discovered skill that cannot be
// loaded — here, it carries a symlink — fails the set and is listed as error.
func TestScanUnloadableBundleFailsClosed(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, filepath.Join(root, "good"), cleanSkill)
	bad := filepath.Join(root, "bad")
	writeSkill(t, bad, cleanSkill)
	if err := os.Symlink("/etc/hostname", filepath.Join(bad, "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	out, code := execScan(t, root)
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.Contains(out, "1 pass, 1 error") || !strings.Contains(out, "symlink") {
		t.Fatalf("summary must list the unloadable skill as error:\n%s", out)
	}
}

func TestScanSkillCardRejectedForMany(t *testing.T) {
	if _, code := execScan(t, fixtures, "--format", "skill-card"); code != 3 {
		t.Fatalf("exit = %d; want 3", code)
	}
}

// TestScanSingleBundleUnchanged: one skill path keeps the single-bundle
// report — no multi envelope, same exit codes as before M9.
func TestScanSingleBundleUnchanged(t *testing.T) {
	out, code := execScan(t, filepath.Join(fixtures, "malicious"), "--format", "json")
	if code != 1 || strings.Contains(out, `"mode"`) {
		t.Fatalf("malicious: exit %d, multi envelope present=%v", code, strings.Contains(out, `"mode"`))
	}
	out, code = execScan(t, filepath.Join(fixtures, "benign"))
	if code != 0 || !strings.HasPrefix(out, "verdict: pass   risk score: 0/100 (L0)") {
		t.Fatalf("benign: exit %d:\n%s", code, out)
	}
}
