package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHome points HOME at a temp dir holding user-scope skills for Claude
// Code and the shared ~/.agents/skills, with the shared skill also symlinked
// into ~/.claude/skills — the layout `npx skills add` produces. Agent env
// overrides are cleared so the host's own configuration cannot leak in.
func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, v := range []string{"CLAUDE_CONFIG_DIR", "CLAUDE_CODE_PLUGIN_CACHE_DIR"} {
		t.Setenv(v, "")
	}
	writeSkill(t, filepath.Join(home, ".claude", "skills", "mine"), cleanSkill)
	shared := filepath.Join(home, ".agents", "skills", "shared")
	writeSkill(t, shared, cleanSkill)
	if err := os.Symlink(shared, filepath.Join(home, ".claude", "skills", "shared")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	return home
}

type multiOut struct {
	Mode    string `json:"mode"`
	Bundles []struct {
		Path     string   `json:"path"`
		RealPath string   `json:"real_path"`
		Also     []string `json:"also"`
		Agents   []string `json:"agents"`
	} `json:"bundles"`
}

func scanInstalledJSON(t *testing.T, extra ...string) (multiOut, int) {
	t.Helper()
	// An empty project dir keeps this repo's own .claude/skills out of it.
	args := append([]string{"--installed", "--project-dir", t.TempDir(), "--format", "json"}, extra...)
	out, code := execScan(t, args...)
	var got multiOut
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON (exit %d): %v\n%s", code, err, out)
	}
	return got, code
}

// TestScanInstalledScansEachRealBundleOnce is the M9-07 acceptance: the
// shared skill is reached from ~/.claude/skills (a symlink) and from
// ~/.agents/skills, is scanned once, and is attributed to every agent that
// reads either path.
func TestScanInstalledScansEachRealBundleOnce(t *testing.T) {
	fakeHome(t)
	got, code := scanInstalledJSON(t)
	if code != 0 {
		t.Fatalf("exit = %d; both skills are clean", code)
	}
	if len(got.Bundles) != 2 {
		t.Fatalf("bundles = %+v; want mine + shared, once each", got.Bundles)
	}
	var shared *struct {
		Path     string   `json:"path"`
		RealPath string   `json:"real_path"`
		Also     []string `json:"also"`
		Agents   []string `json:"agents"`
	}
	for i := range got.Bundles {
		if strings.HasSuffix(got.Bundles[i].Path, "shared") {
			shared = &got.Bundles[i]
		}
	}
	if shared == nil || len(shared.Also) != 1 {
		t.Fatalf("shared skill not reported with its second path: %+v", got.Bundles)
	}
	for _, a := range []string{"claude-code", "codex", "cursor"} {
		if !strings.Contains(strings.Join(shared.Agents, ","), a) {
			t.Errorf("shared skill agents %v missing %s", shared.Agents, a)
		}
	}
}

func TestScanInstalledAgentFilter(t *testing.T) {
	fakeHome(t)
	got, _ := scanInstalledJSON(t, "--agent", "codex")
	if len(got.Bundles) != 1 || !strings.HasSuffix(got.Bundles[0].Path, filepath.Join(".agents", "skills", "shared")) {
		t.Fatalf("--agent codex: %+v; want only the shared ~/.agents skill", got.Bundles)
	}
}

func TestScanInstalledUsageErrors(t *testing.T) {
	fakeHome(t)
	if _, code := execScan(t, "--installed", "--agent", "clade"); code != 3 {
		t.Errorf("unknown agent: exit %d; want 3", code)
	}
	if _, code := execScan(t, "--installed", "--scope", "global"); code != 3 {
		t.Errorf("unknown scope: exit %d; want 3", code)
	}
	if _, code := execScan(t, fixtures, "--agent", "codex"); code != 3 {
		t.Errorf("--agent without --installed: exit %d; want 3", code)
	}
	if _, code := execScan(t, "--installed", "--agent", "gemini", "--scope", "project", "--project-dir", t.TempDir()); code != 3 {
		t.Errorf("no existing location: exit %d; want 3", code)
	}
}

func TestLocationsJSON(t *testing.T) {
	home := fakeHome(t)
	cmd := locationsCmd()
	out := filepath.Join(t.TempDir(), "loc.json")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = f
	cmd.SetArgs([]string{"--json", "--scope", "user"})
	err = cmd.Execute()
	os.Stdout = stdout
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	var rows []struct {
		Path   string   `json:"path"`
		Exists bool     `json:"exists"`
		Skills int      `json:"skills"`
		Agents []string `json:"agents"`
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	byPath := map[string]int{}
	for i, r := range rows {
		byPath[r.Path] = i
	}
	claude, gemini := filepath.Join(home, ".claude", "skills"), filepath.Join(home, ".gemini", "skills")
	if i, ok := byPath[claude]; !ok || !rows[i].Exists || rows[i].Skills != 2 {
		t.Errorf("%s: %+v; want exists with 2 skills", claude, rows)
	}
	if i, ok := byPath[gemini]; !ok || rows[i].Exists {
		t.Errorf("%s must be listed with exists:false", gemini)
	}
}
