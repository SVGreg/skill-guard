package locations

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func fakeEnv(home string, vars map[string]string) Env {
	return Env{Getenv: func(k string) string { return vars[k] }, Home: home, GOOS: "linux"}
}

func mustBuiltin(t *testing.T) *Registry {
	t.Helper()
	r, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func find(locs []Location, path string) *Location {
	for i := range locs {
		if locs[i].Path == path {
			return &locs[i]
		}
	}
	return nil
}

func TestExpand(t *testing.T) {
	env := fakeEnv("/h", map[string]string{"SET": "/custom"})
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"~/.claude/skills", "/h/.claude/skills", true},
		{"${SET:-~/.claude}/skills", "/custom/skills", true},
		{"${UNSET:-~/.claude}/skills", "/h/.claude/skills", true},
		{"${UNSET}/skills", "", false},
		{"/etc/codex/skills", "/etc/codex/skills", true},
		{".claude/skills", ".claude/skills", true},
	}
	for _, c := range cases {
		got, ok := expand(c.in, env)
		if got != filepath.FromSlash(c.want) || ok != c.ok {
			t.Errorf("expand(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestResolveClaudeOverrides: CLAUDE_CONFIG_DIR moves the user skills dir and
// CLAUDE_CODE_PLUGIN_CACHE_DIR moves the plugin roots, as the vendor docs say.
func TestResolveClaudeOverrides(t *testing.T) {
	r := mustBuiltin(t)
	env := fakeEnv("/h", map[string]string{"CLAUDE_CONFIG_DIR": "/cfg", "CLAUDE_CODE_PLUGIN_CACHE_DIR": "/pc"})
	locs, err := r.Resolve(env, Filter{Agents: []string{"claude-code"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/cfg/skills", "/pc/cache", "/pc/marketplaces", "/etc/claude-code/.claude/skills"} {
		if find(locs, filepath.FromSlash(want)) == nil {
			t.Errorf("missing %s in %v", want, locs)
		}
	}
	if find(locs, "/Library/Application Support/ClaudeCode/.claude/skills") != nil {
		t.Error("a darwin-only path resolved on linux")
	}
}

// TestResolveSharedPathOnce: ~/.agents/skills is read by several agents; it
// resolves once and names every one of them, and --agent codex includes it.
func TestResolveSharedPathOnce(t *testing.T) {
	r := mustBuiltin(t)
	env := fakeEnv("/h", nil)
	shared := filepath.FromSlash("/h/.agents/skills")

	all, err := r.Resolve(env, Filter{Scopes: []string{"user"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, l := range all {
		if l.Path == shared {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%s listed %d times", shared, n)
	}
	loc := find(all, shared)
	for _, a := range []string{"codex", "gemini", "copilot", "cursor", "opencode", "goose"} {
		if !contains(loc.Agents, a) {
			t.Errorf("%s: agents %v missing %s", shared, loc.Agents, a)
		}
	}

	codex, err := r.Resolve(env, Filter{Agents: []string{"codex"}, Scopes: []string{"user"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if l := find(codex, shared); l == nil || !reflect.DeepEqual(l.Agents, []string{"codex"}) {
		t.Errorf("--agent codex: %v", codex)
	}
}

// TestResolveWalkUpStopsAtRepoRoot: walk_up entries cover the project dir and
// its ancestors up to the directory holding .git, and no further.
func TestResolveWalkUpStopsAtRepoRoot(t *testing.T) {
	outside := t.TempDir()
	repo := filepath.Join(outside, "repo")
	sub := filepath.Join(repo, "pkg", "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".claude", "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := mustBuiltin(t)
	locs, err := r.Resolve(fakeEnv("/h", nil), Filter{Agents: []string{"claude-code"}, Scopes: []string{"project"}}, sub)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range locs {
		got = append(got, l.Path)
	}
	want := []string{
		filepath.Join(repo, ".claude", "skills"),
		filepath.Join(repo, "pkg", ".claude", "skills"),
		filepath.Join(sub, ".claude", "skills"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("walk-up = %v\nwant      %v", got, want)
	}
	if !find(locs, want[0]).Exists || find(locs, want[1]).Exists {
		t.Error("Exists must reflect the filesystem")
	}

	// Outside a repository there is no root to stop at: project dir only.
	locs, _ = r.Resolve(fakeEnv("/h", nil), Filter{Agents: []string{"claude-code"}, Scopes: []string{"project"}}, outside)
	if len(locs) != 1 {
		t.Errorf("outside a repo: %v; want only the project dir", locs)
	}
}

func TestResolveRejectsUnknownAgentAndScope(t *testing.T) {
	r := mustBuiltin(t)
	if _, err := r.Resolve(fakeEnv("/h", nil), Filter{Agents: []string{"clade"}}, ""); err == nil || !strings.Contains(err.Error(), "claude-code") {
		t.Errorf("unknown agent: err = %v; want one listing valid ids", err)
	}
	if _, err := r.Resolve(fakeEnv("/h", nil), Filter{Scopes: []string{"global"}}, ""); err == nil {
		t.Error("unknown scope accepted")
	}
}

func TestParseIsStrict(t *testing.T) {
	good := "apiVersion: " + APIVersion + "\nversion: 1.0.0\nagents:\n  - id: a\n    name: A\n    source: a\n    locations:\n      - {scope: user, path: ~/.a}\n"
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatalf("good registry rejected: %v", err)
	}
	bad := map[string]string{
		"unknown field": strings.Replace(good, "path: ~/.a", "path: ~/.a, walk-up: true", 1),
		"apiVersion":    strings.Replace(good, APIVersion, "surfaceguard.svgreg.net/locations.v0", 1),
		"scope":         strings.Replace(good, "scope: user", "scope: global", 1),
		"walk_up user":  strings.Replace(good, "path: ~/.a", "path: ~/.a, walk_up: true", 1),
		"no source":     strings.Replace(good, "    source: a\n", "", 1),
	}
	for name, doc := range bad {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestSourcesCiteTheDoc: every agent's source is a heading anchor in
// docs/skill-locations.md, the primary-source record the registry is built
// from — a registry entry with no documented origin is a guess.
func TestSourcesCiteTheDoc(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "skill-locations.md"))
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string]bool{}
	strip := regexp.MustCompile("[^a-z0-9 -]")
	for _, line := range strings.Split(string(doc), "\n") {
		if h, ok := strings.CutPrefix(line, "## "); ok {
			a := strip.ReplaceAllString(strings.ToLower(h), "")
			anchors[strings.ReplaceAll(a, " ", "-")] = true
		}
	}
	for _, a := range mustBuiltin(t).Agents {
		if !anchors[a.Source] {
			t.Errorf("agent %s cites #%s, which is not a heading in docs/skill-locations.md", a.ID, a.Source)
		}
	}
}
