// Package locations knows where well-known agents load Agent Skills from.
//
// The knowledge is data — locations.yaml, embedded — so adding an agent or
// fixing a path is a YAML edit, like a rule pack. Each agent cites its
// section of docs/skill-locations.md, the primary-source record the YAML is
// built from. Resolving reads only the environment and os.UserHomeDir, and
// stats directories: it executes nothing and touches no network.
package locations

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// APIVersion is the registry schema this package reads.
const APIVersion = "surfaceguard.svgreg.net/locations.v1"

// maxWalkUp bounds a walk_up search: a project directory 32 levels deep is
// already absurd, and the bound keeps a hostile cwd from costing anything.
const maxWalkUp = 32

// Scopes, in the order `locations` lists them.
var Scopes = []string{"user", "project", "plugin", "admin"}

//go:embed locations.yaml
var registryYAML []byte

// Registry is the parsed locations.yaml.
type Registry struct {
	APIVersion  string  `yaml:"apiVersion"`
	Version     string  `yaml:"version"`
	Description string  `yaml:"description"`
	Agents      []Agent `yaml:"agents"`
}

// Agent is one agent and the directories it loads skills from.
type Agent struct {
	ID        string  `yaml:"id"`
	Name      string  `yaml:"name"`
	Source    string  `yaml:"source"` // docs/skill-locations.md heading anchor
	Locations []Entry `yaml:"locations"`
}

// Entry is one path template.
type Entry struct {
	Scope  string   `yaml:"scope"`
	Path   string   `yaml:"path"`
	WalkUp bool     `yaml:"walk_up"`
	OS     []string `yaml:"os"`     // GOOS values; empty means every OS
	Status string   `yaml:"status"` // documented (default) | legacy
}

// Location is one resolved directory. Several agents may read the same one;
// it is reported once with all of them.
type Location struct {
	Path    string   `json:"path"`
	Scope   string   `json:"scope"`
	Agents  []string `json:"agents"`
	Status  string   `json:"status"` // documented if any agent documents it
	Sources []string `json:"sources"`
	Exists  bool     `json:"exists"`
}

// Filter selects agents and scopes; empty slices mean all.
type Filter struct {
	Agents []string
	Scopes []string
}

// Env is what resolution reads from the machine, injectable for tests.
type Env struct {
	Getenv func(string) string
	Home   string
	GOOS   string
}

// HostEnv is the running process's environment.
func HostEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, fmt.Errorf("locations: %w", err)
	}
	return Env{Getenv: os.Getenv, Home: home, GOOS: runtime.GOOS}, nil
}

var (
	builtinOnce sync.Once
	builtin     *Registry
	builtinErr  error
)

// Builtin returns the embedded registry. It is parsed once per process and
// must be treated as read-only.
func Builtin() (*Registry, error) {
	builtinOnce.Do(func() { builtin, builtinErr = Parse(registryYAML) })
	return builtin, builtinErr
}

// Parse decodes and validates a registry. Unknown fields are rejected: a
// mistyped `walk-up:` must fail loudly, not silently scan less.
func Parse(data []byte) (*Registry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var r Registry
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("locations: %w", err)
	}
	if r.APIVersion != APIVersion {
		return nil, fmt.Errorf("locations: apiVersion %q, want %q", r.APIVersion, APIVersion)
	}
	seen := map[string]bool{}
	for _, a := range r.Agents {
		if a.ID == "" || seen[a.ID] {
			return nil, fmt.Errorf("locations: agent id %q empty or duplicated", a.ID)
		}
		seen[a.ID] = true
		if a.Source == "" {
			return nil, fmt.Errorf("locations: agent %s cites no source", a.ID)
		}
		for _, e := range a.Locations {
			if !validScope(e.Scope) {
				return nil, fmt.Errorf("locations: agent %s: scope %q not one of %v", a.ID, e.Scope, Scopes)
			}
			if e.Status != "" && e.Status != "documented" && e.Status != "legacy" {
				return nil, fmt.Errorf("locations: agent %s: status %q", a.ID, e.Status)
			}
			if e.WalkUp && e.Scope != "project" {
				return nil, fmt.Errorf("locations: agent %s: walk_up on a %s path", a.ID, e.Scope)
			}
		}
	}
	return &r, nil
}

func validScope(s string) bool {
	for _, v := range Scopes {
		if s == v {
			return true
		}
	}
	return false
}

// AgentIDs lists the registry's agent ids in file order.
func (r *Registry) AgentIDs() []string {
	ids := make([]string, len(r.Agents))
	for i, a := range r.Agents {
		ids[i] = a.ID
	}
	return ids
}

// Resolve expands every selected entry against env and projectDir, drops
// entries for other operating systems, de-duplicates by cleaned path, and
// stats each result. An unknown agent id or scope is an error naming the
// valid ones, so a typo never silently scans nothing.
func (r *Registry) Resolve(env Env, f Filter, projectDir string) ([]Location, error) {
	agents, err := r.selectAgents(f.Agents)
	if err != nil {
		return nil, err
	}
	scopes := map[string]bool{}
	for _, s := range f.Scopes {
		if !validScope(s) {
			return nil, fmt.Errorf("unknown scope %q; valid: %s", s, strings.Join(Scopes, ", "))
		}
		scopes[s] = true
	}
	if projectDir != "" {
		if abs, err := filepath.Abs(projectDir); err == nil {
			projectDir = abs
		}
	}

	byPath := map[string]*Location{}
	var order []string
	add := func(p string, a Agent, e Entry) {
		p = filepath.Clean(p)
		loc, ok := byPath[p]
		if !ok {
			loc = &Location{Path: p, Scope: e.Scope, Status: "legacy"}
			byPath[p] = loc
			order = append(order, p)
		}
		loc.Agents = appendUnique(loc.Agents, a.ID)
		loc.Sources = appendUnique(loc.Sources, a.Source)
		if e.Status != "legacy" {
			loc.Status = "documented"
		}
	}
	for _, a := range agents {
		for _, e := range a.Locations {
			if len(scopes) > 0 && !scopes[e.Scope] {
				continue
			}
			if len(e.OS) > 0 && !contains(e.OS, env.GOOS) {
				continue
			}
			p, ok := expand(e.Path, env)
			if !ok {
				continue
			}
			if e.Scope != "project" {
				add(p, a, e)
				continue
			}
			if projectDir == "" {
				continue
			}
			for _, dir := range projectDirs(projectDir, e.WalkUp) {
				add(filepath.Join(dir, p), a, e)
			}
		}
	}
	out := make([]Location, 0, len(order))
	for _, p := range order {
		loc := *byPath[p]
		if fi, err := os.Stat(loc.Path); err == nil && fi.IsDir() {
			loc.Exists = true
		}
		out = append(out, loc)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return scopeRank(out[i].Scope) < scopeRank(out[j].Scope)
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

func (r *Registry) selectAgents(ids []string) ([]Agent, error) {
	if len(ids) == 0 {
		return r.Agents, nil
	}
	var out []Agent
	for _, id := range ids {
		found := false
		for _, a := range r.Agents {
			if a.ID == id {
				out = append(out, a)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown agent %q; valid: %s", id, strings.Join(r.AgentIDs(), ", "))
		}
	}
	return out, nil
}

// projectDirs is projectDir alone, or — with walkUp — projectDir and each
// ancestor up to and including the first one holding .git (the repository
// root), bounded by maxWalkUp and by the filesystem root. Outside a
// repository the walk stops at projectDir: without a root to stop at, walking
// to / would scan every ancestor's dot-directories, which no agent does.
func projectDirs(projectDir string, walkUp bool) []string {
	if !walkUp {
		return []string{projectDir}
	}
	var dirs []string
	for dir, i := projectDir, 0; i < maxWalkUp; i++ {
		dirs = append(dirs, dir)
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dirs
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return []string{projectDir}
}

// expand resolves `${VAR}` / `${VAR:-default}` and a leading `~`. It reports
// false when a variable without a default is unset.
func expand(tmpl string, env Env) (string, bool) {
	var b strings.Builder
	for {
		i := strings.Index(tmpl, "${")
		if i < 0 {
			b.WriteString(tmpl)
			break
		}
		j := strings.IndexByte(tmpl[i:], '}')
		if j < 0 {
			return "", false
		}
		b.WriteString(tmpl[:i])
		name, def, hasDef := strings.Cut(tmpl[i+2:i+j], ":-")
		v := ""
		if env.Getenv != nil {
			v = env.Getenv(name)
		}
		switch {
		case v != "":
			b.WriteString(v)
		case hasDef:
			b.WriteString(def)
		default:
			return "", false
		}
		tmpl = tmpl[i+j+1:]
	}
	p := b.String()
	if p == "~" || strings.HasPrefix(p, "~/") {
		if env.Home == "" {
			return "", false
		}
		p = env.Home + p[1:]
	}
	return filepath.FromSlash(p), true
}

func scopeRank(s string) int {
	for i, v := range Scopes {
		if v == s {
			return i
		}
	}
	return len(Scopes)
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func appendUnique(ss []string, s string) []string {
	if contains(ss, s) {
		return ss
	}
	return append(ss, s)
}
