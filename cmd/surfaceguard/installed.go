package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/SVGreg/surfaceguard/pkg/locations"
	"github.com/SVGreg/surfaceguard/pkg/report"
	"github.com/SVGreg/surfaceguard/pkg/scan"
	"github.com/SVGreg/surfaceguard/pkg/skill"
	"github.com/spf13/cobra"
)

// installedOpts are the flags shared by `scan --installed` and `locations`.
type installedOpts struct {
	agents     []string
	scope      string
	projectDir string
}

func (o *installedOpts) register(f interface {
	StringSliceVar(*[]string, string, []string, string)
	StringVar(*string, string, string, string)
}) {
	f.StringSliceVar(&o.agents, "agent", nil, "limit to these agents (comma-separated; see 'surfaceguard locations')")
	f.StringVar(&o.scope, "scope", "all", "limit to one scope: user | project | plugin | admin | all")
	f.StringVar(&o.projectDir, "project-dir", "", "project directory for project-scope locations (default: current directory)")
}

// resolve turns the flags into registry locations. Unknown agents and scopes
// are usage errors that list the valid values.
func (o *installedOpts) resolve() ([]locations.Location, error) {
	reg, err := locations.Builtin()
	if err != nil {
		return nil, fail(4, "%v", err)
	}
	env, err := locations.HostEnv()
	if err != nil {
		return nil, fail(4, "%v", err)
	}
	f := locations.Filter{Agents: o.agents}
	if o.scope != "" && o.scope != "all" {
		f.Scopes = []string{o.scope}
	}
	dir := o.projectDir
	if dir == "" {
		if dir, err = os.Getwd(); err != nil {
			return nil, fail(4, "%v", err)
		}
	}
	locs, err := reg.Resolve(env, f, dir)
	if err != nil {
		return nil, fail(3, "%v", err)
	}
	return locs, nil
}

// existingRoots is the discovery roots for an installed scan: every resolved
// location that exists on this machine.
func existingRoots(locs []locations.Location) []string {
	var roots []string
	for _, l := range locs {
		if l.Exists {
			roots = append(roots, l.Path)
		}
	}
	return roots
}

// attributeAgents records, on each result, every agent whose location reaches
// the bundle — through its own path or any other path to the same real
// bundle. A skill in ~/.agents/skills symlinked into ~/.claude/skills is
// scanned once and attributed to both.
func attributeAgents(m *scan.MultiReport, locs []locations.Location) {
	for i := range m.Bundles {
		r := &m.Bundles[i]
		paths := append([]string{r.Path}, r.Also...)
		var agents []string
		for _, l := range locs {
			if !l.Exists {
				continue
			}
			for _, p := range paths {
				if p == l.Path || strings.HasPrefix(p, l.Path+string(filepath.Separator)) {
					for _, a := range l.Agents {
						agents = appendUniq(agents, a)
					}
					break
				}
			}
		}
		sort.Strings(agents)
		r.Agents = agents
	}
}

func appendUniq(ss []string, s string) []string {
	for _, v := range ss {
		if v == s {
			return ss
		}
	}
	return append(ss, s)
}

func locationsCmd() *cobra.Command {
	var o installedOpts
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "locations",
		Short: "List where well-known agents load skills from on this machine",
		Long: `List every skill directory the built-in registry knows for well-known
agents (Claude Code, Codex, Gemini CLI, GitHub Copilot, Cursor, OpenCode,
Goose), resolved for this machine: which exist, and how many skills each holds.
It never scans — it is the dry run for 'scan --installed'.

A directory several agents read (~/.agents/skills) is listed once with all of
them. "legacy" marks a path the vendor no longer documents but may still read;
it is scanned anyway. Sources: docs/skill-locations.md.`,
		Example: `  surfaceguard locations
  surfaceguard locations --agent claude-code --scope user
  surfaceguard locations --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			locs, err := o.resolve()
			if err != nil {
				return err
			}
			type row struct {
				locations.Location
				Skills int `json:"skills"`
			}
			rows := make([]row, len(locs))
			for i, l := range locs {
				rows[i] = row{Location: l}
				if l.Exists {
					if cs, _, err := skill.Discover([]string{l.Path}, skill.DiscoverOptions{}); err == nil {
						rows[i].Skills = len(cs)
					}
				}
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "SCOPE\tEXISTS\tSKILLS\tAGENTS\tPATH")
			for _, r := range rows {
				exists, n := "no", "-"
				if r.Exists {
					exists, n = "yes", fmt.Sprint(r.Skills)
				}
				agents := strings.Join(r.Agents, ",")
				if r.Status == "legacy" {
					agents += " (legacy)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Scope, exists, n, agents, report.Sanitize(r.Path))
			}
			return tw.Flush()
		},
	}
	o.register(cmd.Flags())
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	return cmd
}
