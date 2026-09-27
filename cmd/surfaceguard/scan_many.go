package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/SVGreg/surfaceguard/pkg/model"
	"github.com/SVGreg/surfaceguard/pkg/policy"
	"github.com/SVGreg/surfaceguard/pkg/report"
	"github.com/SVGreg/surfaceguard/pkg/scan"
	"github.com/SVGreg/surfaceguard/pkg/skill"
	"github.com/spf13/cobra"
)

// scanPathsArg is scan's argument check: one or more paths. sign and verify
// keep bundlePathArg, which insists on exactly one.
func scanPathsArg(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return bundlePathArg(cmd, args)
	}
	return nil
}

// isSingleBundle reports whether path, named alone, keeps scan's original
// single-bundle behavior: a file, a directory with SKILL.md at its root, or
// anything that does not resolve to a plain directory — a missing path or a
// symlink — so those reach loadBundleFriendly and fail exactly as they
// always have. Only a real directory without a root SKILL.md is a discovery
// root.
func isSingleBundle(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() {
		return true
	}
	_, err = os.Lstat(filepath.Join(path, "SKILL.md"))
	return err == nil
}

// multiScanOpts carries the flags a multi-bundle scan needs from scanCmd.
type multiScanOpts struct {
	format, out, policyPath, failOn string
	rulepacks                       []string
	verbose, quiet, noColor         bool
	maxDepth, maxBundles            int
}

// runMultiScan discovers bundles under paths, scans them all, and renders one
// aggregate report. Exit codes keep their single-bundle meaning over the set:
// 1 when any bundle fails *or could not be loaded* (fail-closed), 3 when
// nothing was found or a root is unusable.
func runMultiScan(paths []string, o multiScanOpts) error {
	if o.format == "skill-card" {
		return fail(3, "--format skill-card describes one bundle, but this scan covers several\n"+
			"  scan a single skill for a card, or use --format json | sarif | text for the set.")
	}
	cands, derrs, err := skill.Discover(paths, skill.DiscoverOptions{MaxDepth: o.maxDepth, MaxBundles: o.maxBundles})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fail(3, "%v\n  every <path> must exist: a skill directory, a SKILL.md file, or a folder to search.", err)
		}
		return fail(3, "%v", err)
	}
	if len(cands) == 0 {
		return fail(3, "no skills found under %s\n"+
			"  searched for directories containing a SKILL.md (up to %d levels deep, skipping .git and vendored trees).\n"+
			"  check the path, or raise --max-depth.", strings.Join(quoteAll(paths), ", "), depthOr(o.maxDepth))
	}
	pol, err := policy.Load(o.policyPath)
	if err != nil {
		return fail(3, "cannot use policy %q: %v\n  expected a valid .surfaceguard.yaml file (see 'surfaceguard scan --help').", o.policyPath, err)
	}
	if o.failOn != "" {
		pol.FailOn = o.failOn
	}
	rs, cs, err := loadRuleset(o.rulepacks)
	if err != nil {
		return fail(3, "rules: %v", err)
	}
	if isTerminal(os.Stderr) {
		// Progress goes to stderr and only to a terminal, so redirected
		// output and CI logs stay exactly the report.
		fmt.Fprintf(os.Stderr, "scanning %d skills…\n", len(cands))
	}
	m := scan.New(rs, pol).WithContexts(cs).ScanAll(cands, nil, 0)
	for _, d := range derrs {
		m.Notes = append(m.Notes, d.Error())
	}

	w, err := outputWriter(o.out)
	if err != nil {
		return err
	}
	defer closeWriter(w)
	// SARIF URIs are relative to the discovery root; with several paths
	// named, the common base is the working directory they are relative to.
	source := "."
	if len(paths) == 1 {
		source = paths[0]
	}
	opt := report.Options{
		NoColor: o.noColor || o.out != "" || report.ColorDisabled(w),
		Verbose: o.verbose, Source: source, Version: Version,
		Width: terminalWidth(w),
	}
	if err := emitMulti(w, m, o.format, opt); err != nil {
		return fail(4, "%v", err)
	}
	if !o.quiet && o.out != "" {
		stdoutOpt := opt
		stdoutOpt.NoColor = o.noColor || report.ColorDisabled(os.Stdout)
		stdoutOpt.Width = terminalWidth(os.Stdout)
		report.MultiText(os.Stdout, m, stdoutOpt)
	}
	if m.Verdict == model.Fail {
		return exitErr{code: 1, msg: "verdict: fail"}
	}
	return nil
}

func emitMulti(w *os.File, m *scan.MultiReport, format string, opt report.Options) error {
	switch format {
	case "json":
		return report.MultiJSON(w, m, opt)
	case "sarif":
		return report.MultiSARIF(w, m, opt)
	default:
		report.MultiText(w, m, opt)
		return nil
	}
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}

func depthOr(d int) int {
	if d <= 0 {
		return skill.DefaultMaxDepth
	}
	return d
}

// isTerminal reports whether f is a character device. It is only used to
// decide whether a progress line is worth printing, so /dev/null counting as
// one (see report.ColorDisabled) costs nothing.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
