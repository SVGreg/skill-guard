package main

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/skillguard/skill-guard/pkg/model"
	"github.com/skillguard/skill-guard/pkg/skill"
	"github.com/spf13/cobra"
)

// bundlePathArg validates the single <path> positional and, when it is missing
// or duplicated, returns a message that explains what a skill path is and shows
// an example — instead of cobra's terse "accepts 1 arg(s), received 0".
func bundlePathArg(cmd *cobra.Command, args []string) error {
	switch {
	case len(args) == 0:
		return fmt.Errorf(
			"missing <path>\n\n"+
				"  %s needs the path to a skill:\n"+
				"    • a bundle directory that contains a SKILL.md, or\n"+
				"    • a single SKILL.md file\n\n"+
				"  example:\n"+
				"    skill-guard %s ./my-skill\n"+
				"    skill-guard %s ./my-skill/SKILL.md\n\n"+
				"  run 'skill-guard %s --help' for all options.",
			cmd.CommandPath(), cmd.Name(), cmd.Name(), cmd.Name())
	case len(args) > 1:
		return fmt.Errorf(
			"too many arguments: expected one <path>, got %d (%s)\n"+
				"  scan/sign/verify operate on a single skill at a time.",
			len(args), strings.Join(args, " "))
	}
	return nil
}

// loadBundleFriendly wraps skill.LoadBundle and rewrites its errors into
// actionable, user-facing messages (all usage-class, exit 3).
func loadBundleFriendly(path string) (*skill.Bundle, error) {
	b, err := skill.LoadBundle(path)
	if err == nil {
		return b, nil
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fail(3, "no skill found at %q\n"+
			"  expected a bundle directory containing SKILL.md, or a SKILL.md file.\n"+
			"  check the path, or scaffold one: mkdir my-skill && $EDITOR my-skill/SKILL.md", path)
	case strings.Contains(err.Error(), "no SKILL.md found"):
		return nil, fail(3, "%q has no SKILL.md at its root\n"+
			"  a skill bundle must contain a SKILL.md file (the manifest with name/description front-matter).", path)
	case strings.Contains(err.Error(), "symlink"):
		return nil, fail(3, "%q involves a symlink, which skill-guard refuses to follow for safety.\n"+
			"  replace the symlink with a regular file or directory.", path)
	default:
		return nil, fail(3, "cannot read skill at %q: %v", path, err)
	}
}

// validFormats are the accepted --format values for scan.
var validFormats = []string{"text", "json", "skill-card"}

// validateFormat rejects an unknown --format value up-front instead of silently
// falling back to text.
func validateFormat(f string) error {
	for _, v := range validFormats {
		if f == v {
			return nil
		}
	}
	return fail(3, "unknown --format %q\n  valid formats: %s", f, strings.Join(validFormats, ", "))
}

// validateSeverity rejects an unknown severity threshold (e.g. --fail-on).
func validateSeverity(flag, value string) error {
	if value == "" {
		return nil
	}
	if _, err := model.ParseSeverity(value); err != nil {
		return fail(3, "unknown %s %q\n  valid severities: critical, high, medium, low, info", flag, value)
	}
	return nil
}
