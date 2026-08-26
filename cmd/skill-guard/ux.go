package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/skill"
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
	case strings.Contains(err.Error(), "exceeds total size cap"):
		return nil, fail(3, "%v\n"+
			"  skill-guard bounds how much it will load from one bundle so a hostile\n"+
			"  or accidentally huge skill cannot exhaust memory during a batch scan.\n"+
			"  drop large binaries/vendored trees from the bundle, or scan a subdirectory.", err)
	case strings.Contains(err.Error(), "exceeds size cap"):
		return nil, fail(3, "%v\n"+
			"  individual files are capped so a single huge blob cannot exhaust memory.\n"+
			"  a skill bundle should not ship files that large — remove it or scan a subdirectory.", err)
	case strings.Contains(err.Error(), "symlink"):
		return nil, fail(3, "%q involves a symlink, which skill-guard refuses to follow for safety.\n"+
			"  replace the symlink with a regular file or directory.", path)
	default:
		return nil, fail(3, "cannot read skill at %q: %v", path, err)
	}
}

// validFormats are the accepted --format values for scan.
var validFormats = []string{"text", "json", "skill-card", "sarif"}

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

// validateKeyType rejects an unknown --type up-front, listing what is
// available, rather than letting keygen fail deeper with a less useful message.
func validateKeyType(t string) error {
	for _, v := range attest.SupportedAlgorithms {
		if t == v {
			return nil
		}
	}
	return fail(3, "unknown --type %q\n  valid key types: %s", t, strings.Join(attest.SupportedAlgorithms, ", "))
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

// refuseOverwrite stops a keygen that would destroy existing key material.
//
// `skill-guard keygen --out publisher.key` run a second time used to overwrite
// the first key silently and exit 0 — new keyid, new public key, old private
// key gone. That is unrecoverable in a way it would not be for most tools,
// because skill-guard's trust model is deliberately **local and decentralized**:
// there is no key server and no identity authority, so a signing key's only
// value is that consumers have pasted its public key into `trust.keys` in
// *their* `.skillguard.yaml`. Destroying it silently invalidates every roster
// entry anyone made, and no already-signed bundle can be re-signed under that
// identity again.
//
// Refusing rather than prompting: the CLI is meant to run unattended in CI, and
// a prompt there is either ignored or hangs. `--force` is the deliberate opt-in,
// and it says what it destroys.
//
// Lstat, not Stat, so a dangling symlink still counts as "something is here" —
// consistent with attest.writeSecret, which refuses to follow symlinks rather
// than write through them.
func refuseOverwrite(path, what string) error {
	if _, err := os.Lstat(path); err != nil {
		return nil // absent (or unreadable) — let the writer report any real error
	}
	return fail(3, "refusing to overwrite the existing %s %q\n"+
		"  generating over it would destroy the old key permanently, and skill-guard has no\n"+
		"  key server to recover from — consumers trust a key only by having added it to\n"+
		"  trust.keys in their own .skillguard.yaml.\n"+
		"  choose another path:  skill-guard keygen --out <new-name>.key\n"+
		"  or, if you are certain the old key is retired:  --force", what, path)
}
