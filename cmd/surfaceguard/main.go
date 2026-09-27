// Command surfaceguard is the CLI over the surfaceguard library (design §10).
package main

import (
	"fmt"
	"os"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

// Version is the binary version. Release builds set it via -ldflags; every
// other build resolves it from the module's build info at startup.
var Version = devVersion

// devVersion is the compiled-in placeholder, and the signal that no -ldflags
// version was supplied.
const devVersion = "0.1.0-dev"

// resolveVersion reports the version to print and to stamp into skill cards and
// SARIF logs.
//
// Only GoReleaser passes -X main.Version, so `go install <mod>/cmd/surfaceguard@v0.4.0`
// produced a binary claiming to be "0.1.0-dev" — a version that has never been
// released. That is not cosmetic: the string reaches a skill card's
// surfaceguard_version and SARIF's tool.driver.version, both of which are
// provenance. Metadata about what scanned a bundle has to name what actually
// ran, so the module's own build info answers when the ldflag is absent.
func resolveVersion(ldflag string) string {
	if ldflag != devVersion {
		return ldflag // a release build already knows
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ldflag
	}
	return versionFrom(ldflag, info)
}

// pseudoVersion matches the timestamp-and-revision tail Go appends when a
// module has no tag at the built commit, e.g.
// v0.3.1-0.20260907131511-7426ae32609e. Its leading component is derived from
// the previous tag, so it names a version that was never released — fine as a
// module identifier, misleading in a field that says which scanner ran.
var pseudoVersion = regexp.MustCompile(`[-.][0-9]{14}-[0-9a-f]{12}`)

// versionFrom is the pure half of resolveVersion, so the mapping can be tested
// without building binaries.
func versionFrom(ldflag string, info *debug.BuildInfo) string {
	// A module installed by version reports its tag ("v0.4.0"); a build from a
	// local tree reports "(devel)", nothing, or a pseudo-version. Trim the "v"
	// so a real tag matches the bare form GoReleaser injects.
	if v := info.Main.Version; v != "" && v != "(devel)" && !pseudoVersion.MatchString(v) {
		return strings.TrimPrefix(v, "v")
	}
	// A local build has no version to report, but it does have a commit, and
	// naming it turns "0.1.0-dev" from a fiction into something a bug report
	// can be tied back to a tree.
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return ldflag
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	return ldflag + "+" + rev
}

func main() {
	Version = resolveVersion(Version)
	root := &cobra.Command{
		Use:   "surfaceguard <command> <path>",
		Short: "Security, signing & provenance toolchain for Agent Skills (SKILL.md)",
		Long: `surfaceguard scans, signs, and verifies Agent Skills (SKILL.md bundles)
against the OWASP Agentic Skills Top 10.

A skill <path> is either:
  • a bundle directory containing a SKILL.md (plus scripts/config), or
  • a single SKILL.md file.

COMMANDS:
  scan     find injection/exfiltration/exec/secret/metadata risks
  guard    decide whether a skill may be loaded: allow, warn, or deny
  sign     Merkle-hash + DSSE-sign a bundle (writes SKILL.md.skillsig)
  verify   check a signature, Merkle root, and trust
  keygen   create an Ed25519 signing key
  version  print version and built-in rule-pack versions

Run 'surfaceguard <command> --help' for input formats, flags, and examples.

EXIT CODES: 0 ok · 1 scan verdict fail · 2 verification failed · 3 usage · 4 internal.`,
		Example: `  surfaceguard scan ./my-skill
  surfaceguard keygen --out publisher.key
  surfaceguard sign ./my-skill --key publisher.key --identity oidc:you@example.com
  surfaceguard verify ./my-skill --policy .surfaceguard.yaml
  surfaceguard guard ./my-skill --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(scanCmd(), guardCmd(), signCmd(), verifyCmd(), keygenCmd(), locationsCmd(), versionCmd())

	if err := root.Execute(); err != nil {
		// Cobra usage/flag errors → exit 3; command errors set their own code
		// via exitErr.
		if ee, ok := err.(exitErr); ok {
			fmt.Fprintln(os.Stderr, "error:", ee.msg)
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(3)
	}
}

// exitErr carries a specific process exit code (design §10.5).
type exitErr struct {
	code int
	msg  string
}

func (e exitErr) Error() string { return e.msg }

func fail(code int, format string, a ...any) error {
	return exitErr{code: code, msg: fmt.Sprintf(format, a...)}
}

// fileMode returns path's permission bits, or def if they cannot be read. Used
// to report the mode a file actually has instead of the one that was requested.
func fileMode(path string, def os.FileMode) os.FileMode {
	fi, err := os.Stat(path)
	if err != nil {
		return def
	}
	return fi.Mode().Perm()
}
