// Command skill-guard is the CLI over the skill-guard library (design §10).
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is the binary version (set via -ldflags at release).
var Version = "0.1.0-dev"

func main() {
	root := &cobra.Command{
		Use:           "skill-guard",
		Short:         "Security, signing & provenance toolchain for Agent Skills (SKILL.md)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(scanCmd(), signCmd(), verifyCmd(), keygenCmd(), versionCmd())

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
