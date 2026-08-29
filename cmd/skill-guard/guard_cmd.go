package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SVGreg/skill-guard/pkg/guard"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/report"
	"github.com/spf13/cobra"
)

func guardCmd() *cobra.Command {
	var policyPath, format, cacheDir string
	var noScan, noColor bool

	cmd := &cobra.Command{
		Use:   "guard <path>",
		Short: "Decide whether a skill may be loaded: allow, warn, or deny",
		Long: `Answer one question about a skill — may it enter the model's context? —
by verifying whichever signatures it carries, scanning it, and applying policy,
then reporting a single decision.

This is 'scan' and 'verify' collapsed into the answer a caller actually needs.
An agent loop, a PreToolUse hook, or an install wrapper can act on the outcome
without re-deriving one from a report.

DECISION:
  allow   nothing policy gates on
  warn    proceed, but a human should look — a warn verdict, or a missing
          attestation under a policy that only warns about it
  deny    do not load — the scan verdict failed, or verification did

PROVENANCE OUTRANKS THE VERDICT: a signature that does not match its content,
does not verify, or comes from a revoked key denies whatever the scan found.

CACHING (--cache-dir): decisions are keyed by the bundle's content hash, the
policy, and whether scanning was skipped, so one changed byte or one changed
setting is a miss. Off unless asked for.

EXIT CODES: 0 allow or warn · 1 deny · 3 usage error · 4 internal error.`,
		Example: `  skill-guard guard ./my-skill
  skill-guard guard ./my-skill --format json
  skill-guard guard ./my-skill --policy .skillguard.yaml --cache-dir ~/.cache/skill-guard`,
		Args: bundlePathArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" {
				return fail(3, "unknown --format %q\n  valid formats: text, json", format)
			}
			pol, err := policy.Load(policyPath)
			if err != nil {
				return fail(3, "cannot use policy %q: %v\n  expected a valid .skillguard.yaml file.", policyPath, err)
			}

			opt := guard.Options{Policy: pol, SkipScan: noScan}
			if policyPath != "" {
				opt.PolicyDir = filepath.Dir(policyPath)
			}
			if cacheDir != "" {
				// An explicit "-" means "the user cache dir", so a caller can
				// opt into caching without naming a path.
				dir := cacheDir
				if dir == "-" {
					dir = ""
				}
				c, err := guard.NewFileCache(dir)
				if err != nil {
					return fail(3, "%v", err)
				}
				opt.Cache = c
			}

			d, err := guard.Guard(args[0], opt)
			if err != nil {
				return fail(3, "%v", err)
			}

			if format == "json" {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(d); err != nil {
					return fail(4, "%v", err)
				}
			} else {
				printDecision(d, noColor || report.ColorDisabled(os.Stdout))
			}

			// Deny is exit 1, the same code a failing scan already uses — a
			// gate and a scan disagreeing about what "1" means would be worse
			// than either choice. warn shares 0 with allow so a warning does
			// not break a pipeline that has not opted into strictness.
			if d.Outcome == guard.Deny {
				return exitErr{code: 1, msg: "denied: " + d.Reason}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&policyPath, "policy", "", "policy file (.skillguard.yaml) with thresholds and the trust roster")
	f.StringVar(&format, "format", "text", "output format: text | json")
	f.StringVar(&cacheDir, "cache-dir", "", "cache decisions in this directory (\"-\" for the user cache dir)")
	f.BoolVar(&noScan, "no-scan", false, "decide on provenance alone, without scanning")
	f.BoolVar(&noColor, "no-color", false, "disable ANSI color in output")
	return cmd
}

// printDecision renders a decision for a human. The outcome and the reason come
// first because they are what a reader acts on; everything else is evidence.
func printDecision(d *guard.Decision, noColor bool) {
	c := func(s string) string {
		if noColor {
			return ""
		}
		return s
	}
	const (
		red    = "\033[31m"
		yellow = "\033[33m"
		green  = "\033[32m"
		gray   = "\033[90m"
		reset  = "\033[0m"
	)
	col := green
	switch d.Outcome {
	case guard.Deny:
		col = red
	case guard.Warn:
		col = yellow
	}

	// The reason is tool-generated text (verdict names, numbers), so it is
	// printed plainly. Everything below that originates in a scanned bundle
	// goes through report.Sanitize, which escapes terminal control characters
	// without wrapping readable text in quotes.
	fmt.Printf("%s%s%s  %s\n", c(col), d.Outcome, c(reset), d.Reason)

	if d.Scanned {
		fmt.Printf("  scan: %s  risk %d/100 (%s)  %s\n",
			d.Verdict, d.RiskScore, d.RiskTier, countsSummary(d))
	} else {
		fmt.Printf("  scan: %sskipped%s\n", c(gray), c(reset))
	}

	switch {
	case !d.Signature.Present:
		fmt.Printf("  signature: %snone%s\n", c(gray), c(reset))
	case d.Signature.Trusted:
		fmt.Printf("  signature: %s, valid, %strusted%s%s\n",
			d.Signature.Format, c(green), c(reset), publisherSuffix(d))
	case d.Signature.Valid:
		fmt.Printf("  signature: %s, valid, %snot trusted%s%s\n",
			d.Signature.Format, c(yellow), c(reset), publisherSuffix(d))
	default:
		fmt.Printf("  signature: %s, %sdoes not verify%s\n", d.Signature.Format, c(red), c(reset))
	}

	// A decision is not a report. The malicious fixture produces 65 gating
	// findings; printing all of them buries the decision the reader came for,
	// and `scan` already exists for the full picture.
	const maxShown = 5
	for i, f := range d.Findings {
		if i == maxShown {
			fmt.Printf("  %s… and %d more — run `skill-guard scan` for the full report%s\n",
				c(gray), len(d.Findings)-maxShown, c(reset))
			break
		}
		fmt.Printf("  %s  %s  %s\n", f.RuleID, f.Severity, report.Sanitize(f.Title))
	}
	if d.CacheHit {
		fmt.Printf("  %s(from cache)%s\n", c(gray), c(reset))
	}
}

func publisherSuffix(d *guard.Decision) string {
	if d.Signature.Publisher == "" {
		return ""
	}
	return " — " + report.Sanitize(d.Signature.Publisher)
}

func countsSummary(d *guard.Decision) string {
	return fmt.Sprintf("[crit %d, high %d, med %d, low %d, info %d]",
		d.Counts.Critical, d.Counts.High, d.Counts.Medium, d.Counts.Low, d.Counts.Info)
}
