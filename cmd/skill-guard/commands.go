package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/skillguard/skill-guard/pkg/attest"
	"github.com/skillguard/skill-guard/pkg/model"
	"github.com/skillguard/skill-guard/pkg/policy"
	"github.com/skillguard/skill-guard/pkg/report"
	"github.com/skillguard/skill-guard/pkg/rules"
	"github.com/skillguard/skill-guard/pkg/scan"
	"github.com/skillguard/skill-guard/pkg/skill"
	"github.com/spf13/cobra"
)

// loadRuleset loads built-in packs plus any explicit --rulepack files.
func loadRuleset(extra []string) ([]*rules.Rule, error) {
	packs, err := rules.Builtin()
	if err != nil {
		return nil, err
	}
	for _, path := range extra {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		p, err := rules.LoadPack(data)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "note: loaded unsigned rule-pack %s (provenance: unsigned)\n", path)
		packs = append(packs, p)
	}
	return rules.AllRules(packs), nil
}

func scanCmd() *cobra.Command {
	var format, out, policyPath, failOn string
	var rulepacks []string
	var verbose, quiet, noColor bool

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a SKILL.md bundle against the static ruleset",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := skill.LoadBundle(args[0])
			if err != nil {
				return fail(3, "%v", err)
			}
			pol, err := policy.Load(policyPath)
			if err != nil {
				return fail(3, "policy: %v", err)
			}
			if failOn != "" {
				pol.FailOn = failOn
			}
			rs, err := loadRuleset(rulepacks)
			if err != nil {
				return fail(3, "rules: %v", err)
			}
			rep := scan.New(rs, pol).Scan(b)

			w := outputWriter(out)
			defer closeWriter(w)
			opt := report.Options{NoColor: noColor, Verbose: verbose, Source: args[0], Version: Version}
			if err := emit(w, rep, format, opt); err != nil {
				return fail(4, "%v", err)
			}
			if !quiet && out != "" {
				report.Text(os.Stdout, rep, opt)
			}
			if rep.Verdict == model.Fail {
				return exitErr{code: 1, msg: "verdict: fail"}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&format, "format", "text", "output: text|json|skill-card")
	f.StringVar(&out, "out", "", "write output to file")
	f.StringVar(&policyPath, "policy", "", "policy file (.skillguard.yaml)")
	f.StringVar(&failOn, "fail-on", "", "override fail threshold: critical|high|medium|low")
	f.StringArrayVar(&rulepacks, "rulepack", nil, "extra rule-pack YAML (repeatable)")
	f.BoolVarP(&verbose, "verbose", "v", false, "show rationale and fix per finding")
	f.BoolVarP(&quiet, "quiet", "q", false, "suppress secondary text output")
	f.BoolVar(&noColor, "no-color", false, "disable ANSI color")
	return cmd
}

func signCmd() *cobra.Command {
	var keyPath, identity string
	var noScan, emitFields bool
	var ttlDays int

	cmd := &cobra.Command{
		Use:   "sign <path>",
		Short: "Merkle-hash and DSSE-sign a bundle (writes <bundle>.skillsig)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyPath == "" {
				return fail(3, "--key is required (generate one with: skill-guard keygen)")
			}
			signer, err := attest.LoadKey(keyPath)
			if err != nil {
				return fail(3, "key: %v", err)
			}
			b, err := skill.LoadBundle(args[0])
			if err != nil {
				return fail(3, "%v", err)
			}

			var summary *attest.ScanSummary
			if !noScan {
				rs, err := loadRuleset(nil)
				if err != nil {
					return fail(3, "rules: %v", err)
				}
				rep := scan.New(rs, policy.Default()).Scan(b)
				summary = &attest.ScanSummary{
					Verdict: string(rep.Verdict), MaxSeverity: rep.MaxSeverity.String(),
					RiskScore: rep.RiskScore, Version: Version,
				}
			}

			st := attest.BuildStatement(b, summary, signer, identity, time.Duration(ttlDays)*24*time.Hour)
			env, err := attest.SignWith(context.Background(), st, signer)
			if err != nil {
				return fail(4, "%v", err)
			}
			sigPath := attest.SigPath(args[0])
			if err := attest.WriteEnvelope(sigPath, env); err != nil {
				return fail(4, "%v", err)
			}
			scanNote := "scan attached: " + string(scanVerdict(summary))
			if summary == nil {
				scanNote = "integrity-only (--no-scan)"
			}
			fmt.Printf("wrote %s\n  merkle_root %s\n  %s\n", sigPath, st.Subject.MerkleRoot, scanNote)

			if emitFields {
				ch, sig, err := attest.USFFields(context.Background(), b, signer)
				if err != nil {
					return fail(4, "usf: %v", err)
				}
				mdPath := skillMDPath(args[0])
				if err := attest.WriteUSFFields(mdPath, ch, sig); err != nil {
					return fail(4, "usf write: %v", err)
				}
				fmt.Printf("  updated %s front-matter: content_hash, signature\n", mdPath)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&keyPath, "key", "", "Ed25519 key file (from keygen)")
	f.StringVar(&identity, "identity", "", "publisher identity claim (e.g. oidc:you@example.com)")
	f.BoolVar(&noScan, "no-scan", false, "integrity-only attestation (scan: null)")
	f.BoolVar(&emitFields, "emit-manifest-fields", false, "also write USF content_hash/signature into SKILL.md")
	f.IntVar(&ttlDays, "ttl-days", 365, "attestation validity in days")
	return cmd
}

func verifyCmd() *cobra.Command {
	var policyPath, format string
	var noColor bool

	cmd := &cobra.Command{
		Use:   "verify <path>",
		Short: "Verify a bundle's attestation, Merkle root, and trust",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := skill.LoadBundle(args[0])
			if err != nil {
				return fail(3, "%v", err)
			}
			pol, err := policy.Load(policyPath)
			if err != nil {
				return fail(3, "policy: %v", err)
			}
			env, err := attest.ReadEnvelope(attest.SigPath(args[0]))
			if err != nil {
				return fail(3, "read attestation: %v", err)
			}
			res := verifyBundle(b, env, pol)
			printVerify(res, noColor)

			// Exit 2 on verification failure (design §10.5).
			if verificationFailed(res, pol) {
				return exitErr{code: 2, msg: "verification failed"}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&policyPath, "policy", "", "policy file with trust roster")
	f.StringVar(&format, "format", "text", "output: text (json in M3)")
	f.BoolVar(&noColor, "no-color", false, "disable ANSI color")
	return cmd
}

func keygenCmd() *cobra.Command {
	var out, keyID string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a local Ed25519 signing key",
		RunE: func(cmd *cobra.Command, args []string) error {
			signer, err := attest.GenerateKey(keyID)
			if err != nil {
				return fail(4, "%v", err)
			}
			if out == "" {
				out = "skill-guard.key"
			}
			if err := attest.SaveKey(signer, out); err != nil {
				return fail(4, "%v", err)
			}
			fmt.Printf("wrote %s (mode 0600)\n  keyid: %s\n  public_key: %s\n",
				out, signer.KeyID(), signer.PublicKeyBase64())
			fmt.Println("  add this key to your policy trust roster to verify signatures made with it.")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&out, "out", "", "output key path (default skill-guard.key)")
	f.StringVar(&keyID, "keyid", "", "key identifier (default derived from public key)")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and built-in rule-pack versions",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("skill-guard %s\n", Version)
			packs, err := rules.Builtin()
			if err != nil {
				return fail(4, "%v", err)
			}
			for _, p := range packs {
				fmt.Printf("  rulepack %s@%s (%d rules)\n", p.Name, p.Version, len(p.Rules))
			}
			return nil
		},
	}
}

// --- helpers ---

func emit(w *os.File, rep *scan.Report, format string, opt report.Options) error {
	switch format {
	case "json":
		return report.JSON(w, rep, opt)
	case "skill-card":
		return report.SkillCard(w, rep, opt)
	default:
		report.Text(w, rep, opt)
		return nil
	}
}

func outputWriter(path string) *os.File {
	if path == "" {
		return os.Stdout
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(3)
	}
	return f
}

func closeWriter(w *os.File) {
	if w != os.Stdout {
		_ = w.Close()
	}
}

func scanVerdict(s *attest.ScanSummary) model.Verdict {
	if s == nil {
		return ""
	}
	return model.Verdict(s.Verdict)
}

func skillMDPath(bundlePath string) string {
	fi, err := os.Stat(bundlePath)
	if err == nil && fi.IsDir() {
		return filepath.Join(bundlePath, "SKILL.md")
	}
	return bundlePath
}
