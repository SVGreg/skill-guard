package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/report"
	"github.com/SVGreg/skill-guard/pkg/rules"
	"github.com/SVGreg/skill-guard/pkg/scan"
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
		Long: `Scan a skill for prompt-injection, jailbreak, data-exfiltration, unsafe
execution, secret, and metadata risks (OWASP Agentic Skills Top 10).

INPUT <path>:
  • a bundle directory containing SKILL.md (plus any scripts/config), or
  • a single SKILL.md file.

OUTPUT (--format):
  • text        human-readable findings (default)
  • json        machine-readable report for CI/tooling
  • skill-card   signed-summary card + attestation envelope (JSON)

POLICY (--policy .skillguard.yaml): sets fail_on/warn_on thresholds, waivers,
allowlists, and the trust roster. Without one, the default gates fail on high+.

EXIT CODES: 0 pass/warn · 1 fail · 3 usage error · 4 internal error.`,
		Example: `  skill-guard scan ./my-skill
  skill-guard scan ./my-skill/SKILL.md --verbose
  skill-guard scan ./my-skill --format json --out report.json
  skill-guard scan ./my-skill --policy .skillguard.yaml --fail-on critical`,
		Args: bundlePathArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateFormat(format); err != nil {
				return err
			}
			if err := validateSeverity("--fail-on", failOn); err != nil {
				return err
			}
			b, err := loadBundleFriendly(args[0])
			if err != nil {
				return err
			}
			pol, err := policy.Load(policyPath)
			if err != nil {
				return fail(3, "cannot read policy %q: %v\n  expected a .skillguard.yaml file (see 'skill-guard scan --help').", policyPath, err)
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
	f.StringVar(&format, "format", "text", "output format: text | json | skill-card")
	f.StringVar(&out, "out", "", "write output to this file instead of stdout")
	f.StringVar(&policyPath, "policy", "", "policy file (.skillguard.yaml) with thresholds, waivers, and trust roster")
	f.StringVar(&failOn, "fail-on", "", "override fail threshold: critical | high | medium | low")
	f.StringArrayVar(&rulepacks, "rulepack", nil, "extra rule-pack YAML file to load (repeatable)")
	f.BoolVarP(&verbose, "verbose", "v", false, "show rationale and suggested fix per finding")
	f.BoolVarP(&quiet, "quiet", "q", false, "suppress the secondary text summary when using --out")
	f.BoolVar(&noColor, "no-color", false, "disable ANSI color in output")
	return cmd
}

func signCmd() *cobra.Command {
	var keyPath, identity string
	var noScan, emitFields bool
	var ttlDays int

	cmd := &cobra.Command{
		Use:   "sign <path>",
		Short: "Merkle-hash and DSSE-sign a bundle (writes SKILL.md.skillsig)",
		Long: `Compute the bundle's SGMT-1 Merkle root and produce a detached DSSE
attestation signed with your Ed25519 key. The attestation is written next to
the skill as SKILL.md.skillsig and, by default, embeds the result of a scan.

INPUT <path>: a bundle directory or a single SKILL.md file (as with 'scan').

KEY (--key): an Ed25519 key file created by 'skill-guard keygen'. Keep it
secret; publishers add the matching public key to a verifier's trust roster.

IDENTITY (--identity): a free-form publisher claim recorded in the attestation,
e.g. oidc:you@example.com, email:you@example.com, or a URL.

EXIT CODES: 0 success · 3 usage error · 4 internal error.`,
		Example: `  skill-guard keygen --out publisher.key
  skill-guard sign ./my-skill --key publisher.key --identity oidc:you@example.com
  skill-guard sign ./my-skill --key publisher.key --no-scan          # integrity-only
  skill-guard sign ./my-skill --key publisher.key --emit-manifest-fields`,
		Args: bundlePathArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyPath == "" {
				return fail(3, "missing --key\n"+
					"  signing needs an Ed25519 key file. Create one with:\n"+
					"    skill-guard keygen --out publisher.key\n"+
					"  then: skill-guard sign %s --key publisher.key", args[0])
			}
			signer, err := attest.LoadKey(keyPath)
			if err != nil {
				return fail(3, "cannot load key %q: %v\n"+
					"  the key must be one produced by 'skill-guard keygen'.", keyPath, err)
			}
			b, err := loadBundleFriendly(args[0])
			if err != nil {
				return err
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
	f.StringVar(&keyPath, "key", "", "Ed25519 key file from 'keygen' (required)")
	f.StringVar(&identity, "identity", "", "publisher identity claim, e.g. oidc:you@example.com")
	f.BoolVar(&noScan, "no-scan", false, "integrity-only attestation: do not embed a scan result")
	f.BoolVar(&emitFields, "emit-manifest-fields", false, "also write USF content_hash/signature into SKILL.md front-matter")
	f.IntVar(&ttlDays, "ttl-days", 365, "attestation validity in days (expires_at)")
	return cmd
}

func verifyCmd() *cobra.Command {
	var policyPath, format string
	var noColor bool

	cmd := &cobra.Command{
		Use:   "verify <path>",
		Short: "Verify a bundle's attestation, Merkle root, and trust",
		Long: `Check a skill's detached attestation: that the DSSE signature is valid,
that the recomputed Merkle root still matches the signed one (no tampering or
drift), and — with a trust roster — that the signing key is trusted.

INPUT <path>: a bundle directory or a single SKILL.md file. verify reads the
attestation from SKILL.md.skillsig next to it (produced by 'skill-guard sign').

TRUST (--policy .skillguard.yaml): without a trust roster the signature cannot
be cryptographically checked, so the publisher is reported as UNVERIFIED. Add
the publisher's public key under trust.keys to establish trust:

  trust:
    keys:
      - keyid: sg-xxxxxxxxxxxx
        algorithm: ed25519
        public_key: <base64 from keygen>
        identity: oidc:you@example.com

EXIT CODES: 0 ok · 2 verification failed (bad signature / tampered) · 3 usage.`,
		Example: `  skill-guard verify ./my-skill
  skill-guard verify ./my-skill --policy .skillguard.yaml`,
		Args: bundlePathArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := loadBundleFriendly(args[0])
			if err != nil {
				return err
			}
			pol, err := policy.Load(policyPath)
			if err != nil {
				return fail(3, "cannot read policy %q: %v\n  expected a .skillguard.yaml file with a trust roster.", policyPath, err)
			}
			sigPath := attest.SigPath(args[0])
			env, err := attest.ReadEnvelope(sigPath)
			if err != nil {
				return fail(3, "cannot read attestation %q: %v\n  re-create it with: skill-guard sign %s --key <key>", sigPath, err, args[0])
			}
			res := verifyBundle(b, env, pol)
			printVerify(res, noColor, sigPath, args[0])

			// Exit 2 on verification failure (design §10.5).
			if verificationFailed(res, pol) {
				return exitErr{code: 2, msg: "verification failed"}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&policyPath, "policy", "", "policy file (.skillguard.yaml) providing the trust roster")
	f.StringVar(&format, "format", "text", "output format: text (json planned)")
	f.BoolVar(&noColor, "no-color", false, "disable ANSI color in output")
	return cmd
}

func keygenCmd() *cobra.Command {
	var out, keyID string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a local Ed25519 signing key",
		Long: `Generate an Ed25519 key pair for signing skills. The private key is written
to --out (mode 0600) and printed alongside its keyid and base64 public key.

Keep the key file secret. Share the public_key line so verifiers can add it to
their policy trust roster (trust.keys). Use the key with 'skill-guard sign'.

NOTE: the key file is currently stored unencrypted; protect it with filesystem
permissions. At-rest encryption is planned.

EXIT CODES: 0 success · 4 internal error.`,
		Example: `  skill-guard keygen --out publisher.key
  skill-guard keygen --out publisher.key --keyid team-release-2026`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			signer, err := attest.GenerateKey(keyID)
			if err != nil {
				return fail(4, "%v", err)
			}
			if out == "" {
				out = "skill-guard.key"
			}
			if err := attest.SaveKey(signer, out); err != nil {
				return fail(4, "cannot write key to %q: %v", out, err)
			}
			fmt.Printf("wrote %s (mode 0600)\n  keyid: %s\n  public_key: %s\n",
				out, signer.KeyID(), signer.PublicKeyBase64())
			fmt.Println("  add this key to your policy trust roster to verify signatures made with it.")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&out, "out", "", "output key file path (default skill-guard.key)")
	f.StringVar(&keyID, "keyid", "", "key identifier recorded in signatures (default derived from public key)")
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
