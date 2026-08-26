package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/attest/oms"
	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/report"
	"github.com/SVGreg/skill-guard/pkg/rules"
	"github.com/SVGreg/skill-guard/pkg/scan"
	sgverify "github.com/SVGreg/skill-guard/pkg/verify"
	"github.com/spf13/cobra"
)

// loadRuleset loads built-in packs plus any explicit --rulepack files. It
// returns detections and severity-capping context rules separately, because the
// scanner consumes them at different stages (see scan.Scanner.WithContexts).
func loadRuleset(extra []string) ([]*rules.Rule, []*rules.ContextRule, error) {
	packs, err := rules.Builtin()
	if err != nil {
		return nil, nil, err
	}
	for _, path := range extra {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		p, err := rules.LoadPack(data)
		if err != nil {
			return nil, nil, err
		}
		fmt.Fprintf(os.Stderr, "note: loaded unsigned rule-pack %q (provenance: unsigned)\n", path)
		packs = append(packs, p)
	}
	return rules.AllRules(packs), rules.AllContexts(packs), nil
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
  • sarif       SARIF 2.1.0 for GitHub code scanning / any SARIF viewer

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
				return fail(3, "cannot use policy %q: %v\n  expected a valid .skillguard.yaml file (see 'skill-guard scan --help').", policyPath, err)
			}
			if failOn != "" {
				pol.FailOn = failOn
			}
			rs, cs, err := loadRuleset(rulepacks)
			if err != nil {
				return fail(3, "rules: %v", err)
			}
			rep := scan.New(rs, pol).WithContexts(cs).Scan(b)

			w := outputWriter(out)
			defer closeWriter(w)
			// Resolved per writer, not once: with --out these are two different
			// destinations, and the file must stay escape-free even when the
			// mirrored copy on stdout is a terminal that should be coloured.
			// A path the user named with --out is an artifact, never a terminal,
			// so it is unconditional there rather than a device check.
			opt := report.Options{
				NoColor: noColor || out != "" || report.ColorDisabled(w),
				Verbose: verbose, Source: args[0], Version: Version,
			}
			if err := emit(w, rep, format, opt); err != nil {
				return fail(4, "%v", err)
			}
			if !quiet && out != "" {
				stdoutOpt := opt
				stdoutOpt.NoColor = noColor || report.ColorDisabled(os.Stdout)
				report.Text(os.Stdout, rep, stdoutOpt)
			}
			if rep.Verdict == model.Fail {
				return exitErr{code: 1, msg: "verdict: fail"}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&format, "format", "text", "output format: text | json | skill-card | sarif")
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
	var noScan, emitFields, withOMS bool
	var ttlDays int

	cmd := &cobra.Command{
		Use:   "sign <path>",
		Short: "Merkle-hash and DSSE-sign a bundle (writes SKILL.md.skillsig)",
		Long: `Compute the bundle's SGMT-1 Merkle root and produce a detached DSSE
attestation signed with your key. The attestation is written next to
the skill as SKILL.md.skillsig and, by default, embeds the result of a scan.

INPUT <path>: a bundle directory or a single SKILL.md file (as with 'scan').

KEY (--key): a key file created by 'skill-guard keygen'. Keep it secret;
publishers add the matching public key to a verifier's trust roster.

OMS (--oms): additionally write skill.oms.sig, an OpenSSF Model Signing v1.0
bundle covering the whole directory tree, for verifiers outside skill-guard.
It is written alongside SKILL.md.skillsig, never instead of it, and requires an
--type ecdsa-p256 key: the OMS algorithm registry does not include Ed25519.

IDENTITY (--identity): a free-form publisher claim recorded in the attestation,
e.g. oidc:you@example.com, email:you@example.com, or a URL.

EXIT CODES: 0 success · 3 usage error · 4 internal error.`,
		Example: `  skill-guard keygen --out publisher.key
  skill-guard sign ./my-skill --key publisher.key --identity oidc:you@example.com
  skill-guard sign ./my-skill --key publisher.key --no-scan          # integrity-only
  skill-guard sign ./my-skill --key publisher.key --emit-manifest-fields
  skill-guard sign ./my-skill --key oms.key --oms   # also write skill.oms.sig`,
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
			// Checked before anything is written: otherwise --oms with an
			// Ed25519 key leaves a valid .skillsig behind and then errors,
			// which reads like a partial success.
			if withOMS {
				if b.SingleFile {
					return fail(3, "--oms needs a bundle directory\n"+
						"  an OMS bundle describes a directory tree; point --oms at the skill folder.")
				}
				if signer.Algorithm() != attest.AlgECDSAP256 {
					return fail(3, "%v\n"+
						"  create one with: skill-guard keygen --out oms.key --type ecdsa-p256",
						fmt.Errorf("%w (this key is %s)", oms.ErrNotECDSA, signer.Algorithm()))
				}
			}

			var summary *attest.ScanSummary
			if !noScan {
				rs, cs, err := loadRuleset(nil)
				if err != nil {
					return fail(3, "rules: %v", err)
				}
				rep := scan.New(rs, policy.Default()).WithContexts(cs).Scan(b)
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
			fmt.Printf("wrote %q\n  merkle_root %s\n  %s\n", sigPath, st.Subject.MerkleRoot, scanNote)

			if withOMS {
				omsBundle, err := oms.SignBundle(context.Background(), b, signer, oms.EnumOptions{})
				if err != nil {
					return fail(4, "oms: %v", err)
				}
				omsPath := oms.SigPath(b.Root)
				if err := oms.Write(omsPath, omsBundle); err != nil {
					return fail(4, "oms write: %v", err)
				}
				st, err := omsBundle.Statement()
				if err != nil {
					return fail(4, "oms: %v", err)
				}
				root, _ := st.RootDigest()
				fmt.Printf("  wrote %q (OMS v1.0, %d files, root %s)\n",
					omsPath, len(st.Predicate.Resources), root)
			}

			if emitFields {
				ch, sig, err := attest.USFFields(context.Background(), b, signer)
				if err != nil {
					return fail(4, "usf: %v", err)
				}
				mdPath := skillMDPath(args[0])
				if err := attest.WriteUSFFields(mdPath, ch, sig); err != nil {
					return fail(4, "usf write: %v", err)
				}
				fmt.Printf("  updated %q front-matter: content_hash, signature\n", mdPath)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&keyPath, "key", "", "key file from 'keygen' (required)")
	f.BoolVar(&withOMS, "oms", false, "also write skill.oms.sig (OpenSSF Model Signing v1.0; needs an ecdsa-p256 key)")
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

INPUT <path>: a bundle directory or a single SKILL.md file. verify reads
whichever signatures are present next to it and reports each: SKILL.md.skillsig
(skill-guard's own SGMT-1 attestation) and skill.oms.sig (an OpenSSF Model
Signing v1.0 bundle, written by 'sign --oms'). A failure in either exits 2.

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
				return fail(3, "cannot use policy %q: %v\n  expected a valid .skillguard.yaml file with a trust roster.", policyPath, err)
			}
			sigPath := attest.SigPath(args[0])
			omsPath := oms.SigPath(b.Root)
			omsData, omsErr := os.ReadFile(omsPath)
			// Presence is the file existing, not its being non-empty: a
			// truncated signature must be reported as malformed, never as an
			// unsigned skill.
			hasOMS := omsErr == nil

			// Signature-type auto-detection: whichever formats are present are
			// verified, and each is reported with the trust path it used. A
			// bundle carrying only an OMS signature is not "unsigned", which is
			// what reading SKILL.md.skillsig alone would have reported.
			env, err := attest.ReadEnvelope(sigPath)
			if err != nil && !hasOMS {
				return fail(3, "cannot read attestation %q: %v\n  re-create it with: skill-guard sign %s --key <key>", sigPath, err, args[0])
			}

			noColorOut := noColor || report.ColorDisabled(os.Stdout)
			failed := false
			if err == nil {
				res := verifyBundle(b, env, pol)
				printVerify(res, noColorOut, sigPath, args[0], hasOMS)
				failed = failed || verificationFailed(res, pol)
			} else {
				fmt.Printf("attestation: absent (no %q)\n", sigPath)
			}
			if hasOMS {
				fmt.Println()
				omsRes := sgverify.VerifyOMS(b, omsData, pol.Trust)
				printVerify(omsRes, noColorOut, omsPath, args[0], env != nil)
				failed = failed || verificationFailed(omsRes, pol)
			}

			// Exit 2 on verification failure (design §10.5).
			if failed {
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
	var out, keyID, pubOut, keyType string
	var noPub, force bool
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a local signing key",
		Long: `Generate a signing key pair for skills. Two files are written:

  <name>.key   the PRIVATE key (forced to mode 0600) — keep secret, never share/commit.
  <name>.pub   the PUBLIC key (mode 0644 when created) — safe to share, commit, or publish.

The .key is self-contained (signing needs only it); the .pub is a convenience
you hand to consumers so they can add you to their policy trust roster
(trust.keys). Use the .key with 'skill-guard sign'.

ALGORITHM (--type):
  • ed25519      default; used by skill-guard's own SGMT-1 attestations.
  • ecdsa-p256   required by OpenSSF Model Signing (OMS), whose algorithm
                 registry mandates EC P-256/384/521 and does not include
                 Ed25519. Use this for keys that must verify with OMS tooling.

NOTE: the .key is currently stored unencrypted; protect it with filesystem
permissions. At-rest encryption is planned.

EXIT CODES: 0 success · 4 internal error.`,
		Example: `  skill-guard keygen --out publisher.key            # writes publisher.key + publisher.pub
  skill-guard keygen --out publisher.key --keyid team-release-2026
  skill-guard keygen --out publisher.key --no-pub   # private key only
  skill-guard keygen --out oms.key --type ecdsa-p256   # OMS-compatible key`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateKeyType(keyType); err != nil {
				return err
			}
			signer, err := attest.GenerateKeyAlg(keyID, keyType)
			if err != nil {
				return fail(4, "%v", err)
			}
			if out == "" {
				out = "skill-guard.key"
			}
			if pubOut == "" {
				pubOut = attest.PubPath(out)
			}
			// Both paths are checked BEFORE either is written, so a refusal
			// leaves the filesystem untouched rather than half-updated.
			if !force {
				if err := refuseOverwrite(out, "private key"); err != nil {
					return err
				}
				if !noPub {
					if err := refuseOverwrite(pubOut, "public key"); err != nil {
						return err
					}
				}
			}
			if err := attest.SaveKey(signer, out); err != nil {
				return fail(4, "cannot write key to %q: %v", out, err)
			}
			fmt.Printf("wrote %q (mode 0600, private — keep secret)\n  keyid: %s\n  public_key: %s\n",
				out, signer.KeyID(), signer.PublicKeyBase64())
			if !noPub {
				if err := attest.SavePub(signer, pubOut); err != nil {
					return fail(4, "cannot write public key to %q: %v", pubOut, err)
				}
				// Report the mode observed, not the one requested: writing over
				// an existing file keeps that file's mode (os.WriteFile only
				// applies perm on create), so a hard-coded "0644" here could be
				// a lie. Harmless for public material, but don't claim it.
				fmt.Printf("wrote %q (mode %04o, public — safe to share)\n", pubOut, fileMode(pubOut, 0o644))
			}
			fmt.Println("  share the public key so verifiers can add it to their policy trust roster.")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&out, "out", "", "output private key file path (default skill-guard.key)")
	f.StringVar(&keyID, "keyid", "", "key identifier recorded in signatures (default derived from public key)")
	f.StringVar(&keyType, "type", attest.AlgEd25519, "key algorithm: ed25519 | ecdsa-p256 (ecdsa-p256 for OMS compatibility)")
	f.StringVar(&pubOut, "pub", "", "output public key file path (default <name>.pub)")
	f.BoolVar(&noPub, "no-pub", false, "do not write the .pub public-key file")
	f.BoolVar(&force, "force", false, "overwrite an existing key file (DESTROYS the old private key)")
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
				line := fmt.Sprintf("  rulepack %s@%s (%d rules", p.Name, p.Version, len(p.Rules))
				if n := len(p.Contexts); n > 0 {
					line += fmt.Sprintf(", %d context", n)
				}
				fmt.Println(line + ")")
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
	case "sarif":
		return report.SARIF(w, rep, opt)
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
