package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/skill"
	sgverify "github.com/SVGreg/skill-guard/pkg/verify"
)

func verifyBundle(b *skill.Bundle, env *attest.Envelope, pol policy.Policy) *sgverify.Result {
	return sgverify.Verify(b, env, pol.Trust)
}

func printVerify(res *sgverify.Result, noColor bool, sigPath, skillPath string) {
	c := func(s string) string {
		if noColor {
			return ""
		}
		return s
	}
	const (
		red   = "\033[31m"
		green = "\033[32m"
		reset = "\033[0m"
	)
	hasFinding := func(id string) bool {
		for _, f := range res.Findings {
			if f.RuleID == id {
				return true
			}
		}
		return false
	}
	// Paths are printed with %q, not %s: a bundle path can be discovered by
	// tooling rather than typed by the user (e.g. a directory unpacked from a
	// hostile archive), and a filename may contain any byte but '/' and NUL — so
	// a raw %s of the path could smuggle terminal escapes into this output. %q
	// escapes them and matches how the error paths (loadBundleFriendly, fail)
	// already quote paths. Findings below are model-owned SG-PRV-* constants, and
	// merkle_root/keyid are hex/base64, so those stay %s.
	switch {
	case !res.Present:
		fmt.Printf("attestation: absent (no %q)\n", sigPath)
		fmt.Printf("  this skill is unsigned. create an attestation with:\n    skill-guard sign %q --key <key>\n", skillPath)
	case res.SignatureValid && res.Trusted:
		fmt.Printf("attestation: present, signature %sVALID%s (trusted key)\n", c(green), c(reset))
	case res.SignatureValid && res.Revoked:
		// Distinct from the arm below: the key *is* in the roster, listed under
		// `revoked`. Saying "not in trust roster" here contradicted the
		// SG-PRV-004 line printed directly underneath, and understated the
		// state — an unknown key is a decision the consumer has not made, a
		// revoked one is a decision they made against this key.
		fmt.Printf("attestation: present, signature VALID but key %sREVOKED%s\n", c(red), c(reset))
	case res.SignatureValid:
		fmt.Printf("attestation: present, signature VALID (key not in trust roster — identity unverified)\n")
	case hasFinding("SG-PRV-002"):
		fmt.Printf("attestation: present, signature %sINVALID%s (does not verify)\n", c(red), c(reset))
	default:
		// Present but unverifiable: no trust roster to check the signature bytes against.
		fmt.Printf("attestation: present, signature UNVERIFIED (no trust roster — identity unverified)\n")
	}
	if res.Present {
		mm := "MISMATCH"
		col := red
		if res.MerkleMatch {
			mm, col = "MATCH", green
		}
		fmt.Printf("merkle root: %s%s%s\n", c(col), mm, c(reset))
		if res.Statement != nil {
			if res.Publisher != "" {
				fmt.Printf("publisher: %s\n", safeText(res.Publisher))
			}
			if res.Statement.Scan != nil {
				fmt.Printf("scan-at-signing: %s (risk %d/100)\n",
					safeText(res.Statement.Scan.Verdict), res.Statement.Scan.RiskScore)
			} else {
				fmt.Println("scan-at-signing: UNSCANNED (integrity-only)")
			}
		}
	}
	for _, f := range res.Findings {
		fmt.Fprintf(os.Stdout, "  %s  %s  %s\n", f.RuleID, f.Severity.String(), f.Title)
	}
}

// verificationFailed decides exit code 2. The set of failing states is the
// design's exit-code table (design §, "Verification failure: invalid signature,
// Merkle mismatch, revoked/expired key, or attestation absent while
// policy.attestation.required"), which is why SG-PRV-004 belongs here:
//
//   - SG-PRV-002 invalid/malformed/foreign-payload-type signature
//   - SG-PRV-003 Merkle mismatch
//   - SG-PRV-004 revoked key, expired attestation, or an expiry that cannot be
//     read — the same fail-closed reasoning pkg/verify already applies when it
//     sets Expired for a missing or unparseable expires_at
//
// SG-PRV-004 was previously absent, so `verify` exited 0 — success — on a
// bundle signed by a key the consumer had explicitly revoked, and on an
// attestation whose expiry had passed. A revocation list that does not fail the
// command is decoration: CI gating on `skill-guard verify` would have accepted
// exactly the bundle the roster was edited to reject.
//
// SG-PRV-005 (no roster configured) and SG-PRV-006 (integrity-only) stay
// non-failing: they report what could not be established, not something that
// was established and is bad.
func verificationFailed(res *sgverify.Result, pol policy.Policy) bool {
	if pol.Attestation.Required && !res.Present {
		return true
	}
	for _, f := range res.Findings {
		switch f.RuleID {
		case "SG-PRV-002", "SG-PRV-003", "SG-PRV-004":
			return true
		}
	}
	return false
}

// safeText renders a string that came out of an attestation statement. Those
// fields are attacker-controlled until a signature verifies against a roster
// key — and anyone can write a .skillsig, no key required — so printed raw they
// can forge skill-guard's own output: an `identity` carrying "\n\033[32mmerkle
// root: MATCH\033[0m\nsignature: VALID (trusted key)" prints two convincing
// green lines directly under the real MISMATCH. Quoting escapes the control
// characters and makes the tampering visible instead of invisible; pkg/report
// already prints scanned excerpts with %q for exactly this reason.
func safeText(s string) string { return strconv.Quote(s) }
