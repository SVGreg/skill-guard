package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/skill"
	sgverify "github.com/SVGreg/skill-guard/pkg/verify"
)

func verifyBundle(b *skill.Bundle, env *attest.Envelope, pol policy.Policy) *sgverify.Result {
	return sgverify.Verify(b, env, pol.Trust)
}

// printVerify renders one verification result. otherSignature says whether the
// bundle carries a signature in the *other* format, so an absent .skillsig on a
// bundle that does carry an OMS signature is not reported as "unsigned" — it is
// signed, just not in this format.
func printVerify(res *sgverify.Result, noColor bool, sigPath, skillPath string, otherSignature bool) {
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
	// The line label names the format, because the two carry different
	// guarantees: SGMT-1 attests a scan verdict and an expiry, OMS attests file
	// digests only. Printing both as "attestation" would blur that.
	label := "attestation"
	integrity := "merkle root"
	if res.Format == sgverify.FormatOMS {
		label = "OMS signature"
		integrity = "manifest"
	}

	switch {
	case !res.Present:
		fmt.Printf("%s: absent (no %q)\n", label, sigPath)
		switch {
		case otherSignature:
			fmt.Printf("  the skill carries the other signature format; add this one with:\n    skill-guard sign %q --key <key>%s\n",
				skillPath, omsFlagIf(res.Format == sgverify.FormatOMS))
		case res.Format != sgverify.FormatOMS:
			fmt.Printf("  this skill is unsigned. create an attestation with:\n    skill-guard sign %q --key <key>\n", skillPath)
		}
	case res.SignatureValid && res.Trusted:
		fmt.Printf("%s: present, signature %sVALID%s (trusted key)\n", label, c(green), c(reset))
	case res.SignatureValid && res.Revoked:
		// Distinct from the arm below: the key *is* in the roster, listed under
		// `revoked`. Saying "not in trust roster" here contradicted the
		// SG-PRV-004 line printed directly underneath, and understated the
		// state — an unknown key is a decision the consumer has not made, a
		// revoked one is a decision they made against this key.
		fmt.Printf("%s: present, signature VALID but key %sREVOKED%s\n", label, c(red), c(reset))
	case res.SignatureValid && res.IdentityRejected:
		// Distinct from the arm below: the key *is* in the roster. What the
		// policy declined is its identity, which is a narrower and more
		// actionable statement than "unknown key".
		fmt.Printf("%s: present, signature VALID but identity %sNOT PERMITTED%s by trust.identities\n",
			label, c(red), c(reset))
	case res.SignatureValid:
		fmt.Printf("%s: present, signature VALID (key not in trust roster — identity unverified)\n", label)
	case hasFinding("SG-PRV-002"):
		fmt.Printf("%s: present, signature %sINVALID%s (does not verify)\n", label, c(red), c(reset))
	default:
		// Present but unverifiable: no trust roster to check the signature bytes against.
		fmt.Printf("%s: present, signature UNVERIFIED (no trust roster — identity unverified)\n", label)
	}
	if res.Present && res.CertIdentity != "" {
		// Keyless: the identity is the certificate's, and it is worth showing
		// even when trust was withheld — it is the thing a policy scopes on.
		fmt.Printf("certificate identity: %s\n", safeText(res.CertIdentity))
		if res.CertIssuer != "" {
			fmt.Printf("certificate issuer: %s\n", safeText(res.CertIssuer))
		}
		if !res.SignedAt.IsZero() {
			fmt.Printf("signed at: %s (transparency log)\n", res.SignedAt.UTC().Format(time.RFC3339))
		}
	}
	if res.Present && res.CertError != "" {
		fmt.Printf("keyless: %s\n", safeText(res.CertError))
	}
	if res.Present {
		mm := "MISMATCH"
		col := red
		if res.MerkleMatch {
			mm, col = "MATCH", green
		}
		fmt.Printf("%s: %s%s%s\n", integrity, c(col), mm, c(reset))
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

// omsFlagIf appends the --oms flag when the missing signature is the OMS one.
func omsFlagIf(oms bool) string {
	if oms {
		return " --oms"
	}
	return ""
}
