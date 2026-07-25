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
	switch {
	case !res.Present:
		fmt.Printf("attestation: absent (no %s)\n", sigPath)
		fmt.Printf("  this skill is unsigned. create an attestation with:\n    skill-guard sign %s --key <key>\n", skillPath)
	case res.SignatureValid && res.Trusted:
		fmt.Printf("attestation: present, signature %sVALID%s (trusted key)\n", c(green), c(reset))
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

func verificationFailed(res *sgverify.Result, pol policy.Policy) bool {
	if pol.Attestation.Required && !res.Present {
		return true
	}
	for _, f := range res.Findings {
		if f.RuleID == "SG-PRV-002" || f.RuleID == "SG-PRV-003" {
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
