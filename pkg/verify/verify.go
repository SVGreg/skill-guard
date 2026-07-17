// Package verify checks a DSSE attestation against a bundle and a trust roster,
// emitting SG-PRV findings (design §7.3, rule-verification.md §4).
package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/skillguard/skill-guard/pkg/attest"
	"github.com/skillguard/skill-guard/pkg/model"
	"github.com/skillguard/skill-guard/pkg/policy"
	"github.com/skillguard/skill-guard/pkg/skill"
)

// Result summarizes verification.
type Result struct {
	Present        bool
	SignatureValid bool // at least one cryptographically valid signature
	Trusted        bool // a valid signature from a roster key
	MerkleMatch    bool
	Expired        bool
	Publisher      string
	Statement      *attest.Statement
	Findings       []model.Finding
}

// Verify checks env (may be nil) against the bundle under the trust roster.
func Verify(b *skill.Bundle, env *attest.Envelope, roster policy.Trust) *Result {
	res := &Result{}
	if env == nil {
		res.Findings = append(res.Findings, prv("SG-PRV-001", model.SevMedium,
			"No attestation present",
			"The bundle has no .skillsig; integrity and publisher cannot be verified.",
			"Sign the skill: skill-guard sign <path>."))
		return res
	}
	res.Present = true

	st, _, err := attest.DecodeStatement(env)
	if err != nil {
		res.Findings = append(res.Findings, prv("SG-PRV-002", model.SevCritical,
			"Malformed attestation", err.Error(), "Re-sign the bundle."))
		return res
	}
	res.Statement = st
	res.Publisher = st.Publisher.Identity

	keys := map[string]policy.Key{}
	for _, k := range roster.Keys {
		keys[k.KeyID] = k
	}
	revoked := map[string]bool{}
	for _, r := range roster.Revoked {
		revoked[r] = true
	}

	pae := attest.PAE(env.PayloadType, mustDecode(env.Payload))
	var anyValid, anyTrusted bool
	for _, sig := range env.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			continue
		}
		k, known := keys[sig.KeyID]
		if !known {
			continue // can't verify an unknown key's bytes; handled below
		}
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), pae, sigBytes) {
			anyValid = true
			if !revoked[sig.KeyID] {
				anyTrusted = true
			}
			if k.Identity != "" {
				res.Publisher = k.Identity
			}
		}
	}
	res.SignatureValid = anyValid
	res.Trusted = anyTrusted

	switch {
	case !anyValid && len(roster.Keys) == 0:
		// No roster configured: we cannot establish trust, but we should not
		// claim tampering. Report unverified identity, not invalid signature.
		res.Findings = append(res.Findings, prv("SG-PRV-005", model.SevMedium,
			"Publisher identity unverified",
			"No trust roster is configured, so the signing key is not recognized.",
			"Add the publisher's key to the policy trust roster."))
	case !anyValid:
		res.Findings = append(res.Findings, prv("SG-PRV-002", model.SevCritical,
			"Invalid or untrusted signature",
			"No signature verified against a trusted key in the roster.",
			"Confirm the signing key is trusted and the bundle is authentic."))
	case !anyTrusted:
		res.Findings = append(res.Findings, prv("SG-PRV-004", model.SevHigh,
			"Signing key revoked",
			"The valid signature was made with a revoked key.",
			"Obtain a re-signed bundle from a non-revoked key."))
	}

	// Expiry.
	if exp, err := time.Parse(time.RFC3339, st.Predicate.ExpiresAt); err == nil {
		if time.Now().After(exp.Add(2 * time.Minute)) { // small clock-skew tolerance
			res.Expired = true
			res.Findings = append(res.Findings, prv("SG-PRV-004", model.SevHigh,
				"Attestation expired", "The attestation's expires_at is in the past.",
				"Re-sign the bundle."))
		}
	}

	// Merkle integrity.
	got := attest.MerkleRoot(attest.BundleLeaves(b))
	if got != st.Subject.MerkleRoot {
		res.Findings = append(res.Findings, prv("SG-PRV-003", model.SevCritical,
			"Merkle root mismatch (tamper/drift)",
			"Recomputed bundle root does not match the signed root — content changed since signing.",
			"Re-verify the source; do not load a tampered skill."))
	} else {
		res.MerkleMatch = true
	}

	// Integrity-only attestation.
	if st.Scan == nil {
		res.Findings = append(res.Findings, prv("SG-PRV-006", model.SevLow,
			"Integrity-only attestation",
			"Signed with --no-scan; the skill was not scanned at signing time.",
			"Prefer signing after a passing scan."))
	}
	return res
}

func prv(id string, sev model.Severity, title, rationale, fix string) model.Finding {
	return model.Finding{
		RuleID:     id,
		AST:        []string{"AST01", "AST02"},
		Severity:   sev,
		Engine:     "provenance",
		Layer:      "provenance",
		Title:      title,
		File:       "<attestation>",
		Rationale:  rationale,
		Fix:        fix,
		Confidence: 1.0,
	}
}

func mustDecode(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}
