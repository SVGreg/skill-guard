// Package verify checks a DSSE attestation against a bundle and a trust roster,
// emitting SG-PRV findings (design §7.3, rule-verification.md §4).
package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// Result summarizes verification.
type Result struct {
	Present        bool
	SignatureValid bool // at least one cryptographically valid signature
	Trusted        bool // a valid signature from a roster key
	// Revoked reports that every signature which verified did so with a key the
	// roster lists under `revoked`. It is not the negation of Trusted: a key that
	// is simply absent from the roster leaves both false, and the two states need
	// different words — "the key is revoked" is a decision the consumer made,
	// "the key is unknown" is one they have not made yet.
	Revoked     bool
	MerkleMatch bool
	Expired     bool
	Publisher   string
	Statement   *attest.Statement
	Findings    []model.Finding
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

	// design §7.3 step 1: bind the envelope to this payload type before touching
	// the payload. The PAE covers payloadType, so a foreign type cannot verify —
	// but checking it up front is what stops a signature made by the same key in
	// another context (notably the USF field signature, which is published in
	// plaintext in SKILL.md front-matter) from being replayed as an attestation.
	if env.PayloadType != attest.PayloadType {
		res.Findings = append(res.Findings, prv("SG-PRV-002", model.SevCritical,
			"Unexpected attestation payload type",
			"The envelope's payloadType is not "+attest.PayloadType+"; it was signed for a different purpose.",
			"Re-sign the bundle: skill-guard sign <path>."))
		return res
	}

	st, raw, err := attest.DecodeStatement(env)
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

	// Reuse the payload DecodeStatement already decoded rather than base64-decoding
	// env.Payload a second time. The old helper discarded its error, so a payload
	// that decoded here but not there would have silently produced a PAE over nil
	// and reported "invalid signature" instead of "malformed attestation"; it also
	// held a second full copy of an attacker-sized payload.
	pae := attest.PAE(env.PayloadType, raw)
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
		res.Revoked = true
		res.Findings = append(res.Findings, prv("SG-PRV-004", model.SevHigh,
			"Signing key revoked",
			"The valid signature was made with a revoked key.",
			"Obtain a re-signed bundle from a non-revoked key."))
	}

	// Expiry — fail closed. An absent or unparseable expires_at used to skip the
	// check silently, so an attestation claiming `"expires_at": "never"` was
	// treated as perpetually fresh. Same reasoning as the policy-waiver expiry
	// fix (#38): an expiry we cannot read is not an expiry we can honour.
	exp, err := time.Parse(time.RFC3339, st.Predicate.ExpiresAt)
	switch {
	case st.Predicate.ExpiresAt == "":
		res.Expired = true
		res.Findings = append(res.Findings, prv("SG-PRV-004", model.SevHigh,
			"Attestation has no expiry",
			"The statement's predicate omits expires_at, so freshness cannot be established.",
			"Re-sign the bundle: skill-guard sign <path>."))
	case err != nil:
		res.Expired = true
		res.Findings = append(res.Findings, prv("SG-PRV-004", model.SevHigh,
			"Attestation expiry unreadable",
			"expires_at is not an RFC3339 timestamp ("+strconv.Quote(st.Predicate.ExpiresAt)+"), so freshness cannot be established.",
			"Re-sign the bundle: skill-guard sign <path>."))
	case time.Now().After(exp.Add(2 * time.Minute)): // small clock-skew tolerance
		res.Expired = true
		res.Findings = append(res.Findings, prv("SG-PRV-004", model.SevHigh,
			"Attestation expired", "The attestation's expires_at is in the past.",
			"Re-sign the bundle."))
	}

	// Merkle integrity. MerkleRoot returns "" for an empty leaf set — a sentinel
	// meaning "no tree", not a root — so an empty bundle compared equal to a
	// statement carrying an empty merkle_root and was reported as MATCH. The CLI
	// cannot reach that (LoadBundle requires a SKILL.md), but Verify is part of the
	// public library API and takes the *skill.Bundle it is handed. Treat an
	// unbuildable root as a mismatch: integrity that cannot be computed is not
	// integrity that holds.
	got := attest.MerkleRoot(attest.BundleLeaves(b))
	if got == "" || got != st.Subject.MerkleRoot {
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
