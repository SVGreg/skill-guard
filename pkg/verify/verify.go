// Package verify checks a DSSE attestation against a bundle and a trust roster,
// emitting SG-PRV findings (design §7.3, rule-verification.md §4).
package verify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// Signature formats a Result can describe. A consumer reads Format to know
// which trust path produced the verdict — the two formats have different
// guarantees, and reporting one as the other would hide that.
const (
	FormatSGMT1 = "sgmt-1"
	FormatOMS   = "oms"
)

// Result summarizes verification.
type Result struct {
	// Format is the signature format this result describes (FormatSGMT1 or
	// FormatOMS).
	Format         string
	Present        bool
	SignatureValid bool // at least one cryptographically valid signature
	Trusted        bool // a valid signature from a roster key
	// Revoked reports that every signature which verified did so with a key the
	// roster lists under `revoked`. It is not the negation of Trusted: a key that
	// is simply absent from the roster leaves both false, and the two states need
	// different words — "the key is revoked" is a decision the consumer made,
	// "the key is unknown" is one they have not made yet.
	Revoked bool
	// IdentityRejected reports a signature that verified with a roster key
	// whose identity no trust.identities rule admits. It is distinct from
	// Revoked — the consumer did not reject *this publisher*, they scoped which
	// identities they accept — and from an unknown key, which is no decision at
	// all.
	IdentityRejected bool
	MerkleMatch      bool
	// Certificate-bound (keyless) details, set only for a certificate or
	// sigstore OMS bundle. CertError explains why such a signature could not be
	// established — most often that no roots are configured, which is a
	// consumer decision rather than a defect.
	CertIdentity string
	CertIssuer   string
	CertError    string
	SignedAt     time.Time
	// LogInclusionVerified reports that the transparency-log inclusion proof
	// reconstructs its claimed root — the entry really is in that tree.
	// LogCheckpointVerified additionally reports that a log key the consumer
	// pinned signed the checkpoint committing to that tree, which is what makes
	// it *the* log rather than any tree at all.
	LogInclusionVerified  bool
	LogCheckpointVerified bool
	Expired               bool
	Publisher             string
	Statement             *attest.Statement
	Findings              []model.Finding
}

// Verify checks env (may be nil) against the bundle under the trust roster.
func Verify(b *skill.Bundle, env *attest.Envelope, roster policy.Trust) *Result {
	res := &Result{Format: FormatSGMT1}
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
		if verifySignature(k, pae, sigBytes) {
			anyValid = true
			// Trust needs three things, in order: the signature verifies, the
			// key and its identity are not revoked, and the identity is one the
			// policy admits. The identity here is the roster's own — bound to
			// the key by the consumer who added it — never the statement's
			// self-asserted publisher block, which anyone can write.
			switch {
			case roster.Revokes(sig.KeyID, k.Identity):
				res.Revoked = true
			case !roster.Allows(k.Identity, ""):
				res.IdentityRejected = true
			default:
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
	case !anyTrusted && res.IdentityRejected:
		res.Findings = append(res.Findings, prv("SG-PRV-005", model.SevMedium,
			"Publisher identity not permitted",
			"The signature is valid and the key is in the roster, but its identity matches no trust.identities rule.",
			"Add a matching pattern under trust.identities, or remove the key from the roster."))
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

// verifyWithPublicKey verifies a DSSE signature with a public key taken from a
// certificate rather than a roster entry. The key's own type decides the
// scheme — a certificate names its algorithm in its SubjectPublicKeyInfo, so
// unlike a roster entry there is nothing an attacker could mislabel.
func verifyWithPublicKey(pub any, pae, sig []byte) bool {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(pae)
		return ecdsa.VerifyASN1(key, digest[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(key, pae, sig)
	default:
		return false
	}
}

// verifySignature checks one signature against one roster key, dispatching on
// the key's declared algorithm.
//
// The algorithm comes from the *roster entry*, never from the attestation: a
// signature that names its own scheme lets an attacker pick the weaker
// verification path. An entry with no algorithm is Ed25519, which is what every
// roster written before ECDSA support contained.
func verifySignature(k policy.Key, pae, sig []byte) bool {
	pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil {
		return false
	}
	switch alg := strings.ToLower(strings.TrimSpace(k.Algorithm)); alg {
	case "", attest.AlgEd25519:
		if len(pub) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(pub), pae, sig)
	case attest.AlgECDSAP256:
		parsed, err := x509.ParsePKIXPublicKey(pub)
		if err != nil {
			return false
		}
		ec, ok := parsed.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			return false
		}
		digest := sha256.Sum256(pae)
		return ecdsa.VerifyASN1(ec, digest[:], sig)
	default:
		// An unknown algorithm is not a verification failure to paper over —
		// the key simply cannot establish trust, and the caller reports the
		// attestation as unverified.
		return false
	}
}
