package verify

import (
	"errors"
	"fmt"

	"github.com/SVGreg/skill-guard/pkg/attest/oms"
	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// VerifyOMS checks an OpenSSF Model Signing bundle against the skill on disk
// and the trust roster, reporting the same SG-PRV states the SGMT-1 path does
// so a consumer does not need to know which format was used.
//
// data is the raw skill.oms.sig. Pass **nil** when the file is absent; an empty
// but non-nil slice means the file exists and is empty, which is a malformed
// bundle rather than a missing one — the spec's own `invalid/empty.bundle.json`
// vector is exactly that case, and reporting it as "unsigned" would let a
// truncated signature look like a skill nobody had signed yet.
func VerifyOMS(b *skill.Bundle, data []byte, roster policy.Trust) *Result {
	res := &Result{Format: FormatOMS}
	if data == nil {
		res.Findings = append(res.Findings, prv("SG-PRV-001", model.SevMedium,
			"No OMS signature present",
			"The bundle has no skill.oms.sig; OMS verifiers cannot check it.",
			"Sign with an EC key: skill-guard sign <path> --key oms.key --oms."))
		return res
	}
	res.Present = true

	bundle, err := oms.ParseBundle(data)
	if err != nil {
		res.Findings = append(res.Findings, prv("SG-PRV-002", model.SevCritical,
			"Malformed OMS bundle", err.Error(),
			"Re-sign the bundle: skill-guard sign <path> --oms."))
		return res
	}
	st, err := bundle.Statement()
	if err != nil {
		// A deprecated-predicate bundle lands here by name rather than being
		// read as an empty manifest.
		res.Findings = append(res.Findings, prv("SG-PRV-002", model.SevCritical,
			"Unusable OMS statement", err.Error(),
			"Re-sign the bundle with an OMS v1.0 signer."))
		return res
	}

	pae, err := oms.SignedPAE(bundle)
	if err != nil {
		res.Findings = append(res.Findings, prv("SG-PRV-002", model.SevCritical,
			"Malformed OMS envelope", err.Error(), "Re-sign the bundle."))
		return res
	}
	sigs, err := oms.Signatures(bundle)
	if err != nil {
		res.Findings = append(res.Findings, prv("SG-PRV-002", model.SevCritical,
			"OMS bundle carries no usable signature", err.Error(), "Re-sign the bundle."))
		return res
	}

	// OMS does not carry a keyid a roster can be indexed by — §4.1 makes it
	// optional and unused, since the key travels in verificationMaterial. So
	// every roster key is tried, which is also what lets a bundle signed by
	// another implementation verify here.
	for _, sig := range sigs {
		for _, k := range roster.Keys {
			if !verifySignature(k, pae, sig) {
				continue
			}
			res.SignatureValid = true
			switch {
			case roster.Revokes(k.KeyID, k.Identity):
				res.Revoked = true
			case !roster.Allows(k.Identity, ""):
				res.IdentityRejected = true
			default:
				res.Trusted = true
				if k.Identity != "" {
					res.Publisher = k.Identity
				}
			}
		}
	}

	switch {
	case !res.SignatureValid && len(roster.Keys) == 0:
		res.Findings = append(res.Findings, prv("SG-PRV-005", model.SevMedium,
			"Publisher identity unverified",
			"No trust roster is configured, so the OMS signing key is not recognized.",
			"Add the publisher's key to the policy trust roster."))
	case !res.SignatureValid:
		res.Findings = append(res.Findings, prv("SG-PRV-002", model.SevCritical,
			"Invalid or untrusted OMS signature",
			"No signature in the OMS bundle verified against a key in the roster.",
			"Confirm the signing key is trusted and the bundle is authentic."))
	case !res.Trusted && res.IdentityRejected:
		res.Findings = append(res.Findings, prv("SG-PRV-005", model.SevMedium,
			"Publisher identity not permitted",
			"The OMS signature is valid and the key is in the roster, but its identity matches no trust.identities rule.",
			"Add a matching pattern under trust.identities, or remove the key from the roster."))
	case !res.Trusted:
		res.Revoked = true
		res.Findings = append(res.Findings, prv("SG-PRV-004", model.SevHigh,
			"Signing key revoked",
			"The valid OMS signature was made with a revoked key.",
			"Obtain a re-signed bundle from a non-revoked key."))
	}

	manifest, err := oms.VerifyManifest(b, st)
	switch {
	case err != nil:
		res.Findings = append(res.Findings, prv("SG-PRV-003", model.SevCritical,
			"OMS manifest cannot be checked", err.Error(),
			"Re-sign with a supported hash algorithm."))
	case manifest.OK():
		res.MerkleMatch = true
	default:
		res.Findings = append(res.Findings, prv("SG-PRV-003", model.SevCritical,
			"OMS manifest mismatch (tamper/drift)",
			manifestRationale(manifest),
			"Re-verify the source; do not load a tampered skill."))
	}

	// An OMS bundle carries no scan verdict by construction — the format
	// describes file digests, not analysis — so say so rather than let a
	// consumer infer one was performed.
	res.Findings = append(res.Findings, prv("SG-PRV-006", model.SevLow,
		"OMS signature carries no scan result",
		"OMS attests file integrity only; it records no scan verdict.",
		"Also sign with SGMT-1 (the default) to attest a scan at signing time."))
	return res
}

func manifestRationale(m oms.ManifestResult) string {
	switch {
	case len(m.Mismatched) > 0:
		return fmt.Sprintf("%d signed file(s) changed since signing: %v", len(m.Mismatched), m.Mismatched)
	case len(m.Missing) > 0:
		return fmt.Sprintf("%d signed file(s) are missing: %v", len(m.Missing), m.Missing)
	case len(m.Unsigned) > 0:
		return fmt.Sprintf("%d file(s) are not covered by the signature: %v", len(m.Unsigned), m.Unsigned)
	default:
		return "manifest verification failed"
	}
}

// ErrNoSignatureFile is returned by DetectFormats when a bundle carries neither
// signature.
var ErrNoSignatureFile = errors.New("verify: bundle has no signature file")
