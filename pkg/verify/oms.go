package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
// Two trust paths are supported. A `key` bundle is checked against the roster's
// public keys. A `certificate` or `sigstore` bundle is checked against the
// consumer's configured CA roots, and the identity bound into the certificate
// is then admitted (or not) by trust.identities — which is what makes keyless
// signing usable without anyone holding a long-lived key.
//
// data is the raw skill.oms.sig. Pass **nil** when the file is absent; an empty
// but non-nil slice means the file exists and is empty, which is a malformed
// bundle rather than a missing one — the spec's own `invalid/empty.bundle.json`
// vector is exactly that case, and reporting it as "unsigned" would let a
// truncated signature look like a skill nobody had signed yet.
func VerifyOMS(b *skill.Bundle, data []byte, roster policy.Trust) *Result {
	return VerifyOMSAt(b, data, roster, ".")
}

// VerifyOMSAt is VerifyOMS with the directory that relative trust.roots paths
// are resolved against — normally the directory holding the policy file, so a
// policy means the same thing wherever the command is run from.
func VerifyOMSAt(b *skill.Bundle, data []byte, roster policy.Trust, policyDir string) *Result {
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
	method, _ := bundle.SigningMethod()
	if method == oms.MethodCertificate || method == oms.MethodSigstore {
		verifyCertBound(res, bundle, pae, sigs, roster, policyDir)
	} else {
		verifyKeyBound(res, pae, sigs, roster)
	}

	switch {
	case !res.SignatureValid && res.CertError != "":
		res.Findings = append(res.Findings, prv("SG-PRV-005", model.SevMedium,
			"Keyless signature could not be verified",
			res.CertError,
			"Add the issuing CA under trust.roots, then scope the identity under trust.identities."))
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

// verifyKeyBound checks a `key` bundle against the roster's public keys.
//
// OMS carries no keyid a roster can be indexed by — §4.1 makes it optional and
// unused, since the key travels in verificationMaterial — so every roster key
// is tried. That is also what lets a bundle produced by another implementation
// verify here.
func verifyKeyBound(res *Result, pae []byte, sigs [][]byte, roster policy.Trust) {
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
}

// verifyCertBound checks a certificate- or Sigstore-bound bundle: chain the
// signing certificate to a configured root, verify the signature with the
// certificate's public key, then admit the bound identity under
// trust.identities.
//
// Nothing here is trusted by default. With no trust.roots configured the
// signature is reported as unverifiable rather than valid — skill-guard ships
// no CA, and inventing a fallback would be exactly the vendor-anchored trust
// this project exists to avoid.
func verifyCertBound(res *Result, bundle *oms.Bundle, pae []byte, sigs [][]byte, roster policy.Trust, policyDir string) {
	leaf, intermediates, err := oms.Certificates(bundle)
	if err != nil {
		res.CertError = err.Error()
		return
	}
	identity, issuer, idErr := oms.CertIdentity(leaf)
	res.CertIdentity, res.CertIssuer = identity, issuer

	// Short-lived Fulcio certificates expire within minutes, so verification
	// uses the transparency-log timestamp — when the signature was recorded —
	// rather than now. Without a log entry there is no trustworthy time, and
	// guessing "now" would reject every keyless signature older than its
	// certificate's ten-minute window.
	//
	// Read before the roots are consulted so the timestamp is reported even
	// when trust is withheld: "signed at" is an observation about the bundle,
	// not a conclusion about it, and it is exactly what a reader wants when
	// deciding whether to pin the issuing CA.
	when, ok := oms.IntegratedTime(bundle)
	if ok {
		res.SignedAt = when
	}

	// The timestamp above is only a claim until the log entry is checked. Doing
	// it here, before the certificate is chained, means a forged timestamp
	// cannot smuggle an expired certificate through the validity window.
	if err := verifyTransparency(res, bundle, roster); err != nil {
		res.CertError = err.Error()
		return
	}

	pool, err := roster.CertPool(policyDir)
	if err != nil {
		res.CertError = err.Error()
		return
	}
	if pool == nil {
		res.CertError = "no certificate roots are configured (trust.roots), so a keyless signature cannot be checked"
		return
	}
	if !ok {
		res.CertError = "the bundle carries no transparency-log entry, so the certificate's validity window cannot be anchored in time"
		return
	}

	inter := x509.NewCertPool()
	for _, c := range intermediates {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		CurrentTime:   when,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
	}); err != nil {
		res.CertError = "certificate does not chain to a configured root: " + err.Error()
		return
	}

	for _, sig := range sigs {
		if verifyWithPublicKey(leaf.PublicKey, pae, sig) {
			res.SignatureValid = true
			break
		}
	}
	if !res.SignatureValid {
		res.CertError = "the signature does not verify with the certificate's public key"
		return
	}
	if idErr != nil {
		res.CertError = idErr.Error()
		return
	}

	res.Publisher = identity
	switch {
	case roster.Revokes(identity, issuer):
		res.Revoked = true
	case !roster.Allows(identity, issuer):
		res.IdentityRejected = true
	default:
		res.Trusted = true
	}
}

// verifyTransparency checks the bundle's transparency-log entry: that the
// inclusion proof reconstructs its claimed root, that the signed checkpoint
// commits to that same tree, and — when the consumer has pinned log keys — that
// one of them signed the checkpoint.
//
// The inclusion proof is always checked when present, because M4-09 anchors
// certificate validity on the log's timestamp and an unchecked timestamp is
// just a number the signer wrote. Checkpoint *signature* verification is
// enforced only when trust.log_keys is configured: without pinned keys there is
// nothing to check a signature against, and inventing a default log would be
// the same mistake as shipping a default CA.
func verifyTransparency(res *Result, bundle *oms.Bundle, roster policy.Trust) error {
	entries, err := oms.TlogEntries(bundle)
	if err != nil {
		return err
	}
	var lastErr error
	for _, e := range entries {
		if e.Proof == nil {
			continue
		}
		if err := e.VerifyInclusion(); err != nil {
			// A broken proof is evidence, not an absence of it: report the
			// first one rather than letting a later good entry mask it.
			return err
		}
		res.LogInclusionVerified = true

		cp, err := oms.ParseCheckpoint(e.Proof.Checkpoint)
		if err != nil {
			lastErr = err
			continue
		}
		if err := cp.MatchesProof(e.Proof); err != nil {
			return err
		}
		if len(roster.LogKeys) == 0 {
			continue
		}
		if err := verifyCheckpointSignature(cp, e.LogKeyID, roster.LogKeys); err != nil {
			lastErr = err
			continue
		}
		res.LogCheckpointVerified = true
	}

	if !res.LogInclusionVerified {
		return oms.ErrNoInclusionProof
	}
	if len(roster.LogKeys) > 0 && !res.LogCheckpointVerified {
		if lastErr != nil {
			return fmt.Errorf("no configured transparency-log key verified the checkpoint: %w", lastErr)
		}
		return errors.New("no configured transparency-log key verified the checkpoint")
	}
	return nil
}

// verifyCheckpointSignature checks the note signature against the pinned log
// keys. An entry whose key_id is set must match the bundle's log id; an entry
// without one is tried regardless, since a consumer pinning a single log should
// not have to look up its id to make it work.
func verifyCheckpointSignature(cp *oms.Checkpoint, logKeyID []byte, keys []policy.LogKey) error {
	for _, k := range keys {
		if k.KeyID != "" && len(logKeyID) > 0 {
			want, err := base64.StdEncoding.DecodeString(k.KeyID)
			if err != nil || !bytes.Equal(want, logKeyID) {
				continue
			}
		}
		der, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			continue
		}
		if verifyNoteSignature(pub, cp.Signed, cp.Signature) {
			return nil
		}
	}
	return errors.New("checkpoint signature did not verify against any configured log key")
}

// verifyNoteSignature verifies a signed-note signature. Rekor signs with ECDSA
// P-256 over the SHA-256 of the note body; Ed25519 logs sign the body directly.
func verifyNoteSignature(pub any, signed, sig []byte) bool {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(signed)
		return ecdsa.VerifyASN1(key, digest[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(key, signed, sig)
	default:
		return false
	}
}
