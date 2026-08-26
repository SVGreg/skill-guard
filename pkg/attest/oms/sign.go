package oms

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// Bundle assembly per OMS §6.7–§6.8: DSSE-sign the statement, then wrap the
// envelope in a Sigstore bundle.

const (
	// SigFileName is where skill-guard writes the OMS bundle. The spec does not
	// mandate a name — §9 asks only for a `.sig` extension beside the signed
	// tree — so this is skill-guard's choice, and Enumerate excludes it from
	// its own manifest.
	SigFileName = "skill.oms.sig"

	// BundleMediaType is the Sigstore bundle version OMS v1.0 bundles use.
	BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

// Signer is the private-key operation the writer needs. It matches
// attest.Signer, so an *attest.LocalSigner satisfies it without adaptation —
// but the dependency points this way, keeping pkg/attest/oms free of the
// SGMT-1 types.
type Signer interface {
	KeyID() string
	Algorithm() string
	Sign(ctx context.Context, pae []byte) ([]byte, error)
}

var ErrNotECDSA = errors.New("oms: OMS requires an EC key (P-256/384/521); Ed25519 is not in the OMS algorithm registry")

// SignBundle enumerates a skill bundle, builds the OMS statement, DSSE-signs
// it, and returns the Sigstore bundle.
//
// The signer must be an EC key: the OMS algorithm registry requires
// P-256/384/521 for the key and certificate methods, so signing with Ed25519
// would produce a bundle other implementations are entitled to reject. Failing
// here is better than emitting one that only we can verify.
func SignBundle(ctx context.Context, b *skill.Bundle, signer Signer, opt EnumOptions) (*Bundle, error) {
	if signer.Algorithm() != attest.AlgECDSAP256 {
		return nil, fmt.Errorf("%w (this key is %s)", ErrNotECDSA, signer.Algorithm())
	}

	files, ser, err := Enumerate(b, opt)
	if err != nil {
		return nil, err
	}
	st, err := BuildStatement(SubjectName(b.Root), BuildResources(files), ser)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	// DSSE PAE (§6.7 step 3) — the same encoding SGMT-1 signs over, reused
	// rather than restated. The dependency runs oms → attest and never back,
	// so the CLI stays the place the two formats are composed.
	sig, err := signer.Sign(ctx, attest.PAE(PayloadType, payload))
	if err != nil {
		return nil, err
	}

	return &Bundle{
		MediaType: BundleMediaType,
		VerificationMaterial: &VerificationMaterial{
			PublicKey: &PublicKey{Hint: keyHint(signer)},
		},
		DSSEEnvelope: &DSSEEnvelope{
			Payload:     base64.StdEncoding.EncodeToString(payload),
			PayloadType: PayloadType,
			// §4.1: keyid is optional and unused for verification, since the
			// key comes from verificationMaterial. Omitted rather than filled
			// with something a verifier would ignore.
			Signatures: []Signature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
		},
	}, nil
}

// keyHint is the hex-encoded key fingerprint §4.1 asks producers to put in
// publicKey.hint. skill-guard key ids are already a truncated SHA-256 of the
// public key ("sg-<hex>"), so the hex part is used directly when present.
func keyHint(signer Signer) string {
	id := signer.KeyID()
	if len(id) > 3 && id[:3] == "sg-" {
		if _, err := hex.DecodeString(id[3:]); err == nil {
			return id[3:]
		}
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:8])
}

// SigPath is where the OMS bundle lives for a given skill bundle root.
func SigPath(bundleRoot string) string {
	return filepath.Join(bundleRoot, SigFileName)
}

// Write writes the bundle as indented JSON at mode 0644 — it is a signature,
// not a secret.
func Write(path string, b *Bundle) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
