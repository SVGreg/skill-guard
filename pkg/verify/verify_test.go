package verify

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// signedFixture returns the benign bundle, a valid envelope over it, and a
// trust roster containing the signing key.
func signedFixture(t *testing.T) (*skill.Bundle, *attest.Envelope, *attest.LocalSigner, policy.Trust) {
	t.Helper()
	b, err := skill.LoadBundle("../../testdata/benign")
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	signer, err := attest.GenerateKey("verify-test")
	if err != nil {
		t.Fatal(err)
	}
	st := attest.BuildStatement(b, &attest.ScanSummary{Verdict: "pass", MaxSeverity: "low", Version: "test"},
		signer, "test@example.com", 24*time.Hour)
	env, err := attest.SignWith(context.Background(), st, signer)
	if err != nil {
		t.Fatal(err)
	}
	roster := policy.Trust{Keys: []policy.Key{{
		KeyID:     signer.KeyID(),
		Algorithm: "ed25519",
		PublicKey: signer.PublicKeyBase64(),
		Identity:  "test@example.com",
	}}}
	return b, env, signer, roster
}

func hasFinding(res *Result, title string) bool {
	for _, f := range res.Findings {
		if f.Title == title {
			return true
		}
	}
	return false
}

func TestVerifyTrustedRoundTrip(t *testing.T) {
	b, env, _, roster := signedFixture(t)
	res := Verify(b, env, roster)
	if !res.SignatureValid || !res.Trusted || !res.MerkleMatch {
		t.Fatalf("valid attestation not accepted: %+v", res)
	}
	if res.Expired {
		t.Fatal("fresh attestation reported expired")
	}
	for _, f := range res.Findings {
		if f.RuleID != "SG-PRV-006" { // integrity-only is not emitted here
			t.Errorf("unexpected finding on a good bundle: %s %s", f.RuleID, f.Title)
		}
	}
}

// TestVerifyRejectsForeignPayloadType is design §7.3 step 1: the verifier must
// check payloadType. Before that check existed, a mistyped envelope fell through
// to a generic "invalid signature", and rejection of a cross-protocol replay
// depended on the payload happening not to parse as JSON.
func TestVerifyRejectsForeignPayloadType(t *testing.T) {
	b, env, _, roster := signedFixture(t)
	env.PayloadType = attest.USFPayloadType

	res := Verify(b, env, roster)
	if res.SignatureValid || res.Trusted {
		t.Fatalf("envelope with a foreign payloadType was accepted: %+v", res)
	}
	if !hasFinding(res, "Unexpected attestation payload type") {
		t.Fatalf("missing payload-type finding, got %+v", res.Findings)
	}
}

// TestVerifyRejectsUSFSignatureReplay covers the concrete cross-protocol case:
// the USF field signature is published in plaintext in SKILL.md front-matter, so
// anyone can lift it into an envelope shaped like an attestation.
func TestVerifyRejectsUSFSignatureReplay(t *testing.T) {
	b, _, signer, roster := signedFixture(t)
	contentHash, usfSig, err := attest.USFFields(context.Background(), b, signer)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(usfSig[len("ed25519:"):])
	if err != nil {
		t.Fatal(err)
	}
	replay := &attest.Envelope{
		PayloadType: attest.USFPayloadType,
		Payload:     base64.StdEncoding.EncodeToString([]byte(contentHash)),
		Signatures:  []attest.Signature{{KeyID: signer.KeyID(), Sig: base64.StdEncoding.EncodeToString(raw)}},
	}
	res := Verify(b, replay, roster)
	if res.SignatureValid || res.Trusted {
		t.Fatalf("USF signature accepted as an attestation: %+v", res)
	}
}

func TestVerifyNoAttestation(t *testing.T) {
	b, _, _, roster := signedFixture(t)
	res := Verify(b, nil, roster)
	if res.Present {
		t.Fatal("nil envelope reported as present")
	}
	if !hasFinding(res, "No attestation present") {
		t.Fatalf("missing SG-PRV-001, got %+v", res.Findings)
	}
}

// TestVerifyFailsClosedOnUnreadableExpiry: an expiry we cannot read is not an
// expiry we can honour. Before this, a missing or malformed expires_at skipped
// the check silently, so `"expires_at": "never"` read as perpetually fresh.
// Mirrors the policy-waiver expiry fix (#38).
func TestVerifyFailsClosedOnUnreadableExpiry(t *testing.T) {
	for _, tc := range []struct {
		name, expires, wantTitle string
	}{
		{"missing", "", "Attestation has no expiry"},
		{"malformed", "never", "Attestation expiry unreadable"},
		{"not rfc3339", "2027/01/01", "Attestation expiry unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, env, signer, roster := signedFixture(t)
			st, _, err := attest.DecodeStatement(env)
			if err != nil {
				t.Fatal(err)
			}
			st.Predicate.ExpiresAt = tc.expires
			env2, err := attest.SignWith(context.Background(), st, signer)
			if err != nil {
				t.Fatal(err)
			}
			res := Verify(b, env2, roster)
			if !res.Expired {
				t.Errorf("expires_at=%q: Expired=false, want true", tc.expires)
			}
			if !hasFinding(res, tc.wantTitle) {
				t.Errorf("expires_at=%q: missing %q, got %+v", tc.expires, tc.wantTitle, res.Findings)
			}
			// The signature is still valid — this is a freshness problem, not tampering.
			if !res.SignatureValid || !res.MerkleMatch {
				t.Errorf("expires_at=%q: unexpectedly reported as invalid/tampered: %+v", tc.expires, res)
			}
		})
	}
}

// TestVerifyEmptyBundleIsNotAMatch pins the empty-root sentinel. MerkleRoot
// returns "" for an empty leaf set — "no tree", not a root — so an empty bundle
// used to compare equal to a statement carrying an empty merkle_root and was
// reported as MATCH, i.e. the integrity check failed open. The CLI cannot reach
// this (LoadBundle requires a SKILL.md) but Verify is public library API.
func TestVerifyEmptyBundleIsNotAMatch(t *testing.T) {
	_, _, signer, roster := signedFixture(t)
	empty := &skill.Bundle{}
	st := attest.BuildStatement(empty, nil, signer, "test@example.com", 24*time.Hour)
	if st.Subject.MerkleRoot != "" {
		t.Fatalf("precondition: empty bundle should produce an empty root, got %q", st.Subject.MerkleRoot)
	}
	env, err := attest.SignWith(context.Background(), st, signer)
	if err != nil {
		t.Fatal(err)
	}
	res := Verify(empty, env, roster)
	if res.MerkleMatch {
		t.Error("empty bundle reported as a Merkle MATCH; integrity cannot be established over no files")
	}
	if !hasFinding(res, "Merkle root mismatch (tamper/drift)") {
		t.Errorf("missing mismatch finding, got %+v", res.Findings)
	}
}

// TestVerifyUsesTheDecodedPayload guards the PAE input after dropping the second
// base64 decode: a signature made over the real payload must still verify.
func TestVerifyUsesTheDecodedPayload(t *testing.T) {
	b, env, _, roster := signedFixture(t)
	res := Verify(b, env, roster)
	if !res.SignatureValid || !res.Trusted {
		t.Fatalf("valid signature no longer verifies: %+v", res)
	}
}

// TestVerifyMalformedPayloadIsReportedAsMalformed pins the early return that made
// the removed mustDecode helper's swallowed error unreachable: an undecodable
// payload must be reported as malformed, not fall through to a PAE over nil and a
// misleading "invalid signature". This held before the change and must keep
// holding — it is the invariant that let the second decode be deleted safely.
func TestVerifyMalformedPayloadIsReportedAsMalformed(t *testing.T) {
	b, env, _, roster := signedFixture(t)
	bad := &attest.Envelope{PayloadType: env.PayloadType, Payload: "!!!not base64!!!", Signatures: env.Signatures}
	res := Verify(b, bad, roster)
	if !hasFinding(res, "Malformed attestation") {
		t.Errorf("want a malformed-attestation finding, got %+v", res.Findings)
	}
}

// TestVerifyMarksRevokedDistinctlyFromUnknown pins Revoked as its own state
// rather than "not Trusted". The CLI needs the distinction: revocation clears
// Trusted, so without this field a revoked key rendered as "key not in trust
// roster", which contradicted the SG-PRV-004 line printed underneath it. An
// unknown key is a decision the consumer has not made; a revoked key is one
// they made against this key.
func TestVerifyMarksRevokedDistinctlyFromUnknown(t *testing.T) {
	b, env, signer, roster := signedFixture(t)

	revokedRoster := roster
	revokedRoster.Revoked = []string{signer.KeyID()}
	res := Verify(b, env, revokedRoster)
	if !res.SignatureValid {
		t.Fatal("signature should still verify cryptographically when the key is revoked")
	}
	if res.Trusted {
		t.Error("a revoked key must not be Trusted")
	}
	if !res.Revoked {
		t.Error("a revoked key must set Revoked")
	}
	if !hasFinding(res, "Signing key revoked") {
		t.Error("expected SG-PRV-004 for the revoked key")
	}

	// A key that is simply absent from the roster is a different state: not
	// trusted, but not revoked either.
	res = Verify(b, env, policy.Trust{})
	if res.Revoked {
		t.Error("an unknown key must not be reported as revoked")
	}
}
