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
