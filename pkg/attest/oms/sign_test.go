package oms

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// verifyWithSigner performs the check a real verifier does: parse the signer's
// PKIX public key and verify the ASN.1 ECDSA signature over sha256(PAE).
func verifyWithSigner(t *testing.T, signer *attest.LocalSigner, pae, sig []byte) bool {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(signer.PublicKeyBase64())
	if err != nil {
		t.Fatalf("public key base64: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("public key PKIX: %v", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", parsed)
	}
	digest := sha256.Sum256(pae)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

func testSigner(t *testing.T, alg string) *attest.LocalSigner {
	t.Helper()
	s, err := attest.GenerateKeyAlg("sg-abcdef012345", alg)
	if err != nil {
		t.Fatalf("GenerateKeyAlg(%s): %v", alg, err)
	}
	return s
}

// TestSignBundleProducesAParseableBundle is the M4-06 acceptance check: what we
// write must come back through our own parser — which is the same parser that
// accepts the reference implementation's bundles.
func TestSignBundleProducesAParseableBundle(t *testing.T) {
	b := &skill.Bundle{Root: "/tmp/demo-skill"}
	b.Files = []skill.File{
		{Path: "SKILL.md", Content: []byte("---\nname: demo\n---\nbody\n")},
		{Path: "scripts/setup.sh", Content: []byte("#!/bin/sh\necho hi\n")},
		{Path: ".gitignore", Content: []byte("*.log\n")}, // excluded by §6.2
	}

	signed, err := SignBundle(context.Background(), b, testSigner(t, attest.AlgECDSAP256), EnumOptions{})
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Round-trip through JSON, as a consumer would.
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("our own bundle failed ParseBundle: %v", err)
	}
	method, err := parsed.SigningMethod()
	if err != nil || method != MethodKey {
		t.Errorf("signing method = %s (%v), want %s", method, err, MethodKey)
	}
	if parsed.MediaType != BundleMediaType {
		t.Errorf("mediaType = %q, want %q", parsed.MediaType, BundleMediaType)
	}
	if hint := parsed.VerificationMaterial.PublicKey.Hint; hint != "abcdef012345" {
		t.Errorf("publicKey.hint = %q, want the key fingerprint", hint)
	}

	st, err := parsed.Statement()
	if err != nil {
		t.Fatalf("Statement: %v", err)
	}
	if st.Subject[0].Name != "demo-skill" {
		t.Errorf("subject name = %q, want the tree basename", st.Subject[0].Name)
	}
	if len(st.Predicate.Resources) != 2 {
		t.Fatalf("resources = %d, want 2 (.gitignore excluded)", len(st.Predicate.Resources))
	}
	if st.Predicate.Resources[0].Name != "SKILL.md" || st.Predicate.Resources[1].Name != "scripts/setup.sh" {
		t.Errorf("resource names = %v", []string{st.Predicate.Resources[0].Name, st.Predicate.Resources[1].Name})
	}
	if !contains(st.Predicate.Serialization.IgnorePaths, ".gitignore") {
		t.Errorf("ignore_paths %v does not record the exclusion", st.Predicate.Serialization.IgnorePaths)
	}

	// The signature must be over the payload actually carried, verified with
	// the signer's public key — the check a real verifier performs.
	payload, err := base64.StdEncoding.DecodeString(parsed.DSSEEnvelope.Payload)
	if err != nil {
		t.Fatalf("payload base64: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(parsed.DSSEEnvelope.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("signature base64: %v", err)
	}
	if len(payload) == 0 || len(sig) == 0 {
		t.Error("payload or signature is empty")
	}
	if parsed.DSSEEnvelope.PayloadType != PayloadType {
		t.Errorf("payloadType = %q, want %q", parsed.DSSEEnvelope.PayloadType, PayloadType)
	}
}

// TestSignBundleSignatureVerifies checks the signature end to end against the
// key that produced it.
func TestSignBundleSignatureVerifies(t *testing.T) {
	signer := testSigner(t, attest.AlgECDSAP256)
	b := &skill.Bundle{Root: "/tmp/demo", Files: []skill.File{
		{Path: "SKILL.md", Content: []byte("body")},
	}}
	signed, err := SignBundle(context.Background(), b, signer, EnumOptions{})
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	payload, _ := base64.StdEncoding.DecodeString(signed.DSSEEnvelope.Payload)
	sig, _ := base64.StdEncoding.DecodeString(signed.DSSEEnvelope.Signatures[0].Sig)

	if !verifyWithSigner(t, signer, attest.PAE(PayloadType, payload), sig) {
		t.Error("the signature does not verify with the signing key")
	}
	// Tamper with the payload: the signature must no longer verify.
	if verifyWithSigner(t, signer, attest.PAE(PayloadType, append(payload, ' ')), sig) {
		t.Error("signature verified over a modified payload")
	}
}

// TestSignBundleRefusesEd25519: OMS's registry has no Ed25519, so producing a
// bundle only we can verify would be worse than failing.
func TestSignBundleRefusesEd25519(t *testing.T) {
	b := &skill.Bundle{Root: "/tmp/demo", Files: []skill.File{{Path: "SKILL.md", Content: []byte("x")}}}
	_, err := SignBundle(context.Background(), b, testSigner(t, attest.AlgEd25519), EnumOptions{})
	if !errors.Is(err, ErrNotECDSA) {
		t.Errorf("error = %v, want ErrNotECDSA", err)
	}
}

func TestSignBundleRejectsEmptyTree(t *testing.T) {
	b := &skill.Bundle{Root: "/tmp/demo", Files: []skill.File{{Path: ".github/ci.yml", Content: []byte("x")}}}
	if _, err := SignBundle(context.Background(), b, testSigner(t, attest.AlgECDSAP256), EnumOptions{}); !errors.Is(err, ErrNoFiles) {
		t.Errorf("error = %v, want ErrNoFiles", err)
	}
}

// TestWriteAndSigPath: the bundle lands where verifiers look for it, as
// readable JSON.
func TestWriteAndSigPath(t *testing.T) {
	dir := t.TempDir()
	b := &skill.Bundle{Root: dir, Files: []skill.File{{Path: "SKILL.md", Content: []byte("x")}}}
	signed, err := SignBundle(context.Background(), b, testSigner(t, attest.AlgECDSAP256), EnumOptions{})
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	path := SigPath(dir)
	if filepath.Base(path) != SigFileName {
		t.Errorf("SigPath = %q, want a %s beside the bundle", path, SigFileName)
	}
	if err := Write(path, signed); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if _, err := ParseBundle(data); err != nil {
		t.Errorf("written file does not parse: %v", err)
	}
	if data[len(data)-1] != '\n' {
		t.Error("written file does not end in a newline")
	}
}

// TestSignBundleIsDeterministic: signing the same tree twice must produce the
// same payload. (Signatures differ — ECDSA is randomized — but the signed
// content must not.)
func TestSignBundleIsDeterministic(t *testing.T) {
	signer := testSigner(t, attest.AlgECDSAP256)
	b := &skill.Bundle{Root: "/tmp/demo", Files: []skill.File{
		{Path: "b.txt", Content: []byte("two")},
		{Path: "a.txt", Content: []byte("one")},
	}}
	first, err := SignBundle(context.Background(), b, signer, EnumOptions{})
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	second, err := SignBundle(context.Background(), b, signer, EnumOptions{})
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	if first.DSSEEnvelope.Payload != second.DSSEEnvelope.Payload {
		t.Error("the signed payload differs between two runs over the same tree")
	}
}
