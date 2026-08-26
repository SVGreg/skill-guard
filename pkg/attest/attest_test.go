package attest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SVGreg/skill-guard/pkg/skill"
)

func fixtureBundle(t *testing.T) *skill.Bundle {
	t.Helper()
	b, err := skill.LoadBundle("../../testdata/benign")
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	return b
}

func TestMerkleDeterministic(t *testing.T) {
	b := fixtureBundle(t)
	r1 := MerkleRoot(BundleLeaves(b))
	r2 := MerkleRoot(BundleLeaves(b))
	if r1 == "" || r1 != r2 {
		t.Fatalf("merkle not deterministic: %q vs %q", r1, r2)
	}
}

func TestNormalizeStripsReservedLines(t *testing.T) {
	in := []byte("---\nname: x\ncontent_hash: \"sha256:abc\"\nsignature: \"ed25519:zzz\"\ndescription: y\n---\n\nbody\n")
	out := NormalizeSkillMD(in)
	s := string(out)
	if contains(s, "content_hash") || contains(s, "signature:") {
		t.Fatalf("reserved lines not stripped: %q", s)
	}
	if !contains(s, "name: x") || !contains(s, "description: y") || !contains(s, "body") {
		t.Fatalf("normalization removed too much: %q", s)
	}
}

// TestUSFContentHashStableAcrossFieldInjection proves adding USF fields does not
// change the Merkle root (design §7.5).
func TestUSFContentHashStableAcrossFieldInjection(t *testing.T) {
	plain := []byte("---\nname: x\ndescription: y\n---\n\nbody\n")
	withFields := []byte("---\nname: x\ncontent_hash: \"sha256:abc\"\nsignature: \"ed25519:zzz\"\ndescription: y\n---\n\nbody\n")
	if string(NormalizeSkillMD(plain)) != string(NormalizeSkillMD(withFields)) {
		t.Fatal("normalized SKILL.md differs after USF field injection")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	b := fixtureBundle(t)
	signer, err := GenerateKey("test-key")
	if err != nil {
		t.Fatal(err)
	}
	st := BuildStatement(b, &ScanSummary{Verdict: "pass", MaxSeverity: "low", RiskScore: 3, Version: "test"}, signer, "oidc:test@example.com", 365*24*time.Hour)
	env, err := SignWith(context.Background(), st, signer)
	if err != nil {
		t.Fatal(err)
	}
	// Verify PAE round-trips: recompute and check the statement decodes.
	got, _, err := DecodeStatement(env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject.MerkleRoot != st.Subject.MerkleRoot {
		t.Fatalf("merkle root mismatch after round-trip")
	}
	if len(env.Signatures) != 1 || env.Signatures[0].KeyID != "test-key" {
		t.Fatalf("unexpected signatures: %+v", env.Signatures)
	}
}

func TestPubPath(t *testing.T) {
	cases := map[string]string{
		"publisher.key":    "publisher.pub",
		"/tmp/a/b.key":     "/tmp/a/b.pub",
		"mykey":            "mykey.pub",
		"weird.key.backup": "weird.key.backup.pub",
	}
	for in, want := range cases {
		if got := PubPath(in); got != want {
			t.Errorf("PubPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSavePubIsPublicOnly(t *testing.T) {
	signer, err := GenerateKey("pub-test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "k.pub")
	if err := SavePub(signer, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(data), "private_key") {
		t.Fatalf(".pub must not contain private material: %s", data)
	}
	var pf struct {
		KeyID     string `json:"keyid"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(data, &pf); err != nil {
		t.Fatal(err)
	}
	if pf.KeyID != "pub-test" || pf.Algorithm != "ed25519" || pf.PublicKey != signer.PublicKeyBase64() {
		t.Fatalf("unexpected .pub contents: %+v", pf)
	}
}

// TestSaveKeyForcesRestrictiveMode guards the §7.4 promise that keygen prints
// ("mode 0600, private"). os.WriteFile only applies its perm on creation, so
// writing over a pre-existing 0644 file used to leave the seed world-readable.
func TestSaveKeyForcesRestrictiveMode(t *testing.T) {
	signer, err := GenerateKey("mode-test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pre-existing.key")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveKey(signer, path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("private key left at mode %v, want 0600", got)
	}
	if _, err := LoadKey(path); err != nil {
		t.Fatalf("key unreadable after overwrite: %v", err)
	}
}

// TestSaveKeyRefusesSymlink keeps private material from being written through a
// link into an attacker-chosen location.
func TestSaveKeyRefusesSymlink(t *testing.T) {
	signer, err := GenerateKey("symlink-test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.txt")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "publisher.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := SaveKey(signer, link); err == nil {
		t.Fatal("SaveKey followed a symlink instead of refusing")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("key material written through symlink: %s", data)
	}
}

// TestLoadKeyEnforcesAlgorithm covers what the declared algorithm can take:
// absent (pre-field keys, accepted as Ed25519), "ed25519" (accepted), an
// unsupported scheme (rejected), and — since ecdsa-p256 became supported — a
// label that disagrees with the key bytes, which must still be rejected rather
// than loaded under the wrong scheme.
func TestLoadKeyEnforcesAlgorithm(t *testing.T) {
	signer, err := GenerateKey("alg-test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, alg string) string {
		path := filepath.Join(dir, name)
		kf := map[string]string{
			"keyid":       signer.KeyID(),
			"private_key": base64.StdEncoding.EncodeToString(signer.priv.Seed()),
			"public_key":  signer.PublicKeyBase64(),
		}
		if alg != "-" { // "-" means: omit the field entirely
			kf["algorithm"] = alg
		}
		data, err := json.Marshal(kf)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, tc := range []struct {
		name, alg string
		wantErr   bool
	}{
		{"declared.key", "ed25519", false},
		{"cased.key", "Ed25519", false},
		{"absent.key", "-", false},
		{"empty.key", "", false},
		{"mislabelled.key", "ecdsa-p256", true}, // Ed25519 seed, ECDSA label
		{"rsa.key", "rsa-pss-sha256", true},
	} {
		_, err := LoadKey(write(tc.name, tc.alg))
		if tc.wantErr && err == nil {
			t.Errorf("algorithm %q: loaded without error, want rejection", tc.alg)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("algorithm %q: %v", tc.alg, err)
		}
	}
}

// TestNormalizeEmptyFrontMatter covers the degenerate "---\n---\n" manifest.
// fmBlockRe used to require a newline between the delimiters, so the block went
// unrecognized and WriteUSFFields reported "has no front-matter block" for a
// block that plainly exists.
func TestNormalizeEmptyFrontMatter(t *testing.T) {
	in := []byte("---\n---\n\nbody\n")
	if got := string(NormalizeSkillMD(in)); got != string(in) {
		t.Fatalf("empty front-matter normalized to %q, want it unchanged", got)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(path, in, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteUSFFields(path, "sha256:abc", "ed25519:zzz"); err != nil {
		t.Fatalf("WriteUSFFields on an empty front-matter block: %v", err)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(out), "content_hash:") || !contains(string(out), "signature:") {
		t.Fatalf("USF fields not written: %q", out)
	}
	// The whole point of normalization: injecting the fields must not move the
	// Merkle leaf, so the normalized form has to round-trip back to the input.
	if got := string(NormalizeSkillMD(out)); got != string(in) {
		t.Fatalf("normalized %q, want %q", got, in)
	}
}

// TestNormalizeIgnoresMidLineDelimiter guards the anchoring in fmBlockRe: a
// "---" inside a front-matter value is not a closing delimiter.
func TestNormalizeIgnoresMidLineDelimiter(t *testing.T) {
	in := []byte("---\nname: a---b\ncontent_hash: \"sha256:abc\"\ndescription: y\n---\n\nbody\n")
	got := string(NormalizeSkillMD(in))
	if contains(got, "content_hash") {
		t.Fatalf("close delimiter matched mid-line, leaving reserved lines: %q", got)
	}
	if !contains(got, "name: a---b") || !contains(got, "description: y") {
		t.Fatalf("normalization mangled the front matter: %q", got)
	}
}

// TestUSFStableWithReservedLineLast is the layout the old regex handled badly:
// a reserved line at the end of the block left a stray blank line behind, so the
// normalized form no longer matched the same manifest without the fields — and
// the content hash it protects moved.
func TestUSFStableWithReservedLineLast(t *testing.T) {
	plain := []byte("---\nname: x\n---\n\nbody\n")
	withFields := []byte("---\nname: x\ncontent_hash: \"sha256:abc\"\nsignature: \"ed25519:zzz\"\n---\n\nbody\n")
	if string(NormalizeSkillMD(plain)) != string(NormalizeSkillMD(withFields)) {
		t.Fatalf("normalized forms diverge: %q vs %q",
			NormalizeSkillMD(plain), NormalizeSkillMD(withFields))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestReadEnvelopeRefusesOversizedAttestation pins the size cap on the one
// bundle-adjacent file the pkg/skill walk deliberately skips. Because the walk
// skips ".skillsig" it also never applied its 16 MiB per-file cap to it, so a
// hostile bundle could ship an arbitrarily large attestation and `verify` would
// read all of it — measured at 875 MB RSS for a 133 MiB envelope, while the same
// bytes in any other bundle file are refused without being read.
func TestReadEnvelopeRefusesOversizedAttestation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "SKILL.md.skillsig")
	// Valid JSON, so a failure here is the cap and not a parse error.
	oversized := append([]byte(`{"payloadType":"x","payload":"`),
		append(bytes.Repeat([]byte("A"), maxAttestFileSize), []byte(`"}`)...)...)
	if err := os.WriteFile(path, oversized, 0o644); err != nil {
		t.Fatal(err)
	}
	env, err := ReadEnvelope(path)
	if err == nil {
		// Deliberately not printing env — it holds the whole oversized payload.
		t.Fatalf("oversized attestation accepted (%d bytes read)", len(env.Payload))
	}
	if !contains(err.Error(), "size cap") {
		t.Fatalf("error does not name the cap: %v", err)
	}
}

// TestReadEnvelopeAcceptsRealAttestation guards the other side of the cap: the
// largest bundle in the evaluation corpus (1739 files) signs to ~317 KB, so no
// plausible attestation is anywhere near the limit.
func TestReadEnvelopeAcceptsRealAttestation(t *testing.T) {
	b := fixtureBundle(t)
	signer, err := GenerateKey("cap-test")
	if err != nil {
		t.Fatal(err)
	}
	st := BuildStatement(b, nil, signer, "test@example.com", time.Hour)
	env, err := SignWith(context.Background(), st, signer)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "SKILL.md.skillsig")
	if err := WriteEnvelope(path, env); err != nil {
		t.Fatal(err)
	}
	got, err := ReadEnvelope(path)
	if err != nil {
		t.Fatalf("real attestation refused: %v", err)
	}
	if got == nil || got.Payload != env.Payload {
		t.Fatal("round-trip lost the envelope")
	}
}

// TestReadEnvelopeAbsentIsNotAnError keeps ReadEnvelope's (nil, nil) contract for
// an unsigned bundle — the switch to an Open-based read must not turn "no
// attestation" into a hard error, which would break `verify` on unsigned skills.
func TestReadEnvelopeAbsentIsNotAnError(t *testing.T) {
	env, err := ReadEnvelope(filepath.Join(t.TempDir(), "nope.skillsig"))
	if err != nil || env != nil {
		t.Fatalf("absent attestation: got (%+v, %v), want (nil, nil)", env, err)
	}
}

// TestLoadKeyRefusesOversizedFile — same cap, sibling path.
func TestLoadKeyRefusesOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte("A"), maxAttestFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil || !contains(err.Error(), "size cap") {
		t.Fatalf("oversized key file: got %v, want a size-cap error", err)
	}
}

// TestECDSAP256RoundTrip covers the OMS-required algorithm end to end:
// generate, save, reload, sign, and verify — plus the properties that make it
// safe to have two schemes in one key format.
func TestECDSAP256RoundTrip(t *testing.T) {
	signer, err := GenerateKeyAlg("", AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKeyAlg: %v", err)
	}
	if signer.Algorithm() != AlgECDSAP256 {
		t.Fatalf("algorithm = %q, want %q", signer.Algorithm(), AlgECDSAP256)
	}
	if signer.KeyID() == "" {
		t.Error("key id was not derived")
	}

	path := filepath.Join(t.TempDir(), "oms.key")
	if err := SaveKey(signer, path); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}
	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if loaded.Algorithm() != AlgECDSAP256 || loaded.KeyID() != signer.KeyID() {
		t.Errorf("reloaded key = %s/%s, want %s/%s",
			loaded.Algorithm(), loaded.KeyID(), signer.Algorithm(), signer.KeyID())
	}
	if loaded.PublicKeyBase64() != signer.PublicKeyBase64() {
		t.Error("public key changed across save/load")
	}

	// The saved public key must be parseable PKIX DER for a P-256 point —
	// that is what a verifier and any OMS consumer will do with it.
	der, err := base64.StdEncoding.DecodeString(loaded.PublicKeyBase64())
	if err != nil {
		t.Fatalf("public key is not base64: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("public key is not PKIX DER: %v", err)
	}
	ec, ok := parsed.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		t.Fatalf("public key is not ECDSA P-256: %T", parsed)
	}

	pae := PAE(PayloadType, []byte(`{"hello":"world"}`))
	sig, err := loaded.Sign(context.Background(), pae)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	digest := sha256.Sum256(pae)
	if !ecdsa.VerifyASN1(ec, digest[:], sig) {
		t.Error("signature did not verify against the saved public key")
	}
	// Wrong payload must not verify — guards against signing a constant.
	other := sha256.Sum256(PAE(PayloadType, []byte(`{"hello":"tampered"}`)))
	if ecdsa.VerifyASN1(ec, other[:], sig) {
		t.Error("signature verified over the wrong payload")
	}
}

// TestEd25519StaysTheDefault: adding a second algorithm must not change what
// existing callers get, or every stored key and roster entry would shift under
// them.
func TestEd25519StaysTheDefault(t *testing.T) {
	signer, err := GenerateKey("")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if signer.Algorithm() != AlgEd25519 {
		t.Errorf("default algorithm = %q, want %q", signer.Algorithm(), AlgEd25519)
	}
	raw, err := base64.StdEncoding.DecodeString(signer.PublicKeyBase64())
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Errorf("Ed25519 public key encoding changed: %d bytes, err %v", len(raw), err)
	}
}

// TestLoadKeyRejectsMismatchedAlgorithm: a key file must not be loaded under a
// scheme it does not contain, or it would sign while claiming an algorithm the
// bytes do not support.
func TestLoadKeyRejectsMismatchedAlgorithm(t *testing.T) {
	dir := t.TempDir()

	ed, err := GenerateKey("")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := filepath.Join(dir, "mislabelled.key")
	if err := SaveKey(ed, path); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}
	// Relabel an Ed25519 key file as ECDSA.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	swapped := strings.Replace(string(data), `"algorithm": "ed25519"`, `"algorithm": "ecdsa-p256"`, 1)
	if err := os.WriteFile(path, []byte(swapped), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Error("an Ed25519 key file labelled ecdsa-p256 was accepted")
	}

	unknown := strings.Replace(string(data), `"algorithm": "ed25519"`, `"algorithm": "rsa-4096"`, 1)
	unknownPath := filepath.Join(dir, "unknown.key")
	if err := os.WriteFile(unknownPath, []byte(unknown), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadKey(unknownPath); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("unknown algorithm error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestGenerateKeyAlgRejectsUnknown(t *testing.T) {
	if _, err := GenerateKeyAlg("", "rsa-4096"); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("error = %v, want ErrUnsupportedAlgorithm", err)
	}
}
