package attest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
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

// TestLoadKeyEnforcesAlgorithm covers the three cases the declared algorithm can
// take: absent (pre-field keys, accepted), "ed25519" (accepted), and anything
// else (rejected). Without the check a key file naming ecdsa-p256 was loaded as
// Ed25519 and every attestation it produced claimed "ed25519".
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
		{"wrong.key", "ecdsa-p256", true},
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
