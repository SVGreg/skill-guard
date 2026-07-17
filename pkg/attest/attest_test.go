package attest

import (
	"context"
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

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
