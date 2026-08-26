package oms

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
)

// TestInclusionProofFromTheSigstoreVector verifies a real Rekor proof — 14
// audit-path hashes against a tree of 476,246,825 entries. Getting the RFC 6962
// index arithmetic subtly wrong still passes on toy trees; it does not pass
// here.
func TestInclusionProofFromTheSigstoreVector(t *testing.T) {
	b, err := ParseBundle(read(t, "valid/sigstore.bundle.json"))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	entries, err := TlogEntries(b)
	if err != nil {
		t.Fatalf("TlogEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Proof == nil {
		t.Fatal("no inclusion proof")
	}
	if err := e.VerifyInclusion(); err != nil {
		t.Fatalf("VerifyInclusion: %v", err)
	}
	t.Logf("verified inclusion: index %d of %d, %d audit hashes",
		e.Proof.LogIndex, e.Proof.TreeSize, len(e.Proof.Hashes))

	cp, err := ParseCheckpoint(e.Proof.Checkpoint)
	if err != nil {
		t.Fatalf("ParseCheckpoint: %v", err)
	}
	if err := cp.MatchesProof(e.Proof); err != nil {
		t.Errorf("checkpoint does not match the proof: %v", err)
	}
	if cp.Origin != "rekor.sigstore.dev - 1193050959916656506" {
		t.Errorf("origin = %q", cp.Origin)
	}
	if len(cp.Signature) == 0 || len(cp.KeyHint) != 4 {
		t.Errorf("signature block parsed wrong: hint %x, sig %d bytes", cp.KeyHint, len(cp.Signature))
	}
}

// TestInclusionProofDetectsTampering: a proof that has been altered must not
// reconstruct the claimed root. Without this the whole exercise is decoration.
func TestInclusionProofDetectsTampering(t *testing.T) {
	b, err := ParseBundle(read(t, "valid/sigstore.bundle.json"))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	entries, _ := TlogEntries(b)
	base := entries[0]

	t.Run("body changed", func(t *testing.T) {
		e := base
		e.CanonicalizedBody = append(append([]byte{}, base.CanonicalizedBody...), ' ')
		if err := e.VerifyInclusion(); !errors.Is(err, ErrProofMismatch) {
			t.Errorf("error = %v, want ErrProofMismatch", err)
		}
	})
	t.Run("audit hash changed", func(t *testing.T) {
		e := base
		hashes := make([][]byte, len(base.Proof.Hashes))
		copy(hashes, base.Proof.Hashes)
		flipped := append([]byte{}, hashes[0]...)
		flipped[0] ^= 0xff
		hashes[0] = flipped
		p := *base.Proof
		p.Hashes = hashes
		e.Proof = &p
		if err := e.VerifyInclusion(); !errors.Is(err, ErrProofMismatch) {
			t.Errorf("error = %v, want ErrProofMismatch", err)
		}
	})
	t.Run("index changed", func(t *testing.T) {
		e := base
		p := *base.Proof
		p.LogIndex++
		e.Proof = &p
		if err := e.VerifyInclusion(); err == nil {
			t.Error("a changed leaf index still verified")
		}
	})
	t.Run("root changed", func(t *testing.T) {
		e := base
		p := *base.Proof
		root := append([]byte{}, base.Proof.RootHash...)
		root[0] ^= 0xff
		p.RootHash = root
		e.Proof = &p
		if err := e.VerifyInclusion(); !errors.Is(err, ErrProofMismatch) {
			t.Errorf("error = %v, want ErrProofMismatch", err)
		}
	})
	t.Run("proof length wrong", func(t *testing.T) {
		e := base
		p := *base.Proof
		p.Hashes = base.Proof.Hashes[:len(base.Proof.Hashes)-1]
		e.Proof = &p
		if err := e.VerifyInclusion(); !errors.Is(err, ErrProofMalformed) {
			t.Errorf("error = %v, want ErrProofMalformed", err)
		}
	})
}

// TestRootFromInclusionProofSmallTrees checks the arithmetic against hand-built
// trees where the answer can be computed independently.
func TestRootFromInclusionProofSmallTrees(t *testing.T) {
	leaf := func(s string) []byte {
		h := sha256.New()
		h.Write([]byte{0x00})
		h.Write([]byte(s))
		return h.Sum(nil)
	}
	a, bb, c, d := leaf("a"), leaf("b"), leaf("c"), leaf("d")

	// Size 1: the leaf is the root, and the proof is empty.
	got, err := rootFromInclusionProof(a, 0, 1, nil)
	if err != nil || string(got) != string(a) {
		t.Errorf("size 1: %x, %v", got, err)
	}

	// Size 2: root = H(a, b), proof for leaf 0 is [b], for leaf 1 is [a].
	ab := hashChildren(a, bb)
	if got, err := rootFromInclusionProof(a, 0, 2, [][]byte{bb}); err != nil || string(got) != string(ab) {
		t.Errorf("size 2 leaf 0: %x, %v", got, err)
	}
	if got, err := rootFromInclusionProof(bb, 1, 2, [][]byte{a}); err != nil || string(got) != string(ab) {
		t.Errorf("size 2 leaf 1: %x, %v", got, err)
	}

	// Size 4: root = H(H(a,b), H(c,d)); leaf 2's path is [d, H(a,b)].
	cd := hashChildren(c, d)
	root := hashChildren(ab, cd)
	if got, err := rootFromInclusionProof(c, 2, 4, [][]byte{d, ab}); err != nil || string(got) != string(root) {
		t.Errorf("size 4 leaf 2: %x, %v", got, err)
	}

	// Size 3 exercises the border path: root = H(H(a,b), c), leaf 2 has [ab].
	root3 := hashChildren(ab, c)
	if got, err := rootFromInclusionProof(c, 2, 3, [][]byte{ab}); err != nil || string(got) != string(root3) {
		t.Errorf("size 3 leaf 2: %x, %v", got, err)
	}

	// Out-of-range indices are refused rather than producing a root.
	if _, err := rootFromInclusionProof(a, 4, 4, nil); !errors.Is(err, ErrProofMalformed) {
		t.Errorf("index == size: %v", err)
	}
	if _, err := rootFromInclusionProof(a, 0, 0, nil); !errors.Is(err, ErrProofMalformed) {
		t.Errorf("empty tree: %v", err)
	}
}

// TestParseCheckpointRejectsGarbage: a malformed checkpoint must be named, not
// half-parsed into something that later compares equal by accident.
func TestParseCheckpointRejectsGarbage(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"no signature":      "origin\n42\ncm9vdA==\n",
		"short body":        "origin\n42\n\n— name AAAAAAAA\n",
		"bad tree size":     "origin\nnotanumber\ncm9vdA==\n\n— name AAAAAAAA\n",
		"bad root hash":     "origin\n42\n!!!notbase64!!!\n\n— name AAAAAAAA\n",
		"no signature line": "origin\n42\ncm9vdA==\n\nnothing here\n",
	}
	for name, envelope := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCheckpoint(envelope); !errors.Is(err, ErrCheckpointBad) {
				t.Errorf("error = %v, want ErrCheckpointBad", err)
			}
		})
	}
}

// TestCheckpointMustMatchTheProof: a valid proof paired with an unrelated
// signed checkpoint is not evidence of anything.
func TestCheckpointMustMatchTheProof(t *testing.T) {
	root, _ := base64.StdEncoding.DecodeString("cm9vdA==")
	cp := &Checkpoint{TreeSize: 42, RootHash: root}
	if err := cp.MatchesProof(&InclusionProof{TreeSize: 42, RootHash: root}); err != nil {
		t.Errorf("matching checkpoint rejected: %v", err)
	}
	if err := cp.MatchesProof(&InclusionProof{TreeSize: 43, RootHash: root}); !errors.Is(err, ErrCheckpointRoot) {
		t.Errorf("size mismatch accepted: %v", err)
	}
	other, _ := base64.StdEncoding.DecodeString("b3RoZXI=")
	if err := cp.MatchesProof(&InclusionProof{TreeSize: 42, RootHash: other}); !errors.Is(err, ErrCheckpointRoot) {
		t.Errorf("root mismatch accepted: %v", err)
	}
}
