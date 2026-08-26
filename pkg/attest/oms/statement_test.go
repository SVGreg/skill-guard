package oms

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// TestRootDigestMatchesVendoredVectors is the M4-04 acceptance check, and the
// strongest interop signal available offline: recomputing §6.5.1 over a
// reference-implementation bundle's own resource list must reproduce the
// subject digest that bundle was signed over, byte for byte. A canonicalization
// or concatenation mistake shows up here and nowhere else until a real verifier
// rejects us.
func TestRootDigestMatchesVendoredVectors(t *testing.T) {
	for _, file := range []string{
		"valid/key.bundle.json",
		"valid/certificate.bundle.json",
		"valid/sigstore.bundle.json",
	} {
		t.Run(file, func(t *testing.T) {
			b, err := ParseBundle(read(t, file))
			if err != nil {
				t.Fatalf("ParseBundle: %v", err)
			}
			st, err := b.Statement()
			if err != nil {
				t.Fatalf("Statement: %v", err)
			}
			want, err := st.RootDigest()
			if err != nil {
				t.Fatalf("RootDigest: %v", err)
			}
			got, err := RootDigest(st.Predicate.Resources)
			if err != nil {
				t.Fatalf("recompute: %v", err)
			}
			if got != want {
				t.Errorf("recomputed root %s, vector says %s", got, want)
			}
		})
	}
}

// TestRootDigestConcatenatesRawBytes pins the detail most likely to be got
// wrong: §6.5.1 concatenates the *decoded* digest bytes, not the hex strings.
func TestRootDigestConcatenatesRawBytes(t *testing.T) {
	a := sha256.Sum256([]byte("a"))
	b := sha256.Sum256([]byte("b"))
	resources := []Resource{
		{Name: "a.txt", Digest: hex.EncodeToString(a[:]), Algorithm: AlgoSHA256},
		{Name: "b.txt", Digest: hex.EncodeToString(b[:]), Algorithm: AlgoSHA256},
	}

	got, err := RootDigest(resources)
	if err != nil {
		t.Fatalf("RootDigest: %v", err)
	}
	want := sha256.Sum256(append(append([]byte{}, a[:]...), b[:]...))
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("root = %s, want %s", got, hex.EncodeToString(want[:]))
	}

	// The hex-string mistake must not accidentally agree.
	wrong := sha256.Sum256([]byte(resources[0].Digest + resources[1].Digest))
	if got == hex.EncodeToString(wrong[:]) {
		t.Error("root digest was computed over hex strings, not raw bytes")
	}
}

func TestRootDigestRejectsBadInput(t *testing.T) {
	cases := []struct {
		name    string
		res     []Resource
		wantErr error
	}{
		{"empty", nil, ErrEmptyManifest},
		{"unsorted", []Resource{
			{Name: "z.txt", Digest: "00", Algorithm: AlgoSHA256},
			{Name: "a.txt", Digest: "11", Algorithm: AlgoSHA256},
		}, ErrUnsortedManifest},
		{"not hex", []Resource{
			{Name: "a.txt", Digest: "zzzz", Algorithm: AlgoSHA256},
		}, ErrDigestNotHex},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := RootDigest(c.res); !errors.Is(err, c.wantErr) {
				t.Errorf("error = %v, want %v", err, c.wantErr)
			}
		})
	}
}

// TestBuildResourcesHashesAndSorts: descriptors carry the file's own sha256 and
// come back in canonical order regardless of input order.
func TestBuildResourcesHashesAndSorts(t *testing.T) {
	files := []EnumFile{
		{Name: "z.txt", Content: []byte("zed")},
		{Name: "a.txt", Content: []byte("aye")},
		{Name: "m/n.txt", Content: []byte("en")},
	}
	res := BuildResources(files)
	if len(res) != 3 {
		t.Fatalf("got %d resources, want 3", len(res))
	}
	if res[0].Name != "a.txt" || res[1].Name != "m/n.txt" || res[2].Name != "z.txt" {
		t.Errorf("not sorted: %v", []string{res[0].Name, res[1].Name, res[2].Name})
	}
	want := sha256.Sum256([]byte("aye"))
	if res[0].Digest != hex.EncodeToString(want[:]) {
		t.Errorf("a.txt digest = %s, want %s", res[0].Digest, hex.EncodeToString(want[:]))
	}
	for _, r := range res {
		if r.Algorithm != AlgoSHA256 {
			t.Errorf("%s algorithm = %q, want %q", r.Name, r.Algorithm, AlgoSHA256)
		}
	}
}

// TestBuildStatementRoundTripsThroughOurParser: a statement we build must be
// one we accept — the emitter and the verifier cannot drift apart.
func TestBuildStatementRoundTripsThroughOurParser(t *testing.T) {
	files := []EnumFile{
		{Name: "SKILL.md", Content: []byte("---\nname: demo\n---\nbody\n")},
		{Name: "scripts/setup.sh", Content: []byte("#!/bin/sh\necho hi\n")},
	}
	res := BuildResources(files)
	ser := Serialization{Method: MethodFiles, HashType: AlgoSHA256, AllowSymlinks: false}

	st, err := BuildStatement("demo-skill", res, ser)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	if st.Type != StatementType || st.PredicateType != PredicateType {
		t.Errorf("statement types = %q / %q", st.Type, st.PredicateType)
	}
	root, err := st.RootDigest()
	if err != nil {
		t.Fatalf("RootDigest: %v", err)
	}
	recomputed, err := RootDigest(res)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if root != recomputed {
		t.Errorf("statement root %s != recomputed %s", root, recomputed)
	}

	// Changing one byte of one file must change the root — the whole point.
	files[1].Content = append(files[1].Content, '\n')
	changed, err := RootDigest(BuildResources(files))
	if err != nil {
		t.Fatalf("recompute after edit: %v", err)
	}
	if changed == root {
		t.Error("root digest did not change after a file was modified")
	}
}

func TestSubjectName(t *testing.T) {
	cases := map[string]string{
		"/home/u/skills/my-skill":  "my-skill",
		"/home/u/skills/my-skill/": "my-skill",
		"my-skill":                 "my-skill",
		"":                         "skill",
		"/":                        "skill",
		".":                        "skill",
	}
	for in, want := range cases {
		if got := SubjectName(in); got != want {
			t.Errorf("SubjectName(%q) = %q, want %q", in, got, want)
		}
	}
}
