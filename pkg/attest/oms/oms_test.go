package oms

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func read(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "vectors", rel))
	if err != nil {
		t.Fatalf("read vector: %v (see testdata/README.md)", err)
	}
	return data
}

// TestValidVectorsParse is the M4-02 acceptance check: every bundle the spec
// publishes as valid parses into our types, with the signing method, predicate
// type, and resource list recovered. These are produced by the reference
// implementation, so this is interop, not self-consistency.
func TestValidVectorsParse(t *testing.T) {
	cases := []struct {
		file       string
		wantMethod SigningMethod
	}{
		{"valid/key.bundle.json", MethodKey},
		{"valid/certificate.bundle.json", MethodCertificate},
		{"valid/sigstore.bundle.json", MethodSigstore},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			b, err := ParseBundle(read(t, c.file))
			if err != nil {
				t.Fatalf("ParseBundle: %v", err)
			}
			method, err := b.SigningMethod()
			if err != nil {
				t.Fatalf("SigningMethod: %v", err)
			}
			if method != c.wantMethod {
				t.Errorf("signing method = %s, want %s", method, c.wantMethod)
			}

			st, err := b.Statement()
			if err != nil {
				t.Fatalf("Statement: %v", err)
			}
			if st.Type != StatementType {
				t.Errorf("_type = %q, want %q", st.Type, StatementType)
			}
			root, err := st.RootDigest()
			if err != nil {
				t.Fatalf("RootDigest: %v", err)
			}
			if len(root) != 64 {
				t.Errorf("root digest %q is not a 32-byte hex sha256", root)
			}

			// Spec §5.2.1: resources are files only, sorted by name in code
			// point order, each with a digest and an algorithm.
			names := make([]string, 0, len(st.Predicate.Resources))
			for _, r := range st.Predicate.Resources {
				if r.Name == "" || r.Digest == "" || r.Algorithm == "" {
					t.Errorf("incomplete resource: %+v", r)
				}
				names = append(names, r.Name)
			}
			if !sort.StringsAreSorted(names) {
				t.Errorf("resources are not sorted by name: %v", names)
			}
			if st.Predicate.Serialization.HashType == "" || st.Predicate.Serialization.Method == "" {
				t.Errorf("serialization metadata is incomplete: %+v", st.Predicate.Serialization)
			}
			t.Logf("%s: method=%s predicate=%s resources=%d hash=%s symlinks=%v",
				c.file, method, st.PredicateType, len(st.Predicate.Resources),
				st.Predicate.Serialization.HashType, st.Predicate.Serialization.AllowSymlinks)
		})
	}
}

// TestInvalidVectorsRejected: the spec's known-bad bundles must fail, and fail
// for the stated reason rather than by accident.
func TestInvalidVectorsRejected(t *testing.T) {
	cases := []struct {
		file    string
		wantErr error
		atParse bool // rejected by ParseBundle, vs. later by Statement
	}{
		{"invalid/empty.bundle.json", nil, true},
		{"invalid/missing-envelope.bundle.json", ErrNoEnvelope, true},
		{"invalid/missing-verification-material.bundle.json", ErrNoMaterial, true},
		{"invalid/missing-tlog-entries.bundle.json", ErrMissingTlogEnt, true},
		{"invalid-payload/wrong-predicate.bundle.json", ErrPredicateType, false},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			b, err := ParseBundle(read(t, c.file))
			if c.atParse {
				if err == nil {
					t.Fatal("ParseBundle accepted an invalid bundle")
				}
				if c.wantErr != nil && !errors.Is(err, c.wantErr) {
					t.Errorf("ParseBundle error = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBundle: %v", err)
			}
			if _, err := b.Statement(); err == nil {
				t.Fatal("Statement accepted an invalid payload")
			} else if !errors.Is(err, c.wantErr) {
				t.Errorf("Statement error = %v, want %v", err, c.wantErr)
			}
		})
	}
}

// TestBundleRoundTrips: re-encoding a parsed bundle preserves the fields we
// model. Anything we drop here we would drop when re-emitting one.
func TestBundleRoundTrips(t *testing.T) {
	raw := read(t, "valid/key.bundle.json")
	b, err := ParseBundle(raw)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	again, err := ParseBundle(out)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	first, _ := b.Statement()
	second, err := again.Statement()
	if err != nil {
		t.Fatalf("re-parsed statement: %v", err)
	}
	firstRoot, _ := first.RootDigest()
	secondRoot, _ := second.RootDigest()
	if firstRoot != secondRoot {
		t.Errorf("root digest changed across a round trip: %s → %s", firstRoot, secondRoot)
	}
	if len(first.Predicate.Resources) != len(second.Predicate.Resources) {
		t.Errorf("resource count changed across a round trip: %d → %d",
			len(first.Predicate.Resources), len(second.Predicate.Resources))
	}
	if b.MediaType != again.MediaType {
		t.Errorf("mediaType changed across a round trip: %q → %q", b.MediaType, again.MediaType)
	}
}

// TestLegacyPredicateIsNamedNotGuessed: the deprecated v0.2.0 predicate puts
// digests somewhere else entirely, so it must be reported as such rather than
// parsed into an empty resource list.
func TestLegacyPredicateIsNamedNotGuessed(t *testing.T) {
	env := DSSEEnvelope{PayloadType: PayloadType, Signatures: []Signature{{Sig: "x"}}}
	payload, _ := json.Marshal(Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: "m", Digest: map[string]string{"sha256": "ab"}}},
		PredicateType: PredicateTypeLegacy,
	})
	env.Payload = base64.StdEncoding.EncodeToString(payload)
	b := &Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &VerificationMaterial{PublicKey: &PublicKey{Hint: "aa"}},
		DSSEEnvelope:         &env,
	}
	_, err := b.Statement()
	if !errors.Is(err, ErrPredicateType) {
		t.Fatalf("legacy predicate error = %v, want ErrPredicateType", err)
	}
}
