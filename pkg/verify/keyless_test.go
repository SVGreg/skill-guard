package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/attest/oms"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// keylessFixture builds a miniature Fulcio: a CA, a short-lived leaf carrying a
// URI identity and the issuer extension, and an OMS bundle signed by that leaf
// with a transparency-log timestamp inside the certificate's window.
//
// Building it locally rather than borrowing the vendored Sigstore vector is
// deliberate: we cannot sign with that vector's private key, and a verification
// test that cannot produce a *valid* case can only ever prove things fail.
type keylessFixture struct {
	bundle   []byte
	rootPEM  string
	identity string
	issuer   string
	signedAt time.Time
	skill    *skill.Bundle
}

func newKeylessFixture(t *testing.T, identity, issuer string, signedAt time.Time) keylessFixture {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-fulcio"},
		NotBefore:             signedAt.Add(-time.Hour),
		NotAfter:              signedAt.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatalf("identity url: %v", err)
	}
	issuerDER, err := asn1.MarshalWithParams(issuer, "utf8")
	if err != nil {
		t.Fatalf("issuer ext: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		// Fulcio leaves the subject empty and puts identity in the SAN, which
		// is what the extractor must read.
		NotBefore:   signedAt.Add(-time.Minute),
		NotAfter:    signedAt.Add(9 * time.Minute), // short-lived, like Fulcio
		URIs:        []*url.URL{uri},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8},
			Value: issuerDER,
		}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}

	sk := &skill.Bundle{Root: "/tmp/keyless", Files: []skill.File{
		{Path: "SKILL.md", Content: []byte("---\nname: demo\n---\nbody\n")},
	}}
	files, ser, err := oms.Enumerate(sk, oms.EnumOptions{})
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	st, err := oms.BuildStatement("keyless", oms.BuildResources(files), ser)
	if err != nil {
		t.Fatalf("BuildStatement: %v", err)
	}
	payload, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	digest := sha256.Sum256(attest.PAE(oms.PayloadType, payload))
	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tlog, err := json.Marshal(map[string]any{
		"logIndex":       "1",
		"integratedTime": signedAt.Unix(),
	})
	if err != nil {
		t.Fatalf("tlog: %v", err)
	}
	bundle := &oms.Bundle{
		MediaType: oms.BundleMediaType,
		VerificationMaterial: &oms.VerificationMaterial{
			Certificate: &oms.X509Certificate{RawBytes: base64.StdEncoding.EncodeToString(leafDER)},
			TlogEntries: []json.RawMessage{tlog},
		},
		DSSEEnvelope: &oms.DSSEEnvelope{
			Payload:     base64.StdEncoding.EncodeToString(payload),
			PayloadType: oms.PayloadType,
			Signatures:  []oms.Signature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
		},
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	return keylessFixture{bundle: data, rootPEM: rootPEM, identity: identity, issuer: issuer, signedAt: signedAt, skill: sk}
}

const testIdentity = "https://github.com/acme/tools/.github/workflows/sign.yml@refs/heads/main"
const testIssuer = "https://token.actions.githubusercontent.com"

// TestKeylessVerifiesAgainstPinnedRoot is the core of the keyless path: a
// certificate-bound signature verifies with no long-lived key anywhere, against
// a root the consumer pinned themselves.
func TestKeylessVerifiesAgainstPinnedRoot(t *testing.T) {
	f := newKeylessFixture(t, testIdentity, testIssuer, time.Now().Add(-90*24*time.Hour))

	roster := policy.Trust{
		Roots:      []policy.Root{{Name: "test-fulcio", PEM: f.rootPEM}},
		Identities: []policy.IdentityRule{{Pattern: "https://github.com/acme/*", Issuer: testIssuer}},
	}
	res := VerifyOMS(f.skill, f.bundle, roster)

	if res.CertError != "" {
		t.Fatalf("unexpected cert error: %s", res.CertError)
	}
	if !res.SignatureValid || !res.Trusted || !res.MerkleMatch {
		t.Fatalf("keyless bundle not trusted: %+v", res)
	}
	if res.CertIdentity != testIdentity || res.CertIssuer != testIssuer {
		t.Errorf("identity/issuer = %q / %q", res.CertIdentity, res.CertIssuer)
	}
	if res.Publisher != testIdentity {
		t.Errorf("publisher = %q, want the certificate identity", res.Publisher)
	}
	// The certificate expired 90 days ago; verification anchors on the log
	// timestamp, which is the whole reason short-lived certificates work.
	if !res.SignedAt.Equal(f.signedAt.Truncate(time.Second)) {
		t.Errorf("SignedAt = %v, want the integrated time %v", res.SignedAt, f.signedAt)
	}
}

// TestKeylessNeedsRootsConfigured: with no roots, the signature is reported as
// unverifiable — never as valid. skill-guard ships no CA and must not invent one.
func TestKeylessNeedsRootsConfigured(t *testing.T) {
	f := newKeylessFixture(t, testIdentity, testIssuer, time.Now())
	res := VerifyOMS(f.skill, f.bundle, policy.Trust{})
	if res.SignatureValid || res.Trusted {
		t.Fatalf("a keyless signature verified with no roots configured: %+v", res)
	}
	if res.CertError == "" {
		t.Error("no explanation was given for the unverifiable signature")
	}
	if !hasRule(res, "SG-PRV-005") {
		t.Errorf("want SG-PRV-005, got %+v", res.Findings)
	}
}

// TestKeylessRejectsForeignRoot: a certificate from another CA must not verify,
// which is the property that makes pinning meaningful.
func TestKeylessRejectsForeignRoot(t *testing.T) {
	f := newKeylessFixture(t, testIdentity, testIssuer, time.Now())
	other := newKeylessFixture(t, testIdentity, testIssuer, time.Now())

	roster := policy.Trust{Roots: []policy.Root{{Name: "other", PEM: other.rootPEM}}}
	res := VerifyOMS(f.skill, f.bundle, roster)
	if res.SignatureValid || res.Trusted {
		t.Fatalf("a certificate chained to an unpinned root: %+v", res)
	}
	if res.CertError == "" {
		t.Error("no explanation for the rejected chain")
	}
}

// TestKeylessIdentityPolicy: the identity bound into the certificate is subject
// to trust.identities, including issuer scoping.
func TestKeylessIdentityPolicy(t *testing.T) {
	f := newKeylessFixture(t, testIdentity, testIssuer, time.Now())
	base := policy.Trust{Roots: []policy.Root{{Name: "test-fulcio", PEM: f.rootPEM}}}

	// Wrong repo.
	miss := base
	miss.Identities = []policy.IdentityRule{{Pattern: "https://github.com/other/*"}}
	res := VerifyOMS(f.skill, f.bundle, miss)
	if res.Trusted || !res.IdentityRejected {
		t.Errorf("non-matching identity was not rejected: %+v", res)
	}
	if !res.SignatureValid {
		t.Error("the signature itself should still be valid")
	}

	// Right pattern, wrong issuer.
	wrongIssuer := base
	wrongIssuer.Identities = []policy.IdentityRule{{Pattern: "https://github.com/acme/*", Issuer: "https://evil.example/oidc"}}
	if res := VerifyOMS(f.skill, f.bundle, wrongIssuer); res.Trusted {
		t.Error("an identity from another issuer was trusted")
	}

	// Revocation beats a matching rule.
	revoked := base
	revoked.Identities = []policy.IdentityRule{{Pattern: "https://github.com/acme/*"}}
	revoked.Revoked = []string{testIdentity}
	if res := VerifyOMS(f.skill, f.bundle, revoked); res.Trusted || !res.Revoked {
		t.Errorf("a revoked identity was trusted: %+v", res)
	}
}

// TestKeylessRequiresATimestamp: with no transparency-log entry there is no
// trustworthy time to check the certificate window against, and substituting
// "now" would reject every keyless signature older than its certificate's
// few-minute life.
//
// The sigstore method cannot even reach that check — §4.1 requires tlogEntries,
// so such a bundle is malformed and rejected at parse. The reachable case is
// the `certificate` method, where log entries are optional; this test converts
// the fixture into that shape.
func TestKeylessRequiresATimestamp(t *testing.T) {
	f := newKeylessFixture(t, testIdentity, testIssuer, time.Now())
	roster := policy.Trust{Roots: []policy.Root{{Name: "test-fulcio", PEM: f.rootPEM}}}

	var raw map[string]any
	if err := json.Unmarshal(f.bundle, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	vm := raw["verificationMaterial"].(map[string]any)

	// A sigstore-method bundle with its log entries stripped is malformed, not
	// merely untimestamped.
	certRaw := vm["certificate"].(map[string]any)["rawBytes"]
	delete(vm, "tlogEntries")
	strippedSigstore, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res := VerifyOMS(f.skill, strippedSigstore, roster)
	if res.Trusted || res.SignatureValid {
		t.Errorf("a sigstore bundle with no log entries was accepted: %+v", res)
	}
	if !hasRule(res, "SG-PRV-002") {
		t.Errorf("want SG-PRV-002 for a malformed bundle, got %+v", res.Findings)
	}

	// The certificate method allows absent log entries, so it reaches the
	// timestamp check and must fail there with an explanation.
	delete(vm, "certificate")
	vm["x509CertificateChain"] = map[string]any{
		"certificates": []any{map[string]any{"rawBytes": certRaw}},
	}
	asChain, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res = VerifyOMS(f.skill, asChain, roster)
	if res.Trusted || res.SignatureValid {
		t.Errorf("an untimestamped certificate bundle was trusted: %+v", res)
	}
	if res.CertError == "" {
		t.Error("no explanation for the missing timestamp")
	}
}

// TestRootsFromFile: roots may be given by path, resolved relative to the
// policy file so a policy means the same thing from any working directory.
func TestRootsFromFile(t *testing.T) {
	f := newKeylessFixture(t, testIdentity, testIssuer, time.Now())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "roots.pem"), []byte(f.rootPEM), 0o644); err != nil {
		t.Fatalf("write roots: %v", err)
	}
	roster := policy.Trust{Roots: []policy.Root{{Name: "file", Path: "roots.pem"}}}

	if res := VerifyOMSAt(f.skill, f.bundle, roster, dir); !res.SignatureValid {
		t.Errorf("roots from file did not verify: %s", res.CertError)
	}
	// Resolved relative to the policy dir, so the wrong base must fail rather
	// than silently find nothing and report "no roots".
	if res := VerifyOMSAt(f.skill, f.bundle, roster, t.TempDir()); res.SignatureValid {
		t.Error("roots resolved against the wrong directory still verified")
	}
}

// TestKeylessReportsTimestampWithoutRoots: the log timestamp and the bound
// identity are observations about the bundle, not conclusions about it, so they
// must be reported even when no roots are pinned and trust is withheld. A
// reader deciding whether to pin a CA needs exactly these two facts.
func TestKeylessReportsTimestampWithoutRoots(t *testing.T) {
	signedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	f := newKeylessFixture(t, testIdentity, testIssuer, signedAt)

	res := VerifyOMS(f.skill, f.bundle, policy.Trust{})
	if res.Trusted || res.SignatureValid {
		t.Fatalf("trust was granted without roots: %+v", res)
	}
	if res.CertIdentity != testIdentity || res.CertIssuer != testIssuer {
		t.Errorf("identity/issuer withheld: %q / %q", res.CertIdentity, res.CertIssuer)
	}
	if !res.SignedAt.Equal(signedAt) {
		t.Errorf("SignedAt = %v, want %v", res.SignedAt, signedAt)
	}
}
