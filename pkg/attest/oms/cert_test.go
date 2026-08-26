package oms

import (
	"testing"
	"time"
)

// TestCertIdentityFromTheSigstoreVector reads a certificate issued by real
// Fulcio infrastructure, which is the only way to know the OID and SAN handling
// is right: a hand-built certificate would only prove we agree with ourselves.
func TestCertIdentityFromTheSigstoreVector(t *testing.T) {
	b, err := ParseBundle(read(t, "valid/sigstore.bundle.json"))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	leaf, _, err := Certificates(b)
	if err != nil {
		t.Fatalf("Certificates: %v", err)
	}
	identity, issuer, err := CertIdentity(leaf)
	if err != nil {
		t.Fatalf("CertIdentity: %v", err)
	}
	if identity != "stefanb@us.ibm.com" {
		t.Errorf("identity = %q, want the certificate's email SAN", identity)
	}
	if issuer != "https://sigstore.verify.ibm.com/oauth2" {
		t.Errorf("issuer = %q, want the Fulcio issuer extension", issuer)
	}

	// The certificate is valid for ten minutes; the log entry falls inside that
	// window. This is why verification anchors on the integrated time.
	when, ok := IntegratedTime(b)
	if !ok {
		t.Fatal("no integrated time in a sigstore bundle")
	}
	if when.Before(leaf.NotBefore) || when.After(leaf.NotAfter) {
		t.Errorf("integrated time %v is outside the certificate window %v..%v", when, leaf.NotBefore, leaf.NotAfter)
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > time.Hour {
		t.Logf("certificate lifetime %v is longer than expected for Fulcio", leaf.NotAfter.Sub(leaf.NotBefore))
	}
}

// TestCertificatesRequiresMaterial: a key-only bundle has no certificate, and
// saying so beats returning a nil certificate for a caller to trip over.
func TestCertificatesRequiresMaterial(t *testing.T) {
	b, err := ParseBundle(read(t, "valid/key.bundle.json"))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if _, _, err := Certificates(b); err == nil {
		t.Error("a key-method bundle returned a certificate")
	}
}

// TestCertificateChainBundleParses: the certificate method carries a chain,
// leaf first, and the intermediates must come back separately.
func TestCertificateChainBundleParses(t *testing.T) {
	b, err := ParseBundle(read(t, "valid/certificate.bundle.json"))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	leaf, intermediates, err := Certificates(b)
	if err != nil {
		t.Fatalf("Certificates: %v", err)
	}
	if leaf == nil {
		t.Fatal("no leaf certificate")
	}
	t.Logf("leaf subject=%q intermediates=%d", leaf.Subject.String(), len(intermediates))
}

func TestIntegratedTimeAbsent(t *testing.T) {
	b, err := ParseBundle(read(t, "valid/key.bundle.json"))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	// The key vector does carry tlogEntries; a bundle with none must report
	// ok=false rather than a zero time that looks like 1970.
	stripped := *b
	vm := *b.VerificationMaterial
	vm.TlogEntries = nil
	stripped.VerificationMaterial = &vm
	if _, ok := IntegratedTime(&stripped); ok {
		t.Error("IntegratedTime reported a time for a bundle with no log entries")
	}
}
