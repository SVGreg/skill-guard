package oms

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Certificate identity extraction for the `certificate` and `sigstore` signing
// methods (spec §4.1).
//
// A keyless signature is only as good as the identity bound into its
// certificate, so the fields read here — the SAN and the Fulcio issuer
// extension — are the whole point of the format. Nothing in this file trusts
// anything: it decodes. Chain building and policy admission belong to the
// verifier, which owns the root material.

var (
	ErrNoCertificate = errors.New("oms: bundle carries no signing certificate")
	ErrNoIdentity    = errors.New("oms: certificate carries no usable identity SAN")
)

// Fulcio's OID extensions. 1.1 is the original raw-string issuer; 1.8 is the
// current DER-encoded UTF8String form. Both appear in the wild — the spec's own
// sigstore vector carries both — so both are read, preferring the newer one.
//
// Source: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
var (
	oidIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// Certificates returns the leaf signing certificate and any intermediates the
// bundle carries, decoded from DER.
func Certificates(b *Bundle) (leaf *x509.Certificate, intermediates []*x509.Certificate, err error) {
	vm := b.VerificationMaterial
	if vm == nil {
		return nil, nil, ErrNoMaterial
	}
	var ders [][]byte
	switch {
	case vm.Certificate != nil && vm.Certificate.RawBytes != "":
		der, err := base64.StdEncoding.DecodeString(vm.Certificate.RawBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("oms: certificate is not valid base64: %w", err)
		}
		ders = append(ders, der)
	case vm.X509CertificateChain != nil:
		for i, c := range vm.X509CertificateChain.Certificates {
			der, err := base64.StdEncoding.DecodeString(c.RawBytes)
			if err != nil {
				return nil, nil, fmt.Errorf("oms: certificate %d is not valid base64: %w", i, err)
			}
			ders = append(ders, der)
		}
	}
	if len(ders) == 0 {
		return nil, nil, ErrNoCertificate
	}
	for i, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("oms: certificate %d is not valid DER: %w", i, err)
		}
		if i == 0 {
			leaf = cert
			continue
		}
		intermediates = append(intermediates, cert)
	}
	return leaf, intermediates, nil
}

// CertIdentity returns the signer identity and OIDC issuer bound into a Fulcio
// certificate.
//
// The identity is taken from the SAN in the order Fulcio populates it: a URI
// (workflow identities such as
// "https://github.com/org/repo/.github/workflows/x.yml@refs/heads/main"), then
// an email (human OIDC logins), then a DNS name. The subject CN is deliberately
// ignored — Fulcio leaves it empty, and reading it would invite trusting a
// field an attacker's own CA could populate freely.
func CertIdentity(cert *x509.Certificate) (identity, issuer string, err error) {
	if cert == nil {
		return "", "", ErrNoCertificate
	}
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidIssuerV2):
			// DER-encoded UTF8String.
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err == nil && s != "" {
				issuer = s
			}
		case ext.Id.Equal(oidIssuerV1):
			if issuer == "" {
				issuer = string(ext.Value)
			}
		}
	}
	switch {
	case len(cert.URIs) > 0:
		identity = cert.URIs[0].String()
	case len(cert.EmailAddresses) > 0:
		identity = cert.EmailAddresses[0]
	case len(cert.DNSNames) > 0:
		identity = cert.DNSNames[0]
	default:
		return "", issuer, ErrNoIdentity
	}
	return identity, issuer, nil
}

// tlogEntry is the subset of a Rekor transparency-log entry this package reads.
type tlogEntry struct {
	LogIndex       json.Number `json:"logIndex"`
	IntegratedTime json.Number `json:"integratedTime"`
}

// IntegratedTime returns the earliest Rekor integrated timestamp in the bundle.
//
// Short-lived Fulcio certificates expire in minutes, so "is this certificate
// valid *now*" is the wrong question — every keyless signature would fail
// within the hour. The right question is whether it was valid when the
// signature was logged, which is what the transparency log timestamps. ok is
// false when the bundle carries no log entry, and the caller must then decide
// explicitly rather than silently substituting the current time.
func IntegratedTime(b *Bundle) (time.Time, bool) {
	if b.VerificationMaterial == nil {
		return time.Time{}, false
	}
	var earliest time.Time
	for _, raw := range b.VerificationMaterial.TlogEntries {
		var e tlogEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			continue
		}
		secs, err := e.IntegratedTime.Int64()
		if err != nil || secs <= 0 {
			continue
		}
		t := time.Unix(secs, 0).UTC()
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest, !earliest.IsZero()
}
