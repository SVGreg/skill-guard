// Package oms models the OpenSSF Model Signing (OMS) v1.0 bundle format —
// a Sigstore bundle whose DSSE payload is an in-toto Statement v1 describing
// every file in a signed tree.
//
// This file is wire types and parsing only; producing and verifying bundles is
// built on top of it (plan M4-04, M4-06, M4-07). Everything here is stdlib:
// the bundle is JSON, so reading and writing it needs none of the Sigstore Go
// stack — that dependency is only required for Fulcio/Rekor, and is deliberately
// kept behind a build tag (docs/oms-notes.md §4).
//
// Spec: https://github.com/ossf/model-signing-spec/blob/main/spec/v1.0.md
// Findings and section references: docs/oms-notes.md
package oms

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// PredicateType is the only predicate type an OMS v1.0 signer may produce
	// (spec §5.1). PredicateTypeLegacy is the deprecated v0.2.0 shape, which
	// verifiers MAY accept and signers MUST NOT produce.
	PredicateType       = "https://model_signing/signature/v1.0"
	PredicateTypeLegacy = "https://model_signing/Digests/v0.1"

	// StatementType is the in-toto Statement v1 type, and PayloadType the DSSE
	// payloadType that carries it (spec §6.6, §6.7).
	StatementType = "https://in-toto.io/Statement/v1"
	PayloadType   = "application/vnd.in-toto+json"

	// MethodFiles is the serialization method skill-guard produces; "shards"
	// exists for large model weights and is not useful for skill bundles.
	MethodFiles  = "files"
	MethodShards = "shards"

	// AlgoSHA256 is the only hash algorithm the spec requires (algorithm
	// registry); blake2b and blake3 are optional and not produced here.
	AlgoSHA256 = "sha256"
)

// SigningMethod is how the bundle's signer identified itself (spec §4.1). It is
// derived from which verificationMaterial fields are present, not from a field
// of its own.
type SigningMethod string

const (
	MethodKey         SigningMethod = "key"         // long-lived public key
	MethodCertificate SigningMethod = "certificate" // long-lived cert chain
	MethodSigstore    SigningMethod = "sigstore"    // Fulcio cert + Rekor entries
	MethodUnknown     SigningMethod = "unknown"
)

// Bundle is the Sigstore bundle envelope OMS rides in (spec §4). Unknown fields
// are preserved by neither this type nor the spec's verification rules —
// verifiers MUST ignore what they do not recognize.
type Bundle struct {
	MediaType            string                `json:"mediaType"`
	VerificationMaterial *VerificationMaterial `json:"verificationMaterial,omitempty"`
	DSSEEnvelope         *DSSEEnvelope         `json:"dsseEnvelope,omitempty"`
}

// VerificationMaterial carries whichever identity material the signing method
// implies (spec §4.1). Exactly one of PublicKey, X509CertificateChain, or
// Certificate is expected to be set.
type VerificationMaterial struct {
	PublicKey            *PublicKey            `json:"publicKey,omitempty"`
	X509CertificateChain *X509CertificateChain `json:"x509CertificateChain,omitempty"`
	Certificate          *X509Certificate      `json:"certificate,omitempty"`
	TlogEntries          []json.RawMessage     `json:"tlogEntries,omitempty"`
	TimestampData        json.RawMessage       `json:"timestampVerificationData,omitempty"`
}

// PublicKey identifies a long-lived key. Producers set Hint to a hex-encoded
// key fingerprint; pre-v1.1.0 bundles used RawBytes, which verifiers should
// still accept (spec §4.1).
type PublicKey struct {
	Hint     string `json:"hint,omitempty"`
	RawBytes string `json:"rawBytes,omitempty"`
}

type X509CertificateChain struct {
	Certificates []X509Certificate `json:"certificates"`
}

type X509Certificate struct {
	RawBytes string `json:"rawBytes"`
}

// DSSEEnvelope is the signed payload (spec §6.7). Payload is base64.
type DSSEEnvelope struct {
	Payload     string      `json:"payload"`
	PayloadType string      `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature. KeyID is optional and is not used for
// verification — the key comes from verificationMaterial (spec §4.1).
type Signature struct {
	Sig   string `json:"sig"`
	KeyID string `json:"keyid,omitempty"`
}

// Statement is the in-toto Statement v1 carried in the DSSE payload (spec §6.6).
type Statement struct {
	Type          string     `json:"_type"`
	Subject       []Subject  `json:"subject"`
	PredicateType string     `json:"predicateType"`
	Predicate     *Predicate `json:"predicate"`
}

// Subject is the tree as a whole: a name (informational — verifiers must accept
// any non-empty string) and the root digest under the key "sha256" (spec §6.5).
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Predicate is the OMS predicate body (spec §5.2).
type Predicate struct {
	Resources     []Resource    `json:"resources"`
	Serialization Serialization `json:"serialization"`
}

// Resource is one regular file. Name is a canonicalized, tree-relative path
// (spec §6.1.2); directories never appear (spec §5.2.1).
type Resource struct {
	Name      string `json:"name"`
	Digest    string `json:"digest"`
	Algorithm string `json:"algorithm"`
}

// Serialization records how the tree was enumerated and hashed, so a verifier
// can reproduce it (spec §5.2.2).
type Serialization struct {
	Method        string   `json:"method"`
	HashType      string   `json:"hash_type"`
	ShardSize     int      `json:"shard_size,omitempty"`
	AllowSymlinks bool     `json:"allow_symlinks"`
	IgnorePaths   []string `json:"ignore_paths,omitempty"`
}

var (
	ErrNoEnvelope     = errors.New("oms: bundle has no dsseEnvelope")
	ErrNoMaterial     = errors.New("oms: bundle has no verificationMaterial")
	ErrPayloadType    = errors.New("oms: unexpected DSSE payloadType")
	ErrPredicateType  = errors.New("oms: unexpected predicateType")
	ErrNoSubject      = errors.New("oms: statement has no subject")
	ErrNoResources    = errors.New("oms: predicate has no resources")
	ErrNoSignatures   = errors.New("oms: DSSE envelope has no signatures")
	ErrNoRootDigest   = errors.New("oms: subject carries no sha256 root digest")
	ErrUnknownMethod  = errors.New("oms: verificationMaterial matches no signing method")
	ErrMissingTlogEnt = errors.New("oms: sigstore signing method requires tlogEntries")
)

// ParseBundle decodes a bundle and checks the structural invariants the spec
// makes mandatory (§4, §5, §8.1). It does not verify the signature or any file
// digest — that is the verifier's job — but a bundle that fails here can never
// verify, so rejecting early gives a better error than a signature mismatch.
func ParseBundle(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("oms: bundle is not valid JSON: %w", err)
	}
	if b.DSSEEnvelope == nil {
		return nil, ErrNoEnvelope
	}
	if len(b.DSSEEnvelope.Signatures) == 0 {
		return nil, ErrNoSignatures
	}
	if b.VerificationMaterial == nil {
		return nil, ErrNoMaterial
	}
	if _, err := b.SigningMethod(); err != nil {
		return nil, err
	}
	return &b, nil
}

// SigningMethod reports which of the three signing methods the material
// describes (spec §4.1). The sigstore method additionally requires at least one
// Rekor entry, which is what separates it from a bare certificate.
func (b *Bundle) SigningMethod() (SigningMethod, error) {
	vm := b.VerificationMaterial
	if vm == nil {
		return MethodUnknown, ErrNoMaterial
	}
	switch {
	case vm.PublicKey != nil:
		return MethodKey, nil
	case vm.X509CertificateChain != nil:
		return MethodCertificate, nil
	case vm.Certificate != nil:
		if len(vm.TlogEntries) == 0 {
			return MethodUnknown, ErrMissingTlogEnt
		}
		return MethodSigstore, nil
	default:
		return MethodUnknown, ErrUnknownMethod
	}
}

// Statement decodes and validates the in-toto statement inside the envelope
// (spec §5, §8.3). The legacy v0.1 predicate type is rejected here: this
// package reads it only to say so clearly, rather than misinterpreting a
// payload whose digests live somewhere else entirely.
func (b *Bundle) Statement() (*Statement, error) {
	if b.DSSEEnvelope == nil {
		return nil, ErrNoEnvelope
	}
	if b.DSSEEnvelope.PayloadType != PayloadType {
		return nil, fmt.Errorf("%w: %q (want %q)", ErrPayloadType, b.DSSEEnvelope.PayloadType, PayloadType)
	}
	raw, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("oms: DSSE payload is not valid base64: %w", err)
	}
	var st Statement
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("oms: DSSE payload is not a valid in-toto statement: %w", err)
	}
	switch st.PredicateType {
	case PredicateType:
	case PredicateTypeLegacy:
		return nil, fmt.Errorf("%w: %q is the deprecated v0.2.0 format", ErrPredicateType, st.PredicateType)
	default:
		return nil, fmt.Errorf("%w: %q (want %q)", ErrPredicateType, st.PredicateType, PredicateType)
	}
	if len(st.Subject) == 0 || st.Subject[0].Name == "" {
		return nil, ErrNoSubject
	}
	if st.Predicate == nil || len(st.Predicate.Resources) == 0 {
		return nil, ErrNoResources
	}
	return &st, nil
}

// RootDigest returns the statement's sha256 root digest (spec §6.5.1).
func (s *Statement) RootDigest() (string, error) {
	if len(s.Subject) == 0 {
		return "", ErrNoSubject
	}
	d := s.Subject[0].Digest[AlgoSHA256]
	if d == "" {
		return "", ErrNoRootDigest
	}
	return d, nil
}
