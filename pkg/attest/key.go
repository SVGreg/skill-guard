package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Supported signing algorithms.
//
// Ed25519 is SGMT-1's algorithm and stays the default: it is what every
// existing attestation and trust roster entry uses. ECDSA P-256 exists because
// OMS requires it — its algorithm registry mandates EC P-256/384/521 for the
// key and certificate signing methods and does not include Ed25519, so an OMS
// bundle signed with an Ed25519 key is one other implementations may refuse
// (docs/oms-notes.md §3).
const (
	AlgEd25519   = "ed25519"
	AlgECDSAP256 = "ecdsa-p256"
)

// ErrUnsupportedAlgorithm is returned for a key file or --type naming a scheme
// this build does not implement.
var ErrUnsupportedAlgorithm = errors.New("unsupported key algorithm")

// SupportedAlgorithms lists what keygen accepts, default first.
var SupportedAlgorithms = []string{AlgEd25519, AlgECDSAP256}

// keyFile is the on-disk private key format (the self-contained ".key"). It
// carries both halves, so signing needs only this one file. NOTE: stored
// unencrypted at mode 0600 for first drop; encryption-at-rest (age vs secretbox)
// is a tracked M2 decision (PROGRESS.md). Do not commit keys.
type keyFile struct {
	KeyID      string `json:"keyid"`
	Algorithm  string `json:"algorithm"`
	PrivateKey string `json:"private_key"` // base64 std of the 32-byte seed
	PublicKey  string `json:"public_key"`  // base64 std
}

// pubFile is the public-only ".pub" companion — safe to share, commit, or drop
// into a policy trust roster. It is purely additive: the public key is always
// derivable from the ".key", so ".pub" is a convenience, never required for
// signing or verification.
type pubFile struct {
	KeyID     string `json:"keyid"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"` // base64 std
}

// LocalSigner is a signer backed by an in-memory private key. Exactly one of
// the key fields is set, according to alg.
type LocalSigner struct {
	keyID string
	alg   string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	ec    *ecdsa.PrivateKey
}

// KeyID returns the signer's key identifier.
func (s *LocalSigner) KeyID() string { return s.keyID }

// Algorithm returns the signer's algorithm identifier.
func (s *LocalSigner) Algorithm() string {
	if s.alg == "" {
		return AlgEd25519 // keys created before the field existed
	}
	return s.alg
}

// Sign produces a signature over pae.
//
// ECDSA signs the SHA-256 of the PAE and emits ASN.1 DER, which is what
// DSSE/Sigstore consumers expect; Ed25519 signs the PAE directly, as it always
// has, so existing attestations verify unchanged.
func (s *LocalSigner) Sign(_ context.Context, pae []byte) ([]byte, error) {
	switch s.Algorithm() {
	case AlgECDSAP256:
		digest := sha256.Sum256(pae)
		return ecdsa.SignASN1(rand.Reader, s.ec, digest[:])
	case AlgEd25519:
		return ed25519.Sign(s.priv, pae), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, s.alg)
	}
}

// PublicKeyBase64 returns the base64-encoded public key: raw 32 bytes for
// Ed25519 (unchanged, so existing rosters keep working) and PKIX DER for
// ECDSA, which is the only self-describing encoding for an EC point.
func (s *LocalSigner) PublicKeyBase64() string {
	switch s.Algorithm() {
	case AlgECDSAP256:
		der, err := x509.MarshalPKIXPublicKey(&s.ec.PublicKey)
		if err != nil {
			return ""
		}
		return base64.StdEncoding.EncodeToString(der)
	default:
		return base64.StdEncoding.EncodeToString(s.pub)
	}
}

// GenerateKey creates a new Ed25519 key pair with a derived key ID.
func GenerateKey(keyID string) (*LocalSigner, error) {
	return GenerateKeyAlg(keyID, AlgEd25519)
}

// GenerateKeyAlg creates a key pair for the named algorithm. The key ID, when
// not supplied, is derived from the public key so it is stable and collision-
// resistant across both schemes.
func GenerateKeyAlg(keyID, alg string) (*LocalSigner, error) {
	switch alg {
	case "", AlgEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &LocalSigner{keyID: derivedKeyID(keyID, pub), alg: AlgEd25519, priv: priv, pub: pub}, nil
	case AlgECDSAP256:
		ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
		if err != nil {
			return nil, err
		}
		return &LocalSigner{keyID: derivedKeyID(keyID, der), alg: AlgECDSAP256, ec: ec}, nil
	default:
		return nil, fmt.Errorf("%w: %q (supported: %s)", ErrUnsupportedAlgorithm, alg, strings.Join(SupportedAlgorithms, ", "))
	}
}

func derivedKeyID(keyID string, pub []byte) string {
	if keyID != "" {
		return keyID
	}
	sum := sha256.Sum256(pub)
	return "sg-" + hex.EncodeToString(sum[:6])
}

// SaveKey writes the signer's key to path at mode 0600.
func SaveKey(s *LocalSigner, path string) error {
	var privBytes []byte
	switch s.Algorithm() {
	case AlgECDSAP256:
		der, err := x509.MarshalPKCS8PrivateKey(s.ec)
		if err != nil {
			return err
		}
		privBytes = der
	default:
		privBytes = s.priv.Seed()
	}
	kf := keyFile{
		KeyID:      s.keyID,
		Algorithm:  s.Algorithm(),
		PrivateKey: base64.StdEncoding.EncodeToString(privBytes),
		PublicKey:  s.PublicKeyBase64(),
	}
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return writeSecret(path, data)
}

// writeSecret writes private key material to path, forcing mode 0600 even when
// path already exists. os.WriteFile applies its perm argument only when it
// creates the file, so writing over a pre-existing world-readable file (a
// restored backup, a stray `touch`, an earlier tool) would silently leave the
// seed at 0644 while keygen reports "mode 0600". Symlinks are refused rather
// than followed, matching the bundle walk's Lstat guard in pkg/skill.
func writeSecret(path string, data []byte) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write a private key through symlink %q", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	// Chmod before the seed is written: if the mode cannot be tightened the
	// file is still empty when we bail out.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("cannot restrict %q to mode 0600: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// PubPath derives the ".pub" companion path for a ".key" path: "publisher.key"
// -> "publisher.pub"; a path without a ".key" suffix simply gets ".pub".
func PubPath(keyPath string) string {
	if strings.HasSuffix(keyPath, ".key") {
		return strings.TrimSuffix(keyPath, ".key") + ".pub"
	}
	return keyPath + ".pub"
}

// SavePub writes the signer's public half to path. A newly created file gets
// mode 0644; an existing file keeps its own mode, because os.WriteFile applies
// its perm argument only on creation. That is harmless — the ".pub" carries no
// secret — but it means the mode is not guaranteed, so callers must report the
// mode they observe rather than the one requested here (see keygen).
func SavePub(s *LocalSigner, path string) error {
	pf := pubFile{
		KeyID:     s.keyID,
		Algorithm: s.Algorithm(),
		PublicKey: s.PublicKeyBase64(),
	}
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadKey reads a signer from a key file (size-capped, see maxAttestFileSize —
// a key file is a few hundred bytes, so pointing --key at something huge is a
// mistake to refuse, not a read to attempt). The declared algorithm is enforced:
// Ed25519 is the only scheme this signer implements, so a key file naming any
// other one is rejected instead of being silently loaded as Ed25519 and then
// attested as "ed25519" — a claim that would not match the file it came from.
// An empty algorithm is accepted for keys written before the field was
// meaningful; those are Ed25519 by construction.
func LoadKey(path string) (*LocalSigner, error) {
	data, err := readCapped(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	priv, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key")
	}
	switch alg := strings.ToLower(strings.TrimSpace(kf.Algorithm)); alg {
	case "", AlgEd25519:
		if len(priv) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid private key")
		}
		key := ed25519.NewKeyFromSeed(priv)
		return &LocalSigner{keyID: kf.KeyID, alg: AlgEd25519, priv: key, pub: key.Public().(ed25519.PublicKey)}, nil
	case AlgECDSAP256:
		parsed, err := x509.ParsePKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("invalid private key")
		}
		ec, ok := parsed.(*ecdsa.PrivateKey)
		if !ok || ec.Curve != elliptic.P256() {
			// A P-384 key in a file labelled ecdsa-p256 would otherwise sign
			// with the wrong curve and be attested under a false algorithm.
			return nil, fmt.Errorf("invalid private key: not an ECDSA P-256 key")
		}
		return &LocalSigner{keyID: kf.KeyID, alg: AlgECDSAP256, ec: ec}, nil
	default:
		return nil, fmt.Errorf("%w %q (supported: %s)", ErrUnsupportedAlgorithm, kf.Algorithm, strings.Join(SupportedAlgorithms, ", "))
	}
}
