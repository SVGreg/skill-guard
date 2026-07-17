package attest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

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

// LocalSigner is an Ed25519 signer backed by an in-memory private key.
type LocalSigner struct {
	keyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

// KeyID returns the signer's key identifier.
func (s *LocalSigner) KeyID() string { return s.keyID }

// Algorithm returns "ed25519".
func (s *LocalSigner) Algorithm() string { return "ed25519" }

// Sign produces an Ed25519 signature over pae.
func (s *LocalSigner) Sign(_ context.Context, pae []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, pae), nil
}

// PublicKeyBase64 returns the base64-encoded public key.
func (s *LocalSigner) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.pub)
}

// GenerateKey creates a new Ed25519 key pair with a derived key ID.
func GenerateKey(keyID string) (*LocalSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if keyID == "" {
		sum := sha256.Sum256(pub)
		keyID = "sg-" + hex.EncodeToString(sum[:6])
	}
	return &LocalSigner{keyID: keyID, priv: priv, pub: pub}, nil
}

// SaveKey writes the signer's key to path at mode 0600.
func SaveKey(s *LocalSigner, path string) error {
	seed := s.priv.Seed()
	kf := keyFile{
		KeyID:      s.keyID,
		Algorithm:  "ed25519",
		PrivateKey: base64.StdEncoding.EncodeToString(seed),
		PublicKey:  base64.StdEncoding.EncodeToString(s.pub),
	}
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// PubPath derives the ".pub" companion path for a ".key" path: "publisher.key"
// -> "publisher.pub"; a path without a ".key" suffix simply gets ".pub".
func PubPath(keyPath string) string {
	if strings.HasSuffix(keyPath, ".key") {
		return strings.TrimSuffix(keyPath, ".key") + ".pub"
	}
	return keyPath + ".pub"
}

// SavePub writes the signer's public half to path at mode 0644.
func SavePub(s *LocalSigner, path string) error {
	pf := pubFile{
		KeyID:     s.keyID,
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(s.pub),
	}
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadKey reads a signer from a key file.
func LoadKey(path string) (*LocalSigner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid private key")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &LocalSigner{keyID: kf.KeyID, priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}
