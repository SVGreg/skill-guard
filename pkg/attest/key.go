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
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(s.pub),
	}
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadKey reads a signer from a key file. The declared algorithm is enforced:
// Ed25519 is the only scheme this signer implements, so a key file naming any
// other one is rejected instead of being silently loaded as Ed25519 and then
// attested as "ed25519" — a claim that would not match the file it came from.
// An empty algorithm is accepted for keys written before the field was
// meaningful; those are Ed25519 by construction.
func LoadKey(path string) (*LocalSigner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	if alg := strings.ToLower(strings.TrimSpace(kf.Algorithm)); alg != "" && alg != "ed25519" {
		return nil, fmt.Errorf("unsupported key algorithm %q (only ed25519 is supported)", kf.Algorithm)
	}
	seed, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid private key")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &LocalSigner{keyID: kf.KeyID, priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}
