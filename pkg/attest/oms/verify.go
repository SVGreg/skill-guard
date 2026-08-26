package oms

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// Manifest verification per OMS §8.4–§8.5.

var (
	ErrDigestMismatch = errors.New("oms: file content does not match its signed digest")
	ErrMissingFile    = errors.New("oms: a signed file is missing from the bundle")
	ErrUnsignedFile   = errors.New("oms: bundle contains a file the signature does not cover")
	ErrBadAlgorithm   = errors.New("oms: manifest uses a hash algorithm this build does not implement")
)

// SignedPAE returns the DSSE Pre-Authentication Encoding the bundle's signature
// was made over, for a caller that owns key material and trust decisions. The
// payload is returned as signed — never re-serialized — because re-marshalling
// JSON can change bytes the signature covers.
func SignedPAE(b *Bundle) ([]byte, error) {
	if b.DSSEEnvelope == nil {
		return nil, ErrNoEnvelope
	}
	payload, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("oms: DSSE payload is not valid base64: %w", err)
	}
	return attest.PAE(b.DSSEEnvelope.PayloadType, payload), nil
}

// Signatures returns the decoded signature bytes from the envelope.
func Signatures(b *Bundle) ([][]byte, error) {
	if b.DSSEEnvelope == nil {
		return nil, ErrNoEnvelope
	}
	out := make([][]byte, 0, len(b.DSSEEnvelope.Signatures))
	for _, s := range b.DSSEEnvelope.Signatures {
		raw, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		out = append(out, raw)
	}
	if len(out) == 0 {
		return nil, ErrNoSignatures
	}
	return out, nil
}

// ManifestResult reports what manifest verification found. Callers turn this
// into their own findings; nothing here decides policy.
type ManifestResult struct {
	Matched    int      // files whose content matched their signed digest
	Mismatched []string // files whose content changed
	Missing    []string // signed files absent from the bundle
	Unsigned   []string // files present but not covered by the signature
}

// OK reports whether every signed file is present and unchanged and nothing
// uncovered was added.
func (r ManifestResult) OK() bool {
	return len(r.Mismatched) == 0 && len(r.Missing) == 0 && len(r.Unsigned) == 0
}

// Err summarizes the result as an error, or nil when OK.
func (r ManifestResult) Err() error {
	switch {
	case len(r.Mismatched) > 0:
		return fmt.Errorf("%w: %s", ErrDigestMismatch, strings.Join(r.Mismatched, ", "))
	case len(r.Missing) > 0:
		return fmt.Errorf("%w: %s", ErrMissingFile, strings.Join(r.Missing, ", "))
	case len(r.Unsigned) > 0:
		return fmt.Errorf("%w: %s", ErrUnsignedFile, strings.Join(r.Unsigned, ", "))
	default:
		return nil
	}
}

// VerifyManifest recomputes every file digest in the statement against the
// bundle on disk (§8.4) and reports files the signature does not cover (§8.5).
//
// The ignore list comes from the *statement's* serialization metadata, not from
// our defaults: the signer recorded what they excluded, and a verifier that
// substituted its own list would either invent violations or excuse real ones.
func VerifyManifest(b *skill.Bundle, st *Statement) (ManifestResult, error) {
	var res ManifestResult
	if st == nil || st.Predicate == nil {
		return res, ErrNoResources
	}
	if alg := st.Predicate.Serialization.HashType; alg != "" && alg != AlgoSHA256 {
		// blake2b/blake3 are optional in the registry and not implemented here.
		// Saying so beats reporting every file as mismatched.
		return res, fmt.Errorf("%w: %q", ErrBadAlgorithm, alg)
	}

	// Index the bundle by canonical name.
	onDisk := make(map[string][]byte, len(b.Files))
	for _, f := range b.Files {
		name, err := CanonicalPath(f.Path)
		if err != nil {
			// A path we cannot canonicalize cannot be in a conformant
			// manifest either; report it as uncovered rather than skipping.
			res.Unsigned = append(res.Unsigned, f.Path)
			continue
		}
		onDisk[name] = f.Content
	}

	signed := make(map[string]bool, len(st.Predicate.Resources))
	for _, r := range st.Predicate.Resources {
		signed[r.Name] = true
		content, present := onDisk[r.Name]
		if !present {
			res.Missing = append(res.Missing, r.Name)
			continue
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != strings.ToLower(r.Digest) {
			res.Mismatched = append(res.Mismatched, r.Name)
			continue
		}
		res.Matched++
	}

	ignores := st.Predicate.Serialization.IgnorePaths
	for name := range onDisk {
		if signed[name] || excluded(name, ignores) || excluded(name, DefaultIgnorePaths) || excluded(name, SignatureFileNames) {
			continue
		}
		res.Unsigned = append(res.Unsigned, name)
	}

	sort.Strings(res.Mismatched)
	sort.Strings(res.Missing)
	sort.Strings(res.Unsigned)
	return res, nil
}
