package oms

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

// Rekor transparency-log entry verification (RFC 6962 inclusion proofs and
// signed checkpoints).
//
// Why this matters: M4-09 anchors certificate validity on the log's
// integratedTime, and until now that value was simply believed. Anyone who can
// write the signature file can write a timestamp into it. Verifying the
// inclusion proof turns "the bundle claims it was logged then" into "the log
// committed to this entry", and verifying the checkpoint signature against a
// pinned log key turns that into a statement by a log the consumer chose to
// trust. All three steps are offline: the proof travels inside the bundle.

var (
	ErrNoTlogEntry      = errors.New("oms: bundle carries no transparency-log entry")
	ErrNoInclusionProof = errors.New("oms: log entry carries no inclusion proof")
	ErrProofMalformed   = errors.New("oms: malformed inclusion proof")
	ErrProofMismatch    = errors.New("oms: inclusion proof does not reconstruct the log root")
	ErrCheckpointBad    = errors.New("oms: malformed checkpoint")
	ErrCheckpointRoot   = errors.New("oms: checkpoint root does not match the inclusion proof")
)

// TlogEntry is the subset of a Rekor entry needed to verify inclusion.
type TlogEntry struct {
	LogIndex          int64
	LogKeyID          []byte // raw key id from logId.keyId
	IntegratedTime    int64
	CanonicalizedBody []byte
	Proof             *InclusionProof
}

// InclusionProof is an RFC 6962 audit path plus the checkpoint the log signed.
type InclusionProof struct {
	LogIndex   int64
	TreeSize   int64
	RootHash   []byte
	Hashes     [][]byte
	Checkpoint string
}

// wire types mirroring protojson output, where int64 fields are strings and
// bytes fields are base64.
type wireTlogEntry struct {
	LogIndex       json.Number `json:"logIndex"`
	IntegratedTime json.Number `json:"integratedTime"`
	LogID          struct {
		KeyID string `json:"keyId"`
	} `json:"logId"`
	CanonicalizedBody string `json:"canonicalizedBody"`
	InclusionProof    *struct {
		LogIndex   json.Number `json:"logIndex"`
		RootHash   string      `json:"rootHash"`
		TreeSize   json.Number `json:"treeSize"`
		Hashes     []string    `json:"hashes"`
		Checkpoint struct {
			Envelope string `json:"envelope"`
		} `json:"checkpoint"`
	} `json:"inclusionProof"`
}

// TlogEntries decodes every transparency-log entry in the bundle.
func TlogEntries(b *Bundle) ([]TlogEntry, error) {
	if b.VerificationMaterial == nil || len(b.VerificationMaterial.TlogEntries) == 0 {
		return nil, ErrNoTlogEntry
	}
	out := make([]TlogEntry, 0, len(b.VerificationMaterial.TlogEntries))
	for i, raw := range b.VerificationMaterial.TlogEntries {
		var w wireTlogEntry
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, fmt.Errorf("oms: log entry %d is malformed: %w", i, err)
		}
		e := TlogEntry{}
		e.LogIndex, _ = w.LogIndex.Int64()
		e.IntegratedTime, _ = w.IntegratedTime.Int64()
		e.LogKeyID, _ = base64.StdEncoding.DecodeString(w.LogID.KeyID)
		body, err := base64.StdEncoding.DecodeString(w.CanonicalizedBody)
		if err != nil {
			return nil, fmt.Errorf("oms: log entry %d body is not base64: %w", i, err)
		}
		e.CanonicalizedBody = body

		if w.InclusionProof != nil {
			p := &InclusionProof{Checkpoint: w.InclusionProof.Checkpoint.Envelope}
			p.LogIndex, _ = w.InclusionProof.LogIndex.Int64()
			p.TreeSize, _ = w.InclusionProof.TreeSize.Int64()
			p.RootHash, err = base64.StdEncoding.DecodeString(w.InclusionProof.RootHash)
			if err != nil {
				return nil, fmt.Errorf("oms: log entry %d root hash is not base64: %w", i, err)
			}
			for j, h := range w.InclusionProof.Hashes {
				raw, err := base64.StdEncoding.DecodeString(h)
				if err != nil {
					return nil, fmt.Errorf("oms: log entry %d proof hash %d is not base64: %w", i, j, err)
				}
				p.Hashes = append(p.Hashes, raw)
			}
			e.Proof = p
		}
		out = append(out, e)
	}
	return out, nil
}

// LeafHash is the RFC 6962 leaf hash of the entry's canonicalized body:
// SHA-256 over a 0x00 domain-separation prefix and the body. The prefix is what
// stops a leaf from being reinterpreted as an interior node.
func (e TlogEntry) LeafHash() []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(e.CanonicalizedBody)
	return h.Sum(nil)
}

// VerifyInclusion recomputes the log root from the entry's audit path and
// compares it with the root the proof claims (RFC 6962 §2.1.1).
//
// This establishes that the entry really is in a tree with that root. It says
// nothing about *whose* tree — that is what the checkpoint signature is for.
func (e TlogEntry) VerifyInclusion() error {
	if e.Proof == nil {
		return ErrNoInclusionProof
	}
	got, err := rootFromInclusionProof(e.LeafHash(), e.Proof.LogIndex, e.Proof.TreeSize, e.Proof.Hashes)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, e.Proof.RootHash) {
		return fmt.Errorf("%w: computed %x, proof claims %x", ErrProofMismatch, got, e.Proof.RootHash)
	}
	return nil
}

// rootFromInclusionProof is the standard RFC 6962 reconstruction: walk the
// audit path from the leaf, folding left or right according to the bits of the
// leaf index, then fold the remaining border hashes to the right.
func rootFromInclusionProof(leafHash []byte, index, size int64, proof [][]byte) ([]byte, error) {
	if size <= 0 || index < 0 || index >= size {
		return nil, fmt.Errorf("%w: index %d in a tree of size %d", ErrProofMalformed, index, size)
	}
	inner := bits.Len64(uint64(index) ^ uint64(size-1))
	border := bits.OnesCount64(uint64(index) >> uint(inner))
	if len(proof) != inner+border {
		return nil, fmt.Errorf("%w: %d hashes, expected %d", ErrProofMalformed, len(proof), inner+border)
	}
	for _, h := range proof {
		if len(h) != sha256.Size {
			return nil, fmt.Errorf("%w: a proof hash is %d bytes, expected %d", ErrProofMalformed, len(h), sha256.Size)
		}
	}

	res := leafHash
	for i, h := range proof[:inner] {
		if (index>>uint(i))&1 == 0 {
			res = hashChildren(res, h)
		} else {
			res = hashChildren(h, res)
		}
	}
	for _, h := range proof[inner:] {
		res = hashChildren(h, res)
	}
	return res, nil
}

// hashChildren is the RFC 6962 interior node hash: SHA-256 over a 0x01 prefix
// and the two children.
func hashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Checkpoint is a parsed signed note: the log's commitment to a tree size and
// root hash, plus the signature over that commitment.
type Checkpoint struct {
	Origin   string
	TreeSize int64
	RootHash []byte
	// Signed is the exact byte range the signature covers — the note body,
	// including its trailing blank line.
	Signed []byte
	// KeyHint is the first four bytes of the log key's hash, as carried in the
	// signature line; it identifies which key signed without being a security
	// property of its own.
	KeyHint   []byte
	Signature []byte
}

// ParseCheckpoint parses a signed-note checkpoint:
//
//	<origin>\n<tree size>\n<base64 root hash>\n[optional extra lines]\n
//	— <key name> <base64 4-byte key hint || signature>\n
func ParseCheckpoint(envelope string) (*Checkpoint, error) {
	if envelope == "" {
		return nil, fmt.Errorf("%w: empty", ErrCheckpointBad)
	}
	// The note body and the signature block are separated by a blank line. The
	// signature covers the body *including* that terminating newline.
	idx := strings.Index(envelope, "\n\n")
	if idx < 0 {
		return nil, fmt.Errorf("%w: no signature block", ErrCheckpointBad)
	}
	body := envelope[:idx+1]
	sigBlock := envelope[idx+2:]

	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("%w: body has %d lines, expected at least 3", ErrCheckpointBad, len(lines))
	}
	size, err := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: tree size %q", ErrCheckpointBad, lines[1])
	}
	root, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[2]))
	if err != nil {
		return nil, fmt.Errorf("%w: root hash is not base64", ErrCheckpointBad)
	}

	// Signature line: "— <name> <base64>". The dash is an em dash (U+2014).
	var sigLine string
	for _, l := range strings.Split(sigBlock, "\n") {
		if strings.HasPrefix(l, "— ") {
			sigLine = l
			break
		}
	}
	if sigLine == "" {
		return nil, fmt.Errorf("%w: no signature line", ErrCheckpointBad)
	}
	fields := strings.Fields(sigLine)
	if len(fields) < 3 {
		return nil, fmt.Errorf("%w: signature line has %d fields", ErrCheckpointBad, len(fields))
	}
	blob, err := base64.StdEncoding.DecodeString(fields[len(fields)-1])
	if err != nil || len(blob) < 5 {
		return nil, fmt.Errorf("%w: signature is not base64", ErrCheckpointBad)
	}
	return &Checkpoint{
		Origin:    strings.TrimSpace(lines[0]),
		TreeSize:  size,
		RootHash:  root,
		Signed:    []byte(body),
		KeyHint:   blob[:4],
		Signature: blob[4:],
	}, nil
}

// MatchesProof reports whether the checkpoint commits to the same tree the
// inclusion proof was built against. Without this, a valid proof could be
// paired with an unrelated signed checkpoint.
func (c *Checkpoint) MatchesProof(p *InclusionProof) error {
	if p == nil {
		return ErrNoInclusionProof
	}
	if c.TreeSize != p.TreeSize || !bytes.Equal(c.RootHash, p.RootHash) {
		return fmt.Errorf("%w: checkpoint is size %d root %x, proof is size %d root %x",
			ErrCheckpointRoot, c.TreeSize, c.RootHash, p.TreeSize, p.RootHash)
	}
	return nil
}
