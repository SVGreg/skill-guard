// Package attest implements skill-guard provenance: the SGMT-1 Merkle root over
// a bundle, DSSE Ed25519 signing, the attestation statement, and USF manifest
// fields. This is the interop core specified in design §7.
package attest

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"

	"github.com/skillguard/skill-guard/pkg/skill"
)

// Domain-separation prefixes (RFC 6962-style, design §7.1).
const (
	leafPrefix     = 0x00
	interiorPrefix = 0x01
)

// FileLeaf is one (path, content-hash) input to the tree.
type FileLeaf struct {
	Path   string
	SHA256 [32]byte
}

// BundleLeaves builds the sorted leaf set for a bundle, hashing SKILL.md in its
// normalized form so USF manifest fields can be added without changing the root
// (design §7.1/§7.5). NOTE: Unicode NFC path normalization is a documented gap
// for first drop; ASCII paths (all current fixtures) are unaffected.
func BundleLeaves(b *skill.Bundle) []FileLeaf {
	leaves := make([]FileLeaf, 0, len(b.Files))
	for _, f := range b.Files {
		content := f.Content
		if f.Path == "SKILL.md" {
			content = NormalizeSkillMD(content)
		}
		leaves = append(leaves, FileLeaf{Path: f.Path, SHA256: sha256.Sum256(content)})
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].Path < leaves[j].Path })
	return leaves
}

// MerkleRoot computes the SGMT-1 root as "sha256:<hex>". Empty set is invalid
// and returns "".
func MerkleRoot(leaves []FileLeaf) string {
	if len(leaves) == 0 {
		return ""
	}
	level := make([][32]byte, len(leaves))
	for i, lf := range leaves {
		level[i] = leafHash(lf)
	}
	for len(level) > 1 {
		var next [][32]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i]) // odd node promoted unchanged
				continue
			}
			next = append(next, interiorHash(level[i], level[i+1]))
		}
		level = next
	}
	return "sha256:" + hex.EncodeToString(level[0][:])
}

// leafHash = SHA256(0x00 || uvarint(len(path)) || path || file_sha256).
func leafHash(lf FileLeaf) [32]byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(len(lf.Path)))
	h.Write(buf[:n])
	h.Write([]byte(lf.Path))
	h.Write(lf.SHA256[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// interiorHash = SHA256(0x01 || left || right).
func interiorHash(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{interiorPrefix})
	h.Write(l[:])
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

var (
	fmBlockRe    = regexp.MustCompile(`(?s)\A(\x{FEFF}?---\r?\n)(.*?)(\r?\n---\r?\n?)`)
	reservedLine = regexp.MustCompile(`(?im)^(content_hash|signature):.*\r?\n?`)
)

// NormalizeSkillMD strips the two USF reserved front-matter lines
// (content_hash, signature) so the manifest can carry them without altering the
// Merkle leaf (design §7.5). Line-based, front-matter block only.
func NormalizeSkillMD(content []byte) []byte {
	m := fmBlockRe.FindSubmatchIndex(content)
	if m == nil {
		return content
	}
	open := content[m[2]:m[3]]
	body := content[m[4]:m[5]]
	closeD := content[m[6]:m[7]]
	rest := content[m[1]:]
	cleaned := reservedLine.ReplaceAll(body, nil)
	var out []byte
	out = append(out, open...)
	out = append(out, cleaned...)
	out = append(out, closeD...)
	out = append(out, rest...)
	return out
}

// StripReservedLines removes content_hash/signature lines from a front-matter
// string (used when emitting USF fields idempotently).
func StripReservedLines(fm string) string {
	return reservedLine.ReplaceAllString(fm, "")
}

// TrimSpaceKeys is a tiny helper kept for symmetry/testing.
func TrimSpaceKeys(s string) string { return strings.TrimSpace(s) }
