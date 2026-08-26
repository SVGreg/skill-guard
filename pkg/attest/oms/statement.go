package oms

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
)

// Manifest, root digest, and statement assembly per OMS v1.0 §5, §6.4–§6.6.

var (
	ErrDigestNotHex     = errors.New("oms: resource digest is not hex")
	ErrUnsortedManifest = errors.New("oms: resources are not sorted by name")
	ErrEmptyManifest    = errors.New("oms: manifest has no resources")
)

// BuildResources hashes each enumerated file into a resource descriptor
// (§5.2.1, §6.3.1) and returns them sorted by name. Input from Enumerate is
// already sorted; sorting again keeps this function correct on its own, since
// the root digest is defined over *canonical* order and a caller that built the
// slice another way would otherwise get a different — and wrong — root.
func BuildResources(files []EnumFile) []Resource {
	out := make([]Resource, 0, len(files))
	for _, f := range files {
		sum := sha256.Sum256(f.Content)
		out = append(out, Resource{
			Name:      f.Name,
			Digest:    hex.EncodeToString(sum[:]),
			Algorithm: AlgoSHA256,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RootDigest computes §6.5.1: take the resources in canonical order, convert
// each hex digest to raw bytes, concatenate, and SHA-256 the result.
//
// Two details the spec is explicit about and that are easy to get wrong: the
// *raw bytes* are concatenated, not the hex strings, and the root is always
// SHA-256 even when the file digests use blake3.
func RootDigest(resources []Resource) (string, error) {
	if len(resources) == 0 {
		return "", ErrEmptyManifest
	}
	if !sort.SliceIsSorted(resources, func(i, j int) bool { return resources[i].Name < resources[j].Name }) {
		// Computing a root over an unsorted manifest would produce a digest no
		// other implementation can reproduce, so refuse rather than return one.
		return "", ErrUnsortedManifest
	}
	h := sha256.New()
	for _, r := range resources {
		raw, err := hex.DecodeString(r.Digest)
		if err != nil {
			return "", fmt.Errorf("%w: %q for %q", ErrDigestNotHex, r.Digest, r.Name)
		}
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SubjectName is the value §6.5 asks for: the basename of the signed tree.
// Verifiers must accept any non-empty string here, so this is informational —
// but producers are required to set it, and setting it to something meaningful
// costs nothing.
func SubjectName(root string) string {
	if root == "" {
		return "skill"
	}
	base := path.Base(path.Clean(root))
	if base == "." || base == "/" || base == "" {
		return "skill"
	}
	return base
}

// BuildStatement assembles the in-toto Statement v1 that the DSSE envelope
// signs (§6.6).
func BuildStatement(subjectName string, resources []Resource, ser Serialization) (*Statement, error) {
	root, err := RootDigest(resources)
	if err != nil {
		return nil, err
	}
	if subjectName == "" {
		return nil, errors.New("oms: subject name must not be empty")
	}
	return &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: subjectName, Digest: map[string]string{AlgoSHA256: root}}},
		PredicateType: PredicateType,
		Predicate: &Predicate{
			Resources:     resources,
			Serialization: ser,
		},
	}, nil
}
