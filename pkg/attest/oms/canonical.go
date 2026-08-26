package oms

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/SVGreg/skill-guard/pkg/skill"
)

// Path canonicalization and file enumeration per OMS v1.0 §6.1–§6.2.
//
// This is the part of OMS interop that fails *silently* when it is wrong: a
// verifier that canonicalizes one byte differently computes different digests
// and reports a tampered bundle. Every rule below is the spec's, with its
// section cited, rather than a reasonable-looking approximation.

// DefaultIgnorePaths are the exclusions §6.2 makes mandatory. They match as
// **top-level components only**: `.git` excludes `<root>/.git` and its subtree,
// but never `subdir/.git` (§6.2.1).
var DefaultIgnorePaths = []string{".git", ".gitattributes", ".github", ".gitignore"}

// SignatureFileNames are skill-guard's own signature outputs, which §6.2
// requires be excluded from their own manifest. The OMS spec does not mandate a
// filename — it asks only for a `.sig` extension beside the tree (§9) — so
// these are our choice, and are documented as such.
var SignatureFileNames = []string{"skill.oms.sig", "SKILL.md.skillsig"}

var (
	ErrAbsolutePath    = errors.New("oms: path must be relative to the bundle root")
	ErrParentTraversal = errors.New("oms: path must not contain a '..' component")
	ErrEmptyPath       = errors.New("oms: path is empty after canonicalization")
	ErrNotUTF8         = errors.New("oms: path is not valid UTF-8")
	ErrDuplicatePath   = errors.New("oms: two files canonicalize to the same name")
	ErrNoFiles         = errors.New("oms: nothing left to sign after exclusions")
	ErrIgnoreGlob      = errors.New("oms: ignore paths must not contain glob characters")
)

// CanonicalPath applies §6.1.2 to one tree-relative path.
//
// Deliberately *not* done here: case folding and Unicode normalization. §6.1.2
// rule 6 makes comparison byte-exact, so `Model.bin` and `model.bin` are two
// resources; folding them would make our manifest disagree with every other
// implementation's.
func CanonicalPath(p string) (string, error) {
	if !utf8.ValidString(p) {
		// Rule 7: a non-UTF-8 name cannot be losslessly represented in the
		// JSON bundle, so the spec requires rejecting the file rather than
		// transcoding it into something the verifier will not find.
		return "", fmt.Errorf("%w: %q", ErrNotUTF8, p)
	}
	if strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%w: %q", ErrAbsolutePath, p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: %q", ErrParentTraversal, p)
		}
	}
	// path.Clean handles rules 3 and 4: `./` prefixes, interior `.`, repeated
	// separators, and trailing slashes.
	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == "" {
		return "", fmt.Errorf("%w: %q", ErrEmptyPath, p)
	}
	// Clean can still surface a leading ".." when the path climbed above the
	// root before collapsing (e.g. "a/../../b").
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("%w: %q", ErrParentTraversal, p)
	}
	if strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("%w: %q", ErrAbsolutePath, p)
	}
	return cleaned, nil
}

// EnumFile is one enumerated regular file: its canonical OMS name and the
// content that will be hashed.
type EnumFile struct {
	Name    string
	Content []byte
}

// EnumOptions tunes enumeration. The zero value is what skill-guard signs with.
type EnumOptions struct {
	// SingleFile makes the resource name the basename only (§6.1.2 rule 5).
	SingleFile bool
	// ExtraIgnorePaths are user exclusions, matched as **exact relative paths**
	// from the root — `cache` excludes `<root>/cache` and its subtree, never
	// `subdir/cache` (§6.2.1). Globs are rejected.
	ExtraIgnorePaths []string
}

// Enumerate applies §6.1 to a parsed bundle: regular files only, canonical
// names, exclusions applied, sorted lexicographically by name. It returns the
// files together with the serialization metadata that records how the set was
// produced, which is what lets a verifier reproduce it (§5.2.2).
//
// Symlinks need no handling here: the bundle loader refuses to follow them at
// all (`cmd/skill-guard/ux.go`), which is exactly the spec's default
// `allow_symlinks: false` — and the spec expects that mode to become the only
// one.
func Enumerate(b *skill.Bundle, opt EnumOptions) ([]EnumFile, Serialization, error) {
	ignores, err := ignoreSet(opt.ExtraIgnorePaths)
	if err != nil {
		return nil, Serialization{}, err
	}

	files := make([]EnumFile, 0, len(b.Files))
	seen := make(map[string]string, len(b.Files))
	for _, f := range b.Files {
		name, err := CanonicalPath(f.Path)
		if err != nil {
			return nil, Serialization{}, err
		}
		if opt.SingleFile {
			name = path.Base(name)
		}
		if excluded(name, ignores) {
			continue
		}
		if prev, dup := seen[name]; dup {
			// Two distinct source paths collapsing to one name would silently
			// drop a file from the manifest, and §8.4 would then report the
			// survivor as an unsigned file. Fail loudly instead.
			return nil, Serialization{}, fmt.Errorf("%w: %q and %q both become %q", ErrDuplicatePath, prev, f.Path, name)
		}
		seen[name] = f.Path
		files = append(files, EnumFile{Name: name, Content: f.Content})
	}
	if len(files) == 0 {
		// §6.1 rule 1: an empty model MUST be rejected.
		return nil, Serialization{}, ErrNoFiles
	}

	// §5.2.1: sorted lexicographically by name, Unicode code point order —
	// which is what Go's string comparison already is.
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	return files, Serialization{
		Method:        MethodFiles,
		HashType:      AlgoSHA256,
		AllowSymlinks: false,
		IgnorePaths:   ignores,
	}, nil
}

// ignoreSet merges the mandatory exclusions, skill-guard's signature files, and
// any user entries into the sorted list recorded in serialization.ignore_paths.
func ignoreSet(extra []string) ([]string, error) {
	set := map[string]bool{}
	for _, p := range DefaultIgnorePaths {
		set[p] = true
	}
	for _, p := range SignatureFileNames {
		set[p] = true
	}
	for _, p := range extra {
		if strings.ContainsAny(p, "*?[") {
			return nil, fmt.Errorf("%w: %q", ErrIgnoreGlob, p)
		}
		clean, err := CanonicalPath(p)
		if err != nil {
			return nil, err
		}
		set[clean] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// excluded reports whether a canonical name is covered by an ignore entry —
// either the entry itself or anything beneath it, since excluding a directory
// excludes its subtree (§6.2.1).
func excluded(name string, ignores []string) bool {
	for _, ig := range ignores {
		if name == ig || strings.HasPrefix(name, ig+"/") {
			return true
		}
	}
	return false
}
