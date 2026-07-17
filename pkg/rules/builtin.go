package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
)

//go:embed packs/*.yaml
var builtinFS embed.FS

// Builtin loads and compiles all embedded rule-packs. These are compiled into
// the binary (go:embed), so tampering with them is binary tampering; explicit
// signature verification of packs is a hardening item (design §8.2, PROGRESS.md).
func Builtin() ([]*Pack, error) {
	entries, err := fs.Glob(builtinFS, "packs/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	var packs []*Pack
	for _, e := range entries {
		data, err := builtinFS.ReadFile(e)
		if err != nil {
			return nil, err
		}
		p, err := LoadPack(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e, err)
		}
		packs = append(packs, p)
	}
	return packs, nil
}

// AllRules flattens packs into a single ordered rule slice.
func AllRules(packs []*Pack) []*Rule {
	var out []*Rule
	for _, p := range packs {
		out = append(out, p.Rules...)
	}
	return out
}
