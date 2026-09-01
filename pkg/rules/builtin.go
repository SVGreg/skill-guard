package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"sync"
)

//go:embed packs/*.yaml
var builtinFS embed.FS

// The built-in packs are embedded in the binary, so compiling them yields the
// same result every time within a process — yet every caller that did not hand
// its own rules to scan.New or guard.Guard paid for it again. Measured on the
// M5-08 benchmarks, that was ~108 ms and ~17 MB of allocations per cold
// decision, which is most of what a load-time gate costs before its cache warms
// (README, "Measured latency").
var (
	builtinOnce  sync.Once
	builtinPacks []*Pack
	builtinErr   error
)

// Builtin returns the compiled embedded rule-packs. These are compiled into the
// binary (go:embed), so tampering with them is binary tampering; explicit
// signature verification of packs is a hardening item (design §8.2,
// PROGRESS.md).
//
// Compilation happens once per process. The returned *slice* is a fresh copy —
// callers append external --rulepack packs to it (cmd/skill-guard.loadRuleset),
// and appending into a shared backing array would let one caller's rule set
// appear in another's. The *Pack values it points at are shared, and are
// **read-only**: nothing in the tree mutates a compiled rule after loading, and
// a caller that needs to must copy first. That is the whole bargain memoization
// makes, so it is stated rather than implied — see TestBuiltinIsMemoized and
// TestBuiltinCallersCannotDisturbEachOther.
func Builtin() ([]*Pack, error) {
	builtinOnce.Do(func() { builtinPacks, builtinErr = compileBuiltin() })
	if builtinErr != nil {
		return nil, builtinErr
	}
	out := make([]*Pack, len(builtinPacks))
	copy(out, builtinPacks)
	return out, nil
}

func compileBuiltin() ([]*Pack, error) {
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
