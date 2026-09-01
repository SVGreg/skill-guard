package rules

import (
	"sync"
	"testing"
)

// TestBuiltinIsMemoized pins the point of M5-09: compiling the embedded packs
// happens once per process. Pointer identity is the check — two calls that
// returned separately-compiled packs would be equal by value but distinct here,
// and would cost the ~108 ms the memoization exists to remove.
func TestBuiltinIsMemoized(t *testing.T) {
	first, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin(): %v", err)
	}
	second, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin(): %v", err)
	}
	if len(first) == 0 {
		t.Fatal("Builtin() returned no packs")
	}
	if len(first) != len(second) {
		t.Fatalf("pack count changed between calls: %d then %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("pack %d (%s) was recompiled rather than reused", i, first[i].Name)
		}
	}
}

// TestBuiltinCallersCannotDisturbEachOther is the risk memoization introduces,
// and the reason the returned slice is a copy. cmd/skill-guard.loadRuleset
// appends external --rulepack packs to what Builtin() hands back; if that
// appended into a shared backing array, one caller's extra pack would appear in
// another caller's rule set — silently scanning with rules they never loaded.
func TestBuiltinCallersCannotDisturbEachOther(t *testing.T) {
	mine, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin(): %v", err)
	}
	before := len(mine)
	mine = append(mine, &Pack{Name: "external-pack", Version: "0.0.1"})

	yours, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin(): %v", err)
	}
	if len(yours) != before {
		t.Fatalf("a caller's append leaked into another caller: got %d packs, want %d", len(yours), before)
	}
	for _, p := range yours {
		if p.Name == "external-pack" {
			t.Fatal("an externally-appended pack is visible to a fresh Builtin() caller")
		}
	}
	if len(mine) != before+1 {
		t.Fatalf("the appending caller lost its own pack: %d, want %d", len(mine), before+1)
	}
}

// TestBuiltinIsConcurrencySafe: a gate can be called from several goroutines in
// an agent loop, and sync.Once must serialize the one compilation rather than
// let two race. Meaningful under -race.
func TestBuiltinIsConcurrencySafe(t *testing.T) {
	const n = 8
	var wg sync.WaitGroup
	results := make([][]*Pack, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = Builtin()
		}(i)
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if len(results[i]) != len(results[0]) {
			t.Fatalf("goroutine %d saw %d packs, goroutine 0 saw %d", i, len(results[i]), len(results[0]))
		}
		for j := range results[i] {
			if results[i][j] != results[0][j] {
				t.Fatalf("goroutine %d got a different pack %d than goroutine 0", i, j)
			}
		}
	}
}

// TestBuiltinPacksAreComplete guards the memoization against silently returning
// less than it used to: every pack the repo ships must come back, with rules.
func TestBuiltinPacksAreComplete(t *testing.T) {
	packs, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin(): %v", err)
	}
	want := map[string]bool{
		"core-injection": false, "core-network": false, "core-exec": false,
		"core-secret": false, "core-metadata": false, "core-supply": false,
	}
	for _, p := range packs {
		if _, ok := want[p.Name]; ok {
			want[p.Name] = true
		}
		if len(p.Rules) == 0 && len(p.Contexts) == 0 {
			t.Errorf("pack %q compiled to no rules and no contexts", p.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("built-in pack %q missing from Builtin()", name)
		}
	}
}

// BenchmarkBuiltin measures what a caller now pays for the rule set. Before
// memoization this was the ~108 ms that dominated every cold guard.Guard call
// (M5-08); it should now be a slice copy.
func BenchmarkBuiltin(b *testing.B) {
	if _, err := Builtin(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Builtin(); err != nil {
			b.Fatal(err)
		}
	}
}
