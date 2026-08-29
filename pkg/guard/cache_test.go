package guard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/rules"
)

// countingCache wraps a cache to record how it was used, so a test can assert
// a hit actually happened rather than infer it from timing.
type countingCache struct {
	inner Cache
	gets  int
	hits  int
	puts  int
}

func (c *countingCache) Get(key string) (*Decision, bool) {
	c.gets++
	d, ok := c.inner.Get(key)
	if ok {
		c.hits++
	}
	return d, ok
}

func (c *countingCache) Put(key string, d *Decision) {
	c.puts++
	c.inner.Put(key, d)
}

// TestCacheServesUnchangedBundles is half the M5-03 acceptance: the second
// Guard over unchanged bytes is answered from cache.
func TestCacheServesUnchangedBundles(t *testing.T) {
	c := &countingCache{inner: NewMemoryCache()}
	opt := Options{Cache: c}

	first, err := Guard(fixture(t, "malicious"), opt)
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if first.CacheHit {
		t.Error("the first decision claimed to be a cache hit")
	}
	second, err := Guard(fixture(t, "malicious"), opt)
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if !second.CacheHit {
		t.Fatal("the second decision was not served from cache")
	}
	if c.hits != 1 || c.puts != 1 {
		t.Errorf("cache usage: %d hits, %d puts, want 1 and 1", c.hits, c.puts)
	}

	// The cached answer must be the same answer.
	if second.Outcome != first.Outcome || second.Reason != first.Reason ||
		second.ContentHash != first.ContentHash || second.Verdict != first.Verdict {
		t.Errorf("cached decision differs:\n first=%+v\nsecond=%+v", first, second)
	}
	if len(second.Findings) != len(first.Findings) {
		t.Errorf("cached findings: %d, want %d", len(second.Findings), len(first.Findings))
	}
}

// TestCacheMissesOnChangedContent is the other half: one changed byte must not
// be answered from cache. This is the property that makes the cache safe.
func TestCacheMissesOnChangedContent(t *testing.T) {
	dir := t.TempDir()
	md := filepath.Join(dir, "SKILL.md")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(md, []byte("---\nname: demo\ndescription: a demo skill\n---\n"+body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	c := &countingCache{inner: NewMemoryCache()}
	write("body\n")
	first, err := Guard(dir, Options{Cache: c})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}

	write("body\n") // identical bytes → hit
	if d, err := Guard(dir, Options{Cache: c}); err != nil {
		t.Fatalf("Guard: %v", err)
	} else if !d.CacheHit {
		t.Error("identical content was not served from cache")
	}

	write("body plus one line\n") // one byte differs → miss
	changed, err := Guard(dir, Options{Cache: c})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if changed.CacheHit {
		t.Fatal("a changed bundle was answered from cache — a stale allow is exactly what must not happen")
	}
	if changed.ContentHash == first.ContentHash {
		t.Error("content hash did not change with the content")
	}
}

// TestCacheMissesOnChangedPolicy: a policy change must invalidate, or the cache
// answers yesterday's question.
func TestCacheMissesOnChangedPolicy(t *testing.T) {
	c := &countingCache{inner: NewMemoryCache()}
	path := fixture(t, "benign")

	lenient := policy.Default()
	lenient.Attestation.WarnIfMissing = false
	first, err := Guard(path, Options{Policy: lenient, Cache: c})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if first.Outcome != Allow {
		t.Fatalf("outcome = %s, want allow", first.Outcome)
	}

	strict := policy.Default()
	strict.Attestation.Required = true
	second, err := Guard(path, Options{Policy: strict, Cache: c})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if second.CacheHit {
		t.Fatal("a decision made under a different policy was reused")
	}
	if second.Outcome != Deny {
		t.Errorf("outcome = %s under a policy requiring attestation, want deny", second.Outcome)
	}
}

// TestCacheKeySeparatesSkipScan: a decision reached without scanning must not
// satisfy a request that asked for one — that would silently downgrade the gate.
func TestCacheKeySeparatesSkipScan(t *testing.T) {
	c := &countingCache{inner: NewMemoryCache()}
	path := fixture(t, "malicious")

	quick, err := Guard(path, Options{SkipScan: true, Cache: c})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if quick.Scanned {
		t.Fatal("SkipScan decision reports Scanned")
	}

	full, err := Guard(path, Options{Cache: c})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if full.CacheHit {
		t.Fatal("an unscanned decision was served to a scanning caller")
	}
	if full.Outcome != Deny {
		t.Errorf("outcome = %s, want deny once actually scanned", full.Outcome)
	}
}

// TestFileCacheRoundTrip: the on-disk cache survives a new process, which is
// the case a hook or a CLI invocation actually hits.
func TestFileCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fc, err := NewFileCache(dir)
	if err != nil {
		t.Fatalf("NewFileCache: %v", err)
	}
	path := fixture(t, "benign")

	first, err := Guard(path, Options{Cache: fc})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if first.CacheHit {
		t.Error("first call was a hit")
	}

	// A *different* FileCache over the same directory stands in for a second
	// process — the whole reason the on-disk cache exists.
	again, err := NewFileCache(dir)
	if err != nil {
		t.Fatalf("NewFileCache: %v", err)
	}
	second, err := Guard(path, Options{Cache: again})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if !second.CacheHit {
		t.Fatal("a fresh FileCache over the same directory did not hit")
	}
	if second.Outcome != first.Outcome {
		t.Errorf("outcome changed across processes: %s → %s", first.Outcome, second.Outcome)
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("cache directory holds %d entries, want 1 (%v)", len(entries), err)
	}
}

// TestFileCacheCorruptEntryIsAMiss: a broken cache must cost time, never
// correctness.
func TestFileCacheCorruptEntryIsAMiss(t *testing.T) {
	dir := t.TempDir()
	fc, err := NewFileCache(dir)
	if err != nil {
		t.Fatalf("NewFileCache: %v", err)
	}
	path := fixture(t, "benign")
	if _, err := Guard(path, Options{Cache: fc}); err != nil {
		t.Fatalf("Guard: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one cache file: %v %v", entries, err)
	}
	corrupt := filepath.Join(dir, entries[0].Name())
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	d, err := Guard(path, Options{Cache: fc})
	if err != nil {
		t.Fatalf("Guard after corruption: %v", err)
	}
	if d.CacheHit {
		t.Error("a corrupt entry was served as a hit")
	}
	if _, err := os.Stat(corrupt); err == nil {
		// It was rewritten by the Put that followed the miss, which is fine —
		// what matters is that it parses now.
		data, _ := os.ReadFile(corrupt)
		if len(data) > 0 && data[0] != '{' {
			t.Error("the corrupt entry was left in place")
		}
	}
}

func TestNilCacheIsNotAnError(t *testing.T) {
	d, err := Guard(fixture(t, "benign"), Options{})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if d.CacheHit {
		t.Error("CacheHit set with no cache configured")
	}
}

// BenchmarkGuardCold and BenchmarkGuardCached are the card's latency evidence:
// the cached path must be the cheap one.
func BenchmarkGuardCold(b *testing.B) {
	path := filepath.Join("..", "..", "testdata", "malicious")
	for i := 0; i < b.N; i++ {
		if _, err := Guard(path, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGuardCached(b *testing.B) {
	path := filepath.Join("..", "..", "testdata", "malicious")
	opt := Options{Cache: NewMemoryCache()}
	if _, err := Guard(path, opt); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d, err := Guard(path, opt)
		if err != nil {
			b.Fatal(err)
		}
		if !d.CacheHit {
			b.Fatal("benchmark is not measuring the cached path")
		}
	}
}

// BenchmarkGuardColdPrebuiltRules isolates where the cold cost actually sits.
// Guard loads and compiles the built-in rule packs on every call unless the
// caller supplies them; comparing against BenchmarkGuardCold shows how much of
// the cold path is compilation rather than scanning — which decides whether the
// answer for a long-lived host is a cache, reused rules, or both.
func BenchmarkGuardColdPrebuiltRules(b *testing.B) {
	path := filepath.Join("..", "..", "testdata", "malicious")
	packs, err := rules.Builtin()
	if err != nil {
		b.Fatal(err)
	}
	opt := Options{Rules: rules.AllRules(packs), Contexts: rules.AllContexts(packs)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Guard(path, opt); err != nil {
			b.Fatal(err)
		}
	}
}
