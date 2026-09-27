package guard

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SVGreg/surfaceguard/pkg/policy"
)

// copyBundle copies a fixture's top-level files into a fresh directory.
func copyBundle(t *testing.T, name string) string {
	t.Helper()
	src, dst := fixture(t, name), t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// staleSig is TestGuardTamperedSignatureDenies' attestation: well-formed,
// over different content, so it must deny on the Merkle mismatch.
const staleSig = `{"payloadType":"application/vnd.surfaceguard.attestation.v1+json","payload":"eyJfdHlwZSI6Imh0dHBzOi8vc3VyZmFjZWd1YXJkLnN2Z3JlZy5uZXQvYXR0ZXN0YXRpb24vdjEiLCJzdWJqZWN0Ijp7Im5hbWUiOiJkZW1vIiwibWVya2xlX3Jvb3QiOiJzaGEyNTY6ZGVhZGJlZWYiLCJmaWxlX2NvdW50IjoxLCJtYW5pZmVzdF9zaGEyNTYiOiJzaGEyNTY6YWJjIn0sImZpbGVzIjpbXSwic2NhbiI6bnVsbCwicHJlZGljYXRlIjp7Imlzc3VlZF9hdCI6IjIwMjYtMDEtMDFUMDA6MDA6MDBaIiwiZXhwaXJlc19hdCI6IjIwOTktMDEtMDFUMDA6MDA6MDBaIiwiYnVpbGRlciI6InN1cmZhY2VndWFyZCIsInJlcHJvZHVjaWJsZSI6ZmFsc2V9LCJwdWJsaXNoZXIiOnsiaWRlbnRpdHkiOiJvaWRjOmRlbW8iLCJrZXlpZCI6InNnLTAwMDAwMDAwMDAwMCJ9fQ==","signatures":[{"keyid":"sg-000000000000","sig":"AA=="}]}`

// TestCacheMissesWhenSignatureChanges: the content hash excludes detached
// signatures, so before the key bound them a decision about an unsigned
// bundle was served after a bad signature appeared — the gate kept saying
// "warn: unsigned" where a fresh decision denies on the tampered attestation.
func TestCacheMissesWhenSignatureChanges(t *testing.T) {
	dir := copyBundle(t, "benign")
	opt := Options{Cache: NewMemoryCache()}

	first, err := Guard(dir, opt)
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome == Deny {
		t.Fatalf("unsigned benign fixture denied up front: %s", first.Reason)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md.skillsig"), []byte(staleSig), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := Guard(dir, opt)
	if err != nil {
		t.Fatal(err)
	}
	if second.CacheHit || second.Outcome != Deny {
		t.Fatalf("after a bad signature appeared: outcome %s (cache hit %v); want a fresh deny", second.Outcome, second.CacheHit)
	}

	// And back: removing it must not serve the deny either.
	if err := os.Remove(filepath.Join(dir, "SKILL.md.skillsig")); err != nil {
		t.Fatal(err)
	}
	third, err := Guard(dir, opt)
	if err != nil {
		t.Fatal(err)
	}
	if third.Outcome != first.Outcome || !third.CacheHit {
		t.Errorf("signature removed: outcome %s hit %v; want the original %s, from cache", third.Outcome, third.CacheHit, first.Outcome)
	}
}

// TestCacheKeyIncludesPolicyDir: trust.roots paths resolve against the policy
// dir, so one policy in two directories is two trust decisions.
func TestCacheKeyIncludesPolicyDir(t *testing.T) {
	pol := policy.Default()
	a := CacheKey("sha256:x", pol, Options{PolicyDir: t.TempDir()})
	b := CacheKey("sha256:x", pol, Options{PolicyDir: t.TempDir()})
	if a == b {
		t.Fatal("same key for two policy directories")
	}
}

// TestCachedDecisionExpiresWithWaiver: a waiver stops applying on its expiry
// date, so a decision that relied on it must not be served past that date.
func TestCachedDecisionExpiresWithWaiver(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	pol := policy.Default()
	pol.Waivers = []policy.Waiver{
		{Rule: "SG-A", Expires: "2026-10-01"},
		{Rule: "SG-B", Expires: "2026-09-01"}, // already past: not a bound
		{Rule: "SG-C"},                        // no expiry
	}
	got := validUntil(time.Time{}, pol, now)
	if got != "2026-10-01T00:00:00Z" {
		t.Fatalf("validUntil = %q; want the nearest future waiver expiry", got)
	}
	// A nearer attestation expiry wins.
	sig := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	if got := validUntil(sig, pol, now); got != "2026-09-28T00:00:00Z" {
		t.Errorf("validUntil with attestation = %q", got)
	}
	if validUntil(time.Time{}, policy.Default(), now) != "" {
		t.Error("no clock dependence must mean no bound")
	}

	d := &Decision{ValidUntil: "2026-10-01T00:00:00Z"}
	if !fresh(d, now) || fresh(d, now.Add(5*24*time.Hour)) {
		t.Error("fresh() must serve before ValidUntil and refuse after")
	}
	if fresh(&Decision{ValidUntil: "tomorrow"}, now) {
		t.Error("an unreadable bound must count as expired")
	}
}

// TestGuardRecomputesPastValidUntil: a cache entry past its bound is a miss.
func TestGuardRecomputesPastValidUntil(t *testing.T) {
	dir := copyBundle(t, "benign")
	c := &countingCache{inner: NewMemoryCache()}
	opt := Options{Cache: c}
	if _, err := Guard(dir, opt); err != nil {
		t.Fatal(err)
	}
	// Age every stored entry past its bound.
	mc := c.inner.(*MemoryCache)
	for k, d := range mc.entries {
		d.ValidUntil = "2000-01-01T00:00:00Z"
		mc.entries[k] = d
	}
	d, err := Guard(dir, opt)
	if err != nil {
		t.Fatal(err)
	}
	if d.CacheHit {
		t.Fatal("an expired cache entry was served")
	}
}
