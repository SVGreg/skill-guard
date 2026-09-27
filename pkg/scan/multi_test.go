package scan

import (
	"errors"
	"reflect"
	"testing"

	"github.com/SVGreg/surfaceguard/pkg/model"
	"github.com/SVGreg/surfaceguard/pkg/policy"
	"github.com/SVGreg/surfaceguard/pkg/rules"
	"github.com/SVGreg/surfaceguard/pkg/skill"
)

func builtinScanner(t *testing.T) *Scanner {
	t.Helper()
	packs, err := rules.Builtin()
	if err != nil {
		t.Fatalf("builtin: %v", err)
	}
	return New(rules.AllRules(packs), policy.Default()).WithContexts(rules.AllContexts(packs))
}

func cand(p string) skill.Candidate { return skill.Candidate{Path: p, RealPath: p, Root: p} }

// TestScanAllMatchesSingleScans is the M9-03 acceptance: scanning the two
// fixtures together yields verdict fail, two results, and per-bundle findings
// identical to two single Scan calls.
func TestScanAllMatchesSingleScans(t *testing.T) {
	benign, malicious := "../../testdata/benign", "../../testdata/malicious"
	m := builtinScanner(t).ScanAll([]skill.Candidate{cand(benign), cand(malicious)}, nil, 0)

	if m.Verdict != model.Fail || len(m.Bundles) != 2 || m.Errors != 0 {
		t.Fatalf("verdict=%s bundles=%d errors=%d; want fail/2/0", m.Verdict, len(m.Bundles), m.Errors)
	}
	for i, p := range []string{benign, malicious} {
		got, want := m.Bundles[i], scanFixture(t, p)
		if got.Path != p {
			t.Errorf("bundle %d path = %s; want candidate order kept", i, got.Path)
		}
		if !reflect.DeepEqual(got.Findings, want.Findings) || got.Verdict != want.Verdict || got.RiskScore != want.RiskScore {
			t.Errorf("%s: multi-mode result differs from a single Scan", p)
		}
	}
	mal := m.Bundles[1]
	if m.RiskScoreMax != mal.RiskScore || m.Counts != mal.Counts || m.MaxSeverity != mal.MaxSeverity {
		t.Errorf("aggregate = risk %d counts %+v max %v; want the malicious bundle's (benign has none)", m.RiskScoreMax, m.Counts, m.MaxSeverity)
	}
}

func TestScanAllLoadErrorFailsClosed(t *testing.T) {
	boom := func(c skill.Candidate) (*skill.Bundle, error) {
		if c.Path == "bad" {
			return nil, errors.New("bundle contains symlink bad/x (rejected)")
		}
		return skill.LoadBundle(c.RealPath)
	}
	m := builtinScanner(t).ScanAll([]skill.Candidate{cand("../../testdata/benign"), cand("bad")}, boom, 0)
	if m.Verdict != model.Fail || m.Errors != 1 {
		t.Fatalf("verdict=%s errors=%d; a load error must fail the set", m.Verdict, m.Errors)
	}
	bad := m.Bundles[1]
	if bad.Report != nil || bad.Error == "" || bad.Status() != "error" {
		t.Errorf("bad bundle = %+v; want Error set, no Report", bad)
	}
	if first := m.WorstFirst()[0]; first.Path != "bad" {
		t.Errorf("WorstFirst()[0] = %s; errors sort first", first.Path)
	}
}

// TestScanAllConcurrent runs many copies through several workers; under
// -race it proves one Scanner is safe to share across goroutines.
func TestScanAllConcurrent(t *testing.T) {
	var cs []skill.Candidate
	for i := 0; i < 8; i++ {
		cs = append(cs, cand("../../testdata/malicious"), cand("../../testdata/benign"))
	}
	m := builtinScanner(t).ScanAll(cs, nil, 4)
	want := scanFixture(t, "../../testdata/malicious")
	for i, r := range m.Bundles {
		if i%2 == 0 && !reflect.DeepEqual(r.Findings, want.Findings) {
			t.Fatalf("bundle %d differs under concurrency", i)
		}
	}
}

func TestScanAllEmpty(t *testing.T) {
	m := builtinScanner(t).ScanAll(nil, nil, 0)
	if m.Verdict != model.Pass || len(m.Bundles) != 0 {
		t.Fatalf("empty set: verdict %s, %d bundles", m.Verdict, len(m.Bundles))
	}
}
