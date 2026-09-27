package scan

import (
	"runtime"
	"sort"
	"sync"

	"github.com/SVGreg/surfaceguard/pkg/model"
	"github.com/SVGreg/surfaceguard/pkg/skill"
)

// BundleResult is one bundle's outcome within a multi-bundle scan: either a
// Report or, when the bundle could not be loaded, an Error.
type BundleResult struct {
	Path     string   `json:"path"`
	RealPath string   `json:"real_path,omitempty"`
	Via      string   `json:"via,omitempty"`
	Also     []string `json:"also,omitempty"`
	Name     string   `json:"name,omitempty"`
	Error    string   `json:"error,omitempty"`
	*Report
}

// Status is the bundle's row verdict: its Report's verdict, or "error" when it
// did not load.
func (r BundleResult) Status() string {
	if r.Report == nil {
		return "error"
	}
	return string(r.Verdict)
}

// MultiReport aggregates a scan over many bundles. Its verdict is the worst
// of the set, and a bundle that failed to load counts as fail: an audit that
// cannot read a skill has not shown it is safe.
type MultiReport struct {
	Bundles      []BundleResult `json:"bundles"`
	Verdict      model.Verdict  `json:"verdict"`
	RiskScoreMax int            `json:"risk_score_max"`
	MaxSeverity  model.Severity `json:"max_severity"`
	Counts       model.Counts   `json:"counts"`
	Errors       int            `json:"errors"`
	// Notes carries discovery conditions the caller wants on the record —
	// limits hit, symlinks not followed — so a JSON consumer sees what the
	// scan did not cover.
	Notes []string `json:"notes,omitempty"`
}

// Loader turns a discovered candidate into a bundle. The CLI passes a
// wrapper over skill.LoadBundle(c.RealPath); tests can inject failures.
type Loader func(c skill.Candidate) (*skill.Bundle, error)

// LoadCandidate is the default Loader: it loads the candidate's real path,
// since LoadBundle refuses a symlinked root and Discover already resolved it.
func LoadCandidate(c skill.Candidate) (*skill.Bundle, error) {
	return skill.LoadBundle(c.RealPath)
}

// ScanAll loads and scans every candidate, at most parallel at a time. The
// limit is clamped to GOMAXPROCS — never more workers than cores (CLAUDE.md:
// oversubscribed scans have hung low-core hosts) — and zero means GOMAXPROCS.
// Each worker drops its bundle once scanned, so only the reports (findings
// and excerpts) of a large set are held at once, not every bundle's bytes.
// Results keep the candidates' order.
func (s *Scanner) ScanAll(cands []skill.Candidate, load Loader, parallel int) *MultiReport {
	if load == nil {
		load = LoadCandidate
	}
	workers := runtime.GOMAXPROCS(0)
	if parallel > 0 && parallel < workers {
		workers = parallel
	}
	if workers > len(cands) {
		workers = len(cands)
	}
	results := make([]BundleResult, len(cands))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = s.scanOne(cands[i], load)
			}
		}()
	}
	for i := range cands {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return Aggregate(results)
}

func (s *Scanner) scanOne(c skill.Candidate, load Loader) BundleResult {
	r := BundleResult{Path: c.Path, Via: c.Via, Also: c.Also}
	if c.RealPath != c.Path {
		r.RealPath = c.RealPath
	}
	b, err := load(c)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Name = b.Manifest.Name
	r.Report = s.Scan(b)
	return r
}

// Aggregate folds per-bundle results into a MultiReport.
func Aggregate(results []BundleResult) *MultiReport {
	m := &MultiReport{Bundles: results, Verdict: model.Pass}
	for _, r := range results {
		if r.Report == nil {
			m.Errors++
			m.Verdict = model.Fail
			continue
		}
		m.Counts.Critical += r.Counts.Critical
		m.Counts.High += r.Counts.High
		m.Counts.Medium += r.Counts.Medium
		m.Counts.Low += r.Counts.Low
		m.Counts.Info += r.Counts.Info
		if r.RiskScore > m.RiskScoreMax {
			m.RiskScoreMax = r.RiskScore
		}
		if r.MaxSeverity > m.MaxSeverity {
			m.MaxSeverity = r.MaxSeverity
		}
		if verdictRank(r.Verdict) > verdictRank(m.Verdict) {
			m.Verdict = r.Verdict
		}
	}
	return m
}

func verdictRank(v model.Verdict) int {
	switch v {
	case model.Fail:
		return 2
	case model.Warn:
		return 1
	}
	return 0
}

// WorstFirst returns the bundle results ordered for a reader: load errors,
// then fail, warn, pass; higher risk first within a verdict; path last, so
// the order is total and stable.
func (m *MultiReport) WorstFirst() []BundleResult {
	out := append([]BundleResult(nil), m.Bundles...)
	rank := func(r BundleResult) int {
		if r.Report == nil {
			return 3
		}
		return verdictRank(r.Verdict)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if rank(a) != rank(b) {
			return rank(a) > rank(b)
		}
		if a.Report != nil && b.Report != nil && a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		return a.Path < b.Path
	})
	return out
}
