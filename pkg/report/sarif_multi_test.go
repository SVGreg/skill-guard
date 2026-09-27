package report

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SVGreg/surfaceguard/pkg/model"
	"github.com/SVGreg/surfaceguard/pkg/scan"
)

// multiRoot is a two-bundle discovery root with real files, so the test can
// check every emitted URI resolves to something on disk.
const multiRoot = "testdata/multi"

// syntheticMulti is hand-built for the same reason syntheticReport is: the
// golden pins the wire format, not the rule packs. The two bundles share a
// rule and an identical excerpt, which must stay two alerts.
func syntheticMulti() *scan.MultiReport {
	shared := model.Finding{
		RuleID: "SG-INJ-001", Title: "imperative instruction override",
		Severity: model.SevHigh, Engine: "static", Layer: "content",
		File: "SKILL.md", StartLine: 7, Excerpt: "ignore previous instructions",
		AST: []string{"AST01"}, Confidence: 0.8,
	}
	alpha := &scan.Report{
		Verdict: model.Fail, RiskScore: 27, RiskTier: "L1", MaxSeverity: model.SevHigh,
		Counts: model.Counts{High: 1, Medium: 1},
		Findings: []model.Finding{shared, {
			RuleID: "SG-EXE-001", Title: "shell execution",
			Severity: model.SevMedium, Engine: "static", Layer: "code",
			File: "scripts/run.sh", StartLine: 2, AST: []string{"AST01"}, Confidence: 0.6,
		}},
		Waived: []model.Finding{{
			RuleID: "SG-MTA-003", Title: "manifest declares no allowed-tools",
			Severity: model.SevLow, Engine: "static", Layer: "content",
			AST: []string{"AST03"}, Confidence: 0.55,
			Waived: true, WaiverReason: "reviewed",
		}},
	}
	beta := &scan.Report{
		Verdict: model.Fail, RiskScore: 12, RiskTier: "L1", MaxSeverity: model.SevHigh,
		Counts: model.Counts{High: 1}, Findings: []model.Finding{shared},
	}
	return scan.Aggregate([]scan.BundleResult{
		{Path: filepath.Join(multiRoot, "skills", "alpha"), Name: "alpha", Report: alpha},
		{Path: filepath.Join(multiRoot, "skills", "beta"), Name: "beta", Report: beta},
		{Path: filepath.Join(multiRoot, "skills", "gamma"), Error: "bundle contains symlink (rejected)"},
	})
}

func emitMulti(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := MultiSARIF(&buf, syntheticMulti(), Options{Source: multiRoot, Version: "1.2.3"}); err != nil {
		t.Fatalf("MultiSARIF: %v", err)
	}
	return buf.Bytes()
}

// TestMultiSARIFGolden is the M9-04 acceptance golden. Regenerate with
// `go test ./pkg/report -run TestMultiSARIFGolden -update` and read the diff.
func TestMultiSARIFGolden(t *testing.T) {
	got := emitMulti(t)
	path := filepath.Join("testdata", "golden", "multi.sarif")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (regenerate with -update)", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("emitted SARIF differs from %s\n--- got ---\n%s", path, got)
	}
	if !bytes.Equal(got, emitMulti(t)) {
		t.Error("two emissions differ")
	}
}

func TestMultiSARIFValidatesAndResolves(t *testing.T) {
	raw := emitMulti(t)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if errs := loadSchema(t).validate(doc); len(errs) > 0 {
		t.Fatalf("%d schema violations:\n  %s", len(errs), strings.Join(errs, "\n  "))
	}

	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string } `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Invocations []struct {
				ExecutionSuccessful        bool              `json:"executionSuccessful"`
				ToolExecutionNotifications []json.RawMessage `json:"toolExecutionNotifications"`
			} `json:"invocations"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d; a multi-bundle scan is one run", len(log.Runs))
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("rules = %d; each rule once for the set (INJ-001, EXE-001, MTA-003)", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 4 {
		t.Fatalf("results = %d; want 4 (alpha 2 + 1 waived, beta 1)", len(run.Results))
	}
	fps := map[string]bool{}
	for _, r := range run.Results {
		fps[r.PartialFingerprints[fingerprintKey]] = true
		for _, l := range r.Locations {
			rel, err := url.PathUnescape(l.PhysicalLocation.ArtifactLocation.URI)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(rel, "skills/") {
				t.Errorf("uri %q is not relative to the discovery root", rel)
			}
			if _, err := os.Stat(filepath.Join(multiRoot, filepath.FromSlash(rel))); err != nil {
				t.Errorf("uri %q does not resolve under %s: %v", rel, multiRoot, err)
			}
		}
	}
	if len(fps) != 4 {
		t.Errorf("fingerprints collide across bundles: %d distinct for 4 results", len(fps))
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful || len(run.Invocations[0].ToolExecutionNotifications) != 1 {
		t.Errorf("the unloadable bundle must surface as a failed-execution notification: %+v", run.Invocations)
	}
}
