package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/rules"
	"github.com/SVGreg/skill-guard/pkg/scan"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// decodeSARIF renders a report and parses it back as generic JSON, which is how
// a consumer sees it — the wire shape is the contract, not our Go structs.
func decodeSARIF(t *testing.T, rep *scan.Report, opt Options) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := SARIF(&buf, rep, opt); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("emitted SARIF is not valid JSON: %v\n%s", err, buf.String())
	}
	return got
}

func run0(t *testing.T, log map[string]any) map[string]any {
	t.Helper()
	runs, ok := log["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("want exactly one run, got %v", log["runs"])
	}
	r, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("run is not an object: %T", runs[0])
	}
	return r
}

func scanFixture(t *testing.T, dir string) *scan.Report {
	t.Helper()
	b, err := skill.LoadBundle(filepath.Join("..", "..", "testdata", dir))
	if err != nil {
		t.Fatalf("LoadBundle(%s): %v", dir, err)
	}
	packs, err := rules.Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	return scan.New(rules.AllRules(packs), policy.Default()).
		WithContexts(rules.AllContexts(packs)).Scan(b)
}

// TestSARIFResultsMatchFindings is the M3-01 acceptance check: the emitted
// results must be exactly the scan's non-waived findings, no more and no fewer.
func TestSARIFResultsMatchFindings(t *testing.T) {
	rep := scanFixture(t, "malicious")
	if len(rep.Findings) == 0 {
		t.Fatal("fixture produced no findings; the test would be vacuous")
	}

	run := run0(t, decodeSARIF(t, rep, Options{Source: "testdata/malicious", Version: "test"}))
	results, _ := run["results"].([]any)
	if len(results) != len(rep.Findings) {
		t.Fatalf("results %d, findings %d", len(results), len(rep.Findings))
	}

	wantIDs := map[string]int{}
	for _, f := range rep.Findings {
		wantIDs[f.RuleID]++
	}
	gotIDs := map[string]int{}
	for _, r := range results {
		gotIDs[r.(map[string]any)["ruleId"].(string)]++
	}
	for id, n := range wantIDs {
		if gotIDs[id] != n {
			t.Errorf("rule %s: emitted %d results, scan found %d", id, gotIDs[id], n)
		}
	}
	for id := range gotIDs {
		if _, ok := wantIDs[id]; !ok {
			t.Errorf("rule %s emitted but not found by the scan", id)
		}
	}
}

// TestSARIFRuleIndexResolves guards the rules[] ↔ results[] wiring: every
// result's ruleIndex must point at the rules[] entry with the same id, or
// GitHub attributes the alert to the wrong rule.
func TestSARIFRuleIndexResolves(t *testing.T) {
	rep := scanFixture(t, "malicious")
	run := run0(t, decodeSARIF(t, rep, Options{Version: "test"}))

	driverRules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	for _, r := range run["results"].([]any) {
		res := r.(map[string]any)
		idx := int(res["ruleIndex"].(float64))
		if idx < 0 || idx >= len(driverRules) {
			t.Fatalf("ruleIndex %d out of range (%d rules)", idx, len(driverRules))
		}
		if got := driverRules[idx].(map[string]any)["id"].(string); got != res["ruleId"] {
			t.Errorf("ruleIndex %d resolves to %s, result says %s", idx, got, res["ruleId"])
		}
	}
	// rules[] must be deduplicated and sorted — the order is part of what makes
	// the output byte-stable.
	var ids []string
	for _, r := range driverRules {
		ids = append(ids, r.(map[string]any)["id"].(string))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("rules[] not sorted/unique at %d: %s then %s", i, ids[i-1], ids[i])
		}
	}
}

// TestSARIFDeterministic pins the no-timestamps, no-map-order promise: two
// emissions of one report are byte-identical.
func TestSARIFDeterministic(t *testing.T) {
	rep := scanFixture(t, "malicious")
	opt := Options{Source: "testdata/malicious", Version: "test"}
	var a, b bytes.Buffer
	if err := SARIF(&a, rep, opt); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	if err := SARIF(&b, rep, opt); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("two emissions of the same report differ")
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	cases := []struct {
		sev  model.Severity
		want string
	}{
		{model.SevCritical, "error"},
		{model.SevHigh, "error"},
		{model.SevMedium, "warning"},
		{model.SevLow, "note"},
		{model.SevInfo, "note"},
	}
	for _, c := range cases {
		if got := sarifLevel(c.sev); got != c.want {
			t.Errorf("sarifLevel(%s) = %s, want %s", c.sev, got, c.want)
		}
	}
}

// TestSARIFFingerprintIgnoresLineDrift is the reason partialFingerprints exist:
// text inserted above a finding must not close the alert and open a new one.
func TestSARIFFingerprintIgnoresLineDrift(t *testing.T) {
	f := model.Finding{RuleID: "SG-NET-002", File: "setup.sh", StartLine: 3, Excerpt: "curl http://x"}
	moved := f
	moved.StartLine = 41
	// Same content reflowed: whitespace is normalized out.
	reflowed := f
	reflowed.Excerpt = "curl   http://x"

	if a, b := fingerprint(f, map[string]int{}), fingerprint(moved, map[string]int{}); a != b {
		t.Errorf("line drift changed the fingerprint: %s vs %s", a, b)
	}
	if a, b := fingerprint(f, map[string]int{}), fingerprint(reflowed, map[string]int{}); a != b {
		t.Errorf("whitespace changed the fingerprint: %s vs %s", a, b)
	}

	// Two identical hits in one file must still be distinguishable.
	seen := map[string]int{}
	if a, b := fingerprint(f, seen), fingerprint(f, seen); a == b {
		t.Error("duplicate findings share a fingerprint; they would merge into one alert")
	}

	other := f
	other.RuleID = "SG-NET-003"
	if a, b := fingerprint(f, map[string]int{}), fingerprint(other, map[string]int{}); a == b {
		t.Error("different rules share a fingerprint")
	}
}

// TestSARIFDemotedRuleKeepsUndemotedDefault: a demoted hit reports the capped
// level, while the rule's defaultConfiguration keeps the rule's own severity.
func TestSARIFDemotedRuleKeepsUndemotedDefault(t *testing.T) {
	rep := &scan.Report{
		Verdict: model.Warn,
		Findings: []model.Finding{{
			RuleID: "SG-EXE-001", Title: "shell exec", Severity: model.SevMedium,
			OriginalSeverity: model.SevCritical, DemotedBy: "CTX-DOC", File: "SKILL.md", StartLine: 4,
		}},
	}
	run := run0(t, decodeSARIF(t, rep, Options{Version: "test"}))
	res := run["results"].([]any)[0].(map[string]any)
	if res["level"] != "warning" {
		t.Errorf("demoted result level = %v, want warning", res["level"])
	}
	rule := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if got := rule["defaultConfiguration"].(map[string]any)["level"]; got != "error" {
		t.Errorf("rule defaultConfiguration level = %v, want error (undemoted critical)", got)
	}
}

// TestSARIFBenignIsEmpty: a clean bundle still emits a well-formed log with an
// empty results array, which is what code scanning needs to clear stale alerts.
func TestSARIFBenignIsEmpty(t *testing.T) {
	rep := scanFixture(t, "benign")
	log := decodeSARIF(t, rep, Options{Source: "testdata/benign", Version: "test"})
	if log["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", log["version"])
	}
	run := run0(t, log)
	if results, ok := run["results"].([]any); !ok || len(results) != 0 {
		t.Errorf("benign fixture produced %v results, want an empty array", run["results"])
	}
	if run["properties"].(map[string]any)["verdict"] != string(rep.Verdict) {
		t.Errorf("run verdict property = %v, want %s", run["properties"], rep.Verdict)
	}
}
