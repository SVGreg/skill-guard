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

// TestSARIFTaxonomyIsTheWholeAST is the M3-03 acceptance check, part one: the
// run must describe all ten OWASP risks, comprehensively and in id order.
func TestSARIFTaxonomyIsTheWholeAST(t *testing.T) {
	rep := scanFixture(t, "malicious")
	run := run0(t, decodeSARIF(t, rep, Options{Version: "test"}))

	taxonomies, ok := run["taxonomies"].([]any)
	if !ok || len(taxonomies) != 1 {
		t.Fatalf("want exactly one taxonomy, got %v", run["taxonomies"])
	}
	tax := taxonomies[0].(map[string]any)
	if tax["isComprehensive"] != true {
		t.Error("taxonomy is not marked comprehensive")
	}
	if tax["guid"] == "" || tax["name"] == "" {
		t.Error("taxonomy needs a stable name and guid to be referenceable")
	}
	taxa := tax["taxa"].([]any)
	if len(taxa) != 10 {
		t.Fatalf("taxonomy has %d taxa, want 10 (AST01–AST10)", len(taxa))
	}
	for i, entry := range taxa {
		e := entry.(map[string]any)
		want := model.ASTAll()[i]
		if e["id"] != want.ID || e["name"] != want.Title || e["helpUri"] != want.URL {
			t.Errorf("taxon %d = %v, want %+v", i, e, want)
		}
	}
}

// TestSARIFEveryASTFindingCarriesTagsAndTaxa is the M3-03 acceptance check,
// part two: a rule that cites AST ids must carry both the tags and a resolvable
// taxa reference, or the OWASP mapping is lost on export.
func TestSARIFEveryASTFindingCarriesTagsAndTaxa(t *testing.T) {
	rep := scanFixture(t, "malicious")
	run := run0(t, decodeSARIF(t, rep, Options{Version: "test"}))
	taxa := run["taxonomies"].([]any)[0].(map[string]any)["taxa"].([]any)

	checked := 0
	for _, r := range run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any) {
		rule := r.(map[string]any)
		props, _ := rule["properties"].(map[string]any)
		tags := toStrings(props["tags"])
		if len(tags) == 0 || tags[0] != "security" {
			t.Errorf("rule %v tags = %v, want a leading \"security\"", rule["id"], tags)
		}
		ids := toStrings(props["ast"])
		if len(ids) == 0 {
			continue
		}
		checked++
		for _, id := range ids {
			if !containsStr(tags, id) {
				t.Errorf("rule %v cites %s but does not tag it", rule["id"], id)
			}
		}
		rels, _ := rule["relationships"].([]any)
		if len(rels) != len(ids) {
			t.Errorf("rule %v cites %d ast ids but has %d relationships", rule["id"], len(ids), len(rels))
		}
		for _, rel := range rels {
			target := rel.(map[string]any)["target"].(map[string]any)
			idx := int(target["index"].(float64))
			if idx < 0 || idx >= len(taxa) {
				t.Fatalf("rule %v relationship index %d out of range", rule["id"], idx)
			}
			if got := taxa[idx].(map[string]any)["id"]; got != target["id"] {
				t.Errorf("rule %v relationship index %d resolves to %v, target says %v",
					rule["id"], idx, got, target["id"])
			}
		}
	}
	if checked == 0 {
		t.Fatal("no rule in the fixture cited an AST id; the test would be vacuous")
	}

	for _, r := range run["results"].([]any) {
		res := r.(map[string]any)
		ids := toStrings(res["properties"].(map[string]any)["ast"])
		refs, _ := res["taxa"].([]any)
		if len(refs) != len(ids) {
			t.Errorf("result %v cites %d ast ids but references %d taxa", res["ruleId"], len(ids), len(refs))
		}
		for i, ref := range refs {
			target := ref.(map[string]any)
			if target["id"] != ids[i] {
				t.Errorf("result %v taxa[%d] = %v, want %s", res["ruleId"], i, target["id"], ids[i])
			}
			if target["toolComponent"].(map[string]any)["guid"] != run["taxonomies"].([]any)[0].(map[string]any)["guid"] {
				t.Errorf("result %v taxa[%d] points at an unknown tool component", res["ruleId"], i)
			}
		}
	}
}

// TestSARIFUnknownASTIDIsNotReferenced: an external --rulepack may cite an id
// outside the catalog. It stays in tags and properties, but must not produce a
// dangling taxa index.
func TestSARIFUnknownASTIDIsNotReferenced(t *testing.T) {
	rep := &scan.Report{
		Verdict: model.Warn,
		Findings: []model.Finding{{
			RuleID: "X-CUSTOM-001", Title: "custom", Severity: model.SevLow,
			File: "SKILL.md", StartLine: 1, AST: []string{"AST01", "AST99"},
		}},
	}
	run := run0(t, decodeSARIF(t, rep, Options{Version: "test"}))
	res := run["results"].([]any)[0].(map[string]any)
	refs := res["taxa"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["id"] != "AST01" {
		t.Errorf("taxa = %v, want only the known AST01", refs)
	}
	tags := toStrings(run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)["properties"].(map[string]any)["tags"])
	if !containsStr(tags, "AST99") {
		t.Errorf("tags = %v; the unknown id should still be visible", tags)
	}
}

func toStrings(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, e.(string))
	}
	return out
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// scanFixtureWithPolicy is scanFixture with a caller-supplied policy, for the
// waiver path.
func scanFixtureWithPolicy(t *testing.T, dir string, pol policy.Policy) *scan.Report {
	t.Helper()
	b, err := skill.LoadBundle(filepath.Join("..", "..", "testdata", dir))
	if err != nil {
		t.Fatalf("LoadBundle(%s): %v", dir, err)
	}
	packs, err := rules.Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	return scan.New(rules.AllRules(packs), pol).
		WithContexts(rules.AllContexts(packs)).Scan(b)
}

// TestSARIFWaiverBecomesSuppression is the M3-04 acceptance check: a waived
// rule appears exactly once, suppressed, with the waiver's reason as the
// justification — and the run's counts still exclude it.
func TestSARIFWaiverBecomesSuppression(t *testing.T) {
	const waivedRule = "SG-NET-002"
	const reason = "reviewed: vendored installer, egress is to our own mirror"

	base := scanFixture(t, "malicious")
	var want int
	for _, f := range base.Findings {
		if f.RuleID == waivedRule {
			want++
		}
	}
	if want == 0 {
		t.Fatalf("%s does not fire on the fixture; pick another rule", waivedRule)
	}

	pol := policy.Default()
	pol.Waivers = append(pol.Waivers, policy.Waiver{Rule: waivedRule, Reason: reason})
	rep := scanFixtureWithPolicy(t, "malicious", pol)
	if len(rep.Waived) != want {
		t.Fatalf("policy waived %d findings, want %d", len(rep.Waived), want)
	}

	run := run0(t, decodeSARIF(t, rep, Options{Version: "test"}))
	results := run["results"].([]any)

	suppressed, plain := 0, 0
	for _, r := range results {
		res := r.(map[string]any)
		sup, has := res["suppressions"].([]any)
		if res["ruleId"] == waivedRule {
			if !has || len(sup) != 1 {
				t.Fatalf("waived result %v has suppressions %v, want exactly one", res["ruleId"], res["suppressions"])
			}
			s := sup[0].(map[string]any)
			if s["kind"] != "external" {
				t.Errorf("suppression kind = %v, want external", s["kind"])
			}
			if s["justification"] != reason {
				t.Errorf("justification = %v, want the waiver's reason", s["justification"])
			}
			suppressed++
			continue
		}
		if has {
			t.Errorf("result %v is suppressed but was not waived", res["ruleId"])
		}
		plain++
	}
	if suppressed != want {
		t.Errorf("emitted %d suppressed results, want %d", suppressed, want)
	}
	if plain != len(rep.Findings) {
		t.Errorf("emitted %d unsuppressed results, want %d", plain, len(rep.Findings))
	}

	// The waiver must not leak into the run's severity counts.
	counts := run["properties"].(map[string]any)["counts"].(map[string]any)
	total := 0.0
	for _, v := range counts {
		total += v.(float64)
	}
	if int(total) != len(rep.Findings) {
		t.Errorf("counts total %v, want %d (waived excluded)", total, len(rep.Findings))
	}
}

// TestSARIFWaivedRuleIsDefined: a suppressed result must still resolve to a
// rules[] entry, or the log references a rule it never defines.
func TestSARIFWaivedRuleIsDefined(t *testing.T) {
	pol := policy.Default()
	pol.Waivers = append(pol.Waivers, policy.Waiver{Rule: "SG-NET-002", Reason: "reviewed"})
	rep := scanFixtureWithPolicy(t, "malicious", pol)

	run := run0(t, decodeSARIF(t, rep, Options{Version: "test"}))
	defined := map[string]bool{}
	for _, r := range run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any) {
		defined[r.(map[string]any)["id"].(string)] = true
	}
	for _, r := range run["results"].([]any) {
		if id := r.(map[string]any)["ruleId"].(string); !defined[id] {
			t.Errorf("result cites %s, which rules[] does not define", id)
		}
	}
}

// TestSARIFDemotionPropertiesSurvive: the capped level is what a consumer
// gates on, but the original severity and the capping rule stay visible.
func TestSARIFDemotionPropertiesSurvive(t *testing.T) {
	rep := &scan.Report{
		Verdict: model.Warn,
		Findings: []model.Finding{{
			RuleID: "SG-EXE-001", Title: "shell exec", Severity: model.SevMedium,
			OriginalSeverity: model.SevCritical, DemotedBy: "CTX-DOC",
			File: "SKILL.md", StartLine: 4,
		}},
	}
	run := run0(t, decodeSARIF(t, rep, Options{Version: "test"}))
	props := run["results"].([]any)[0].(map[string]any)["properties"].(map[string]any)
	if props["demoted_by"] != "CTX-DOC" {
		t.Errorf("demoted_by = %v, want CTX-DOC", props["demoted_by"])
	}
	if props["original_severity"] != "critical" {
		t.Errorf("original_severity = %v, want critical", props["original_severity"])
	}
	if props["severity"] != "medium" {
		t.Errorf("severity = %v, want the capped medium", props["severity"])
	}
}
