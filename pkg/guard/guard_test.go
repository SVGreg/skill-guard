package guard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/policy"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", name)
}

// TestGuardDecidesOnFixtures is the M5-02 acceptance table.
//
// The benign fixture is unsigned, and policy.Default() sets
// Attestation.WarnIfMissing — so under the default policy a clean but unsigned
// skill is a *warn*, not an allow. That is the policy's decision, faithfully
// reported; the third case pins what "allow" requires.
func TestGuardDecidesOnFixtures(t *testing.T) {
	quiet := policy.Default()
	quiet.Attestation.WarnIfMissing = false

	cases := []struct {
		name string
		path string
		pol  policy.Policy
		want Outcome
	}{
		{"malicious (default policy)", fixture(t, "malicious"), policy.Default(), Deny},
		{"benign, unsigned (default policy warns)", fixture(t, "benign"), policy.Default(), Warn},
		{"benign, unsigned (policy does not warn)", fixture(t, "benign"), quiet, Allow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Guard(c.path, Options{Policy: c.pol})
			if err != nil {
				t.Fatalf("Guard: %v", err)
			}
			if d.Outcome != c.want {
				t.Errorf("outcome = %s, want %s (reason: %s)", d.Outcome, c.want, d.Reason)
			}
			if d.Reason == "" {
				t.Error("a decision with no reason is not actionable")
			}
			if !d.Scanned {
				t.Error("Scanned should be true when scanning was not skipped")
			}
			if d.ContentHash == "" {
				t.Error("no content hash: the decision cannot be tied to what was judged")
			}
		})
	}
}

// TestGuardDeniesAtTheSameThresholdAsScan: the gate must agree with the CLI, or
// a skill that passes CI is blocked at load — or, worse, the reverse.
func TestGuardDeniesAtTheSameThresholdAsScan(t *testing.T) {
	d, err := Guard(fixture(t, "malicious"), Options{})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if d.Verdict != "fail" {
		t.Fatalf("verdict = %q, want fail", d.Verdict)
	}
	if d.Outcome != Deny {
		t.Errorf("a failing scan produced %s", d.Outcome)
	}
	if len(d.Findings) == 0 {
		t.Error("a denial with no findings does not explain itself")
	}
	// A decision explains itself; it does not reproduce the report.
	if len(d.Findings) > 0 && d.Findings[0].Severity < d.Findings[len(d.Findings)-1].Severity {
		t.Error("findings are not ordered most-severe-first")
	}
}

// TestGuardSkipScan distinguishes "nothing found" from "nothing looked".
func TestGuardSkipScan(t *testing.T) {
	d, err := Guard(fixture(t, "malicious"), Options{SkipScan: true})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if d.Scanned {
		t.Error("Scanned is true although scanning was skipped")
	}
	if d.Outcome == Deny {
		t.Error("the malicious fixture was denied without being scanned; only provenance should apply")
	}
	if d.Verdict != "" {
		t.Errorf("verdict = %q, want empty when unscanned", d.Verdict)
	}
}

// TestGuardAttestationRequired: policy can demand provenance the fixtures do
// not have, and that is a denial rather than a warning.
func TestGuardAttestationRequired(t *testing.T) {
	pol := policy.Default()
	pol.Attestation.Required = true

	d, err := Guard(fixture(t, "benign"), Options{Policy: pol})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if d.Outcome != Deny {
		t.Errorf("outcome = %s, want deny when attestation is required and absent", d.Outcome)
	}
	if d.Reason == "" || d.Signature.Trusted {
		t.Errorf("unexpected decision: %+v", d)
	}
}

// TestGuardWarnIfMissing: the softer policy warns instead of denying, and says
// which of the two reasons applies.
func TestGuardWarnIfMissing(t *testing.T) {
	pol := policy.Default()
	pol.Attestation.WarnIfMissing = true

	d, err := Guard(fixture(t, "benign"), Options{Policy: pol})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if d.Outcome != Warn {
		t.Errorf("outcome = %s, want warn", d.Outcome)
	}
	if d.Reason != "no attestation present" {
		t.Errorf("reason = %q", d.Reason)
	}
}

// TestGuardTamperedSignatureDenies: a signature that does not match the content
// is a denial whatever the scan says — and the reason must name tampering, not
// a verdict.
func TestGuardTamperedSignatureDenies(t *testing.T) {
	dir := t.TempDir()
	src := fixture(t, "benign")
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// A syntactically valid attestation over different content.
	stale := `{"payloadType":"application/vnd.skillguard.attestation.v1+json","payload":"eyJfdHlwZSI6InNraWxsZ3VhcmQubmV0L2F0dGVzdGF0aW9uL3YxIiwic3ViamVjdCI6eyJuYW1lIjoiZGVtbyIsIm1lcmtsZV9yb290Ijoic2hhMjU2OmRlYWRiZWVmIiwiZmlsZV9jb3VudCI6MSwibWFuaWZlc3Rfc2hhMjU2Ijoic2hhMjU2OmFiYyJ9LCJmaWxlcyI6W10sInNjYW4iOm51bGwsInByZWRpY2F0ZSI6eyJpc3N1ZWRfYXQiOiIyMDI2LTAxLTAxVDAwOjAwOjAwWiIsImV4cGlyZXNfYXQiOiIyMDk5LTAxLTAxVDAwOjAwOjAwWiIsImJ1aWxkZXIiOiJza2lsbC1ndWFyZCIsInJlcHJvZHVjaWJsZSI6ZmFsc2V9LCJwdWJsaXNoZXIiOnsiaWRlbnRpdHkiOiJvaWRjOmRlbW8iLCJrZXlpZCI6InNnLTAwMDAwMDAwMDAwMCJ9fQ==","signatures":[{"keyid":"sg-000000000000","sig":"AA=="}]}`
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md.skillsig"), []byte(stale), 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	d, err := Guard(dir, Options{})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if d.Outcome != Deny {
		t.Fatalf("outcome = %s, want deny for a signature over different content (%s)", d.Outcome, d.Reason)
	}
	if d.Verdict == "fail" {
		t.Fatal("fixture is meant to be clean; the denial must come from provenance, not the scan")
	}
	if d.Reason == "" {
		t.Error("no reason given")
	}
	t.Logf("denied: %s", d.Reason)
}

// TestGuardContentHashTracksContent: the hash identifies exactly what was
// judged, which is what makes caching sound in M5-03.
func TestGuardContentHashTracksContent(t *testing.T) {
	dir := t.TempDir()
	md := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(md, []byte("---\nname: demo\ndescription: a demo skill\n---\nbody\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	first, err := Guard(dir, Options{})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	again, err := Guard(dir, Options{})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if first.ContentHash != again.ContentHash {
		t.Error("content hash changed between two runs over unchanged bytes")
	}

	if err := os.WriteFile(md, []byte("---\nname: demo\ndescription: a demo skill\n---\nbody changed\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	changed, err := Guard(dir, Options{})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if changed.ContentHash == first.ContentHash {
		t.Error("content hash did not change after the bundle did")
	}
}

func TestGuardMissingPath(t *testing.T) {
	if _, err := Guard(filepath.Join(t.TempDir(), "nope"), Options{}); err == nil {
		t.Error("a missing bundle was accepted")
	}
}
