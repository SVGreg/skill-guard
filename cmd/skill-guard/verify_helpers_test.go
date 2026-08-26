package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/policy"
	sgverify "github.com/SVGreg/skill-guard/pkg/verify"
)

// captureStdout runs f with os.Stdout redirected to a pipe and returns what it
// printed. printVerify writes to os.Stdout via fmt.Printf, so this is how we
// observe its rendered output.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	f()
	w.Close()
	os.Stdout = orig
	return <-done
}

// TestPrintVerifyEscapesBundlePath is the regression for terminal-injection via
// a bundle path. A path can be discovered by tooling (a directory unpacked from
// a hostile archive), and a filename may hold any byte but '/' and NUL — so the
// "attestation: absent (no <path>)" and "skill-guard sign <path>" lines, printed
// raw, could forge output. %q neutralizes it.
func TestPrintVerifyEscapesBundlePath(t *testing.T) {
	evil := "skill\x1b[32m\nmerkle root: MATCH\nsignature: VALID (trusted key)\x1b[0m/SKILL.md"
	out := captureStdout(t, func() {
		printVerify(&sgverify.Result{Present: false}, true, evil+".skillsig", evil, false)
	})
	if strings.ContainsRune(out, '\x1b') {
		t.Errorf("raw ESC from the bundle path reached the terminal:\n%q", out)
	}
	// The forged "merkle root: MATCH" line must not appear as its own line — %q
	// keeps the whole path on the single line it belongs to.
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "merkle root: MATCH") {
			t.Errorf("bundle path forged a standalone verdict line:\n%q", out)
		}
	}
}

// TestSafeTextNeutralizesForgedVerdictLines is the regression for a real
// spoof: anyone can write a .skillsig (no key required), so every statement
// field is attacker-controlled until a signature verifies. Printed raw, an
// `identity` carrying newlines and ANSI escapes forged two convincing lines —
// a green "merkle root: MATCH" and "signature: VALID (trusted key)" — directly
// beneath the real MISMATCH.
func TestSafeTextNeutralizesForgedVerdictLines(t *testing.T) {
	forged := "acme-corp\n\x1b[32mmerkle root: MATCH\x1b[0m\nsignature: VALID (trusted key)"
	got := safeText(forged)

	if strings.ContainsAny(got, "\n\r\x1b") {
		t.Errorf("safeText left a control character in output: %q", got)
	}
	// The text is still readable and reports what was actually in the field —
	// tampering becomes visible rather than invisible.
	if !strings.Contains(got, "acme-corp") {
		t.Errorf("safeText dropped the legible content: %q", got)
	}
	if strings.Count(got, "\n") != 0 {
		t.Errorf("safeText allowed a line break, so output can still be forged: %q", got)
	}
}

func TestSafeTextLeavesOrdinaryIdentitiesReadable(t *testing.T) {
	for _, s := range []string{"svgreg", "oidc:dev@example.com", "ACME Corp Release Key"} {
		got := safeText(s)
		if !strings.Contains(got, s) {
			t.Errorf("safeText(%q) = %q, want the original text preserved", s, got)
		}
	}
}

// TestVerificationFailsOnRevokedOrExpired pins the exit-code contract to the
// design's table ("Verification failure: invalid signature, Merkle mismatch,
// revoked/expired key…"). SG-PRV-004 covers both the revoked key and the
// expired/unreadable expiry, and its absence from verificationFailed meant
// `verify` exited 0 — success — on a bundle signed with a key the consumer had
// explicitly revoked. A revocation list that does not fail the command is
// decoration.
func TestVerificationFailsOnRevokedOrExpired(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want bool
	}{
		{"revoked key / expired attestation", "SG-PRV-004", true},
		{"invalid signature", "SG-PRV-002", true},
		{"merkle mismatch", "SG-PRV-003", true},
		// Not failures: these report what could not be established, rather than
		// something established and bad.
		{"no trust roster", "SG-PRV-005", false},
		{"integrity-only", "SG-PRV-006", false},
		{"no attestation (not required)", "SG-PRV-001", false},
	}
	for _, c := range cases {
		res := &sgverify.Result{Present: true, Findings: []model.Finding{{RuleID: c.id}}}
		if got := verificationFailed(res, policy.Default()); got != c.want {
			t.Errorf("%s (%s): verificationFailed = %v, want %v", c.name, c.id, got, c.want)
		}
	}
}

// TestPrintVerifyDistinguishesRevokedFromUnknownKey guards the headline line.
// Revocation clears Trusted, so the revoked case used to fall into the "key not
// in trust roster" arm — which contradicted the SG-PRV-004 line printed directly
// underneath it, and understated the state: an unknown key is a decision the
// consumer has not made, a revoked key is one they made against this key.
func TestPrintVerifyDistinguishesRevokedFromUnknownKey(t *testing.T) {
	revoked := &sgverify.Result{Present: true, SignatureValid: true, Revoked: true}
	out := captureStdout(t, func() { printVerify(revoked, true, "sig", "skill", false) })
	if !strings.Contains(out, "REVOKED") {
		t.Errorf("revoked key not reported as REVOKED; got:\n%s", out)
	}
	if strings.Contains(out, "not in trust roster") {
		t.Errorf("revoked key described as absent from the roster; got:\n%s", out)
	}

	unknown := &sgverify.Result{Present: true, SignatureValid: true}
	out = captureStdout(t, func() { printVerify(unknown, true, "sig", "skill", false) })
	if !strings.Contains(out, "not in trust roster") {
		t.Errorf("unknown key should still report as absent from the roster; got:\n%s", out)
	}
	if strings.Contains(out, "REVOKED") {
		t.Errorf("unknown key wrongly reported as revoked; got:\n%s", out)
	}
}

// TestRefuseOverwriteProtectsExistingKey pins the keygen clobber guard.
//
// `keygen --out publisher.key` run twice used to overwrite the first key
// silently and exit 0 — new keyid, new public key, old private key gone. That
// matters more here than it would for most tools: skill-guard's trust model is
// deliberately local and decentralized, with no key server and no identity
// authority, so a signing key's only value is that consumers pasted its public
// key into `trust.keys` in their own policy. Destroying it invalidates every
// roster entry anyone made, and nothing already signed can be re-signed under
// that identity again.
func TestRefuseOverwriteProtectsExistingKey(t *testing.T) {
	dir := t.TempDir()

	absent := filepath.Join(dir, "new.key")
	if err := refuseOverwrite(absent, "private key"); err != nil {
		t.Errorf("refuseOverwrite on an absent path returned %v, want nil", err)
	}

	existing := filepath.Join(dir, "publisher.key")
	if err := os.WriteFile(existing, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := refuseOverwrite(existing, "private key")
	if err == nil {
		t.Fatal("refuseOverwrite on an existing key returned nil — the clobber guard is off")
	}
	ee, ok := err.(exitErr)
	if !ok {
		t.Fatalf("got %T, want exitErr so the process exit code is the documented usage code", err)
	}
	if ee.code != 3 {
		t.Errorf("exit code %d, want 3 (usage)", ee.code)
	}
	// The message has to name the escape hatch, or the guard just blocks people.
	if !strings.Contains(ee.msg, "--force") {
		t.Errorf("refusal does not mention --force:\n%s", ee.msg)
	}

	// A dangling symlink still counts as "something is here": Lstat, not Stat.
	// attest.writeSecret refuses to follow symlinks rather than write through
	// them, so silently generating over one would be inconsistent with that.
	dangling := filepath.Join(dir, "dangling.key")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := refuseOverwrite(dangling, "private key"); err == nil {
		t.Error("refuseOverwrite followed a dangling symlink instead of refusing")
	}
}
