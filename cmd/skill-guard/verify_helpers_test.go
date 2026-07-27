package main

import (
	"io"
	"os"
	"strings"
	"testing"

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
		printVerify(&sgverify.Result{Present: false}, true, evil+".skillsig", evil)
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
