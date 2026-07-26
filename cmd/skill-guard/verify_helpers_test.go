package main

import (
	"strings"
	"testing"
)

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
