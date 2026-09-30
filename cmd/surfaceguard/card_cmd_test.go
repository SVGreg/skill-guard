package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SVGreg/surfaceguard/pkg/policy"
	"github.com/SVGreg/surfaceguard/pkg/scan"
	"github.com/SVGreg/surfaceguard/pkg/skill"
)

// emitCard writes the card `scan --format skill-card` would produce for a
// bundle, to a temp file, and returns its path.
func emitCard(t *testing.T, bundlePath string) string {
	t.Helper()
	b, err := skill.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("load %s: %v", bundlePath, err)
	}
	rs, cs, err := loadRuleset(nil)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	rep := scan.New(rs, policy.Default()).WithContexts(cs).Scan(b)
	blob, err := json.MarshalIndent(map[string]any{"card": rep.Card}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "card.json")
	if err := os.WriteFile(p, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestVerifyCardCmdRoundTrip is the M5-06 acceptance check at the CLI level: a
// card emitted for a bundle verifies against it (exit 0), and the same card
// fails (exit 2) once a byte of the bundle changes.
func TestVerifyCardCmdRoundTrip(t *testing.T) {
	dir := t.TempDir()
	skillMD := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(skillMD, []byte("---\nname: roundtrip\ndescription: Probe.\n---\nBody.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cardPath := emitCard(t, dir)

	out := capture(func(w io.Writer) {
		if err := runVerifyCard(t, w, dir, cardPath); err != nil {
			t.Fatalf("card did not verify against its own bundle: %v", err)
		}
	})
	if !strings.Contains(out, "content hash: MATCH") {
		t.Errorf("output does not report a match:\n%s", out)
	}

	if err := os.WriteFile(skillMD, []byte("---\nname: roundtrip\ndescription: Probe.\n---\nBody!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var ee exitErr
	out = capture(func(w io.Writer) {
		err := runVerifyCard(t, w, dir, cardPath)
		if err == nil {
			t.Fatal("card still verified after the bundle changed")
		}
		if !errors.As(err, &ee) || ee.code != 2 {
			t.Fatalf("error = %v, want exitErr code 2", err)
		}
	})
	if !strings.Contains(out, "SG-PRV-007") {
		t.Errorf("mismatch output does not name SG-PRV-007:\n%s", out)
	}
}

// TestVerifyCardCmdRejectsNonCards: an unreadable or foreign document is a
// usage error (3), not a verification failure (2) — it makes no claim to be
// wrong about.
func TestVerifyCardCmdRejectsNonCards(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"),
		[]byte("---\nname: x\ndescription: Probe.\n---\nBody.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	notACard := filepath.Join(t.TempDir(), "other.json")
	if err := os.WriteFile(notACard, []byte(`{"_type":"example.com/other/v1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{notACard, filepath.Join(dir, "does-not-exist.json")} {
		err := runVerifyCard(t, io.Discard, dir, path)
		var ee exitErr
		if !errors.As(err, &ee) || ee.code != 3 {
			t.Errorf("verify --card %q: error = %v, want exitErr code 3", path, err)
		}
	}
}

func runVerifyCard(t *testing.T, out io.Writer, bundlePath, cardPath string) error {
	t.Helper()
	cmd := verifyCmd()
	cmd.SetArgs([]string{"--card", cardPath, "--no-color", bundlePath})
	cmd.SetOut(out)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}
