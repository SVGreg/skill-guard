package verify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/scan"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// cardForBundle builds the card a scan would emit for a bundle, without pulling
// the rule engine in: what a card check exercises is content_hash, and the card
// body is otherwise inert data here.
func cardForBundle(t *testing.T, b *skill.Bundle) *scan.Card {
	t.Helper()
	return &scan.Card{
		Type:        scan.CardType,
		Name:        b.Manifest.Name,
		ContentHash: attest.MerkleRoot(attest.BundleLeaves(b)),
	}
}

func loadTemp(t *testing.T, files map[string]string) *skill.Bundle {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := skill.LoadBundle(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return b
}

// TestVerifyCardMatchesItsSubject is the M5-06 acceptance property: a card
// verifies against the bundle it was emitted for, and fails against the same
// bundle with one byte changed.
func TestVerifyCardMatchesItsSubject(t *testing.T) {
	files := map[string]string{
		"SKILL.md":     "---\nname: subject\ndescription: Probe.\n---\nBody.\n",
		"scripts/a.sh": "#!/bin/sh\necho hi\n",
	}
	b := loadTemp(t, files)
	card := cardForBundle(t, b)

	res := VerifyCard(b, card)
	if !res.Match {
		t.Fatalf("card does not verify against its own bundle: card %s bundle %s", res.CardHash, res.BundleHash)
	}
	if len(res.Findings) != 0 {
		t.Errorf("matching card produced findings: %v", res.Findings)
	}
	if CardVerificationFailed(res) {
		t.Error("matching card reported as a verification failure")
	}

	files["scripts/a.sh"] = "#!/bin/sh\necho hI\n" // one byte
	changed := loadTemp(t, files)

	res = VerifyCard(changed, card)
	if res.Match {
		t.Fatal("card still verifies after a one-byte change to the bundle")
	}
	if !CardVerificationFailed(res) {
		t.Error("mismatched card must be a verification failure (exit 2)")
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "SG-PRV-007" {
		t.Errorf("want one SG-PRV-007 finding, got %v", res.Findings)
	}
	if res.Findings[0].File != "<skill-card>" {
		t.Errorf("finding attributed to %q, want <skill-card>", res.Findings[0].File)
	}
}

// TestParseCardAcceptsBothShapes: `scan --format skill-card` writes the card
// inside an envelope, and a consumer that has pulled the body out has a bare
// card. Both are on-disk realities, so both must parse.
func TestParseCardAcceptsBothShapes(t *testing.T) {
	b := loadTemp(t, map[string]string{"SKILL.md": "---\nname: shapes\ndescription: Probe.\n---\nBody.\n"})
	card := cardForBundle(t, b)

	bare, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := json.Marshal(map[string]any{
		"card":     card,
		"envelope": map[string]any{"scanned_at": "2026-09-01T00:00:00Z", "source": "x", "skillguard_version": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	for name, data := range map[string][]byte{"bare": bare, "envelope": wrapped} {
		got, err := ParseCard(data)
		if err != nil {
			t.Fatalf("%s: ParseCard: %v", name, err)
		}
		if got.ContentHash != card.ContentHash {
			t.Errorf("%s: content_hash = %q, want %q", name, got.ContentHash, card.ContentHash)
		}
		if !VerifyCard(b, got).Match {
			t.Errorf("%s: parsed card does not verify against its bundle", name)
		}
	}
}

// TestParseCardRejectsUncheckableDocuments: these are malformed input, not a
// false claim, so they must be distinguishable from a mismatch — the command
// maps them to exit 3 rather than 2.
func TestParseCardRejectsUncheckableDocuments(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want error
	}{
		{"not json", "hello", ErrNotACard},
		{"no _type", `{"name":"x","content_hash":"sha256:aa"}`, ErrNotACard},
		{"future schema", `{"_type":"skillguard.net/skill-card/v2","content_hash":"sha256:aa"}`, ErrUnsupportedSchema},
		{"foreign card", `{"_type":"example.com/other-card/v1","content_hash":"sha256:aa"}`, ErrUnsupportedSchema},
		{"pre-hash card", `{"_type":"` + scan.CardType + `","name":"x"}`, ErrNoContentHash},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCard([]byte(tc.doc))
			if !errors.Is(err, tc.want) {
				t.Errorf("ParseCard(%q) error = %v, want %v", tc.doc, err, tc.want)
			}
		})
	}
}

// TestVerifyCardIgnoresCardClaims: a card check establishes the *subject*, not
// the verdict. A card whose verdict was produced under a different policy still
// verifies, so long as it describes this bundle — otherwise a policy difference
// would be reported as tampering.
func TestVerifyCardIgnoresCardClaims(t *testing.T) {
	b := loadTemp(t, map[string]string{"SKILL.md": "---\nname: claims\ndescription: Probe.\n---\nBody.\n"})
	card := cardForBundle(t, b)
	card.Verdict = "fail"
	card.RiskScore = 99
	card.RiskTier = "L3"
	if !VerifyCard(b, card).Match {
		t.Error("card with a differing verdict failed to verify against its own bundle")
	}
}
