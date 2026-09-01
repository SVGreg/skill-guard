package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// TestCardContentHashIsTheBundleRoot pins the field that makes a card checkable
// (M5-06): content_hash must be the bundle's SGMT-1 Merkle root — the same value
// an attestation signs — and not some other digest, or `verify --card` would be
// comparing two things that were never meant to be equal.
func TestCardContentHashIsTheBundleRoot(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"SKILL.md":     "---\nname: hashed\ndescription: Probe.\n---\nBody.\n",
		"scripts/a.sh": "#!/bin/sh\necho hi\n",
	})
	b, err := skill.LoadBundle(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rep := scanFixture(t, dir)
	want := attest.MerkleRoot(attest.BundleLeaves(b))
	if want == "" {
		t.Fatal("fixture produced an empty merkle root")
	}
	if rep.Card.ContentHash != want {
		t.Errorf("card content_hash = %q, want the bundle root %q", rep.Card.ContentHash, want)
	}
}

// TestCardContentHashChangesWithOneByte is the acceptance property behind
// `verify --card`: a card must stop describing a bundle the moment the bundle
// changes, including in a file that is not SKILL.md.
func TestCardContentHashChangesWithOneByte(t *testing.T) {
	files := map[string]string{
		"SKILL.md":     "---\nname: hashed\ndescription: Probe.\n---\nBody.\n",
		"scripts/a.sh": "#!/bin/sh\necho hi\n",
	}
	before := cardFixture(t, files)

	files["scripts/a.sh"] = "#!/bin/sh\necho hI\n" // one byte
	after := cardFixture(t, files)

	if before.ContentHash == after.ContentHash {
		t.Errorf("content_hash unchanged (%s) after a one-byte edit to a bundled script", before.ContentHash)
	}
}

// TestCardContentHashSurvivesUSFFields guards the interaction with §7.5: the
// Merkle root hashes SKILL.md in its *normalized* form, so `sign
// --emit-manifest-fields` writing content_hash/signature into the front-matter
// must not invalidate a card emitted before signing.
func TestCardContentHashSurvivesUSFFields(t *testing.T) {
	plain := cardFixture(t, map[string]string{
		"SKILL.md": "---\nname: usf\ndescription: Probe.\n---\nBody.\n",
	})
	signed := cardFixture(t, map[string]string{
		"SKILL.md": "---\nname: usf\ndescription: Probe.\ncontent_hash: sha256:deadbeef\nsignature: AAAA\n---\nBody.\n",
	})
	if plain.ContentHash != signed.ContentHash {
		t.Errorf("content_hash changed when USF fields were added: %s -> %s", plain.ContentHash, signed.ContentHash)
	}
}

// TestCardNotesPublisherCards covers the "note it, never parse it" rule from the
// M5-01 spike: an NVIDIA-style prose card shipped in the bundle is recorded by
// path, and unrelated documents are not claimed as one.
func TestCardNotesPublisherCards(t *testing.T) {
	card := cardFixture(t, map[string]string{
		"SKILL.md":            "---\nname: carded\ndescription: Probe.\n---\nBody.\n",
		"Skill Card.md":       "# Skill Card\nOwner: someone\n",
		"docs/model_card.md":  "# Model Card\n",
		"references/notes.md": "Just notes.\n",
		"card.json":           "{}\n",
	})
	got := card.PublisherCards
	want := []string{"Skill Card.md", "docs/model_card.md"}
	if len(got) != len(want) {
		t.Fatalf("publisher_cards = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("publisher_cards = %v, want %v", got, want)
		}
	}
}

// TestCardPublisherCardsAreNeverNull keeps the JSON shape stable for the common
// case, the same invariant TestCardPermissionsAreNeverNull pins.
func TestCardPublisherCardsAreNeverNull(t *testing.T) {
	card := cardFixture(t, map[string]string{
		"SKILL.md": "---\nname: plain\ndescription: Probe.\n---\nBody.\n",
	})
	if card.PublisherCards == nil {
		t.Fatal("card.publisher_cards is nil; want an empty slice so it marshals to []")
	}
	blob, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(blob, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"content_hash", "publisher_cards"} {
		if _, ok := round[field]; !ok {
			t.Errorf("emitted card has no %q field", field)
		}
	}
	if round["_type"] != CardType {
		t.Errorf("_type = %v, want %q", round["_type"], CardType)
	}
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
}
