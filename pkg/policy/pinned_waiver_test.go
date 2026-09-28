package policy

import (
	"strings"
	"testing"
)

const root = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestPinnedWaiverValidation(t *testing.T) {
	cases := []struct {
		name    string
		w       Waiver
		wantErr string
	}{
		{"pinned, no rule, with reason", Waiver{MerkleRoot: root, Reason: "my own skill"}, ""},
		{"pinned with bundle and rule", Waiver{MerkleRoot: root, Bundle: "x", Rule: "SG-NET-002", Reason: "r"}, ""},
		{"pinned without reason", Waiver{MerkleRoot: root}, "must give a reason"},
		{"malformed root", Waiver{MerkleRoot: "sha256:ABC", Reason: "r"}, "is not sha256"},
		{"bundle without root", Waiver{Bundle: "x", Rule: "SG-NET-002"}, "only meaningful with merkle_root"},
		{"unpinned without rule", Waiver{Reason: "r"}, "rule is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Default()
			p.Waivers = []Waiver{c.w}
			err := p.validate()
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("err = %v, want one containing %q", err, c.wantErr)
			}
		})
	}
}

// TestPinnedWaiverMatchesOnlyThatContent: a waiver pinned to a Merkle root
// covers every rule for exactly that content — and nothing once a byte
// changes, which is what stops it covering a later rug-pull.
func TestPinnedWaiverMatchesOnlyThatContent(t *testing.T) {
	p := Default()
	p.Waivers = []Waiver{{MerkleRoot: root, Bundle: "my-skill", Reason: "authoring my own skill"}}
	this := BundleID{Name: "my-skill", MerkleRoot: root}

	for _, rule := range []string{"SG-NET-002", "SG-EXE-001", "SG-SEC-001"} {
		if p.WaiverForBundle(rule, "scripts/setup.sh", this) == "" {
			t.Errorf("%s not waived for the pinned content", rule)
		}
	}
	changed := BundleID{Name: "my-skill", MerkleRoot: "sha256:" + strings.Repeat("f", 64)}
	if p.WaiverForBundle("SG-NET-002", "setup.sh", changed) != "" {
		t.Error("waiver still applies after the content changed")
	}
	if p.WaiverForBundle("SG-NET-002", "setup.sh", BundleID{Name: "other", MerkleRoot: root}) != "" {
		t.Error("waiver applies to a different bundle name")
	}
	if p.WaiverFor("SG-NET-002", "setup.sh") != "" {
		t.Error("WaiverFor without an identity must never match a pinned waiver")
	}
	p.Waivers[0].Expires = "2000-01-01"
	if p.WaiverForBundle("SG-NET-002", "setup.sh", this) != "" {
		t.Error("an expired pinned waiver still applies")
	}
}
