package policy

import "testing"

// TestWaiverForExpiry covers the waiver gate, with emphasis on the fail-closed
// handling of a malformed `expires` date: a typo must NOT turn into a permanent
// suppression of a security finding.
func TestWaiverForExpiry(t *testing.T) {
	cases := []struct {
		name    string
		waiver  Waiver
		ruleID  string
		file    string
		wantHit bool // true = waiver applies (returns a non-empty reason)
	}{
		{
			name:   "no expiry, rule match, no path -> applies",
			waiver: Waiver{Rule: "SG-NET-001", Reason: "reviewed"},
			ruleID: "SG-NET-001", file: "SKILL.md",
			wantHit: true,
		},
		{
			name:   "future expiry -> applies",
			waiver: Waiver{Rule: "SG-NET-001", Expires: "2999-01-01"},
			ruleID: "SG-NET-001", file: "SKILL.md",
			wantHit: true,
		},
		{
			name:   "past expiry -> does not apply",
			waiver: Waiver{Rule: "SG-NET-001", Expires: "2000-01-01"},
			ruleID: "SG-NET-001", file: "SKILL.md",
			wantHit: false,
		},
		{
			name:   "malformed expiry -> fail closed, does not apply",
			waiver: Waiver{Rule: "SG-NET-001", Expires: "2026-13-99"},
			ruleID: "SG-NET-001", file: "SKILL.md",
			wantHit: false,
		},
		{
			name:   "malformed expiry (non-date) -> fail closed, does not apply",
			waiver: Waiver{Rule: "SG-NET-001", Expires: "next-week"},
			ruleID: "SG-NET-001", file: "SKILL.md",
			wantHit: false,
		},
		{
			name:   "rule mismatch -> does not apply",
			waiver: Waiver{Rule: "SG-NET-001"},
			ruleID: "SG-SEC-001", file: "SKILL.md",
			wantHit: false,
		},
		{
			name:   "path glob match -> applies",
			waiver: Waiver{Rule: "SG-NET-001", Path: "scripts/*.sh"},
			ruleID: "SG-NET-001", file: "scripts/setup.sh",
			wantHit: true,
		},
		{
			name:   "path glob non-match -> does not apply",
			waiver: Waiver{Rule: "SG-NET-001", Path: "scripts/*.sh"},
			ruleID: "SG-NET-001", file: "SKILL.md",
			wantHit: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Policy{Waivers: []Waiver{c.waiver}}
			got := p.WaiverFor(c.ruleID, c.file) != ""
			if got != c.wantHit {
				t.Errorf("WaiverFor(%q,%q) applied=%v want %v", c.ruleID, c.file, got, c.wantHit)
			}
		})
	}
}

// TestWaiverForReasonDefault checks that an applied waiver with no reason still
// returns a non-empty marker (so callers can treat "" as "not waived").
func TestWaiverForReasonDefault(t *testing.T) {
	p := Policy{Waivers: []Waiver{{Rule: "SG-NET-001"}}}
	if got := p.WaiverFor("SG-NET-001", "SKILL.md"); got != "waived" {
		t.Errorf("empty-reason waiver returned %q, want \"waived\"", got)
	}
}
