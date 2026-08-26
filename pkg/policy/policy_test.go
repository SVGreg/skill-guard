package policy

import (
	"os"
	"path/filepath"
	"testing"
)

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

// writePolicy writes a policy file into a temp dir and returns its path.
func writePolicy(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".skillguard.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return p
}

// TestLoadRejectsSilentMisconfiguration pins the property that a policy file is
// a security control, so every way it can be wrong must be loud. Each of these
// loaded without a word before: a typo'd key was dropped, a typo'd severity
// silently resolved to the default, a malformed glob or date made a waiver
// permanently inert, a duplicate keyid silently re-pointed a trusted id at
// another public key, and `trust.include` was ignored entirely.
func TestLoadRejectsSilentMisconfiguration(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"typo'd top-level key", "failon: low\n"},
		{"typo'd waivers key", "waiver:\n  - rule: SG-NET-001\n"},
		{"unknown nested key", "trust:\n  key:\n    - keyid: k1\n"},
		{"bad fail_on", "fail_on: hgih\n"},
		{"bad warn_on", "warn_on: bogus\n"},
		{"waiver with no rule", "waivers:\n  - path: \"*.sh\"\n    reason: x\n"},
		{"waiver with malformed glob", "waivers:\n  - rule: SG-NET-001\n    path: \"[\"\n"},
		{"waiver with malformed expiry", "waivers:\n  - rule: SG-NET-001\n    expires: next-week\n"},
		{"key with no keyid", "trust:\n  keys:\n    - public_key: AAAA\n"},
		{"duplicate keyid", "trust:\n  keys:\n    - keyid: k1\n      public_key: AAAA\n    - keyid: k1\n      public_key: BBBB\n"},
		{"unimplemented trust.include", "trust:\n  include: [./org-roster.yaml]\n"},
		{"unimplemented trust.pack_keys", "trust:\n  pack_keys:\n    - keyid: k1\n"},
		{"unimplemented scoring override", "scoring:\n  critical: 40\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Load(writePolicy(t, c.body)); err == nil {
				t.Errorf("Load accepted a policy that should be rejected:\n%s", c.body)
			}
		})
	}
}

// TestLoadAcceptsValidPolicies guards the other side of the strictness: the
// shapes the README and design doc tell people to write must still load, and an
// empty or comment-only file must still mean "use the defaults" rather than
// becoming an EOF error under the streaming decoder.
func TestLoadAcceptsValidPolicies(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty file", ""},
		{"comments only", "# nothing to see here\n"},
		{"apiVersion only", "apiVersion: skillguard.net/policy.v1\n"},
		{"README trust roster", "apiVersion: skillguard.net/policy.v1\ntrust:\n  keys:\n    - keyid: sg-8f7164b591be\n      algorithm: ed25519\n      public_key: xllKlT5UIVX+Pw1QC+W2SDzM8mYCeebWrW+mOuA2/aM=\n      identity: oidc:you@example.com\n  revoked: []\n"},
		{"thresholds and a waiver", "fail_on: critical\nwarn_on: low\nwaivers:\n  - rule: SG-NET-001\n    path: scripts/*.sh\n    reason: reviewed\n    expires: 2999-01-01\n"},
		{"empty include/pack_keys/scoring are harmless", "scoring: {}\ntrust:\n  include: []\n  pack_keys: []\n"},
		{"attestation block keeps unset defaults", "attestation:\n  required: true\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Load(writePolicy(t, c.body)); err != nil {
				t.Errorf("Load rejected a valid policy: %v\n%s", err, c.body)
			}
		})
	}
}

// TestLoadDefaultsSurviveAPartialAttestationBlock pins that decoding a mapping
// only sets the keys present: `required: true` alone must not silently reset
// warn_if_missing to Go's zero value.
func TestLoadDefaultsSurviveAPartialAttestationBlock(t *testing.T) {
	p, err := Load(writePolicy(t, "attestation:\n  required: true\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !p.Attestation.Required {
		t.Error("attestation.required did not take effect")
	}
	if !p.Attestation.WarnIfMissing {
		t.Error("attestation.warn_if_missing lost its default when only `required` was set")
	}
}

// TestRepoPolicyLoads keeps the repo's own .skillguard.yaml loadable under the
// strict decoder — it is the worked example users copy.
func TestRepoPolicyLoads(t *testing.T) {
	if _, err := Load("../../.skillguard.yaml"); err != nil {
		t.Fatalf("the repo's own .skillguard.yaml no longer loads: %v", err)
	}
}

// TestWaiverPathGlobIsSingleSegment documents the filepath.Match semantics that
// the Waiver.Path comment now spells out: `*` does not cross `/`, so a bare `*`
// is NOT the "waive everywhere" form — an empty path is.
func TestWaiverPathGlobIsSingleSegment(t *testing.T) {
	star := Policy{Waivers: []Waiver{{Rule: "SG-X", Path: "*", Reason: "star"}}}
	if got := star.WaiverFor("SG-X", "SKILL.md"); got == "" {
		t.Error(`path "*" should waive a top-level file`)
	}
	if got := star.WaiverFor("SG-X", "scripts/a.sh"); got != "" {
		t.Errorf(`path "*" waived a nested file (%q); filepath.Match must not cross "/"`, got)
	}
	empty := Policy{Waivers: []Waiver{{Rule: "SG-X", Reason: "all"}}}
	if got := empty.WaiverFor("SG-X", "scripts/a.sh"); got == "" {
		t.Error("an empty path is the bundle-wide form and should waive a nested file")
	}
}

// TestDesignDocExamplePolicyLoads keeps the worked example in
// docs/skill-guard-design.md §10.4 loadable. Strict decoding makes every
// documented key load-bearing: the first cut of this change rejected the
// project's own example over `scoring: {}`, which is exactly the failure mode
// users would have hit by copying it.
func TestDesignDocExamplePolicyLoads(t *testing.T) {
	body := `apiVersion: skillguard.net/policy.v1
fail_on: high
warn_on: medium
attestation: { required: false, warn_if_missing: true }
waivers:
  - rule: SG-DEP-001
    path: "skills/legacy-*"
    reason: "vendored pin migration, ticket SEC-142"
    expires: 2026-10-01
allowlists: { domains: ["docs.example.com"], paths: [] }
scoring: {}
trust:
  include: []
  keys:
    - keyid: author-2026
      algorithm: ed25519
      public_key: "base64"
      identity: "oidc:author@example.com"
  pack_keys: []
  revoked: []
`
	if _, err := Load(writePolicy(t, body)); err != nil {
		t.Fatalf("the design doc's own \u00a710.4 example policy no longer loads: %v", err)
	}
}

// TestTrustAllowsIdentityPatterns is the M4-08 acceptance table: a matching
// identity is admitted, a near miss is not, and no rules at all admits
// everything (identity rules narrow a roster; they are not a gate that every
// existing policy must now opt into).
func TestTrustAllowsIdentityPatterns(t *testing.T) {
	rules := []IdentityRule{
		{Pattern: "repo:acme/*"},
		{Pattern: "oidc:release@acme.example"},
		{Pattern: "https://github.com/acme/*/.github/workflows/*.yml@refs/heads/main"},
	}
	trust := Trust{Identities: rules}

	allowed := []string{
		"repo:acme/tools",
		"repo:acme/tools/nested", // `*` crosses `/` on purpose
		"oidc:release@acme.example",
		"https://github.com/acme/tools/.github/workflows/sign.yml@refs/heads/main",
	}
	for _, id := range allowed {
		if !trust.Allows(id, "") {
			t.Errorf("Allows(%q) = false, want true", id)
		}
	}

	rejected := []string{
		"repo:acme-evil/tools", // prefix must not be a substring match
		"repo:notacme/tools",
		"oidc:release@acme.example.evil.com", // exact rule, suffix appended
		"oidc:other@acme.example",
		"https://github.com/acme/tools/.github/workflows/sign.yml@refs/heads/attacker",
		"",
	}
	for _, id := range rejected {
		if trust.Allows(id, "") {
			t.Errorf("Allows(%q) = true, want false", id)
		}
	}

	if !(Trust{}).Allows("anything", "") {
		t.Error("with no identity rules configured, every identity should be admissible")
	}
}

// TestTrustAllowsIssuerScoping: a rule naming an issuer only applies to that
// issuer, so a pattern cannot be satisfied by an identity minted elsewhere.
func TestTrustAllowsIssuerScoping(t *testing.T) {
	trust := Trust{Identities: []IdentityRule{
		{Pattern: "repo:acme/*", Issuer: "https://token.actions.githubusercontent.com"},
	}}
	if !trust.Allows("repo:acme/tools", "https://token.actions.githubusercontent.com") {
		t.Error("matching pattern and issuer should be admitted")
	}
	if trust.Allows("repo:acme/tools", "https://evil.example/oidc") {
		t.Error("the same identity from another issuer must not be admitted")
	}
	if trust.Allows("repo:acme/tools", "") {
		t.Error("an issuer-scoped rule must not match when no issuer is known")
	}
}

// TestTrustRevokesKeyOrIdentity: revocation covers both, from one list.
func TestTrustRevokesKeyOrIdentity(t *testing.T) {
	trust := Trust{Revoked: []string{"sg-deadbeef", "oidc:leaver@acme.example"}}
	if !trust.Revokes("sg-deadbeef", "") {
		t.Error("a revoked key id was not reported as revoked")
	}
	if !trust.Revokes("sg-unknown", "oidc:leaver@acme.example") {
		t.Error("a revoked identity was not reported as revoked")
	}
	if trust.Revokes("sg-other", "oidc:current@acme.example") {
		t.Error("an unrelated key/identity was reported as revoked")
	}
	if trust.Revokes("", "") {
		t.Error("empty values must not match a revocation entry")
	}
}

// TestValidateRejectsUselessIdentityRules: a rule that cannot work should fail
// at load, not silently admit or reject everything at verify time.
func TestValidateRejectsUselessIdentityRules(t *testing.T) {
	base := Default()
	base.Trust.Identities = []IdentityRule{{Pattern: ""}}
	if err := base.validate(); err == nil {
		t.Error("an empty identity pattern was accepted")
	}
	base.Trust.Identities = []IdentityRule{{Pattern: "repo:acme/?"}}
	if err := base.validate(); err == nil {
		t.Error("a pattern using ? was accepted without explanation")
	}
	base.Trust.Identities = []IdentityRule{{Pattern: "repo:acme/*"}}
	if err := base.validate(); err != nil {
		t.Errorf("a valid identity rule was rejected: %v", err)
	}
}
