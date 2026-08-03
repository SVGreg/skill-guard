// Package policy models .skillguard.yaml: gating thresholds, waivers, allowlists,
// and the trust roster (design §10.4). Trust and policy live in one document.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/SVGreg/skill-guard/pkg/model"
	"gopkg.in/yaml.v3"
)

// Policy is the loaded, defaulted configuration.
type Policy struct {
	APIVersion  string          `yaml:"apiVersion"`
	FailOn      string          `yaml:"fail_on"`
	WarnOn      string          `yaml:"warn_on"`
	Attestation AttestationRule `yaml:"attestation"`
	Waivers     []Waiver        `yaml:"waivers"`
	Allowlists  Allowlists      `yaml:"allowlists"`
	Trust       Trust           `yaml:"trust"`

	// Scoring is the per-severity risk-score weight override from design §9.
	// Like Trust.Include/PackKeys it is documented (it appears in the §10.4
	// example policy) but **not implemented** — riskScore in pkg/scan hardcodes
	// the weights. The field exists so the documented example still parses, and
	// Load rejects it when non-empty rather than letting an override that
	// changes nothing look like it worked.
	Scoring map[string]float64 `yaml:"scoring"`
}

// AttestationRule controls provenance gating.
type AttestationRule struct {
	Required      bool `yaml:"required"`
	WarnIfMissing bool `yaml:"warn_if_missing"`
}

// Waiver suppresses a rule for matching paths until it expires.
//
// Path is a filepath.Match glob, which matches a **single path segment**: `*`
// does not cross `/`, so `scripts/*.sh` covers `scripts/setup.sh` but a bare
// `*` covers `SKILL.md` and NOT `scripts/setup.sh`. Leave Path empty to waive
// the rule bundle-wide — that, not `*`, is the "everywhere" form. `**` is not
// supported (it behaves as a single `*`).
type Waiver struct {
	Rule    string `yaml:"rule"`
	Path    string `yaml:"path"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"` // YYYY-MM-DD
}

// Allowlists holds domains/paths exempt from certain rules.
type Allowlists struct {
	Domains []string `yaml:"domains"`
	Paths   []string `yaml:"paths"`
}

// Trust is the roster (design §10.4).
//
// Include and PackKeys are part of the documented schema (design §10.4) but are
// **not implemented**: nothing reads them. They are kept as fields so a policy
// declaring them parses, and Load rejects them when non-empty rather than
// letting them fail silently — a silently-ignored `include:` means the org's
// roster was never loaded and every skill reports as unverified, which reads
// exactly like "the publisher didn't sign it".
type Trust struct {
	Include  []string `yaml:"include"`
	Keys     []Key    `yaml:"keys"`
	PackKeys []Key    `yaml:"pack_keys"`
	Revoked  []string `yaml:"revoked"`
}

// Key is a trusted public key/identity.
type Key struct {
	KeyID     string `yaml:"keyid"`
	Algorithm string `yaml:"algorithm"`
	PublicKey string `yaml:"public_key"` // base64
	Identity  string `yaml:"identity"`
}

// Default returns the built-in policy used when no file is present.
func Default() Policy {
	return Policy{
		APIVersion:  "skillguard.net/policy.v1",
		FailOn:      "high",
		WarnOn:      "medium",
		Attestation: AttestationRule{Required: false, WarnIfMissing: true},
	}
}

// Load reads a policy file, applying defaults for unset fields. An empty path
// returns Default().
//
// Decoding is **strict** (KnownFields) and the result is validated, because a
// policy file is a security control: every way it can be wrong must be loud.
// Silently dropping `failon:` (a typo for `fail_on:`) leaves the threshold at
// its default while the author believes they tightened it, and silently
// dropping `waiver:` (a typo for `waivers:`) leaves findings unwaived while the
// author believes they reviewed them. Both used to load without a word.
func Load(path string) (Policy, error) {
	p := Default()
	if path == "" {
		return p, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	// io.EOF is an empty (or comment-only) document: no overrides, not an error.
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return p, err
	}
	if p.FailOn == "" {
		p.FailOn = "high"
	}
	if p.WarnOn == "" {
		p.WarnOn = "medium"
	}
	if err := p.validate(); err != nil {
		return p, err
	}
	return p, nil
}

// validate rejects a policy that would misbehave silently. It is deliberately
// stricter than the accessors below: FailOnSeverity/WarnOnSeverity still fall
// back to a safe default, because Policy values are also built directly in
// code and by tests, but a policy *file* never reaches those fallbacks.
func (p Policy) validate() error {
	if _, err := model.ParseSeverity(p.FailOn); err != nil {
		return fmt.Errorf("fail_on %q is not a severity (valid: critical, high, medium, low, info)", p.FailOn)
	}
	if _, err := model.ParseSeverity(p.WarnOn); err != nil {
		return fmt.Errorf("warn_on %q is not a severity (valid: critical, high, medium, low, info)", p.WarnOn)
	}
	for i, w := range p.Waivers {
		if w.Rule == "" {
			return fmt.Errorf("waivers[%d]: rule is required (a waiver with no rule matches nothing)", i)
		}
		if w.Path != "" {
			// filepath.Match only reports a bad pattern once it is used, and
			// WaiverFor discards that error — so an unclosed `[` would make the
			// waiver silently inert forever. Catch it here instead.
			if _, err := filepath.Match(w.Path, "probe"); err != nil {
				return fmt.Errorf("waivers[%d] (rule %s): invalid path glob %q: %v", i, w.Rule, w.Path, err)
			}
		}
		if w.Expires != "" {
			if _, err := time.Parse("2006-01-02", w.Expires); err != nil {
				return fmt.Errorf("waivers[%d] (rule %s): expires %q is not a YYYY-MM-DD date", i, w.Rule, w.Expires)
			}
		}
	}
	seen := map[string]int{}
	for i, k := range p.Trust.Keys {
		if k.KeyID == "" {
			return fmt.Errorf("trust.keys[%d]: keyid is required", i)
		}
		// The roster is indexed by keyid (pkg/verify), so a duplicate silently
		// replaces the public key bound to that id — an append is enough to
		// re-point a trusted id at another key. Never resolve that quietly.
		if j, dup := seen[k.KeyID]; dup {
			return fmt.Errorf("trust.keys[%d]: duplicate keyid %q (already declared at trust.keys[%d]); the later entry would silently replace the earlier key", i, k.KeyID, j)
		}
		seen[k.KeyID] = i
	}
	if len(p.Trust.Include) > 0 {
		return errors.New("trust.include is documented but not implemented — the listed rosters would be ignored and every signature would report as unverified; inline the keys under trust.keys for now")
	}
	if len(p.Trust.PackKeys) > 0 {
		return errors.New("trust.pack_keys is documented but not implemented — rule packs are not signature-checked, so the listed keys would be ignored; remove the section")
	}
	if len(p.Scoring) > 0 {
		return errors.New("scoring weights are documented but not implemented — pkg/scan hardcodes the per-severity points, so the override would change nothing; remove the section")
	}
	return nil
}

// FailOnSeverity resolves the fail threshold.
func (p Policy) FailOnSeverity() model.Severity {
	s, err := model.ParseSeverity(p.FailOn)
	if err != nil {
		return model.SevHigh
	}
	return s
}

// WarnOnSeverity resolves the warn threshold.
func (p Policy) WarnOnSeverity() model.Severity {
	s, err := model.ParseSeverity(p.WarnOn)
	if err != nil {
		return model.SevMedium
	}
	return s
}

// WaiverFor returns a non-empty reason if an unexpired waiver covers rule+file.
func (p Policy) WaiverFor(ruleID, file string) string {
	for _, w := range p.Waivers {
		if w.Rule != ruleID {
			continue
		}
		if w.Expires != "" {
			exp, err := time.Parse("2006-01-02", w.Expires)
			if err != nil {
				// A malformed expiry cannot bound the waiver. Fail closed: do not
				// honor it, so the suppressed finding surfaces rather than being
				// silently waived forever by a typo in the date.
				continue
			}
			if time.Now().After(exp) {
				continue // expired waiver no longer applies
			}
		}
		if w.Path == "" {
			return orReason(w.Reason)
		}
		if ok, _ := filepath.Match(w.Path, file); ok {
			return orReason(w.Reason)
		}
	}
	return ""
}

func orReason(s string) string {
	if s == "" {
		return "waived"
	}
	return s
}
