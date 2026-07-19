// Package policy models .skillguard.yaml: gating thresholds, waivers, allowlists,
// and the trust roster (design §10.4). Trust and policy live in one document.
package policy

import (
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
}

// AttestationRule controls provenance gating.
type AttestationRule struct {
	Required      bool `yaml:"required"`
	WarnIfMissing bool `yaml:"warn_if_missing"`
}

// Waiver suppresses a rule for matching paths until it expires.
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
func Load(path string) (Policy, error) {
	p := Default()
	if path == "" {
		return p, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := yaml.Unmarshal(data, &p); err != nil {
		return p, err
	}
	if p.FailOn == "" {
		p.FailOn = "high"
	}
	if p.WarnOn == "" {
		p.WarnOn = "medium"
	}
	return p, nil
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
			if exp, err := time.Parse("2006-01-02", w.Expires); err == nil && time.Now().After(exp) {
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
