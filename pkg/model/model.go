// Package model holds the shared, dependency-free core types (severity,
// verdict, findings, reports) used across every skill-guard package. Keeping
// them here avoids import cycles between skill, rules, scan, and report.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity ranks a finding. Higher is worse. The zero value is Info.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var sevNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < SevInfo || s > SevCritical {
		return "unknown"
	}
	return sevNames[s]
}

// ParseSeverity converts a lowercase name to a Severity.
func ParseSeverity(s string) (Severity, error) {
	for i, n := range sevNames {
		if n == strings.ToLower(strings.TrimSpace(s)) {
			return Severity(i), nil
		}
	}
	return SevInfo, fmt.Errorf("unknown severity %q", s)
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	v, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Verdict is the gating outcome. Serialized values are always lowercase.
type Verdict string

const (
	Pass Verdict = "pass"
	Warn Verdict = "warn"
	Fail Verdict = "fail"
)

// Finding is a single rule hit against a bundle. See design doc §6.2.
type Finding struct {
	RuleID     string   `json:"rule_id"`
	AST        []string `json:"ast,omitempty"`
	Severity   Severity `json:"severity"`
	Engine     string   `json:"engine"`
	Layer      string   `json:"layer,omitempty"` // content | code | provenance | drift
	Title      string   `json:"title"`
	File       string   `json:"file"`
	StartLine  int      `json:"start_line,omitempty"`
	EndLine    int      `json:"end_line,omitempty"`
	Excerpt    string   `json:"excerpt,omitempty"` // secret-redacted
	Rationale  string   `json:"rationale,omitempty"`
	Fix        string   `json:"fix,omitempty"`
	Confidence float64  `json:"confidence"`
	Waived     bool     `json:"waived,omitempty"`
}

// Counts summarizes findings by severity (waived excluded).
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Add increments the bucket for s.
func (c *Counts) Add(s Severity) {
	switch s {
	case SevCritical:
		c.Critical++
	case SevHigh:
		c.High++
	case SevMedium:
		c.Medium++
	case SevLow:
		c.Low++
	default:
		c.Info++
	}
}
