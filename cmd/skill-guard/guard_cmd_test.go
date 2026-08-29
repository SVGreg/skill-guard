package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/guard"
	"github.com/SVGreg/skill-guard/pkg/model"
)

// TestGuardCmdFormatValidation: an unknown format is a usage error, caught
// before any work, exactly as scan's --format is.
func TestGuardCmdFormatValidation(t *testing.T) {
	cmd := guardCmd()
	cmd.SetArgs([]string{"--format", "yaml", "../../testdata/benign"})
	cmd.SetOut(os.Stderr)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("unknown format accepted")
	}
	var ee exitErr
	if !errors.As(err, &ee) || ee.code != 3 {
		t.Errorf("error = %v, want exitErr code 3", err)
	}
}

// TestPrintDecisionTruncatesFindings: a decision is not a report. The malicious
// fixture produces dozens of gating findings, and burying the outcome under all
// of them defeats the purpose of having a decision at all.
func TestPrintDecisionTruncatesFindings(t *testing.T) {
	d := &guard.Decision{
		Outcome: guard.Deny,
		Reason:  "scan verdict: fail",
		Scanned: true,
		Verdict: model.Fail,
	}
	for i := 0; i < 12; i++ {
		d.Findings = append(d.Findings, model.Finding{
			RuleID: "SG-TEST-001", Severity: model.SevHigh, Title: "finding",
		})
	}

	out := captureStdout(t, func() { printDecision(d, true) })
	if strings.Count(out, "SG-TEST-001") > 5 {
		t.Errorf("printed more than five findings:\n%s", out)
	}
	if !strings.Contains(out, "and 7 more") {
		t.Errorf("no summary line for the remaining findings:\n%s", out)
	}
	if !strings.Contains(out, "skill-guard scan") {
		t.Error("the truncation line should point at the command that shows everything")
	}
}

// TestPrintDecisionEscapesBundleText: finding titles come from rule packs, and
// an external --rulepack is attacker-controlled. A title carrying terminal
// escapes must not reach the terminal raw — it could forge the decision line
// printed directly above it.
func TestPrintDecisionEscapesBundleText(t *testing.T) {
	d := &guard.Decision{
		Outcome: guard.Warn,
		Reason:  "scan verdict: warn",
		Scanned: true,
		Findings: []model.Finding{{
			RuleID:   "SG-EVIL-001",
			Severity: model.SevMedium,
			Title:    "safe\x1b[2K\x1b[1;32mallow  nothing to see\x1b[0m",
		}},
		Signature: guard.SignatureState{
			Present: true, Valid: true, Trusted: true, Format: "sgmt-1",
			Publisher: "pub\x1b[31mlisher",
		},
	}
	out := captureStdout(t, func() { printDecision(d, true) })
	if strings.Contains(out, "\x1b[") {
		t.Errorf("raw escape sequence reached the terminal:\n%q", out)
	}
}

// TestDecisionJSONIsComplete: the human output truncates, the machine output
// must not — a consumer parsing JSON wants every finding that drove the call.
func TestDecisionJSONIsComplete(t *testing.T) {
	d := &guard.Decision{Outcome: guard.Deny, Reason: "x", Scanned: true}
	for i := 0; i < 12; i++ {
		d.Findings = append(d.Findings, model.Finding{RuleID: "SG-TEST-001", Severity: model.SevHigh})
	}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back guard.Decision
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Findings) != 12 {
		t.Errorf("JSON carried %d findings, want all 12", len(back.Findings))
	}
	if back.Outcome != guard.Deny {
		t.Errorf("outcome did not survive the round trip: %s", back.Outcome)
	}
}
