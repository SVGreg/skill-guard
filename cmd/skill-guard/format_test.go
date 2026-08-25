package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/report"
	"github.com/SVGreg/skill-guard/pkg/scan"
)

// TestValidateFormatAcceptsEveryEmittedFormat keeps the flag validator and the
// emit switch from drifting apart: a format the validator accepts but emit does
// not handle silently falls back to text, which is exactly the failure mode the
// validator exists to prevent.
func TestValidateFormatAcceptsEveryEmittedFormat(t *testing.T) {
	for _, f := range validFormats {
		if err := validateFormat(f); err != nil {
			t.Errorf("validateFormat(%q) = %v, want nil", f, err)
		}
	}
	if !contains(validFormats, "sarif") {
		t.Error("sarif is not an accepted --format value")
	}
}

func TestValidateFormatRejectsUnknownWithUsageExit(t *testing.T) {
	err := validateFormat("sarif2")
	if err == nil {
		t.Fatal("unknown format accepted")
	}
	var ee exitErr
	if !errors.As(err, &ee) || ee.code != 3 {
		t.Errorf("unknown format returned %v, want exitErr code 3", err)
	}
}

// TestEmitSARIFWritesSARIFLog covers the wiring itself — emit must route
// "sarif" to report.SARIF rather than falling through to the text default.
func TestEmitSARIFWritesSARIFLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	rep := &scan.Report{
		Verdict: model.Fail,
		Findings: []model.Finding{{
			RuleID: "SG-NET-002", Title: "exfiltration", Severity: model.SevCritical,
			File: "setup.sh", StartLine: 3, AST: []string{"AST01"},
		}},
	}
	if err := emit(f, rep, "sarif", report.Options{Version: "test"}); err != nil {
		t.Fatalf("emit: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("emitted file is not JSON: %v\n%s", err, data)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0 — emit likely fell through to text", log.Version)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 {
		t.Fatalf("want one run with one result, got %+v", log.Runs)
	}
	if got := log.Runs[0].Results[0]; got.RuleID != "SG-NET-002" || got.Level != "error" {
		t.Errorf("result = %+v, want SG-NET-002/error", got)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
