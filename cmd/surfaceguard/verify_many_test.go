package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SVGreg/surfaceguard/pkg/attest"
	"github.com/SVGreg/surfaceguard/pkg/skill"
)

// signBundle writes a valid SGMT-1 attestation for dir and returns the
// policy YAML that trusts its key.
func signBundle(t *testing.T, dir string) string {
	t.Helper()
	signer, err := attest.GenerateKey("sg-test-key")
	if err != nil {
		t.Fatal(err)
	}
	b, err := skill.LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := attest.BuildStatement(b, nil, signer, "oidc:tester@example.com", 24*time.Hour)
	env, err := attest.SignWith(context.Background(), st, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.WriteEnvelope(attest.SigPath(dir), env); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("apiVersion: surfaceguard.svgreg.net/policy.v1\ntrust:\n  keys:\n    - keyid: %s\n      algorithm: %s\n      public_key: %s\n      identity: oidc:tester@example.com\n",
		signer.KeyID(), signer.Algorithm(), signer.PublicKeyBase64())
}

// execVerify runs `verify args...`, capturing stdout, and returns it with
// the exit code the command would produce.
func execVerify(t *testing.T, args ...string) (string, int) {
	t.Helper()
	outPath := filepath.Join(t.TempDir(), "out")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = f
	cmd := verifyCmd()
	cmd.SetOut(f)
	cmd.SetErr(f)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	err = cmd.Execute()
	os.Stdout = stdout
	f.Close()
	code := 0
	if err != nil {
		var ee exitErr
		if !errors.As(err, &ee) {
			t.Fatalf("verify %v: %v", args, err)
		}
		code = ee.code
	}
	b, _ := os.ReadFile(outPath)
	return string(b), code
}

// stateOfPath returns the STATE column of the table row ending in path.
func stateOfPath(out, path string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasSuffix(line, path) {
			return strings.Fields(line)[0]
		}
	}
	return ""
}

// TestVerifyInstalledReportsEachState is the M9-10 acceptance: across the
// installed skills, a signed-and-trusted, an unsigned and a tampered bundle
// read verified / unsigned / merkle-mismatch, and the tampered one exits 2.
func TestVerifyInstalledReportsEachState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", "")
	skills := filepath.Join(home, ".claude", "skills")
	good, unsigned, tampered := filepath.Join(skills, "good"), filepath.Join(skills, "unsigned"), filepath.Join(skills, "tampered")
	for _, d := range []string{good, unsigned, tampered} {
		writeSkill(t, d, cleanSkill)
	}
	pol := signBundle(t, good)
	signBundle(t, tampered)
	if err := os.WriteFile(filepath.Join(tampered, "SKILL.md"), []byte(cleanSkill+"\nAdded after signing.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The tampered bundle's key is not in the policy, but its Merkle
	// mismatch is reported whatever the roster says.
	polPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(polPath, []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := execVerify(t, "--installed", "--scope", "user", "--policy", polPath)
	if code != 2 {
		t.Fatalf("exit = %d; want 2 (a tampered skill)\n%s", code, out)
	}
	for path, want := range map[string]string{good: "verified", unsigned: "unsigned", tampered: "merkle-mismatch"} {
		if got := stateOfPath(out, path); got != want {
			t.Errorf("%s: state %q, want %q\n%s", filepath.Base(path), got, want, out)
		}
	}

	// Without the tampered one, nothing fails: unsigned is not a failure.
	if err := os.RemoveAll(tampered); err != nil {
		t.Fatal(err)
	}
	if out, code := execVerify(t, "--installed", "--scope", "user", "--policy", polPath); code != 0 {
		t.Errorf("exit = %d; unsigned alone must not fail verification\n%s", code, out)
	}
}

func TestVerifyManyUsageErrors(t *testing.T) {
	if _, code := execVerify(t, fixtures, "--card", "x.json"); code != 3 {
		t.Errorf("--card over a folder: exit %d; want 3", code)
	}
	if _, code := execVerify(t, fixtures, "--agent", "codex"); code != 3 {
		t.Errorf("--agent without --installed: exit %d; want 3", code)
	}
	if _, code := execVerify(t, t.TempDir()); code != 3 {
		t.Errorf("empty folder: exit %d; want 3", code)
	}
}
