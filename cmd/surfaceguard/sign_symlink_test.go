package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SVGreg/surfaceguard/pkg/attest"
)

// TestSignSingleFileRefusesSymlinkedSkillsig is the CLI reproduction from
// issue #140. `sign <bundle>/SKILL.md` never walks the directory, so the
// loader's symlink reject never sees a sibling SKILL.md.skillsig; before the
// fix WriteEnvelope followed that link and overwrote a file outside the bundle
// with the envelope JSON.
func TestSignSingleFileRefusesSymlinkedSkillsig(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.key")
	signer, err := attest.GenerateKey("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.SaveKey(signer, keyPath); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "skill")
	if err := os.Mkdir(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	skillMD := filepath.Join(bundle, "SKILL.md")
	if err := os.WriteFile(skillMD, []byte("---\nname: t\ndescription: d\n---\nBody.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, skillMD+".skillsig"); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	cmd := signCmd()
	cmd.SetArgs([]string{"--key", keyPath, "--no-scan", skillMD})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err == nil {
		t.Error("sign wrote the attestation through a symlink instead of refusing")
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Errorf("file outside the bundle was overwritten: %q", got)
	}
}
