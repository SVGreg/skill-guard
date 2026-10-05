//go:build unix

package skill

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// loadWithin runs LoadBundle and fails, rather than hanging the suite, if it
// does not return in time. A blocked read on a FIFO is exactly the bug.
func loadWithin(t *testing.T, src string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := LoadBundle(src); done <- err }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("LoadBundle(%s) blocked; a non-regular file was read", src)
		return nil
	}
}

// TestLoadBundleRejectsNamedPipes is the reproduction: a FIFO in a bundle, or a
// FIFO named like a signature, or a FIFO passed as the single file, made
// `scan`/`guard` hang forever, and the load-gate hook then timed out into its
// fail-open default.
func TestLoadBundleRejectsNamedPipes(t *testing.T) {
	for _, name := range []string{"notes.txt", "skill.oms.sig", "SKILL.md.skillsig"} {
		dir := writeBundle(t)
		if err := syscall.Mkfifo(filepath.Join(dir, name), 0o644); err != nil {
			t.Skipf("mkfifo unavailable: %v", err)
		}
		if err := loadWithin(t, dir); err == nil {
			t.Errorf("bundle with a FIFO %s loaded; want rejection", name)
		}
	}
	single := filepath.Join(t.TempDir(), "SKILL.md")
	if err := syscall.Mkfifo(single, 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if err := loadWithin(t, single); err == nil {
		t.Error("a FIFO passed as the single SKILL.md loaded; want rejection")
	}
	// A regular bundle is unaffected.
	if err := loadWithin(t, writeBundle(t)); err != nil {
		t.Errorf("regular bundle rejected: %v", err)
	}
}
