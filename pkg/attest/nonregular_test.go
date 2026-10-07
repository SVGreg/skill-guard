//go:build unix

package attest

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReadSignatureFileRefusesNamedPipe: a FIFO at a signature path must be an
// error, not a read that never returns.
func TestReadSignatureFileRefusesNamedPipe(t *testing.T) {
	p := filepath.Join(t.TempDir(), "skill.oms.sig")
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadSignatureFile(p); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadSignatureFile read a FIFO; want an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadSignatureFile blocked on a FIFO")
	}
	go func() { _, err := ReadEnvelope(p); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadEnvelope read a FIFO; want an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadEnvelope blocked on a FIFO")
	}
}
