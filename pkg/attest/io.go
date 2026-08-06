package attest

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// maxAttestFileSize caps the bytes read from a single attest-owned file — the
// detached ".skillsig" and the ".key" — so parsing one cannot exhaust memory.
//
// The .skillsig needed this most: pkg/skill's walk enforces a 16 MiB per-file
// and 256 MiB per-bundle cap, but it skips ".skillsig" so the attestation is
// never scanned as content — which also exempted it from both caps. That made it
// the one bundle-adjacent, fully attacker-controlled file read with no ceiling.
// A well-formed envelope also amplifies on the way through (file bytes → JSON
// string → base64-decoded payload → unmarshalled statement → PAE copy): a
// 133 MiB .skillsig measured 875 MB RSS and still ran to completion, while the
// same bytes in any other bundle file are refused at 16 MiB without being read.
//
// 16 MiB matches pkg/skill's per-file cap: it answers the same question ("how
// much of one file am I willing to read"), so it gets the same answer rather
// than a second number to keep in sync. It is ~50× the largest attestation the
// 877-bundle evaluation corpus can produce — its biggest bundle (1739 files)
// signs to 317 KB, so reaching the cap would take roughly 60,000 files.
const maxAttestFileSize = 16 << 20

// readCapped reads at most maxAttestFileSize bytes from path, refusing anything
// larger. The bound is applied through a LimitReader rather than a stat-then-read
// size check so the allocation is capped by construction — a file that grows (or
// is swapped) between the check and the read cannot widen it.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxAttestFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAttestFileSize {
		return nil, fmt.Errorf("%s exceeds the %d MiB attestation size cap", path, maxAttestFileSize>>20)
	}
	return data, nil
}

// SigPath returns the conventional .skillsig path for a bundle root or file.
func SigPath(bundlePath string) string {
	fi, err := os.Stat(bundlePath)
	if err == nil && fi.IsDir() {
		return bundlePath + string(os.PathSeparator) + "SKILL.md.skillsig"
	}
	return bundlePath + ".skillsig"
}

// WriteEnvelope writes a DSSE envelope to path as indented JSON. As with
// SavePub, 0644 applies only when the file is created — re-signing over an
// existing .skillsig leaves that file's mode alone. The envelope is public
// (it carries a signature, never key material), so this is deliberate: it
// preserves whatever mode the publisher chose rather than widening it.
func WriteEnvelope(path string, env *Envelope) error {
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ReadEnvelope reads a DSSE envelope from path. Returns (nil, nil) if absent.
func ReadEnvelope(path string) (*Envelope, error) {
	data, err := readCapped(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return &env, nil
}
