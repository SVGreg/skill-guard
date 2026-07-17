package attest

import (
	"encoding/json"
	"os"
)

// SigPath returns the conventional .skillsig path for a bundle root or file.
func SigPath(bundlePath string) string {
	fi, err := os.Stat(bundlePath)
	if err == nil && fi.IsDir() {
		return bundlePath + string(os.PathSeparator) + "SKILL.md.skillsig"
	}
	return bundlePath + ".skillsig"
}

// WriteEnvelope writes a DSSE envelope to path as indented JSON.
func WriteEnvelope(path string, env *Envelope) error {
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ReadEnvelope reads a DSSE envelope from path. Returns (nil, nil) if absent.
func ReadEnvelope(path string) (*Envelope, error) {
	data, err := os.ReadFile(path)
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
