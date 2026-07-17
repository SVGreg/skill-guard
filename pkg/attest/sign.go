package attest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/SVGreg/skill-guard/pkg/skill"
)

// PayloadType is the DSSE payloadType for skill-guard attestations.
const PayloadType = "application/vnd.skillguard.attestation.v1+json"

// Signer abstracts the private-key operation (design §7.4).
type Signer interface {
	KeyID() string
	Algorithm() string
	Sign(ctx context.Context, pae []byte) ([]byte, error)
}

// Statement is the signed attestation payload (design §7.2).
type Statement struct {
	Type      string       `json:"_type"`
	Subject   Subject      `json:"subject"`
	Files     []FileEntry  `json:"files"`
	Scan      *ScanSummary `json:"scan"`
	Predicate Predicate    `json:"predicate"`
	Publisher Publisher    `json:"publisher"`
}

type Subject struct {
	Name           string `json:"name"`
	MerkleRoot     string `json:"merkle_root"`
	FileCount      int    `json:"file_count"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ScanSummary records the verdict at signing time. nil ⇒ integrity-only.
type ScanSummary struct {
	Verdict     string `json:"verdict"`
	MaxSeverity string `json:"max_severity"`
	RiskScore   int    `json:"risk_score"`
	Rulepacks   string `json:"rulepacks,omitempty"`
	Version     string `json:"skillguard_version"`
}

type Predicate struct {
	IssuedAt     string `json:"issued_at"`
	ExpiresAt    string `json:"expires_at"`
	Builder      string `json:"builder"`
	Reproducible bool   `json:"reproducible"`
}

type Publisher struct {
	Identity string `json:"identity,omitempty"`
	KeyID    string `json:"keyid"`
}

// Envelope is the DSSE envelope written to <bundle>.skillsig (design §7.3).
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64(std) of the statement JSON
	Signatures  []Signature `json:"signatures"`
}

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64(std)
}

// BuildStatement assembles the statement for a bundle + scan summary.
func BuildStatement(b *skill.Bundle, scan *ScanSummary, signer Signer, identity string, ttl time.Duration) *Statement {
	leaves := BundleLeaves(b)
	files := make([]FileEntry, 0, len(leaves))
	for _, lf := range leaves {
		files = append(files, FileEntry{Path: lf.Path, SHA256: "sha256:" + hex.EncodeToString(lf.SHA256[:])})
	}
	manifestSum := sha256.Sum256(NormalizeSkillMD(b.SkillMDRaw))
	now := time.Now().UTC()
	return &Statement{
		Type: "skillguard.dev/attestation/v1",
		Subject: Subject{
			Name:           b.Manifest.Name,
			MerkleRoot:     MerkleRoot(leaves),
			FileCount:      len(leaves),
			ManifestSHA256: "sha256:" + hex.EncodeToString(manifestSum[:]),
		},
		Files:     files,
		Scan:      scan,
		Predicate: Predicate{IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(ttl).Format(time.RFC3339), Builder: "skill-guard", Reproducible: scan != nil},
		Publisher: Publisher{Identity: identity, KeyID: signer.KeyID()},
	}
}

// SignWith signs the statement with the given signer.
func SignWith(ctx context.Context, st *Statement, signer Signer) (*Envelope, error) {
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	pae := PAE(PayloadType, payload)
	sig, err := signer.Sign(ctx, pae)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return &Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: signer.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// PAE builds the DSSE Pre-Authentication Encoding (design §7.3):
// "DSSEv1" SP len(type) SP type SP len(payload) SP payload.
func PAE(payloadType string, payload []byte) []byte {
	var b []byte
	b = append(b, "DSSEv1 "...)
	b = append(b, strconv.Itoa(len(payloadType))...)
	b = append(b, ' ')
	b = append(b, payloadType...)
	b = append(b, ' ')
	b = append(b, strconv.Itoa(len(payload))...)
	b = append(b, ' ')
	b = append(b, payload...)
	return b
}

// DecodeStatement extracts and parses the statement from an envelope.
func DecodeStatement(env *Envelope) (*Statement, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("decode payload: %w", err)
	}
	var st Statement
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, nil, fmt.Errorf("parse statement: %w", err)
	}
	return &st, raw, nil
}
