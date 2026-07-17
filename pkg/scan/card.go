package scan

import (
	"github.com/skillguard/skill-guard/pkg/model"
	"github.com/skillguard/skill-guard/pkg/skill"
)

// Card is the machine-readable verdict (design §9). The card body is the
// reproducible part; emission metadata (timestamps) lives in the envelope
// produced by the report layer.
type Card struct {
	Type        string        `json:"_type"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Verdict     model.Verdict `json:"verdict"`
	RiskScore   int           `json:"risk_score"`
	RiskTier    string        `json:"risk_tier"`
	MaxSeverity string        `json:"max_severity"`
	Counts      model.Counts  `json:"counts"`
	Waived      int           `json:"waived"`
	ASTFindings []string      `json:"ast_findings"`
	Permissions Permissions   `json:"permissions"`
	Attestation *Attestation  `json:"attestation"`
}

// Permissions summarizes declared/observed capability surface.
type Permissions struct {
	AllowedTools []string `json:"allowed_tools"`
	ExternalRefs []string `json:"external_refs"`
}

// Attestation summary for the card (filled by verify; nil until then).
type Attestation struct {
	Present        bool   `json:"present"`
	SignatureValid bool   `json:"signature_valid"`
	Trusted        bool   `json:"trusted"`
	Publisher      string `json:"publisher,omitempty"`
}

func buildCard(b *skill.Bundle, rep *Report) *Card {
	astSet := map[string]bool{}
	for _, f := range rep.Findings {
		for _, a := range f.AST {
			astSet[a] = true
		}
	}
	asts := make([]string, 0, len(astSet))
	for a := range astSet {
		asts = append(asts, a)
	}
	sortStrings(asts)

	refs := make([]string, 0, len(b.Refs))
	for _, r := range b.Refs {
		refs = append(refs, r.URL)
	}

	return &Card{
		Type:        "skillguard.dev/skill-card/v1",
		Name:        b.Manifest.Name,
		Description: b.Manifest.Description,
		Verdict:     rep.Verdict,
		RiskScore:   rep.RiskScore,
		RiskTier:    rep.RiskTier,
		MaxSeverity: rep.MaxSeverity.String(),
		Counts:      rep.Counts,
		Waived:      len(rep.Waived),
		ASTFindings: asts,
		Permissions: Permissions{AllowedTools: b.Manifest.AllowedTools, ExternalRefs: refs},
		Attestation: nil,
	}
}

func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j-1] > ss[j]; j-- {
			ss[j-1], ss[j] = ss[j], ss[j-1]
		}
	}
}
