package scan

import (
	"sort"

	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/skill"
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

	// skill.gatherRefs keys its inventory on (file, URL) so each occurrence can
	// cite where it appears. The card summarizes the skill's *outbound surface*,
	// where the same host reached from three files is one destination, not three
	// — so project to the URL and dedup, preserving first-seen order. This grew
	// teeth when reference docs became scanned surface (#99): before that,
	// `references/*.md` were inert assets and gatherRefs skipped them, so a URL
	// repeated across N bundled docs now lands in the card N times.
	refs := make([]string, 0, len(b.Refs))
	seenRef := make(map[string]struct{}, len(b.Refs))
	for _, r := range b.Refs {
		if _, dup := seenRef[r.URL]; dup {
			continue
		}
		seenRef[r.URL] = struct{}{}
		refs = append(refs, r.URL)
	}

	// Normalize to an empty slice, never nil. The card is consumed as machine-
	// readable JSON, and a nil slice marshals to `null` while ExternalRefs (built
	// with make) always marshals to `[]` — so a manifest that simply declares no
	// tools handed consumers a different *shape*, not just a different value.
	tools := b.Manifest.AllowedTools
	if tools == nil {
		tools = []string{}
	}

	return &Card{
		Type:        "skillguard.net/skill-card/v1",
		Name:        b.Manifest.Name,
		Description: b.Manifest.Description,
		Verdict:     rep.Verdict,
		RiskScore:   rep.RiskScore,
		RiskTier:    rep.RiskTier,
		MaxSeverity: rep.MaxSeverity.String(),
		Counts:      rep.Counts,
		Waived:      len(rep.Waived),
		ASTFindings: asts,
		Permissions: Permissions{AllowedTools: tools, ExternalRefs: refs},
		Attestation: nil,
	}
}

func sortStrings(ss []string) { sort.Strings(ss) }
