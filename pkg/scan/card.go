package scan

import (
	"path"
	"sort"
	"strings"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// CardType is the card's schema identifier. It carries the schema version, so a
// consumer can refuse a card it does not understand rather than silently
// misreading one; the schema itself is documented in docs/skill-card-schema.md.
const CardType = "skillguard.net/skill-card/v1"

// Card is the machine-readable verdict (design §9). The card body is the
// reproducible part; emission metadata (timestamps) lives in the envelope
// produced by the report layer.
type Card struct {
	Type        string `json:"_type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// ContentHash is the bundle's SGMT-1 Merkle root — the same value a
	// .skillsig attests — recomputed here whether or not a signature exists, so
	// it means the same thing either way. It is what ties a card to the bundle
	// it describes: without it a card can be detached from its subject, edited,
	// and re-presented (M5-01/M5-06). `verify --card` checks exactly this field.
	ContentHash string        `json:"content_hash"`
	Verdict     model.Verdict `json:"verdict"`
	RiskScore   int           `json:"risk_score"`
	RiskTier    string        `json:"risk_tier"`
	MaxSeverity string        `json:"max_severity"`
	Counts      model.Counts  `json:"counts"`
	Waived      int           `json:"waived"`
	ASTFindings []string      `json:"ast_findings"`
	Permissions Permissions   `json:"permissions"`
	Attestation *Attestation  `json:"attestation"`
	// PublisherCards names publisher-authored card documents the bundle ships
	// (NVIDIA's "Skill Card.md" template and its siblings). Their fields are
	// disclosures only a publisher can make — owner, licence, deployment
	// geography, evaluation results — so a scanner cannot derive them and must
	// not invent them (docs/skill-card-notes.md §2). We record that one is
	// present, and never parse its prose.
	PublisherCards []string `json:"publisher_cards"`
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
		Type:        CardType,
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

		ContentHash:    attest.MerkleRoot(attest.BundleLeaves(b)),
		PublisherCards: publisherCards(b),
	}
}

func sortStrings(ss []string) { sort.Strings(ss) }

// publisherCardBases are the base names (separators and case normalized) of the
// prose card templates the ecosystem publishes — NVIDIA's Trustworthy-AI family.
// The set is deliberately small: this is a "the publisher documented themselves"
// note, and a loose match would turn every `card.md` in a bundle into a claim.
var publisherCardBases = map[string]bool{
	"skillcard":  true,
	"modelcard":  true,
	"agentcard":  true,
	"systemcard": true,
}

// publisherCardExts are prose extensions. A publisher card is a human document;
// a .json named "model-card" is somebody's data file, not this artifact.
var publisherCardExts = map[string]bool{".md": true, ".markdown": true, ".mdx": true}

// publisherCards lists bundled publisher-authored card documents, path-sorted.
// Never nil: the card is consumed as JSON, where a nil slice would change the
// shape to `null` for the common case of a bundle that ships no such document.
func publisherCards(b *skill.Bundle) []string {
	found := make([]string, 0, 1)
	for _, f := range b.Files {
		ext := strings.ToLower(path.Ext(f.Path))
		if !publisherCardExts[ext] {
			continue
		}
		base := strings.ToLower(strings.TrimSuffix(path.Base(f.Path), ext))
		base = strings.NewReplacer(" ", "", "-", "", "_", "").Replace(base)
		if publisherCardBases[base] {
			found = append(found, f.Path)
		}
	}
	sortStrings(found)
	return found
}
