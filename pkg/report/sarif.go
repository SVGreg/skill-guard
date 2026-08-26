// SARIF 2.1.0 emission (plan M3-01). Kept in its own file because the schema
// subset we serialize is large enough to drown report.go, and because the
// mapping decisions below — level, fingerprints, properties — are a contract
// with GitHub code scanning rather than a rendering detail.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/scan"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	toolName     = "skill-guard"
	toolInfoURI  = "https://github.com/SVGreg/skill-guard"

	// srcRoot names the base every artifact URI is relative to. Findings carry
	// bundle-relative paths ("SKILL.md", "scripts/setup.sh"), not
	// repo-relative ones, so the scanned path is recorded here rather than
	// being pasted onto every URI.
	srcRoot = "SRCROOT"

	// astTaxonomyName / astTaxonomyGUID identify the OWASP taxonomy component
	// that results and rules point at. The GUID is a fixed, arbitrary UUID: SARIF
	// requires one to reference a toolComponent, and it must not change between
	// runs or consumers see a different taxonomy each scan.
	astTaxonomyName = "OWASP Agentic Skills Top 10"
	astTaxonomyGUID = "6f5b7b8a-3f2e-4d31-9a0c-2c9a1f0e7d10"
	astTaxonomyOrg  = "OWASP"
	// astBaseInfoURI is the taxonomy's project page — the per-risk pages come
	// from model.ASTAll, this is just the parent.
	astBaseInfoURI = "https://owasp.org/www-project-agentic-skills-top-10/"

	// fingerprintKey is versioned: changing how the fingerprint is computed
	// would otherwise silently re-open every existing alert. Bump the suffix
	// and consumers keep both, which is the documented SARIF behavior.
	fingerprintKey = "skillGuard/v1"
)

// --- wire types (the subset of SARIF 2.1.0 we emit) ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool               `json:"tool"`
	OriginalURIBaseIDs map[string]sarifURIBase `json:"originalUriBaseIds,omitempty"`
	Taxonomies         []sarifTaxonomy         `json:"taxonomies,omitempty"`
	Results            []sarifResult           `json:"results"`
	Properties         map[string]any          `json:"properties,omitempty"`
}

// sarifTaxonomy is a toolComponent describing an external classification —
// here the OWASP Agentic Skills Top 10, carried verbatim from pkg/model so the
// taxonomy has exactly one definition in the codebase.
type sarifTaxonomy struct {
	Name             string      `json:"name"`
	GUID             string      `json:"guid"`
	Organization     string      `json:"organization,omitempty"`
	ShortDescription sarifText   `json:"shortDescription"`
	InformationURI   string      `json:"informationUri,omitempty"`
	IsComprehensive  bool        `json:"isComprehensive"`
	Taxa             []sarifTaxa `json:"taxa"`
}

type sarifTaxa struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
	HelpURI          string    `json:"helpUri,omitempty"`
}

// sarifTaxaRef points at one taxon inside the taxonomy component. Both the id
// and the index are emitted: the index is what consumers resolve, the id is
// what a human reads in raw output.
type sarifTaxaRef struct {
	ID            string            `json:"id"`
	Index         int               `json:"index"`
	ToolComponent sarifComponentRef `json:"toolComponent"`
}

type sarifComponentRef struct {
	Name  string `json:"name,omitempty"`
	GUID  string `json:"guid"`
	Index int    `json:"index"`
}

// sarifRelationship ties a rule to the taxa it maps onto. "relevant" is the
// SARIF kind for "this rule concerns that classification", which is exactly the
// ast_references relation.
type sarifRelationship struct {
	Target sarifTaxaRef `json:"target"`
	Kinds  []string     `json:"kinds"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifURIBase struct {
	URI string `json:"uri"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name,omitempty"`
	ShortDescription     sarifText           `json:"shortDescription"`
	FullDescription      *sarifText          `json:"fullDescription,omitempty"`
	Help                 *sarifText          `json:"help,omitempty"`
	HelpURI              string              `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig         `json:"defaultConfiguration"`
	Relationships        []sarifRelationship `json:"relationships,omitempty"`
	Properties           map[string]any      `json:"properties,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	Taxa                []sarifTaxaRef    `json:"taxa,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

// SARIF writes the report as a SARIF 2.1.0 log, the interchange format GitHub
// code scanning ingests.
//
// The output is deterministic — no timestamps, no map iteration order — so it
// can be golden-tested and so two scans of an unchanged bundle produce
// byte-identical logs.
//
// Waived findings are deliberately absent here; emitting them as SARIF
// suppressions is M3-04.
func SARIF(w io.Writer, rep *scan.Report, opt Options) error {
	taxonomy, taxaIndex := astTaxonomy()
	rules, index := sarifRules(rep.Findings, taxaIndex)

	results := make([]sarifResult, 0, len(rep.Findings))
	seen := map[string]int{}
	for _, f := range rep.Findings {
		results = append(results, sarifResultFor(f, index[f.RuleID], taxaIndex, seen))
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           toolName,
			Version:        opt.Version,
			InformationURI: toolInfoURI,
			Rules:          rules,
		}},
		Taxonomies: []sarifTaxonomy{taxonomy},
		Results:    results,
		Properties: map[string]any{
			"verdict":    string(rep.Verdict),
			"risk_score": rep.RiskScore,
			"risk_tier":  rep.RiskTier,
			"counts":     rep.Counts,
		},
	}
	if opt.Source != "" {
		run.OriginalURIBaseIDs = map[string]sarifURIBase{srcRoot: {URI: opt.Source}}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}})
}

// astTaxonomy renders the OWASP Agentic Skills Top 10 as a SARIF taxonomy
// component, plus an id → index map for the references that point into it. The
// catalog comes from pkg/model, never from strings kept here: AST traceability
// through every output format is a core differentiator, and a second copy of
// the taxonomy is how it silently rots.
func astTaxonomy() (sarifTaxonomy, map[string]int) {
	all := model.ASTAll()
	taxa := make([]sarifTaxa, 0, len(all))
	index := make(map[string]int, len(all))
	for i, ref := range all {
		index[ref.ID] = i
		taxa = append(taxa, sarifTaxa{
			ID:               ref.ID,
			Name:             ref.Title,
			ShortDescription: sarifText{Text: ref.Title},
			HelpURI:          ref.URL,
		})
	}
	return sarifTaxonomy{
		Name:             astTaxonomyName,
		GUID:             astTaxonomyGUID,
		Organization:     astTaxonomyOrg,
		ShortDescription: sarifText{Text: "OWASP Agentic Skills Top 10 (AST01–AST10)"},
		InformationURI:   astBaseInfoURI,
		IsComprehensive:  true,
		Taxa:             taxa,
	}, index
}

// taxaRefs resolves a finding's ast ids to taxonomy references. An id the
// catalog does not know — an external --rulepack may cite anything — is skipped
// rather than emitted as a dangling index.
func taxaRefs(ids []string, taxaIndex map[string]int) []sarifTaxaRef {
	var out []sarifTaxaRef
	for _, id := range ids {
		i, ok := taxaIndex[id]
		if !ok {
			continue
		}
		out = append(out, sarifTaxaRef{
			ID:            id,
			Index:         i,
			ToolComponent: sarifComponentRef{Name: astTaxonomyName, GUID: astTaxonomyGUID, Index: 0},
		})
	}
	return out
}

// sarifTags is the rule's tag list. "security" is what makes GitHub treat the
// alert as a security finding; the AST ids ride alongside so the taxonomy is
// visible even in a consumer that ignores taxonomies[].
func sarifTags(ids []string) []string {
	tags := make([]string, 0, len(ids)+1)
	tags = append(tags, "security")
	tags = append(tags, ids...)
	return tags
}

// sarifRules builds the driver's rule metadata from the findings themselves —
// the report carries every field SARIF wants (title, rationale, fix, ast), so
// the emitter stays decoupled from pkg/rules and an external --rulepack needs
// no special case. Returned sorted by id, with an id → index map for
// results[].ruleIndex.
func sarifRules(findings []model.Finding, taxaIndex map[string]int) ([]sarifRule, map[string]int) {
	// A rule can fire many times and its metadata is identical each time —
	// except severity, which context demotion may have capped on an individual
	// hit. defaultConfiguration must describe the *rule*, so the worst
	// undemoted severity seen wins.
	maxSev := map[string]model.Severity{}
	for _, f := range findings {
		s := ruleSeverity(f)
		if cur, seen := maxSev[f.RuleID]; !seen || s > cur {
			maxSev[f.RuleID] = s
		}
	}

	byID := map[string]sarifRule{}
	for _, f := range findings {
		if _, ok := byID[f.RuleID]; ok {
			continue
		}
		r := sarifRule{
			ID:                   f.RuleID,
			Name:                 f.Title,
			ShortDescription:     sarifText{Text: f.Title},
			DefaultConfiguration: sarifConfig{Level: sarifLevel(maxSev[f.RuleID])},
			HelpURI:              helpURI(f),
			Properties: map[string]any{
				"severity": maxSev[f.RuleID].String(),
			},
		}
		if f.Rationale != "" {
			r.FullDescription = &sarifText{Text: f.Rationale}
		}
		if f.Fix != "" {
			r.Help = &sarifText{Text: f.Fix}
		}
		if len(f.AST) > 0 {
			r.Properties["ast"] = f.AST
			for _, ref := range taxaRefs(f.AST, taxaIndex) {
				r.Relationships = append(r.Relationships, sarifRelationship{Target: ref, Kinds: []string{"relevant"}})
			}
		}
		r.Properties["tags"] = sarifTags(f.AST)
		if f.Engine != "" {
			r.Properties["engine"] = f.Engine
		}
		if f.Layer != "" {
			r.Properties["layer"] = f.Layer
		}
		byID[f.RuleID] = r
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]sarifRule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		index[id] = i
		out = append(out, byID[id])
	}
	return out, index
}

func sarifResultFor(f model.Finding, ruleIndex int, taxaIndex map[string]int, seen map[string]int) sarifResult {
	res := sarifResult{
		RuleID:    f.RuleID,
		RuleIndex: ruleIndex,
		Level:     sarifLevel(f.Severity),
		Message:   sarifText{Text: f.Title},
		PartialFingerprints: map[string]string{
			fingerprintKey: fingerprint(f, seen),
		},
		Properties: map[string]any{
			"severity":   f.Severity.String(),
			"confidence": f.Confidence,
		},
	}
	if f.File != "" {
		loc := sarifLocation{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: f.File, URIBaseID: srcRoot},
		}}
		if f.StartLine > 0 {
			// EndLine is omitted when it would just repeat StartLine; SARIF
			// treats a missing endLine as "same line".
			r := &sarifRegion{StartLine: f.StartLine}
			if f.EndLine > f.StartLine {
				r.EndLine = f.EndLine
			}
			loc.PhysicalLocation.Region = r
		}
		res.Locations = []sarifLocation{loc}
	}
	if f.Engine != "" {
		res.Properties["engine"] = f.Engine
	}
	if f.Layer != "" {
		res.Properties["layer"] = f.Layer
	}
	if len(f.AST) > 0 {
		res.Properties["ast"] = f.AST
		res.Taxa = taxaRefs(f.AST, taxaIndex)
	}
	return res
}

// fingerprint is a stable per-finding identity for cross-run dedup. It hashes
// rule + file + the normalized excerpt but deliberately *not* the line number,
// so inserting a paragraph above a finding does not close the old alert and
// open an identical new one.
//
// Two hits of the same rule on the same file with the same excerpt would
// otherwise collide and be merged into one alert, so an occurrence counter
// disambiguates them; findings arrive in a deterministic order, which makes the
// counter deterministic too.
func fingerprint(f model.Finding, seen map[string]int) string {
	base := strings.Join([]string{f.RuleID, f.File, normalizeExcerpt(f.Excerpt)}, "|")
	n := seen[base]
	seen[base] = n + 1
	if n > 0 {
		base = fmt.Sprintf("%s|#%d", base, n)
	}
	sum := sha256.Sum256([]byte(base))
	return hex.EncodeToString(sum[:8])
}

// normalizeExcerpt collapses whitespace so reflowing a line does not change the
// fingerprint. An empty excerpt (structural findings carry none) falls back to
// the empty string, which is fine — rule+file still identifies it.
func normalizeExcerpt(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// helpURI points at the OWASP page for the finding's first AST id. skill-guard
// rules have no per-rule page of their own yet; the taxonomy link is the most
// useful destination a reviewer can be given from an alert.
func helpURI(f model.Finding) string {
	for _, id := range f.AST {
		if ref, ok := model.ASTInfo(id); ok {
			return ref.URL
		}
	}
	return toolInfoURI
}

// ruleSeverity is the finding's severity before any context demotion — the
// rule's own default, as opposed to what this particular hit was capped to.
func ruleSeverity(f model.Finding) model.Severity {
	if f.DemotedBy != "" {
		return f.OriginalSeverity
	}
	return f.Severity
}

// sarifLevel maps skill-guard severity onto SARIF's three-value level. critical
// and high both become "error" because SARIF has no fourth level; the raw
// severity is preserved in properties so nothing is lost.
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SevCritical, model.SevHigh:
		return "error"
	case model.SevMedium:
		return "warning"
	default:
		return "note"
	}
}
