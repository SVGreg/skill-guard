package rules

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/SVGreg/surfaceguard/pkg/model"
	"gopkg.in/yaml.v3"
)

// Pack is a compiled rule-pack. Contexts are kept separate from Rules because
// they are a different kind of thing: they never produce a finding, they only
// cap the severity of findings other rules produced (design-note-demotion.md).
type Pack struct {
	APIVersion string
	Name       string
	Version    string
	Rules      []*Rule
	Contexts   []*ContextRule
}

// YAML DTOs (parsed, then compiled into runtime types).
type packDTO struct {
	APIVersion string    `yaml:"apiVersion"`
	Name       string    `yaml:"name"`
	Version    string    `yaml:"version"`
	Rules      []ruleDTO `yaml:"rules"`
}

type ruleDTO struct {
	ID         string     `yaml:"id"`
	Kind       string     `yaml:"kind"` // "" (a detection) | "context"
	Scope      string     `yaml:"scope"`
	Effect     *effectDTO `yaml:"effect"`
	Title      string     `yaml:"title"`
	AST        []string   `yaml:"ast"`
	Severity   string     `yaml:"severity"`
	Engine     string     `yaml:"engine"`
	Layer      string     `yaml:"layer"`
	Confidence float64    `yaml:"confidence"`
	Languages  []string   `yaml:"languages"`
	Targets    []string   `yaml:"targets"`
	Match      condDTO    `yaml:"match"`
	Suppress   []string   `yaml:"suppress"`
	Rationale  string     `yaml:"rationale"`
	Fix        string     `yaml:"fix"`
}

// effectDTO is what a context rule does instead of emitting: cap severity.
type effectDTO struct {
	MaxSeverity string   `yaml:"max_severity"`
	Layers      []string `yaml:"layers"`
}

type condDTO struct {
	Any             []condDTO     `yaml:"any"`
	All             []condDTO     `yaml:"all"`
	Not             []condDTO     `yaml:"not"`
	Regex           string        `yaml:"regex"`
	Substring       string        `yaml:"substring"`
	UnicodeCategory []string      `yaml:"unicode_category"`
	BidiControl     bool          `yaml:"bidi_control"`
	TagBlock        bool          `yaml:"tag_block"`
	EscapeSequence  bool          `yaml:"escape_sequence"`
	URLHost         []string      `yaml:"url_host"`
	HomoglyphRatio  *homoglyphDTO `yaml:"homoglyph_ratio"`
	Confidence      *float64      `yaml:"confidence"`
}

// APIVersion is the rule-pack schema id; a pack declaring anything else is
// refused. The bare `authority/name.vN` shape (no scheme) is the Kubernetes
// convention this field follows — the domain makes the name globally unique
// through DNS ownership, and is never dereferenced. Nothing in this binary
// performs network I/O.
const APIVersion = "surfaceguard.svgreg.net/rulepack.v1"

// ErrAPIVersion is returned for a pack whose apiVersion this build does not
// understand — including a missing one. The engine registry is already
// fail-closed on an unknown `engine:` (design §8.1); leaving apiVersion
// unchecked meant a pack written against a *future* schema would silently load
// under today's semantics, which is the same class of bug with a wider blast
// radius. External packs (`--rulepack`) must declare one.
var ErrAPIVersion = errors.New("unsupported rule-pack apiVersion")

// LoadPack parses and compiles a rule-pack from YAML bytes.
func LoadPack(data []byte) (*Pack, error) {
	var dto packDTO
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("parse pack: %w", err)
	}
	if dto.Name == "" {
		return nil, fmt.Errorf("pack missing name")
	}
	switch dto.APIVersion {
	case APIVersion:
	case "":
		return nil, fmt.Errorf("%w: pack %q declares none (want %q)", ErrAPIVersion, dto.Name, APIVersion)
	default:
		return nil, fmt.Errorf("%w: %q in pack %q (this build understands %q)",
			ErrAPIVersion, dto.APIVersion, dto.Name, APIVersion)
	}
	p := &Pack{APIVersion: dto.APIVersion, Name: dto.Name, Version: dto.Version}
	for _, rd := range dto.Rules {
		switch rd.Kind {
		case "", "detection":
			// An `effect`/`scope` on a detection is a context rule someone forgot
			// to mark; failing loudly beats silently ignoring the field, because
			// the author's intent was to reduce severity and the shipped rule
			// would not.
			if rd.Effect != nil || rd.Scope != "" {
				return nil, fmt.Errorf("rule %s: effect/scope require kind: context", rd.ID)
			}
			r, err := compileRule(rd)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", rd.ID, err)
			}
			p.Rules = append(p.Rules, r)
		case "context":
			c, err := compileContext(rd)
			if err != nil {
				return nil, fmt.Errorf("context %s: %w", rd.ID, err)
			}
			p.Contexts = append(p.Contexts, c)
		default:
			return nil, fmt.Errorf("rule %s: unknown kind %q", rd.ID, rd.Kind)
		}
	}
	return p, nil
}

// compileContext builds a severity-capping context rule. It deliberately does
// not accept `severity`, `confidence` or `suppress`: a context rule emits
// nothing, so those fields would be inert, and an inert field that looks
// meaningful is how the `scoring:` key became a load error in PR #125.
func compileContext(rd ruleDTO) (*ContextRule, error) {
	if rd.ID == "" {
		return nil, fmt.Errorf("missing id")
	}
	if rd.Effect == nil || rd.Effect.MaxSeverity == "" {
		return nil, fmt.Errorf("missing effect.max_severity")
	}
	max, err := model.ParseSeverity(rd.Effect.MaxSeverity)
	if err != nil {
		return nil, err
	}
	scope := orDefault(rd.Scope, "line")
	if scope != "line" && scope != "file" && scope != "section" {
		return nil, fmt.Errorf("unknown scope %q (want line, file or section)", scope)
	}
	if scope == "section" {
		// Headings exist only in markdown. Accepting scripts/configs here would
		// load fine and never fire — an inert field that looks meaningful.
		for _, t := range rd.Targets {
			if t != "body" && t != "refs" && t != "manifest" {
				return nil, fmt.Errorf("scope section applies to markdown targets only (body, refs, manifest), not %q", t)
			}
		}
	}
	for _, l := range rd.Effect.Layers {
		switch l {
		case "content", "code", "provenance", "drift":
		default:
			return nil, fmt.Errorf("unknown effect.layers value %q (want content, code, provenance or drift)", l)
		}
	}
	if rd.Severity != "" || rd.Confidence != 0 || len(rd.Suppress) > 0 {
		return nil, fmt.Errorf("severity/confidence/suppress are meaningless on a context rule")
	}
	cond, err := compileCond(rd.Match)
	if err != nil {
		return nil, err
	}
	return &ContextRule{
		ID:          rd.ID,
		Title:       rd.Title,
		Scope:       scope,
		MaxSeverity: max,
		Layers:      rd.Effect.Layers,
		Targets:     rd.Targets,
		Rationale:   rd.Rationale,
		matcher: &Rule{
			ID:         rd.ID,
			Confidence: 1,
			Targets:    rd.Targets,
			Languages:  rd.Languages,
			Match:      cond,
		},
	}, nil
}

func compileRule(rd ruleDTO) (*Rule, error) {
	sev, err := model.ParseSeverity(rd.Severity)
	if err != nil {
		return nil, err
	}
	cond, err := compileCond(rd.Match)
	if err != nil {
		return nil, err
	}
	r := &Rule{
		ID:         rd.ID,
		Title:      rd.Title,
		AST:        rd.AST,
		Severity:   sev,
		Engine:     orDefault(rd.Engine, "static"),
		Layer:      rd.Layer,
		Confidence: rd.Confidence,
		Languages:  rd.Languages,
		Targets:    rd.Targets,
		Match:      cond,
		Rationale:  rd.Rationale,
		Fix:        rd.Fix,
	}
	for _, s := range rd.Suppress {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("suppress %q: %w", s, err)
		}
		r.Suppress = append(r.Suppress, re)
	}
	return r, nil
}

func compileCond(cd condDTO) (Condition, error) {
	c := Condition{
		substring:       cd.Substring,
		unicodeCategory: cd.UnicodeCategory,
		bidiControl:     cd.BidiControl,
		tagBlock:        cd.TagBlock,
		escapeSequence:  cd.EscapeSequence,
		urlHost:         cd.URLHost,
		homoglyph:       compileHomoglyph(cd.HomoglyphRatio),
		confidence:      cd.Confidence,
	}
	if cd.Regex != "" {
		re, err := regexp.Compile(cd.Regex)
		if err != nil {
			return c, fmt.Errorf("regex %q: %w", cd.Regex, err)
		}
		c.regex = re
	}
	for _, sub := range cd.Any {
		cc, err := compileCond(sub)
		if err != nil {
			return c, err
		}
		c.Any = append(c.Any, cc)
	}
	for _, sub := range cd.All {
		cc, err := compileCond(sub)
		if err != nil {
			return c, err
		}
		c.All = append(c.All, cc)
	}
	for _, sub := range cd.Not {
		cc, err := compileCond(sub)
		if err != nil {
			return c, err
		}
		c.Not = append(c.Not, cc)
	}
	return c, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// homoglyphDTO is the YAML shape of the homoglyph_ratio primitive:
//
//   - homoglyph_ratio: { min_count: 1 }
//   - homoglyph_ratio: { gt: 0.15, min_count: 2 }
//
// `gt` is the density gate the design note specifies; `min_count` is the one
// that actually fires on a real document (see the measurement in homoglyph.go).
// An empty mapping means min_count: 1 — presence.
type homoglyphDTO struct {
	Gt       float64 `yaml:"gt"`
	MinCount int     `yaml:"min_count"`
}

func compileHomoglyph(d *homoglyphDTO) *homoglyphCond {
	if d == nil {
		return nil
	}
	return &homoglyphCond{Gt: d.Gt, MinCount: d.MinCount}
}
