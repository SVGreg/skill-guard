package rules

import (
	"fmt"
	"regexp"

	"github.com/SVGreg/skill-guard/pkg/model"
	"gopkg.in/yaml.v3"
)

// Pack is a compiled rule-pack.
type Pack struct {
	APIVersion string
	Name       string
	Version    string
	Rules      []*Rule
}

// YAML DTOs (parsed, then compiled into runtime types).
type packDTO struct {
	APIVersion string    `yaml:"apiVersion"`
	Name       string    `yaml:"name"`
	Version    string    `yaml:"version"`
	Rules      []ruleDTO `yaml:"rules"`
}

type ruleDTO struct {
	ID         string   `yaml:"id"`
	Title      string   `yaml:"title"`
	AST        []string `yaml:"ast"`
	Severity   string   `yaml:"severity"`
	Engine     string   `yaml:"engine"`
	Layer      string   `yaml:"layer"`
	Confidence float64  `yaml:"confidence"`
	Languages  []string `yaml:"languages"`
	Targets    []string `yaml:"targets"`
	Match      condDTO  `yaml:"match"`
	Suppress   []string `yaml:"suppress"`
	Rationale  string   `yaml:"rationale"`
	Fix        string   `yaml:"fix"`
}

type condDTO struct {
	Any             []condDTO `yaml:"any"`
	All             []condDTO `yaml:"all"`
	Not             []condDTO `yaml:"not"`
	Regex           string    `yaml:"regex"`
	Substring       string    `yaml:"substring"`
	UnicodeCategory []string  `yaml:"unicode_category"`
	BidiControl     bool      `yaml:"bidi_control"`
	TagBlock        bool      `yaml:"tag_block"`
	URLHost         []string  `yaml:"url_host"`
	Confidence      *float64  `yaml:"confidence"`
}

// LoadPack parses and compiles a rule-pack from YAML bytes.
func LoadPack(data []byte) (*Pack, error) {
	var dto packDTO
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("parse pack: %w", err)
	}
	if dto.Name == "" {
		return nil, fmt.Errorf("pack missing name")
	}
	p := &Pack{APIVersion: dto.APIVersion, Name: dto.Name, Version: dto.Version}
	for _, rd := range dto.Rules {
		r, err := compileRule(rd)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rd.ID, err)
		}
		p.Rules = append(p.Rules, r)
	}
	return p, nil
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
		urlHost:         cd.URLHost,
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
