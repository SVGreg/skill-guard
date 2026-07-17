package model

import "strings"

// ASTRef is a reference to one OWASP Agentic Skills Top 10 risk. Findings carry
// AST ids (e.g. "AST01"); this maps each id to its human title and canonical
// OWASP page so reports can cite the corresponding issue.
type ASTRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

// astTitles is the OWASP Agentic Skills Top 10 taxonomy (AST01–AST10).
// Source: https://owasp.org/www-project-agentic-skills-top-10/
var astTitles = map[string]string{
	"AST01": "Malicious Skills",
	"AST02": "Supply Chain Compromise",
	"AST03": "Over-Privileged Skills",
	"AST04": "Insecure Metadata",
	"AST05": "Untrusted External Instructions",
	"AST06": "Weak Isolation",
	"AST07": "Update Drift",
	"AST08": "Poor Scanning",
	"AST09": "No Governance",
	"AST10": "Cross-Platform Reuse",
}

// astBaseURL is the OWASP project page; per-risk pages are <base>/astNN.html.
const astBaseURL = "https://owasp.org/www-project-agentic-skills-top-10/"

// ASTInfo returns the title and reference URL for an AST id (e.g. "AST01").
// ok is false for an unknown id (the returned ref still carries the id).
func ASTInfo(id string) (ASTRef, bool) {
	title, ok := astTitles[id]
	if !ok {
		return ASTRef{ID: id}, false
	}
	return ASTRef{ID: id, Title: title, URL: astBaseURL + strings.ToLower(id) + ".html"}, true
}
