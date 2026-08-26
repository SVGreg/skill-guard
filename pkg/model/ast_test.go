package model

import "testing"

func TestASTInfoKnown(t *testing.T) {
	ref, ok := ASTInfo("AST01")
	if !ok {
		t.Fatal("AST01 should be known")
	}
	if ref.Title != "Malicious Skills" {
		t.Errorf("AST01 title = %q", ref.Title)
	}
	if ref.URL != "https://owasp.org/www-project-agentic-skills-top-10/ast01.html" {
		t.Errorf("AST01 url = %q", ref.URL)
	}
}

func TestASTInfoAllTenPresent(t *testing.T) {
	for _, id := range []string{"AST01", "AST02", "AST03", "AST04", "AST05", "AST06", "AST07", "AST08", "AST09", "AST10"} {
		if ref, ok := ASTInfo(id); !ok || ref.Title == "" {
			t.Errorf("%s missing from catalog", id)
		}
	}
}

func TestASTInfoUnknown(t *testing.T) {
	ref, ok := ASTInfo("AST99")
	if ok {
		t.Fatal("AST99 should be unknown")
	}
	if ref.ID != "AST99" {
		t.Errorf("unknown ref should still carry id, got %q", ref.ID)
	}
}

// TestASTAllIsTheWholeCatalogInOrder: SARIF's taxonomies[] claims to be
// comprehensive, so a gap or a shuffle here is a wire-format bug elsewhere.
func TestASTAllIsTheWholeCatalogInOrder(t *testing.T) {
	all := ASTAll()
	if len(all) != 10 {
		t.Fatalf("ASTAll returned %d entries, want 10", len(all))
	}
	for i, ref := range all {
		want := "AST" + string(rune('0'+(i+1)/10)) + string(rune('0'+(i+1)%10))
		if ref.ID != want {
			t.Errorf("entry %d = %s, want %s", i, ref.ID, want)
		}
		if ref.Title == "" || ref.URL == "" {
			t.Errorf("%s has an empty title or url", ref.ID)
		}
	}
}
