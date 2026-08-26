package keyless

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/SVGreg/skill-guard/pkg/skill"
)

// TestIDTokenPrecedence: an explicit token wins, then a file, then CI. The
// order matters because a stale CI token silently signing under the wrong
// identity is worse than an error.
func TestIDTokenPrecedence(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("  from-file\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := IDToken(context.Background(), " explicit ", file, "")
	if err != nil || got != "explicit" {
		t.Errorf("explicit token: got %q, %v", got, err)
	}
	got, err = IDToken(context.Background(), "", file, "")
	if err != nil || got != "from-file" {
		t.Errorf("token file: got %q, %v (whitespace must be trimmed)", got, err)
	}
	if _, err := IDToken(context.Background(), "", filepath.Join(dir, "missing"), ""); err == nil {
		t.Error("a missing token file was accepted")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := IDToken(context.Background(), "", empty, ""); err == nil {
		t.Error("an empty token file was accepted")
	}
}

// TestIDTokenFromGitHubActions drives the real code path against a stand-in for
// the runner's OIDC endpoint, including the audience parameter and the bearer
// credential it expects.
func TestIDTokenFromGitHubActions(t *testing.T) {
	var gotAudience, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAudience = r.URL.Query().Get("audience")
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "ci-token"})
	}))
	defer srv.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"?x=1")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-secret")

	got, err := IDToken(context.Background(), "", "", "sigstore")
	if err != nil {
		t.Fatalf("IDToken: %v", err)
	}
	if got != "ci-token" {
		t.Errorf("token = %q, want the endpoint's value", got)
	}
	if gotAudience != "sigstore" {
		t.Errorf("audience = %q, want sigstore", gotAudience)
	}
	if gotAuth != "Bearer runner-secret" {
		t.Errorf("authorization = %q", gotAuth)
	}
}

// TestIDTokenErrorHidesTheRequestToken: the endpoint can echo the runner
// credential in an error body, and a signing tool must not print it.
func TestIDTokenErrorHidesTheRequestToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad credential: runner-secret", http.StatusForbidden)
	}))
	defer srv.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-secret")

	_, err := IDToken(context.Background(), "", "", "")
	if err == nil {
		t.Fatal("a 403 was accepted")
	}
	if got := err.Error(); contains(got, "runner-secret") {
		t.Errorf("the error leaked the request token: %q", got)
	}
}

// TestIDTokenAbsentOutsideCI: no identity is an expected state with actionable
// advice, not a crash.
func TestIDTokenAbsentOutsideCI(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	if _, err := IDToken(context.Background(), "", "", ""); !errors.Is(err, ErrNoIDToken) {
		t.Errorf("error = %v, want ErrNoIDToken", err)
	}
}

// TestSignBundleNeedsAnIdentity: signing must refuse before touching the
// network — or even hashing the tree — when there is no identity to bind.
func TestSignBundleNeedsAnIdentity(t *testing.T) {
	b := &skill.Bundle{Root: "/tmp/demo", Files: []skill.File{
		{Path: "SKILL.md", Content: []byte("---\nname: demo\n---\nbody\n")},
	}}
	if _, err := SignBundle(context.Background(), b, Options{}); !errors.Is(err, ErrNoIDToken) {
		t.Errorf("error = %v, want ErrNoIDToken", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
