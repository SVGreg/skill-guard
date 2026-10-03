package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func runArgs(t *testing.T, args ...string) int {
	t.Helper()
	old := os.Args
	os.Args = append([]string{"surfaceguard-keyless"}, args...)
	defer func() { os.Args = old }()
	return run()
}

func skillDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: t\ndescription: d\n---\nBody.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestExitCodesForIdentityFailures pins the exit-code contract for the
// identity step, all before any Fulcio/Rekor call: no identity is usage (3), a
// user-supplied token that cannot be used is usage (3), and a failing CI OIDC
// endpoint is an environment failure (4), not a mistake in the invocation.
func TestExitCodesForIdentityFailures(t *testing.T) {
	dir := skillDir(t)

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	if got := runArgs(t, "sign", dir); got != exitUsage {
		t.Errorf("no identity: exit %d, want %d", got, exitUsage)
	}
	if got := runArgs(t, "sign", "--token", "   ", dir); got != exitUsage {
		t.Errorf("whitespace --token: exit %d, want %d", got, exitUsage)
	}
	if got := runArgs(t, "sign", "--token-file", filepath.Join(dir, "missing"), dir); got != exitUsage {
		t.Errorf("missing --token-file: exit %d, want %d", got, exitUsage)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-secret")
	if got := runArgs(t, "sign", dir); got != exitInternal {
		t.Errorf("failing CI OIDC endpoint: exit %d, want %d", got, exitInternal)
	}
}
