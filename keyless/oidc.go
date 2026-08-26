// Package keyless signs skill bundles with Sigstore: an ephemeral key, a
// short-lived Fulcio certificate bound to an OIDC identity, and a Rekor
// transparency-log entry. No long-lived key material exists at any point, which
// is the property that makes CI signing safe.
//
// This is a separate Go module from skill-guard's core. See go.mod for why.
package keyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ErrNoIDToken is returned when no OIDC identity is available. It is the
// expected outcome outside CI, so callers should say how to supply one rather
// than treat it as a defect.
var ErrNoIDToken = errors.New("keyless: no OIDC token available")

// IDToken resolves the OIDC identity to present to Fulcio, in order:
//
//  1. an explicit token (--token), for callers that already have one;
//  2. a token file (--token-file), so a token never has to appear in a process
//     listing or a shell history;
//  3. GitHub Actions' OIDC endpoint, using the credentials the runner injects.
//
// Nothing else is attempted. In particular there is no interactive browser
// flow: this exists to be run by CI, and a signing tool that can silently open
// a browser is a signing tool that can be triggered into signing something a
// human did not intend.
func IDToken(ctx context.Context, token, tokenFile, audience string) (string, error) {
	if token != "" {
		return strings.TrimSpace(token), nil
	}
	if tokenFile != "" {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("keyless: cannot read token file: %w", err)
		}
		t := strings.TrimSpace(string(data))
		if t == "" {
			return "", fmt.Errorf("keyless: token file %q is empty", tokenFile)
		}
		return t, nil
	}
	return githubActionsToken(ctx, audience)
}

// githubActionsToken requests an OIDC token from the endpoint GitHub Actions
// injects when a job declares `permissions: id-token: write`.
func githubActionsToken(ctx context.Context, audience string) (string, error) {
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqToken == "" {
		return "", ErrNoIDToken
	}
	if audience != "" {
		u, err := url.Parse(reqURL)
		if err != nil {
			return "", fmt.Errorf("keyless: malformed ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
		}
		q := u.Query()
		q.Set("audience", audience)
		u.RawQuery = q.Encode()
		reqURL = u.String()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+reqToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("keyless: requesting a GitHub OIDC token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("keyless: reading the OIDC response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body can echo the request token, so it is deliberately not
		// included in the message.
		return "", fmt.Errorf("keyless: GitHub OIDC endpoint returned %s", resp.Status)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("keyless: malformed OIDC response: %w", err)
	}
	if out.Value == "" {
		return "", ErrNoIDToken
	}
	return out.Value, nil
}
