// Command skill-guard-keyless signs a skill bundle with Sigstore, producing an
// OMS signature (skill.oms.sig) bound to an OIDC identity rather than to a key.
//
// It is a separate binary from skill-guard because it is a separate module: the
// Sigstore client pulls in hundreds of packages, and the core tool's offline,
// two-dependency profile is a property worth keeping. Verifying what this
// produces needs only `skill-guard verify`.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SVGreg/skill-guard/keyless"
	"github.com/SVGreg/skill-guard/pkg/attest/oms"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// Exit codes match skill-guard's contract (README "Exit codes"), so a workflow
// can gate on either tool the same way.
const (
	exitOK       = 0
	exitUsage    = 3
	exitInternal = 4
)

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("skill-guard-keyless", flag.ContinueOnError)
	var (
		out       = fs.String("out", "", "output path (default <bundle>/skill.oms.sig)")
		fulcioURL = fs.String("fulcio-url", keyless.DefaultFulcioURL, "Fulcio certificate authority URL")
		rekorURL  = fs.String("rekor-url", keyless.DefaultRekorURL, "Rekor transparency log URL")
		token     = fs.String("token", "", "OIDC ID token (prefer --token-file, or let CI supply it)")
		tokenFile = fs.String("token-file", "", "file containing an OIDC ID token")
		audience  = fs.String("audience", "sigstore", "audience to request when fetching a CI OIDC token")
		timeout   = fs.Duration("timeout", 30*time.Second, "per-request network timeout")
	)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `skill-guard-keyless sign <path>

Sign a skill bundle with Sigstore: an ephemeral key, a short-lived Fulcio
certificate bound to your OIDC identity, and a Rekor transparency-log entry.
No long-lived key material is created or stored.

The signature is written as skill.oms.sig — the same OpenSSF Model Signing
format 'skill-guard sign --oms' produces, over a byte-identical statement — and
is verified with:

  skill-guard verify <path> --policy .skillguard.yaml

Verification needs the issuing CA pinned under trust.roots and the identity
scoped under trust.identities. skill-guard trusts no CA by default.

IDENTITY, in order: --token, --token-file, then GitHub Actions' OIDC endpoint
(which needs 'permissions: id-token: write'). There is no browser flow.

NETWORK: this command contacts Fulcio and Rekor. It is the one part of
skill-guard that requires network access; scanning and verifying never do.

EXIT CODES: 0 success · 3 usage error · 4 internal error.

FLAGS:
`)
		fs.PrintDefaults()
	}

	args := os.Args[1:]
	if len(args) > 0 && args[0] == "sign" {
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}
	path := fs.Arg(0)

	b, err := skill.LoadBundle(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read skill at %q: %v\n", path, err)
		return exitUsage
	}
	if b.SingleFile {
		fmt.Fprintf(os.Stderr, "error: an OMS signature describes a directory tree; point this at the skill folder.\n")
		return exitUsage
	}

	ctx := context.Background()
	idToken, err := keyless.IDToken(ctx, *token, *tokenFile, *audience)
	if err != nil {
		if errors.Is(err, keyless.ErrNoIDToken) {
			fmt.Fprint(os.Stderr, "error: no OIDC identity available.\n"+
				"  in GitHub Actions, add:  permissions:\n                             id-token: write\n"+
				"  elsewhere, pass --token-file <path> with an OIDC ID token.\n")
			return exitUsage
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitUsage
	}

	data, err := keyless.SignBundle(ctx, b, keyless.Options{
		FulcioURL: *fulcioURL,
		RekorURL:  *rekorURL,
		IDToken:   idToken,
		Timeout:   *timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitInternal
	}

	dest := *out
	if dest == "" {
		dest = oms.SigPath(b.Root)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitInternal
	}
	if err := os.WriteFile(dest, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitInternal
	}

	fmt.Printf("wrote %q (keyless, Fulcio + Rekor)\n", dest)
	if parsed, err := oms.ParseBundle(data); err == nil {
		if leaf, _, err := oms.Certificates(parsed); err == nil {
			if identity, issuer, err := oms.CertIdentity(leaf); err == nil {
				fmt.Printf("  identity: %s\n  issuer:   %s\n", identity, issuer)
			}
		}
		if when, ok := oms.IntegratedTime(parsed); ok {
			fmt.Printf("  logged:   %s\n", when.Format(time.RFC3339))
		}
	}
	fmt.Printf("  verify:   skill-guard verify %q --policy .skillguard.yaml\n", path)
	return exitOK
}
