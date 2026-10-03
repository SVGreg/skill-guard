package keyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"

	"github.com/SVGreg/surfaceguard/pkg/attest/oms"
	"github.com/SVGreg/surfaceguard/pkg/skill"
)

// Public Sigstore infrastructure. They are defaults, not constants baked into
// the trust model: --fulcio-url and --rekor-url point the signer at a private
// deployment, and verification trusts only the roots the *consumer* pins. No
// vendor root is compiled into surfaceguard anywhere.
const (
	DefaultFulcioURL = "https://fulcio.sigstore.dev"
	DefaultRekorURL  = "https://rekor.sigstore.dev"
)

// ErrSingleFile is returned for a bundle loaded from a single SKILL.md: an OMS
// signature covers a directory tree, so point the signer at the skill folder.
var ErrSingleFile = errors.New("keyless: an OMS signature describes a directory tree; load the skill folder, not a single file")

// Options configures a keyless signing run.
type Options struct {
	FulcioURL string
	RekorURL  string
	// IDToken is the OIDC identity presented to Fulcio; resolve it with IDToken().
	IDToken string
	// Timeout bounds each network call. Zero uses sigstore-go's default.
	Timeout time.Duration
}

// SignBundle produces an OMS-conformant Sigstore bundle for a skill directory.
//
// The signed payload is built by the *core* module — the same enumeration,
// canonicalization, manifest and root digest that `surfaceguard sign --oms`
// uses — so a keyless signature and a key-signed one attest byte-identical
// statements about the same tree. Only the verification material differs.
func SignBundle(ctx context.Context, b *skill.Bundle, opt Options) ([]byte, error) {
	// Checked first: there is no point enumerating and hashing a tree we have
	// no identity to sign it with, and failing before any work makes the error
	// unambiguous.
	if opt.IDToken == "" {
		return nil, ErrNoIDToken
	}
	// An OMS signature describes a directory tree. A single SKILL.md enumerated
	// as if it were the tree yields a statement naming the directory while
	// covering one file, which verify then reports as a mismatch against the
	// real tree. The CLI refused this; the library did not.
	if b.SingleFile {
		return nil, ErrSingleFile
	}

	files, ser, err := oms.Enumerate(b, oms.EnumOptions{})
	if err != nil {
		return nil, err
	}
	st, err := oms.BuildStatement(oms.SubjectName(b.Root), oms.BuildResources(files), ser)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}

	if opt.FulcioURL == "" {
		opt.FulcioURL = DefaultFulcioURL
	}
	if opt.RekorURL == "" {
		opt.RekorURL = DefaultRekorURL
	}

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("keyless: generating an ephemeral key: %w", err)
	}

	content := &sign.DSSEData{Data: payload, PayloadType: oms.PayloadType}
	opts := sign.BundleOptions{
		Context:                    ctx,
		CertificateProvider:        sign.NewFulcio(&sign.FulcioOptions{BaseURL: opt.FulcioURL, Timeout: opt.Timeout}),
		CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: opt.IDToken},
		TransparencyLogs: []sign.Transparency{
			sign.NewRekor(&sign.RekorOptions{BaseURL: opt.RekorURL, Timeout: opt.Timeout}),
		},
	}

	pb, err := sign.Bundle(content, keypair, opts)
	if err != nil {
		return nil, fmt.Errorf("keyless: signing: %w", err)
	}
	wrapped, err := bundle.NewBundle(pb)
	if err != nil {
		return nil, fmt.Errorf("keyless: assembling the bundle: %w", err)
	}
	data, err := wrapped.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("keyless: serializing the bundle: %w", err)
	}

	// Round-trip through the core module's parser before writing. sigstore-go
	// produces a Sigstore bundle; whether it is a *conformant OMS* bundle is
	// our claim to make, and one surfaceguard verify must accept. Failing here
	// beats shipping a file that only looks signed.
	parsed, err := oms.ParseBundle(data)
	if err != nil {
		return nil, fmt.Errorf("keyless: produced a bundle surfaceguard cannot read: %w", err)
	}
	if _, err := parsed.Statement(); err != nil {
		return nil, fmt.Errorf("keyless: produced a bundle with an unusable statement: %w", err)
	}
	return data, nil
}
