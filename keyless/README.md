# `surfaceguard-keyless`

Sign a skill with [Sigstore](https://www.sigstore.dev/): an ephemeral key, a
short-lived Fulcio certificate bound to your OIDC identity, and a Rekor
transparency-log entry. **No long-lived key material is created or stored** —
which is what makes signing in CI safe, since there is no secret to leak.

The output is `skill.oms.sig`, the same OpenSSF Model Signing format
`surfaceguard sign --oms` produces, over a byte-identical statement. Only the
verification material differs: a certificate instead of a public key.

## Why this is a separate module

The Sigstore client pulls in roughly **370 modules**. surfaceguard's core is a
**two-dependency**, offline, single-static-binary tool, and that is a property
people choose it for. Keeping the graph out here means

```sh
go install github.com/SVGreg/surfaceguard/cmd/surfaceguard@latest
```

downloads two dependencies whether or not anyone ever signs keylessly. CI
asserts this: a job fails if the core module gains a direct dependency or if the
`surfaceguard` binary ever links Sigstore or protobuf code.

**Verifying** a keyless signature needs nothing from this module — it is in the
core module's `pkg/verify` and uses only the standard library.

## Install

```sh
go install github.com/SVGreg/surfaceguard/keyless/cmd/surfaceguard-keyless@latest
```

This module pins a **released** core version in its `go.mod` (currently
`v0.6.0`), not the adjacent source. So a core change this module depends on
must be released before it can be used here: bump the requirement with
`go get github.com/SVGreg/surfaceguard@<tag>`, then `go mod tidy`. For local
development against unreleased core code, add a temporary
`go work init . ..` workspace instead of a `replace`, since `go install`
refuses modules with replaces.

## Use

```sh
surfaceguard-keyless sign ./my-skill
```

```
wrote "my-skill/skill.oms.sig" (keyless, Fulcio + Rekor)
  identity: https://github.com/acme/tools/.github/workflows/release.yml@refs/heads/main
  issuer:   https://token.actions.githubusercontent.com
  logged:   2026-08-26T09:14:22Z
  verify:   surfaceguard verify "./my-skill" --policy .surfaceguard.yaml
```

| Flag | Default | Description |
|------|---------|-------------|
| `--token-file` | – | file containing an OIDC ID token |
| `--token` | – | an OIDC ID token directly (prefer `--token-file`) |
| `--audience` | `sigstore` | audience requested when fetching a CI token |
| `--fulcio-url` | `https://fulcio.sigstore.dev` | certificate authority |
| `--rekor-url` | `https://rekor.sigstore.dev` | transparency log |
| `--timeout` | `30s` | per-request network timeout |

Identity resolution order: `--token`, then `--token-file`, then GitHub Actions'
OIDC endpoint (which needs `permissions: id-token: write`). **There is no
browser flow** — this runs in CI, and a signing tool that can silently open a
browser is one that can be nudged into signing something nobody intended.

In a workflow, use the reusable
[`keyless-sign.yml`](../.github/workflows/keyless-sign.yml):

```yaml
jobs:
  sign:
    uses: SVGreg/surfaceguard/.github/workflows/keyless-sign.yml@main
    with:
      path: ./my-skill
```

## Network

This is the **only** part of surfaceguard that requires network access — it
contacts Fulcio and Rekor by necessity. Scanning and verifying never do:
verification uses the roots you pinned and the proof that travels inside the
bundle.

## Verifying what it produces

```yaml
# .surfaceguard.yaml
trust:
  roots:
    - name: sigstore-public
      path: ./fulcio-roots.pem
  identities:
    - pattern: "https://github.com/acme/*/.github/workflows/*.yml@refs/heads/main"
      issuer: "https://token.actions.githubusercontent.com"
```

```sh
surfaceguard verify ./my-skill --policy .surfaceguard.yaml
```

surfaceguard trusts no certificate authority by default, including Sigstore's.
Pinning is the consumer's decision — see the main README's
[Keyless (certificate-bound) signatures](../README.md#keyless-certificate-bound-signatures).
