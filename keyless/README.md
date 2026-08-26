# `skill-guard-keyless`

Sign a skill with [Sigstore](https://www.sigstore.dev/): an ephemeral key, a
short-lived Fulcio certificate bound to your OIDC identity, and a Rekor
transparency-log entry. **No long-lived key material is created or stored** —
which is what makes signing in CI safe, since there is no secret to leak.

The output is `skill.oms.sig`, the same OpenSSF Model Signing format
`skill-guard sign --oms` produces, over a byte-identical statement. Only the
verification material differs: a certificate instead of a public key.

## Why this is a separate module

The Sigstore client pulls in roughly **370 modules**. skill-guard's core is a
**two-dependency**, offline, single-static-binary tool, and that is a property
people choose it for. Keeping the graph out here means

```sh
go install github.com/SVGreg/skill-guard/cmd/skill-guard@latest
```

downloads two dependencies whether or not anyone ever signs keylessly. CI
asserts this: a job fails if the core module gains a direct dependency or if the
`skill-guard` binary ever links Sigstore or protobuf code.

**Verifying** a keyless signature needs nothing from this module — it is in the
core module's `pkg/verify` and uses only the standard library.

## Install

```sh
git clone https://github.com/SVGreg/skill-guard && cd skill-guard/keyless
go build -o skill-guard-keyless ./cmd/skill-guard-keyless
```

`go install …/keyless/cmd/skill-guard-keyless@latest` does not work yet: this
module resolves the core module through a `replace` directive so it always
builds against the adjacent source, and `go install` refuses a module with
replaces. That goes away once a core release containing `pkg/attest/oms` is
tagged (plan row **M4-13**).

## Use

```sh
skill-guard-keyless sign ./my-skill
```

```
wrote "my-skill/skill.oms.sig" (keyless, Fulcio + Rekor)
  identity: https://github.com/acme/tools/.github/workflows/release.yml@refs/heads/main
  issuer:   https://token.actions.githubusercontent.com
  logged:   2026-08-26T09:14:22Z
  verify:   skill-guard verify "./my-skill" --policy .skillguard.yaml
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
    uses: SVGreg/skill-guard/.github/workflows/keyless-sign.yml@main
    with:
      path: ./my-skill
```

## Network

This is the **only** part of skill-guard that requires network access — it
contacts Fulcio and Rekor by necessity. Scanning and verifying never do:
verification uses the roots you pinned and the proof that travels inside the
bundle.

## Verifying what it produces

```yaml
# .skillguard.yaml
trust:
  roots:
    - name: sigstore-public
      path: ./fulcio-roots.pem
  identities:
    - pattern: "https://github.com/acme/*/.github/workflows/*.yml@refs/heads/main"
      issuer: "https://token.actions.githubusercontent.com"
```

```sh
skill-guard verify ./my-skill --policy .skillguard.yaml
```

skill-guard trusts no certificate authority by default, including Sigstore's.
Pinning is the consumer's decision — see the main README's
[Keyless (certificate-bound) signatures](../README.md#keyless-certificate-bound-signatures).
