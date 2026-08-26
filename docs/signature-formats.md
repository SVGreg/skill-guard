# Signature formats: SGMT-1 and OMS

skill-guard can produce two detached signatures over the same skill. They are
not competitors — they answer different questions — but if you are choosing one,
**new work should prefer OMS**, and SGMT-1 should be treated as **legacy: fully
supported, still the default, no longer where new capability lands**.

| | `SKILL.md.skillsig` (SGMT-1) | `skill.oms.sig` (OMS v1.0) |
|---|---|---|
| Spec | skill-guard's own (`docs/skill-guard-design.md §7`) | [OpenSSF Model Signing v1.0](https://github.com/ossf/model-signing-spec) |
| Integrity | SGMT-1 Merkle root over the bundle | per-file digests + a root digest over the manifest |
| Envelope | DSSE | DSSE inside a Sigstore bundle |
| Attests a scan verdict | **yes** — the scan result at signing time | no |
| Carries an expiry | **yes** (`--ttl-days`) | no |
| Publisher identity | a self-asserted label bound to a key you registered | a key you registered, **or** an identity bound into a certificate |
| Keyless signing | no | **yes** (Fulcio + Rekor) |
| Verified by other tools | no — nobody else implements SGMT-1 | **yes** — any OMS verifier |
| Algorithms | Ed25519 (default), ECDSA P-256 | ECDSA P-256/384/521 (Ed25519 is not in the OMS registry) |

## Why both exist

SGMT-1 came first and attests something OMS deliberately does not: **the scan
verdict at the moment of signing**. "This bundle was clean when I signed it" is
a different claim from "this bundle is unchanged", and skill-guard's own gating
uses it. It also carries an expiry, so a stale attestation stops being evidence.

OMS came from the ecosystem converging on one format. Its value is that
**someone else can check it** — a signature only skill-guard can verify is not
provenance, it is a private note. It also brings keyless signing, which removes
the hardest part of key management: having a key at all.

## Which to use

- **Signing in CI** → OMS, keyless. No key exists to leak, and the identity in
  the signature is the workflow that produced it.
  See [`keyless/README.md`](../keyless/README.md).
- **Publishing for consumers outside your team** → OMS. They can verify it with
  their own tooling; they cannot verify SGMT-1 without skill-guard.
- **Gating your own pipeline on a scan verdict** → SGMT-1, or both. Only SGMT-1
  records what the scanner concluded.
- **Air-gapped review** → either. Both verify offline; neither needs the network.

Emitting both is normal and costs one flag:

```sh
skill-guard sign ./my-skill --key oms.key --oms
```

`verify` detects whichever are present and reports each with the trust path it
used. A failure in either exits `2`.

## The two trust models

**SGMT-1 — local roster.** You add a publisher's public key to `trust.keys` in
your own `.skillguard.yaml`. There is no key server and no authority: the
`--identity` recorded at signing is a self-asserted label, meaningful only
because *you* bound it to a key you chose to trust.

**OMS — roster or certificate.** A `key`-method bundle works exactly as above. A
certificate-bound bundle instead carries a short-lived certificate whose SAN
holds the signer's OIDC identity, and trust runs:

1. the certificate chains to a CA **you pinned** under `trust.roots`;
2. the transparency-log inclusion proof reconstructs its claimed root, and the
   signed checkpoint commits to that same tree;
3. the identity in the certificate matches a `trust.identities` pattern.

skill-guard ships **no** root of trust and no default log — not Sigstore's, not
anyone's. Every anchor is one the consumer chose. That is a deliberate contrast
with the vendor-anchored implementations in this space.

## Migrating

Nothing to do, and nothing is going away. SGMT-1 stays the default, keeps
working, and keeps being tested; `sign` writes it unless you say otherwise.
Adding OMS is additive:

1. Generate an EC key — `skill-guard keygen --out oms.key --type ecdsa-p256` —
   because the OMS algorithm registry does not include Ed25519.
2. Add `--oms` to your existing `sign` invocation. Both files are written.
3. Publish the EC public key alongside your existing one; consumers can list
   both in `trust.keys`.
4. When you are ready to drop long-lived keys entirely, sign keylessly in CI
   instead and hand consumers a `trust.roots` + `trust.identities` snippet.

If a future skill-guard ever deprecates SGMT-1 in earnest, it will be announced
with a migration path and a major version — not by quietly changing what `sign`
writes.

## See also

- [`docs/oms-notes.md`](oms-notes.md) — the OMS spec findings this implements, with sources.
- [`docs/skill-guard-design.md §7`](skill-guard-design.md) — the normative SGMT-1 specification.
- README: [`sign`](../README.md#sign), [`verify`](../README.md#verify),
  [Publisher identity & trust](../README.md#publisher-identity--trust-sg-prv-005).
