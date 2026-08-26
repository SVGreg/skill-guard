# OMS + Sigstore: primary-source findings (M4-01 spike)

Roadmap §6.3 requires the roadmap's OMS assumptions to be re-checked against
primary sources **before** any M4 code is written. This is that check. Every
claim below cites a source read on **2026-08-26**; nothing here is from memory
or from secondary write-ups.

**Bottom line:** OMS is real, versioned, and specified in enough detail to
implement against — including canonicalization rules and test vectors. Three
roadmap assumptions were wrong, and one of them (key algorithm) changes what
`sign` has to produce.

---

## Sources

| What | URL | Read |
|---|---|---|
| OMS specification v1.0 | `https://github.com/ossf/model-signing-spec/blob/main/spec/v1.0.md` | 2026-08-26 |
| OMS changelog (v1.0.0 scope) | `.../main/CHANGELOG.md` | 2026-08-26 |
| OMS algorithm registry | `.../main/algorithm-registry.md` | 2026-08-26 |
| OMS test vectors | `.../main/test-vectors/v1.0/{valid,invalid,invalid-payload}` | 2026-08-26 |
| `sigstore/sigstore-go` releases | `https://github.com/sigstore/sigstore-go` (v1.3.0, 2026-07-30) | 2026-08-26 |
| `sigstore/model-transparency` (reference impl) | `https://github.com/sigstore/model-transparency` — Python | 2026-08-26 |

---

## 1. What OMS actually is

An OMS bundle is a **Sigstore bundle** (`mediaType`, `verificationMaterial`,
`dsseEnvelope`) whose DSSE payload is an **in-toto Statement v1** with:

- `predicateType` — exactly `https://model_signing/signature/v1.0` (spec §5.1).
  The older `https://model_signing/Digests/v0.1` is deprecated; verifiers *may*
  accept it, new signers must not produce it.
- `predicate.resources[]` — one entry per **regular file**, each
  `{name, digest, algorithm}`, sorted lexicographically by `name` in Unicode
  code-point order. Directory entries are forbidden (§5.2.1).
- `predicate.serialization` — `{method, hash_type, allow_symlinks[, shard_size,
  ignore_paths]}`, the metadata a verifier needs to reproduce enumeration
  (§5.2.2).
- `subject[0]` — `{name: <basename of the model dir>, digest: {sha256: <root>}}`
  where the root digest is **SHA-256 over the concatenated raw bytes of each
  resource digest in canonical order** (§6.5.1) — always SHA-256, even when file
  digests use blake3. `subject[0].name` is informational; verifiers must accept
  any non-empty string.

DSSE `payloadType` is `application/vnd.in-toto+json`; `signatures[].keyid` is
optional and not used for verification (§4.1, §6.7).

## 2. Canonicalization — the part that silently breaks interop

Spec §6.1.2, and it is stricter than the roadmap assumed:

1. `/` separators regardless of host OS.
2. Relative to the model root; no leading `/`, no `../`.
3. Normalized: `./` prefixes and interior `.` collapsed, repeated `//` collapsed.
4. No trailing `/`.
5. Single-file models use the **basename only**.
6. Comparison is **byte-exact and case-sensitive** — `Model.bin` and `model.bin`
   are distinct resources.
7. Every path component must be valid UTF-8; a non-UTF-8 filename must be
   **rejected**, not transcoded.

**Symlinks** (§6.1.1): default `allow_symlinks: false`, links must not be
followed and should be an error; `allow_symlinks: true` is documented as headed
for removal in a future version. skill-guard already refuses to follow symlinks
(`cmd/skill-guard/ux.go`), so `false` is both the spec default and our existing
behavior — no decision needed.

**Empty directories** simply never appear: only regular files are enumerated, so
the roadmap's "empty-dir handling" concern is moot.

**Default exclusions** (§6.2): `.git`, `.gitignore`, `.gitattributes`,
`.github` MUST be excluded; implementations MAY exclude more. The signature file
itself SHOULD be excluded from its own scope (§9).

## 3. Where the roadmap was wrong

| Roadmap said | Primary source says | Consequence |
|---|---|---|
| The signature file is `skill.oms.sig` | §9: the bundle SHOULD use a **`.sig` extension** and sit alongside the model. No name is mandated. | Free choice; `skill.oms.sig` is conformant. Keep it, and document that the name is ours, not the spec's. |
| "Directory-tree canonicalization must be exactly compatible … symlink and empty-dir handling" | Fully specified in §6.1.1/§6.1.2, and empty dirs cannot occur | M4-02 is **smaller than feared** — it is implementing a written spec, not reverse-engineering one. |
| (unstated) Any signing key would do | Algorithm registry: `key`/`certificate` methods **MUST support EC P-256/P-384/P-521**. Ed25519 is not in the required set. | **This is the real finding.** skill-guard's SGMT-1 signs with **Ed25519**. An OMS bundle other tools verify needs an **ECDSA P-256** key, so `keygen`/`sign` must grow an EC path. Ed25519 stays for SGMT-1. |

## 4. Sigstore in Go

- **`sigstore/sigstore-go` v1.3.0** (2026-07-30) is active and is the right
  library for bundle construction, Fulcio, and Rekor.
- **Dependency weight measured, not guessed:** a throwaway module requiring only
  `sigstore-go` resolves to **90 modules**, pulling in `protobuf-specs`, `rekor`,
  `rekor-tiles`, `certificate-transparency-go`, `go-containerregistry`, and the
  protobuf runtime. skill-guard currently has **two** direct dependencies.
  → The roadmap's "keep it behind a build tag or isolated package" is not
  optional. Recommended split: the **bundle format** (JSON + DSSE + in-toto,
  buildable with stdlib) in the default build, and **Fulcio/Rekor** behind a
  build tag.
- The OMS reference implementation is **Python** (`sigstore/model-transparency`).
  There is no Go OMS implementation — which is precisely the gap the roadmap
  identified as the wedge.

## 5. A gift for interop testing

`test-vectors/v1.0/` ships `valid/{key,certificate,sigstore}.bundle.json` plus
`invalid/` and `invalid-payload/` cases, with a `validate.sh`. Vendoring these
gives **M4-08 cross-verification without network access** — an independently
produced bundle we must verify, and known-bad bundles we must reject, in
ordinary `go test`.

## 6. What this changes in the plan

- **M4-02** narrows to implementing §6.1.1/§6.1.2/§6.2 plus the §6.5.1 root
  digest, with the vendored vectors as the oracle.
- **M4-03** gains an explicit prerequisite: an **ECDSA P-256** signing path.
- **M4-08** becomes cheap and offline (vendored vectors) instead of requiring a
  second toolchain in CI.
- **M4-05** must isolate Fulcio/Rekor; the 90-module figure is the justification.
- Nothing here invalidates SGMT-1: it stays the local-trust format, Ed25519 and
  all, and OMS is emitted **alongside** it.

## 7. Still unverified

- Whether GitHub's `upload-sarif` honours `originalUriBaseIds` (that is M3-09,
  unrelated to OMS but the other open external assumption).
- Whether any registry currently distributes **Agent Skills** signed with OMS —
  the spec is model-oriented, and the `subject[0].name`/"model root" language is
  written for model directories. Nothing in the format prevents a skill bundle
  from being the tree, but we would be an early adopter of that usage.
