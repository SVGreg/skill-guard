# skill-guard — v1.0 Development Plan (execution tracker)

> **What this file is.** The executable breakdown of `docs/v1-dev-roadmap.md` into tasks that
> consecutive agent sessions can pick up, finish, and tick off without re-reading the whole
> roadmap. The roadmap says *what and why*; this file says *what is next, what it depends on,
> and how we know it is done*.
>
> **Who writes it:** `/sg-plan` (planning only — never code).
> **Who executes it:** `/sg-develop` (one task per cycle, one PR per cycle).
> **Do not delete completed rows** — the history is the audit trail.

## How to read a task

Every task is one PR and one session's work. A task row is:

| Field | Meaning |
|---|---|
| **ID** | `M<milestone>-<nn>`, stable forever. Never renumber; retire with status `dropped`. |
| **Status** | `todo` · `in-progress` · `done` · `blocked` · `owner` · `dropped` |
| **Deps** | Task IDs that must be `done` first. Empty = startable now. |
| **PR** | Set by `sg-develop` when it opens the PR; the row flips to `done` when that PR merges. |

`blocked` = waiting on an external answer (record what, in the card).
`owner` = needs a human with credentials/accounts (marketplace publish, demo repo, key material).
`sg-develop` never picks `blocked` or `owner` rows; it reports them instead.

**Planning horizon.** Only the current and next milestone are expanded into full task cards.
Later milestones stay as task titles until `/sg-plan` expands them — that keeps the plan honest,
because each expansion re-checks the repo and (for M4) primary sources first.

---

## 0. Reconciliation with the repo (2026-08-24)

Roadmap §6.6 says: where the roadmap and the repo disagree, trust the repo and flag it. Flagged:

1. **Rule packs.** The roadmap lists five packs; the repo ships **seven** files —
   `core-injection`, `core-network`, `core-exec`, `core-secret`, `core-metadata`,
   **`core-supply`** (AST02) and **`context.yaml`** (context/demotion rules). Plan text uses the
   repo's set.
2. **Milestone numbering collides.** `docs/skill-guard-design.md §14` also has an M1–M5 ladder
   whose M3/M4/M5 mean different things (cards+SARIF / embedding / advanced engines) than the
   roadmap's M3–M8. **This plan uses the roadmap numbering (M3–M8).** When a commit or doc says
   "M4", it means the roadmap's OMS milestone unless it cites `design §14`.
3. **Version targets are behind the tag line.** The roadmap's table maps M3 → v0.2, but
   **v0.2.1 is already released** without SARIF. Working assumption for this plan: the milestone
   *order* stands, the version labels shift by one — M3 → v0.3, M4 → v0.4, M5 → v0.5, M6 → v0.6,
   M7 → v0.7, M8 → v1.0. Actual release numbering is `release-please`'s call at merge time; this
   mapping is for planning only.
4. **README lag.** README's install snippet still pins `VERSION=v0.1.0` and its status section says
   "beyond M1/M2 … not yet implemented". Reconciling it is task **M3-07**, per roadmap §6.5.
6. **A load-time gate already exists.** `hooks/` ships a Claude Code `PreToolUse` hook (pure
   stdlib Python) that resolves a skill name to a bundle and allows/blocks the call. The roadmap
   described M5's reference integration as unbuilt; it was substantially built, so M5-07
   *finished* it rather than starting it — replacing the part worth replacing, which was the hook
   re-deriving a decision from `verify`'s **text** output. Since #235 it reads `guard`'s JSON
   `outcome`.
7. **The design already specifies this milestone's API.** `docs/skill-guard-design.md §11.1`
   defines `Guard()` as the agent-loop entrypoint and `WithVerdictCache` as merkle-root-keyed.
   M5-02/M5-03 implement that spec rather than inventing one, and §15's open question 1 (what
   `fail_on` `Guard()` defaults to) is surfaced on the M5-02 card as an owner decision.
5. **Waivers already survive scanning** — `scan.Report.Waived` keeps waived findings rather than
   dropping them, so the SARIF `suppressions` requirement (M3-04) needs no scan-engine change.

---

## 1. Milestone board

| Milestone | Theme | Tasks | Status |
|---|---|---|---|
| **M3** | SARIF output + CI surface | M3-01 … M3-09 | M3-01…M3-07 done; M3-08/09 need the owner |
| **M4** | OMS + Sigstore keyless interop | M4-01 … M4-13 | **complete** except M4-13 (needs a release) |
| **M5** | Load-time / install-time gate + skill cards | M5-01 … M5-09 | expanded |
| **M6** | Taint analysis engine | titles only | needs `/sg-plan` |
| **M7** | LLM / semantic engine (opt-in) | titles only | needs `/sg-plan` |
| **M8** | Hardening (parallel) | titles only | needs `/sg-plan` |
| **D** | Distribution track (parallel from M3) | D-01 … D-06 | expanded |

---

## 2. Cross-cutting definition of done

Applies to **every** task; `sg-develop` checks it before opening any PR. From roadmap §2.

- [ ] `gofmt -l .` empty · `go vet ./...` · `go test ./...` green
- [ ] Exit-code smoke: `scan testdata/malicious` → 1, `scan testdata/benign` → 0
- [ ] Backwards compatible: `scan`/`sign`/`verify` CLI surface and JSON shape are additive-only
- [ ] `ast_references` survives into every output format the task touches
- [ ] Any new network dependency ships its offline path **in the same task**
- [ ] Docs updated in the same PR (roadmap §2: docs ship with the feature)
- [ ] Rule-pack edits bump that pack's `version:` (CLAUDE.md / design §8.1)
- [ ] Perf budget intact: `scan` well under a second on a typical bundle; cached `verify` in
      single-digit ms

---

## M3 — SARIF output and CI surface

**Goal (roadmap §M3):** skill-guard findings render in the GitHub Security tab, with AST refs
visible per finding and waivers shown as suppressions.

| ID | Task | Status | Deps | PR |
|---|---|---|---|---|
| M3-01 | SARIF 2.1.0 emitter in `pkg/report` | done | — | #205 |
| M3-02 | `--format sarif` wired into `scan` | done | M3-01 | #207 |
| M3-03 | AST01–AST10 carried into SARIF taxonomy | done | M3-01 | #208 |
| M3-04 | Waivers → SARIF `suppressions`; demotion preserved | done | M3-01 | #209 |
| M3-05 | Golden-file + offline schema-validation tests | done | M3-01 | #210 |
| M3-06 | GitHub Action (`action.yml`) running scan + upload-sarif | done | M3-02 | #211 |
| M3-07 | Docs: SARIF mapping page, README version reconcile | done | M3-02 | #212 |
| M3-08 | Public demo repo showing findings in the Security tab | owner | M3-06 | |
| M3-09 | Artifact URIs resolvable from the repo workspace (GitHub alert linking) | todo | M3-06 | |

### M3-01 — SARIF 2.1.0 emitter
**Goal.** `report.SARIF(w, rep, opt)` alongside `Text`/`JSON`/`SkillCard`, emitting a valid SARIF
2.1.0 log for one scan run.
**Deliverables.** Emitter in `pkg/report`; `runs[0].tool.driver` = name/version/informationUri +
`rules[]` for every rule that produced a result (`id`, `name`, `shortDescription`,
`fullDescription` from `rationale`, `helpUri`, `defaultConfiguration.level`); `results[]` with
`ruleId`, `level`, `message.text`, `locations[]` (`artifactLocation.uri` relative to the bundle
root, `region.startLine`/`endLine`), and `partialFingerprints` — a stable hash over
`rule|file|normalized-excerpt` so GitHub dedups across runs and **line drift does not create a new
alert**. Raw `confidence`, `risk_score`, `engine`, `layer` go in `properties`.
**Acceptance.** `go test ./pkg/report/` green; a scan of `testdata/malicious` produces a log whose
`results[].ruleId` set equals the scan's non-waived finding rule ids.

### M3-02 — `--format sarif` on `scan`
**Goal.** The emitter is reachable from the CLI without changing existing behavior.
**Deliverables.** `sarif` added to `validFormats` (`cmd/skill-guard/ux.go`) and the `emit` switch
(`cmd/skill-guard/commands.go`); `--format` help text and the `OUTPUT (--format)` block updated;
`--out` works as for JSON.
**Acceptance.** `skill-guard scan testdata/malicious --format sarif --out x.sarif` exits **1**
(verdict unchanged by format) and writes parseable JSON; an unknown format still exits 3.

### M3-03 — AST taxonomy in SARIF
**Goal.** The OWASP mapping — the project's differentiator — survives the export.
**Deliverables.** Per-rule `properties.tags` carrying `AST0X` plus `security`; a
`runs[0].taxonomies[]` entry describing AST01–AST10 from `pkg/model/ast.go` with
`results[].taxa` / `rules[].relationships` pointing at it. No hard-coded taxonomy strings — read
`model.ASTInfo`.
**Acceptance.** Every emitted rule with `ast` ids has matching tags **and** a taxa reference; test
asserts the taxonomy has exactly ten entries.

### M3-04 — Suppressions and demotion
**Goal.** Policy decisions are visible, not silent.
**Deliverables.** Each `rep.Waived` finding emitted as a `result` with
`suppressions[] {kind: "external", justification: <waiver reason>}` rather than being dropped;
a context-demoted finding keeps `DemotedBy`/`OriginalSeverity` in `properties` while its `level`
reflects the demoted severity.
**Acceptance.** Fixture policy with one waiver → the waived rule appears exactly once, suppressed;
counts in `properties` still exclude it.

### M3-05 — Golden files and schema validation
**Goal.** The format is pinned and validated **offline** (principle #1 — CI must not need network).
**Deliverables.** Vendored SARIF 2.1.0 JSON schema under `testdata/` (or `pkg/report/testdata/`)
with provenance noted; golden `.sarif` outputs for the benign and malicious fixtures; a
validation test. Prefer a stdlib/existing-dep validator; adding a dependency needs a note in the
PR body explaining why the two-dep policy bends.
**Acceptance.** Golden diff is stable across two consecutive runs (no timestamps, no map-order
churn) and validates against the vendored schema with the network off.

### M3-06 — GitHub Action
**Goal.** One copy-pasteable step gets skill-guard results into code scanning.
**Deliverables.** A composite `action.yml` at the repo root (decision: ship in-repo first —
`SVGreg/skill-guard@v0` — a separate `skill-guard-action` repo only if marketplace listing
requires it); inputs `path`, `format`, `fail-on`, `policy`, `sarif-file`; installs the released
binary (no `go build` on the runner), runs the scan, always uploads SARIF via
`github/codeql-action/upload-sarif` even when the scan fails the gate; documented exit-code
behavior and a `continue-on-error` pattern.
**Acceptance.** A workflow in this repo scans `testdata/malicious`, uploads SARIF, and the job's
gate fails on exit 1 while the upload still happens.

### M3-07 — Docs
**Goal.** Roadmap §2 "docs ship with the feature" and §6.5 README reconcile.
**Amended in M3-02** — the user-visible half (README format table, `--format sarif` examples, the
code-scanning workflow snippet, and the status paragraph) shipped with the flag itself, because
documenting a format the CLI does not accept would have been false and documenting it later would
have left a released feature invisible. What remains here: `docs/sarif-mapping.md` (severity →
level, fingerprints, tags/taxa, suppressions) once M3-03/M3-04 fix those mappings, the exit-code
contract restated for gating, and pinning the README install snippet to the current tag.
**Acceptance.** README no longer claims SARIF is unimplemented; the snippet's version matches
`git tag --sort=-v:refname | head -1`.

### M3-09 — Repo-workspace-relative artifact URIs
**Why this exists.** Findings carry **bundle**-relative paths (`SKILL.md`, `scripts/setup.sh`), not
repo-relative ones, so a bundle scanned at `./skills/foo` yields `SKILL.md` — which GitHub resolves
against the checkout root and fails to link. M3-01 emits the SARIF-standard escape hatch
(`uriBaseId: SRCROOT` + `originalUriBaseIds`), but whether GitHub's uploader honours it must be
confirmed against a real upload, not assumed.
**Deliverables.** Confirm behavior with an actual code-scanning upload during M3-06; if the base id
is ignored, prefix result URIs with the scanned path (an emitter option, not a change to
`Finding.File`, which stays bundle-relative for the JSON contract).
**Acceptance.** An alert in the Security tab links to the correct file in the repo tree.

### M3-08 — Public demo (owner)
**Goal.** Roadmap's "done when" for M3.
**Blocked on the owner:** a public repo + Advanced Security enabled. Deliverable is a screenshot
or link in the M3 wrap-up showing findings with AST refs and a suppressed waiver.

---

## M4 — OMS-compatible signing + Sigstore keyless verification

**Goal (roadmap §M4):** cross-verification with independent OMS tooling, keyless CI signing with
no stored secrets, and offline verification against a pinned trust bundle. **This is the wedge —
if effort must be cut, cut M6/M7, never this.**

| ID | Task | Status | Deps | PR |
|---|---|---|---|---|
| M4-01 | Spike: re-verify OMS spec + Sigstore Go surface against primary sources | done | — | #213 |
| M4-02 | Vendor the OMS v1.0 test vectors as the interop oracle | done | M4-01 | #214 |
| M4-03 | OMS path canonicalization + file enumeration (spec §6.1–§6.2) | done | M4-02 | #215 |
| M4-04 | OMS manifest, root digest, in-toto statement (spec §5, §6.4–§6.6) | done | M4-03 | #216 |
| M4-05 | ECDSA P-256 signing path (`keygen`/`sign`), Ed25519 kept for SGMT-1 | done | M4-01 | #217 |
| M4-06 | OMS bundle writer — `skill.oms.sig` alongside `.skillsig` | done | M4-04, M4-05 | #218 |
| M4-07 | OMS verifier + signature-type auto-detection in `verify` | done | M4-06 | #219 |
| M4-08 | Identity-based trust policy in `.skillguard.yaml` | done | M4-07 | #220 |
| M4-09 | Keyless **verification**: pinned roots, cert identity, log-anchored time | done | M4-07, M4-08 | #221 |
| M4-12 | Keyless **signing** in a separate `keyless/` module | done | M4-09 | #222 |
| M4-13 | Drop `keyless/`'s replace directive once a core release ships `pkg/attest/oms` | blocked | M4-12 | |
| M4-10 | Rekor inclusion-proof checking (pinned log keys, offline) | done | M4-09 | #224 |
| M4-11 | SGMT-1 documented as legacy; migration guidance | done | M4-12 | #225 |

### M4-01 — Primary-source spike (do this first)
**Done.** Findings in [`docs/oms-notes.md`](oms-notes.md), read 2026-08-26 from the OMS v1.0
spec, its algorithm registry, its test vectors, and the `sigstore-go` release/dependency surface.
The M4 cards below were rewritten from those findings; three roadmap assumptions were wrong and
one of them changes what `sign` must produce. Summary:

- OMS v1.0 **is** fully specified — canonicalization (§6.1.2), symlinks (§6.1.1), exclusions
  (§6.2), root digest (§6.5.1) — so this is implementing a written spec, not reverse-engineering.
- **Key algorithm is the real finding:** the `key`/`certificate` methods require **EC
  P-256/384/521**. skill-guard signs with **Ed25519**, so an OMS bundle needs a new EC path.
- `sigstore-go` v1.3.0 pulls **90 modules** (measured). Fulcio/Rekor must be behind a build tag;
  the bundle format itself is stdlib-only JSON + DSSE + in-toto.
- The spec ships **test vectors**, so interop testing is offline and cheap.
- Empty directories cannot occur (only regular files are enumerated), and the signature filename
  is not mandated — `skill.oms.sig` is our choice, and conformant.

### M4-02 — Vendor the OMS v1.0 test vectors
**Goal.** Get the interop oracle in-tree before writing code against the spec.
**Deliverables.** `valid/{key,certificate,sigstore}.bundle.json`, the `invalid/` and
`invalid-payload/` cases, and a provenance note (source, commit, retrieval date) under
`pkg/attest/testdata/oms/` or `pkg/verify/testdata/oms/`. A test that parses each valid bundle
into our types and round-trips it, ignoring nothing silently.
**Acceptance.** `go test ./pkg/...` parses every vendored valid vector and reports, per file, the
predicate type, resource count, and signing method — with the network off.

### M4-03 — Path canonicalization and file enumeration
**Goal.** Byte-exact agreement with spec §6.1–§6.2; a mismatch here fails cross-verification
*silently*, which is the worst failure mode available.
**Deliverables.** Enumerate regular files only; `/` separators; reject `../`, leading `/`, and
non-UTF-8 names; collapse `./` and `//`; no trailing `/`; single-file bundles use the basename;
byte-exact case-sensitive comparison; default exclusions `.git`, `.gitignore`, `.gitattributes`,
`.github`, plus the signature files themselves; `allow_symlinks: false` (which matches
skill-guard's existing refusal to follow symlinks). Shares the walk with SGMT-1, not the
serialization.
**Acceptance.** Table test covering every §6.1.2 rule, including the rejection cases; a bundle
with a non-UTF-8 filename is refused rather than transcoded.

### M4-04 — Manifest, root digest, in-toto statement
**Goal.** Produce the signed payload OMS verifiers expect.
**Deliverables.** `predicate.resources[]` (`name`/`digest`/`algorithm`, sorted lexicographically
by name in code-point order, files only); `predicate.serialization`
(`method: "files"`, `hash_type: "sha256"`, `allow_symlinks: false`, `ignore_paths`); root digest
= SHA-256 over concatenated **raw** resource-digest bytes in canonical order (§6.5.1);
`subject[0] = {name: <bundle dir basename>, digest: {sha256: …}}`; statement `_type`
`https://in-toto.io/Statement/v1` and `predicateType`
`https://model_signing/signature/v1.0`.
**Acceptance.** Recomputing the statement for a vendored valid vector's file set reproduces that
vector's `subject[0].digest.sha256` byte for byte.

### M4-05 — ECDSA P-256 signing path
**Goal.** Sign with an algorithm OMS verifiers are required to support.
**Deliverables.** `keygen --type ecdsa-p256` (Ed25519 stays the default for SGMT-1); signer
interface extended rather than replaced; key files distinguish their type; `verify` handles both.
**Acceptance.** An ECDSA P-256 key signs and verifies end to end; every existing Ed25519
attestation still verifies unchanged.

### M4-06 — OMS bundle writer
**Goal.** Emit a real Sigstore bundle.
**Deliverables.** DSSE envelope (`payloadType: application/vnd.in-toto+json`, PAE, base64
payload) wrapped in a Sigstore bundle with `verificationMaterial.publicKey` for the `key` method
(hex fingerprint `hint`); written as `skill.oms.sig` **alongside** the existing `.skillsig`,
never instead of it. Document that the filename is skill-guard's choice — the spec only asks for
a `.sig` extension beside the bundle.
**Acceptance.** `sign` produces both files; the OMS bundle validates against the OMS JSON schema;
SGMT-1 output is byte-identical to before.

### M4-07 — OMS verifier + auto-detection
**Goal.** `verify` accepts either format and says which trust path it used.
**Deliverables.** Detect which signature file(s) are present; verify the DSSE signature, then
each file digest per §8.4; report the trust path in text and JSON. Reuse existing `SG-PRV-*` ids
where the meaning matches — `docs/rule-verification.md` is the authority. Reject the vendored
`invalid/` and `invalid-payload/` vectors with distinguishable errors.
**Acceptance.** Bundle with only `.skillsig`, only `skill.oms.sig`, and both — all verify
correctly; every vendored invalid vector is rejected; tamper still exits 2.

### M4-08 — Identity-based trust policy
**Goal.** Trust an identity pattern, not only a key.
**Deliverables.** `.skillguard.yaml` gains identity-pattern trust (e.g. `repo:org/*` OIDC
identities) beside the key roster; multiple roots configurable; **no hard-coded vendor root**;
documented precedence between roster and identity rules; revocation still wins.
**Acceptance.** Table test: matching identity → trusted; near-miss → untrusted; revoked → untrusted.

### M4-09 — Keyless verification (split from the original card)
**Goal.** Verify a certificate-bound OMS bundle — the *consuming* half of keyless — with no new
dependencies.
**Deliverables.** Certificate and chain extraction; identity + OIDC issuer from the SAN and the
Fulcio OID extensions; chain verification against **consumer-pinned** `trust.roots` (inline PEM or
path, resolved relative to the policy file); validity anchored on the transparency-log integrated
time; the bound identity admitted through M4-08's `trust.identities`.
**Acceptance.** A certificate-bound bundle verifies against a pinned root and is refused without
one; `go list -deps ./cmd/skill-guard` contains no Sigstore or protobuf package.

### M4-12 — Keyless signing (Fulcio/Rekor) — **needs an owner decision**
**Goal.** Produce a keyless signature in CI with no stored secrets.
**Why it is blocked.** The roadmap says to keep Sigstore "behind a build tag or isolated package
so the offline core stays lean". A build tag does **not** achieve that: build-tagged files are
still scanned for imports, so `go.mod`/`go.sum` gain the full ~90-module graph for everyone, and
`go install` downloads it. The README's "two dependencies" claim would stop being true. Three ways
out, for the owner to pick:

1. **Separate module** (`keyless/` with its own `go.mod`, or a sibling repo). Core stays at two
   dependencies; users who want keyless signing install a second binary. Most faithful to the
   roadmap's stated intent, least convenient.
2. **Build tag in this module.** One binary, one repo; `go.mod` grows to ~90 modules and the
   dependency-thinness claim goes with it.
3. **Implement the Fulcio/Rekor client with stdlib.** Fulcio is an OIDC token plus a CSR over
   HTTPS; Rekor is a JSON upload. No dependency, but we own the correctness of a security-critical
   client — and the verification half (M4-09) already shows the shape is tractable.

**Owner decision (2026-08-26): option 1, the separate module.**
**Deliverables.** `keyless/` module (own `go.mod`), `skill-guard-keyless sign`, OIDC identity from
`--token`/`--token-file`/GitHub Actions with no browser flow, a reusable signing workflow, and a CI
job that **asserts** the core module stays at two direct dependencies and that the `skill-guard`
binary links no Sigstore or protobuf code.
**Acceptance.** A workflow signs a skill keylessly with zero stored secrets, `skill-guard verify`
reads the result, and the core dependency graph is unchanged.

### M4-13 — Drop the `replace` directive
`keyless/go.mod` resolves the core module through `replace ../` so it always builds against
adjacent source. `go install` refuses a module with replaces, so installation is clone-and-build
until a core release contains `pkg/attest/oms`. Once one is tagged, drop the replace, pin the
release, and document `go install`.
**Acceptance.** `go install github.com/SVGreg/skill-guard/keyless/cmd/skill-guard-keyless@latest`
works from a clean machine.

### M4-10 — Rekor inclusion-proof checking
**Deliverables.** M4-09 trusts the bundle's own `integratedTime`; this verifies it — Merkle
inclusion proof against a checkpoint signed by a **pinned** log key, plus the RFC 3161 timestamp
when present. Rekor availability is never required: the proof travels in the bundle.
**Acceptance.** A bundle with a tampered `integratedTime` or a broken inclusion proof is refused,
with the network disabled.

### M4-11 — SGMT-1 as legacy; format guidance
**Deliverables.** `docs/signature-formats.md` comparing the two formats, the two trust models, and
migration; README section and Contents entry; `sign --help` naming SGMT-1 legacy; the stale
"Roadmap" note under Publisher identity replaced, since keyless shipped. The reusable signing
workflow was delivered with M4-12.
**Acceptance.** SGMT-1 is described as legacy-but-supported wherever a reader chooses a format,
with no suggestion of removal, and every cross-link resolves.

---

## M5 — Load-time verification hook + skill cards

**Goal (roadmap §M5):** verify at the moment a skill is installed or loaded into an agent, and
emit a machine-readable trust artifact downstream tools can consume. Latency budget: single-digit
milliseconds on the cached path.

| ID | Task | Status | Deps | PR |
|---|---|---|---|---|
| M5-01 | Spike: skill-card schemas against primary sources; rewrite M5-06 | done | — | #228 |
| M5-02 | `Guard()` one-shot API — load + verify + scan + policy → one decision | done | — | #229 |
| M5-03 | Verdict cache keyed by content hash, pluggable `Cache` interface | done | M5-02 | #230 |
| M5-04 | `skill-guard guard` command: allow / deny / warn, JSON decision output | done | M5-02, M5-03 | #231 |
| M5-05 | Install-time gate mode (`--mode install`) | done | M5-04 | #233 |
| M5-06 | Skill cards: add `content_hash`, document our schema, make cards verifiable | done | M5-01 | #234 |
| M5-07 | `hooks/` uses `guard` instead of `verify`; malicious skill blocked at load | done | M5-04 | #235 |
| M5-08 | Latency benchmark proving the cached path, plus docs | done | M5-03, M5-04 | #236 |
| M5-09 | Memoize `rules.Builtin()` — ~108 ms and 17 MB of every cold decision | in-progress | M5-08 | |

### M5-01 — Skill-card schema spike
**Done.** Findings in [`docs/skill-card-notes.md`](skill-card-notes.md), read 2026-08-28 from the
agentskills.io specification, the NVIDIA Trustworthy-AI card templates, and NVIDIA's verified-skills
announcement. **Neither source defines the artifact the roadmap describes:**

- **agentskills.io** specifies the *skill format* — frontmatter, directories, progressive
  disclosure, validation — and contains no card, provenance, signature, or hash concept at all.
- **NVIDIA's "skill card"** is a CC0 **prose disclosure template** (owner, licence, deployment
  geography, known risks, evaluation results, ethical considerations). It has no `content_hash`,
  no risk tier, no findings summary, and no signature status; "Skill Version: [Signing Identifier]"
  is a human-typed line. Its fields are publisher disclosures a scanner cannot honestly derive.
- What NVIDIA *does* do machine-readably is **sign**: `skill.oms.sig`, OMS, verified against
  `nv-agent-root-cert.pem`. That corroborates M4 three ways — our filename matches the ecosystem
  convention, OMS-over-a-skill-directory is no longer unproven (`oms-notes.md §7`), and the vendor
  root is exactly what consumer-pinned `trust.roots` exists to avoid.

**Consequence:** there is no schema to conform to, so M5-06 changes from translation work to the
one real gap — `scan.Card` carries every field the roadmap listed **except `content_hash`**, and
without that a card cannot be tied to the bundle it describes.

### M5-06 — Skill cards: content hash, documented schema, verifiable
**Goal.** Make our card the thing nobody else offers — one that can be *checked* against its
subject — rather than a translation of a schema that does not exist (M5-01).
**Deliverables.** `content_hash` on `scan.Card` (the SGMT-1 root where a signature exists, a
recomputed root otherwise, so it means the same thing either way); a documented, versioned schema
in `docs/skill-card-schema.md` with the `_type` version marker explained; `skill-guard verify
--card <file>` checking a card against a bundle — content hash match, not merely schema validity;
and a note in the card when the bundle ships a publisher-authored card of its own, without
attempting to parse prose.
**Acceptance.** A card emitted for a bundle verifies against that bundle and **fails against the
same bundle with one byte changed**; the emitted card validates against the documented schema.

### M5-02 — `Guard()`: the agent-loop entrypoint
**Goal.** One call that answers "may this skill enter the model's context?" — the API
`docs/skill-guard-design.md §11.1` already specifies.
**Deliverables.** `Guard(ctx, path, opts...) (*Decision, error)` in a new `pkg/guard`: load the
bundle, verify whichever signatures are present (both formats — `pkg/verify` handles that since
M4-07), scan unless the caller opts out, apply policy, and return one `Decision` carrying the
outcome, the reason, the verdict, and the signature state. Options mirror §11.1 (`WithPolicy`,
`WithoutScan`, `WithVerdictCache`). Dependency-light: no new module dependencies.
**Acceptance.** Table test over the fixtures: `testdata/malicious` → deny, `testdata/benign` →
allow, unsigned-but-clean → the policy's configured outcome; every case names its reason.

**Owner decision needed:** `design §15` open question 1 asks what `fail_on` an agent-loop `Guard()`
should default to, recommending `high` (the CLI default). This card assumes **`high`**, so a skill
that fails a normal `scan` is denied at load. Say so if you want the gate stricter than the CLI.

### M5-03 — Verdict cache
**Goal.** Make the repeated-load path cheap enough to sit in an agent loop.
**Deliverables.** A `Cache` interface (get/put by content key) and an in-process implementation
keyed by the bundle's **content hash** — the SGMT-1 Merkle root where a signature exists, a
recomputed root otherwise — so a changed byte is a cache miss by construction, never a stale
allow. Optional on-disk cache under the user cache dir, off by default. Entries record the policy
digest too: a policy change must invalidate, or the cache would answer yesterday's question.
**Acceptance.** Benchmark showing the second `Guard()` on an unchanged bundle skips scanning; a
test proving one changed byte and one changed policy each miss.

### M5-04 — `skill-guard guard`
**Goal.** The gate as a command, for callers that are not Go.
**Deliverables.** `skill-guard guard <path>` with `--format json` emitting the `Decision`
(outcome, reason, verdict, risk, signature state, cache hit) and exit codes distinguishing
**allow (0)**, **warn (0 + warning)** and **deny (1)** — reusing the established contract rather
than inventing codes, with `3`/`4` unchanged. `--policy`, `--no-scan`, `--cache-dir` flags.
**Acceptance.** `guard testdata/malicious` → deny, exit 1, parseable JSON naming the rule that
denied it; `guard testdata/benign` → allow, exit 0.

### M5-05 — Install-time gate
**Goal.** The same decision at install time, where the blast radius is smaller.
**Deliverables.** `--mode load|install` on `guard`. Install mode is stricter by default: it
requires an attestation when the policy asks for one and reports the skill's declared capability
surface (`allowed-tools`, external refs) so a human approving an install sees what they are
admitting. Documented recipe for wrapping a `git clone`/copy install step.
**Acceptance (amended).** The card originally asked for `attestation.required: true` to deny at
install *while still allowing at load* — which would require making the **load** gate laxer than
the install gate. That is backwards: load is the moment untrusted content reaches the model, and a
policy that says "required" must mean required everywhere. The modes therefore differ by
**escalation**: a policy that merely *warns* about a missing attestation **denies at install** and
still **warns at load**, and whatever load denies, install denies too. Tested both ways, including
an ordering test over both fixtures × three policies that fails if the modes ever invert.

### M5-06 — Skill cards *(to be rewritten by M5-01)*
**Goal.** Emit and verify a machine-readable trust artifact a downstream tool can consume.
**Provisional deliverables** — the shape depends on what M5-01 finds: `content_hash`, risk tier,
AST findings summary, declared capabilities and signature status in the emitted card; a
`--verify-card` path that checks a card against the bundle it claims to describe (content hash
match, not just schema validity).
**Acceptance.** A card emitted for a bundle verifies against that bundle and fails against a
modified one.

### M5-07 — Wire the existing hook to the gate
**Goal.** The reference integration the roadmap asks for — mostly **already shipped**, and this
card finishes it rather than starting it (see §0.6).
**Deliverables.** `hooks/skillguard_hook.py` calls `skill-guard guard --format json` instead of
parsing `verify` text output, so the hook stops re-deriving a decision the binary already makes;
its `classify()`/`decide()` collapse into reading one JSON field. Keep the pure-stdlib property
and the existing config surface. Demonstrate a **malicious skill blocked at load** end to end.
**Acceptance.** `python3 -m unittest` in `hooks/tests` green; a recorded run showing the hook
denying `testdata/malicious` and allowing `testdata/benign`.

### M5-08 — Latency benchmark and docs
**Goal.** Prove the budget rather than assert it.
**Deliverables.** `go test -bench` over cold and cached `Guard()`; README section on load-time and
install-time gating with the measured numbers; note the cached-path budget from roadmap §2
(single-digit ms) and say plainly whether it is met.
**Data already in hand from M5-03** (`-benchtime 20x`, this machine): cached **0.58 ms** — inside
budget; cold **268 ms**, of which **~110 ms is compiling the built-in rule packs on every call**
(prebuilt rules: 158 ms). So the guidance for a long-lived host is *reuse the rules and the cache*,
and memoizing `rules.Builtin()` is worth its own row if the numbers hold up on other hardware.
**Acceptance.** Benchmark output in the PR; the README quotes the measured figure, not the target.

**Measured (M5-08, i5-2415M @ 2.30 GHz, `-benchtime 20x`).** The M5-03 figures reproduce, and the
set grew to cover what a deployment actually pays:

| Path | Cost |
|---|---:|
| cached, in-process | **0.57 ms** ✅ |
| cached, on disk (`--cache-dir` — what the hook uses) | **1.5 ms** ✅ |
| provenance only (`--no-scan`) | 1.0 ms |
| cold, typical bundle (`testdata/benign`) | 166 ms ✅ under a second |
| cold, 60-finding corpus (`testdata/malicious`) | 270 ms |

Budget met on both counts. The on-disk cache was added to the set because quoting only the
in-process number would quote a figure no hook deployment experiences. `~108 ms` of every cold
call is rule-pack compilation, and it is ~17 MB of the ~17.5 MB allocated — hence **M5-09**.

### M5-09 — Memoize the built-in rule packs
**Goal.** Stop paying ~108 ms and ~17 MB to compile the same embedded YAML on every cold
decision. `rules.Builtin()` reads and compiles `//go:embed`ed packs that cannot change within a
process, yet every `Guard()` without explicit `Options.Rules` does it again.
**Deliverables.** Memoize inside `pkg/rules` (`sync.Once` over the compiled packs), returning a
set callers cannot mutate into each other's state — that is the whole risk, so the API shape
decides the task: either return deep copies or document and enforce read-only sharing. `--rulepack`
must still compose with the memoized built-ins.
**Acceptance.** `BenchmarkGuardCold` drops to within noise of `BenchmarkGuardColdPrebuiltRules`;
a test proves two `Builtin()` callers cannot observe each other's mutations; the full suite and the
evaluation corpus are unchanged (identical findings, since nothing about matching changes).

**Result (measured, same machine and `-benchtime 20x`).** `GuardCold` **270 ms → 165 ms**, against
`GuardColdPrebuiltRules` at 162 ms — within noise, as the acceptance asked. Allocations
**17.5 MB → 366 KB**; `GuardColdBenign` **166 ms → 50 ms**; `Builtin()` itself is now 196 ns.
The honest caveat, written into the README: a benchmark amortizes the one compilation over its
iterations, so this buys a **long-lived host** (agent loop, server) everything after its first
decision and buys a **one-shot CLI run** nothing, since that process exits. A host wanting the
first call cheap too still passes `Options.Rules`.

## M6 — Taint analysis engine *(titles only)*

- M6-01 Source / sink / sanitizer model expressed in the YAML rule-pack style
- M6-02 Shell frontend · M6-03 Python frontend (cap the language set deliberately)
- M6-04 Instruction-flow analysis over `SKILL.md`
- M6-05 Lethal-Trifecta detector (sensitive data + untrusted content + egress in one flow)
- M6-06 Confidence integration + conservative defaults + `--strict`
- M6-07 Measured detection rate and FP rate on the evaluation corpora
- M6-08 Performance on large bundles

## M7 — LLM / semantic engine, opt-in *(titles only)*

- M7-01 Pluggable backend interface, off by default, no network in the default path
- M7-02 Semantic intent analysis of `SKILL.md` (obfuscated intent, social framing, smuggling)
- M7-03 LLM-derived findings tagged in text / JSON / SARIF; never suppress a deterministic finding
- M7-04 Optional triage mode (rank/explain existing findings)
- M7-05 Reproducibility record (model + version + prompt hash) and a disabled-path no-change test
- Note: `/sg-llm-polish` is a self-checking no-op until M7-01 lands; it becomes live here.

## M8 — Hardening *(titles only, runs in parallel)*

- M8-01 Skill SBOM + dependency provenance, drift detection vs signed state (AST07)
- M8-02 Cross-platform reuse safety — divergent runtime semantics (AST10)
- M8-03 Evasion corpus fixture + detections (padding, multi-layer encoding, zero-width, homoglyphs)
- M8-04 Over-privilege analysis: declared `allowed-tools` vs capabilities actually exercised (AST03)

---

## D — Distribution track (parallel from M3)

| ID | Task | Status | Deps | PR |
|---|---|---|---|---|
| D-01 | GitHub Action published to the marketplace | owner | M3-06 | |
| D-02 | Install paths: Homebrew tap, container image (GoReleaser already ships binaries) | todo | — | |
| D-03 | Marketplace / awesome-list registry listings | owner | — | |
| D-04 | Writeup: "Scanning and signing Agent Skills against OWASP AST10" | todo | M3-07 | |
| D-05 | Standards watch: AAIF / agentskills.io / OpenSSF signing work | todo | — | |
| D-06 | Reference integration in a real agent runtime or skill loader | todo | M5-05 | |

`D-05` is recurring, not one-shot: `/sg-plan` re-checks it whenever it expands a milestone, and
`/sg-threat-research` may feed it.

---

## Change log

Newest last. One line per planning change, written by `/sg-plan`.

- 2026-09-01 — M5-09 makes the memoized `Builtin()` return a **copy of the slice** while sharing
  the `*Pack` pointers, and says in the doc comment that the packs are read-only. The copy is not
  ceremony: `loadRuleset` appends `--rulepack` packs to what `Builtin()` returns, and appending into
  a shared backing array would put one caller's external rules into another caller's scan. Nothing
  in the tree mutates a compiled rule today, so sharing is safe — but memoization is what makes that
  a *contract* rather than a coincidence, so it is stated and tested.
- 2026-09-01 — M5-08 files **M5-09** (memoize `rules.Builtin()`), which its own card invited "if
  the numbers hold up". They did, on a second machine-run: ~108 ms of every cold decision, and
  ~17 MB of its ~17.5 MB of allocations, is compiling embedded YAML that cannot change within a
  process. M5-08 also added an **on-disk** cache benchmark — the in-process figure is not the one a
  hook deployment pays, and quoting only the faster number would have been quoting the wrong one
  (1.5 ms vs 0.57 ms; both inside the single-digit-ms budget).
- 2026-09-01 — M5-07 **widens what the hook blocks**, which is a behaviour change worth recording
  rather than a refactor. Reading `guard`'s outcome instead of regexing `verify`'s text means the
  hook now sees the *scan*: in the default `block-invalid` mode a malicious skill is denied at load
  on its verdict, where before only a compromised signature was. It also fixes a blind spot nobody
  had filed — the hook probed for `SKILL.md.skillsig`, so an OMS-signed skill (M4-07) classified as
  **unsigned** and was blocked in `enforce` mode. The hook README leads with a "run `log` mode
  first" note for anyone retrofitting this onto a machine full of unscanned skills.
- 2026-09-01 — M5-06 ships the card's subject field as **`content_hash`**, not `merkle_root` as the
  design §9 sketch has it: it matches the USF front-matter field and `guard.Decision`, and the value
  is identical. `docs/skill-card-schema.md` is now the authority for the emitted schema, and §9
  points at it. New id **SG-PRV-007** allocated in `rule-verification.md` for a card that does not
  describe its bundle.
- 2026-08-29 — M5-05 **amended its own acceptance check**. As written it required the load gate to
  be laxer than the install gate; weakening the gate that runs when untrusted content reaches the
  model, in order to make a test pass, is exactly backwards. Modes now differ by escalation only,
  with an ordering test that fails on any inversion. `Mode` also joins the cache key, since the same
  bundle and policy legitimately yield different outcomes per mode.
- 2026-08-29 — M5-04 truncates the **human** finding list to five and leaves the **JSON** complete.
  The malicious fixture yields 65 gating findings; printing all of them buries the decision the
  reader came for, while a machine consumer wants every one. Also exported `report.Sanitize` so the
  CLI can escape rule-pack-supplied titles without `%q`-quoting readable text — an external
  `--rulepack` can name a rule anything, including terminal escapes that forge the decision line.
- 2026-08-29 — M5-03 keys the cache on **content hash + policy digest + `SkipScan`**, not content
  alone: a decision reached without scanning must never satisfy a caller who asked for one, and a
  policy change must invalidate or the cache answers yesterday's question. The policy digest hashes
  the whole struct rather than a hand-picked subset — a subset means remembering to update it every
  time policy grows a field, and forgetting once yields a cache that ignores the new setting.
- 2026-08-28 — M5-02 puts **provenance findings ahead of scan findings** in a decision, and denies
  on a broken signature before consulting any verdict: "verdict: pass" printed over a tamper
  finding would be actively misleading. Writing the test caught the bug that made this explicit —
  the scan's findings were being assigned *over* the provenance ones, so a tampered bundle that
  otherwise scanned clean lost its tamper finding entirely.
- 2026-08-28 — **M5-01 spike done.** The roadmap's "agentskills.io / NVIDIA-style skill card
  schema" does not exist: agentskills.io specifies the skill *format* with no provenance concept,
  and NVIDIA's skill card is a prose disclosure template with no hash, tier, findings, or signature
  status. M5-06 rewritten from schema-conformance to the one real gap — `content_hash` and a
  *verifiable* card. Corroboration for M4 recorded: NVIDIA signs skills as `skill.oms.sig` with
  OMS against a vendor root, which settles `oms-notes.md §7`'s open question about OMS being used
  for skill directories.
- 2026-08-28 — **M5 expanded** into eight cards. Two repo facts moved it away from the roadmap's
  framing: `hooks/` already implements the load-time gate (so M5-07 finishes an integration rather
  than starting one), and `design §11.1` already specifies `Guard()` and a merkle-keyed cache (so
  M5-02/M5-03 implement a written spec). M5-01 is a skill-card schema spike first, on the M4-01
  precedent — "conform to the agentskills.io / NVIDIA-style schema" is an assumption about an
  external spec, and the last such assumption was wrong three ways.
- 2026-08-26 — M4-11 replaced the "Roadmap" paragraph under *Publisher identity & trust*, which
  still described keyless signing as planned after it had shipped — the exact doc drift roadmap
  §6.5 asks to keep closed.
- 2026-08-26 — M4-10 makes the inclusion proof **mandatory** whenever a log entry carries one,
  rather than optional: M4-09 anchors certificate validity on `integratedTime`, and an unchecked
  timestamp is a number the signer wrote. Checkpoint *signature* verification is enforced only when
  `trust.log_keys` is configured — with no pinned key there is nothing to verify against, and
  inventing a default log would repeat the default-CA mistake. M4-13 marked `blocked`: it cannot
  proceed until a core release ships `pkg/attest/oms`.
- 2026-08-26 — **Owner chose the separate-module option for M4-12.** `keyless/` is its own Go
  module; the core keeps its two dependencies and CI now fails if that ever stops being true.
  Follow-up **M4-13**: the `replace` directive that makes the submodule build against adjacent
  source also blocks `go install`, until a core release ships `pkg/attest/oms`.
- 2026-08-26 — **M4-09 split.** The original card bundled keyless *verification* and *signing*.
  Verification needs no new dependency and is done. Signing needs one — and the roadmap's "behind a
  build tag" instruction does not work: a build tag still puts the whole ~90-module graph in
  `go.mod` for everyone. That is now **M4-12**, `blocked` on an owner decision between a separate
  module, accepting the dependency, or a stdlib Fulcio/Rekor client. M4-10 narrowed to
  inclusion-proof checking, since pinned-root offline verification landed with M4-09.
- 2026-08-26 — M4-08 implements identity rules as a **narrowing** gate over the key roster, not as
  a way to admit unbound identities: an identity is only usable when the consumer bound it to a key
  in their own roster. Admitting a certificate identity needs the keyless path (M4-09); trusting a
  statement's self-asserted `publisher` field would be no trust at all. A scoped-out identity is
  SG-PRV-005 (non-gating, like an unknown key), not SG-PRV-004 — the consumer scoped, they did not
  revoke.
- 2026-08-26 — M4-07 caught a real M4-06 bug: `skill.oms.sig` was a Merkle leaf, so writing it
  invalidated the `.skillsig` written moments earlier — a freshly signed bundle verified as
  MISMATCH. `pkg/skill` now excludes it from the bundle model exactly as it excludes `.skillsig`;
  a signature must never cover another signature. Also: an OMS file that exists but is empty is
  reported as **malformed**, not absent, so a truncated signature cannot look like an unsigned skill.
- 2026-08-26 — M4-06 validates the key algorithm **before** writing anything: `--oms` with an
  Ed25519 key was leaving a valid `.skillsig` behind and then failing, which reads like a partial
  success. `pkg/attest/oms` imports `pkg/attest` (for PAE and the algorithm ids) and never the
  reverse, so the CLI stays the single place the two signature formats are composed.
- 2026-08-26 — M4-05 takes the verification algorithm from the **trust roster entry**, never from
  the attestation: a signature that names its own scheme would let an attacker choose the weaker
  verification path. A roster entry with no algorithm stays Ed25519, so existing rosters are
  unaffected.
- 2026-08-26 — M4-03 rejects any `..` component outright rather than resolving it: §6.1.2 rule 2
  forbids the component, and rule 3 only asks for `.` and `//` to be collapsed. Quietly resolving
  `a/b/../c.txt` would accept a path the spec calls invalid, and a verifier that rejects it would
  then disagree with our manifest.
- 2026-08-26 — M4-02 landed the OMS wire types (`pkg/attest/oms`) alongside the vectors: the card
  said "parses into our types", and those types did not exist yet. They are JSON structs plus
  structural validation, stdlib only — no dependency added, and M4-04/M4-06 now have their shape.
- 2026-08-26 — **M4-01 spike done** (`docs/oms-notes.md`); M4 re-planned from primary sources.
  M4-02…M4-09 became M4-02…M4-11: canonicalization split from manifest/root-digest, a new ECDSA
  P-256 card added (OMS requires EC P-256/384/521 — skill-guard signs Ed25519), and the interop
  test moved *earlier* and became offline because the spec ships test vectors. Also reconciled two
  stale rows: M3-01 and M3-07 were left `in-progress` after their PRs merged, because a status
  edit silently no-matched — status edits now assert before replacing.
- 2026-08-26 — M3-07 also refreshed `PROGRESS.md`, which still listed SARIF as deferred; the card
  named only the README, but leaving the other status file stale would have reproduced exactly the
  drift §6.5 of the roadmap asked to close.
- 2026-08-26 — M3-06 added a `version: preinstalled` input the card did not list, so the demo
  workflow tests the action against a binary built from the same commit rather than the last
  release — otherwise the action could only ever be tested one release behind. Its code-scanning
  upload is `workflow_dispatch`-only: 65 fixture findings in this repo's own Security tab would
  bury real alerts. The card's "uploads SARIF" acceptance is met by that manual job.
- 2026-08-26 — M3-05 took the golden files from a **hand-built** report plus the finding-free
  benign fixture, not from `testdata/malicious`: a 65-finding golden would regenerate on every
  rule-pack tweak, and a golden nobody reads is not a test. The malicious scan is still covered —
  by schema validation and the determinism test. No JSON-schema dependency was added; the draft-04
  subset the SARIF schema uses is ~150 test-only lines.
- 2026-08-26 — M3-04 found the waiver *reason* was computed and discarded by `pkg/scan`, so SARIF
  had no justification to emit; added `Finding.WaiverReason` (additive JSON field) and made
  `Report.Waived` sorted, since it is now rendered output rather than a side list.
- 2026-08-25 — M3-03 added `model.ASTAll()` rather than letting the SARIF emitter keep its own
  copy of the ten risks; the taxonomy now has exactly one definition in the codebase.
- 2026-08-25 — M3-01 merged (#205). M3-02 pulled the user-visible README documentation forward
  from M3-07: the flag and its docs must land together, or the release either advertises a format
  the CLI rejects or ships one nobody can find. M3-07 keeps the mapping page and the version pin.
- 2026-08-24 — M3-01 started; added **M3-09** (repo-workspace-relative artifact URIs) as a
  follow-up found while implementing the emitter — GitHub cannot link an alert whose URI is
  bundle-relative, and the SARIF `uriBaseId` escape hatch needs confirming against a real upload.
- 2026-08-24 — plan created from `docs/v1-dev-roadmap.md`; M3, M4 and D expanded; repo
  reconciliation recorded in §0 (pack count, milestone-numbering collision, version-target drift,
  README lag).
