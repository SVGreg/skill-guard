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
5. **Waivers already survive scanning** — `scan.Report.Waived` keeps waived findings rather than
   dropping them, so the SARIF `suppressions` requirement (M3-04) needs no scan-engine change.

---

## 1. Milestone board

| Milestone | Theme | Tasks | Status |
|---|---|---|---|
| **M3** | SARIF output + CI surface | M3-01 … M3-09 | expanded |
| **M4** | OMS + Sigstore keyless interop | M4-01 … M4-09 | expanded |
| **M5** | Load-time / install-time gate + skill cards | titles only | needs `/sg-plan` |
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
| M3-01 | SARIF 2.1.0 emitter in `pkg/report` | in-progress | — | #205 |
| M3-02 | `--format sarif` wired into `scan` | done | M3-01 | #207 |
| M3-03 | AST01–AST10 carried into SARIF taxonomy | done | M3-01 | #208 |
| M3-04 | Waivers → SARIF `suppressions`; demotion preserved | done | M3-01 | #209 |
| M3-05 | Golden-file + offline schema-validation tests | done | M3-01 | #210 |
| M3-06 | GitHub Action (`action.yml`) running scan + upload-sarif | in-progress | M3-02 | #211 |
| M3-07 | Docs: SARIF mapping page, README version reconcile | todo | M3-02 | |
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
| M4-01 | Spike: re-verify OMS spec + Sigstore Go surface against primary sources | todo | — | |
| M4-02 | Bundle-tree canonicalization compatible with OMS | todo | M4-01 | |
| M4-03 | OMS signer — emit `skill.oms.sig` alongside `.skillsig` | todo | M4-02 | |
| M4-04 | OMS verifier + signature-type auto-detection in `verify` | todo | M4-03 | |
| M4-05 | Sigstore keyless signing (Fulcio/Rekor), isolated behind a build tag | todo | M4-03 | |
| M4-06 | Offline verification: pinned trust bundle / cached inclusion proof | todo | M4-05 | |
| M4-07 | Identity-based trust policy in `.skillguard.yaml` | todo | M4-04 | |
| M4-08 | Cross-verification interop test vs an independent OMS implementation | todo | M4-04 | |
| M4-09 | Keyless-signing workflow + docs; SGMT-1 documented as legacy | todo | M4-05 | |

### M4-01 — Primary-source spike (do this first)
**Goal.** Roadmap §6.3: the roadmap's format assumptions must be re-checked before code.
**Deliverables.** `docs/oms-notes.md` recording, with links and access dates: the current OMS
signature layout and manifest/canonicalization rules; which Go libraries are viable
(`sigstore-go`, `protobuf-specs`) and their dependency weight; how OMS names and locates the
signature file; whether `skill.oms.sig` is still the expected filename. Ends by **rewriting
M4-02 … M4-09 in this plan** to match what was found — including dropping tasks that reality
invalidates.
**Acceptance.** Every factual claim in the notes cites a primary source; the plan's M4 cards are
updated in the same PR. No code in this PR.

### M4-02 — Canonicalization
**Goal.** Byte-exact tree canonicalization; a mismatch here fails cross-verification *silently*.
**Deliverables.** File ordering, path normalization (Unicode, separators, case), symlink policy,
empty-dir handling, and exclusion rules stated as a spec section and implemented in `pkg/attest`
next to SGMT-1 (shared walk, separate serialization). Test vectors committed.
**Acceptance.** Vectors match an independent implementation's digests for the same tree.

### M4-03 — OMS signer
**Deliverables.** `sign --format oms` (default stays SGMT-1; both may be emitted) writing
`skill.oms.sig` covering the **whole bundle tree**, not just `SKILL.md`. Existing `.skillsig`
output and its tests unchanged.
**Acceptance.** Signing the benign fixture yields both files; SGMT-1 tests still pass byte-identically.

### M4-04 — OMS verifier + auto-detect
**Deliverables.** `verify` detects which signature(s) are present, verifies each, and reports
**which trust path was used** in text and JSON. New `SG-PRV-*` states only if genuinely new;
reuse existing ids where the meaning matches (`docs/rule-verification.md` is the authority).
**Acceptance.** Bundle with only `.skillsig`, only `skill.oms.sig`, and both — all three verify
with correct provenance reporting; tamper still exits 2.

### M4-05 — Sigstore keyless
**Deliverables.** Fulcio short-lived certs from OIDC, Rekor inclusion, GitHub Actions OIDC path.
**Isolated package + build tag** so the default binary stays lean and offline; document the
resulting binary-size / dependency delta.
**Acceptance.** Default build has no Sigstore imports in `go list -deps ./cmd/skill-guard`; the
tagged build signs from a workflow with zero stored secrets.

### M4-06 — Offline verification path
**Deliverables.** Verify against a pinned trust bundle and a cached Rekor proof; **Rekor
availability is never required for `scan`**, and never for `verify` when a pin is configured.
**Acceptance.** Verification of a keyless-signed bundle succeeds with the network disabled.

### M4-07 — Identity trust policy
**Deliverables.** `.skillguard.yaml` gains identity-pattern trust (e.g. `repo:org/*` OIDC
identities) beside the existing key roster; multiple roots configurable; **no hard-coded vendor
root** (roadmap §5). Precedence between key roster and identity rules documented.
**Acceptance.** Policy table test: matching identity → trusted; near-miss pattern → untrusted;
revoked entry still wins.

### M4-08 — Interop test
**Deliverables.** A test (or documented, scripted manual procedure if the counterpart tool cannot
run in CI) proving both directions: our signature verifies under an independent OMS verifier, and
an OMS-signed bundle verifies with `skill-guard verify`.
**Acceptance.** Both directions demonstrated with recorded output.

### M4-09 — Workflow + docs
**Deliverables.** Reusable signing workflow; README/docs section on OMS vs SGMT-1, trust models,
and the offline path; SGMT-1 marked **legacy but supported** — not removed in this milestone.

---

## M5 — Load-time verification hook + skill cards *(titles only — run `/sg-plan M5`)*

- M5-01 Fast embeddable gate API in `pkg/verify` (single-digit-ms cached path)
- M5-02 Verification cache keyed by content hash
- M5-03 Install-time gate mode with allow / deny / warn outcomes
- M5-04 Skill cards conforming to the agentskills.io / NVIDIA-style schema (emit **and** verify)
- M5-05 Reference integration wiring the gate into a real skill loader
- M5-06 Latency benchmark + docs

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
