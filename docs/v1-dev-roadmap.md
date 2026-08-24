# skill-guard — Development Roadmap (v0.2 → v1.0)

> **Purpose of this document.** This is a machine-and-human readable roadmap intended to be
> handed to an agentic coding tool (Claude Code) as the source of truth for planning
> implementation work. It states *what* to build, *in what order*, *why that order*, and
> *how to know a milestone is done*. It deliberately does not prescribe internal code
> structure beyond existing package boundaries — the implementing agent should propose that.

**Repo:** `github.com/SVGreg/skill-guard`
**Language:** Go (1.26+)
**Current state:** `scan`, `keygen`, `sign`, `verify` implemented. Rule packs
(`core-injection`, `core-network`, `core-exec`, `core-secret`, `core-metadata`) mapped to
OWASP Agentic Skills Top 10 (AST01–AST10). Own signing format (SGMT-1 / DSSE / Ed25519,
detached `SKILL.md.skillsig`) with local trust roster. Outputs: text / JSON / skill-card.
GoReleaser + release-please in place.

---

## 0. Strategic framing (read this before planning)

skill-guard competes in two sub-markets with very different dynamics:

| Sub-market | Competitive reality | Our stance |
|---|---|---|
| **Skill scanning / detection** | Crowded. Cisco AI Defense, Snyk `snyk-agent-scan`, Sentry, Mondoo, NVIDIA SkillSpector, Semgrep rules, academic tools. Several ship LLM + behavioral analysis. | Do **not** try to out-detect them. Compete on determinism, offline operation, AST10 fidelity, and CI ergonomics. |
| **Signing / provenance / verification** | Thin. Most rivals are scanners only. A de-facto standard exists (OpenSSF **OMS**, Sigstore-bundle based) but the only prominent implementation is vendor-anchored (NVIDIA, `nv-agent-root-cert.pem`). | **This is the wedge.** Become the vendor-neutral, Go-native, OSS implementation of skill signing + verification. |

**Three principles that constrain every decision below:**

1. **Determinism is the moat.** Static analysis, no code execution, no network required, single
   static binary. Anything that breaks "runs offline in CI and in air-gapped review" must be
   opt-in, never default.
2. **Interoperate, don't invent.** Where a standard exists (OMS, Sigstore, SARIF, AST10,
   skill cards), implement it. Bespoke formats isolate us.
3. **Distribution is currently the bottleneck, not capability.** Milestones that unlock
   adoption surfaces (SARIF → GitHub code scanning, GitHub Action, marketplace listings)
   outrank milestones that add depth.

### Explicit reprioritization decision

The previously stated intent was **LLM/semantic engine first**. This roadmap **reverses that**
and moves the LLM engine to last, as an optional plugin. Rationale:

- It attacks rivals at their strongest point (Cisco/Snyk/Mondoo/NVIDIA already ship semantic
  and behavioral analysis) with the fewest resources.
- It breaks the determinism moat: non-deterministic output, API keys, network dependency,
  hard-to-unit-test behavior.
- Cheaper, more defensible work is available first (SARIF is days; OMS interop is the
  strategic differentiator and leverages existing Sigstore/Cosign familiarity).

The LLM engine still gets built — as an **augmenting, opt-in backend** in M7, not as the core.

---

## 1. Milestone sequence (authoritative order)

```
M3  SARIF output + CI surface            ── unlock adoption        (days)
M4  OMS + Sigstore keyless interop       ── strategic wedge        (weeks)
M5  Load-time verification + skill cards ── differentiation        (1–2 weeks)
M6  Taint analysis engine                ── deterministic depth    (weeks)
M7  LLM/semantic engine (opt-in plugin)  ── augmentation           (weeks)
M8  Hardening: SBOM, AST07/AST10, evasion resistance               (ongoing)
```

Distribution work (§3) runs **in parallel** starting at M3, not after M8.

---

## M3 — SARIF output and CI surface
**Priority:** highest. **Size:** weekend → small. **Blocks:** enterprise adoption.

### Why
Without SARIF, findings cannot populate the GitHub Advanced Security code-scanning tab. This
is table stakes for CI adoption and is the single cheapest unlock available.

### Scope
- `--format sarif` on `scan`, emitting SARIF 2.1.0.
- Correct mapping of skill-guard concepts onto SARIF: rules → `rules[]` with `id`,
  `shortDescription`, `helpUri`; findings → `results[]` with `ruleId`, `level`,
  `message`, `locations` (file + line/region where determinable), `partialFingerprints`
  for stable dedup across runs.
- Carry AST01–AST10 mapping into SARIF (`properties.tags` and/or `relationships`) so the
  OWASP taxonomy survives the export.
- Severity mapping: internal severity → SARIF `level` (`error` / `warning` / `note`) with the
  raw score preserved in `properties`.
- Respect existing policy config (`.skillguard.yaml` thresholds, waivers, allowlists) —
  suppressed findings should be emitted as SARIF `suppressions`, not silently dropped.
- Exit-code semantics documented and stable for CI gating.

### Deliverables
- SARIF emitter + golden-file tests validated against the SARIF 2.1.0 schema.
- A published **GitHub Action** (`skill-guard-action`) that runs a scan and uploads SARIF via
  `github/codeql-action/upload-sarif`.
- README/docs section: "Use in CI" with a copy-pasteable workflow.

### Done when
A public demo repo shows skill-guard findings rendered in the GitHub Security tab, with AST
references visible on each finding, and waivers correctly shown as suppressed.

---

## M4 — OMS-compatible signing + Sigstore keyless verification
**Priority:** highest strategic value. **Size:** small → medium. **This is the wedge.**

### Why
The market converged on **OpenSSF Model Signing (OMS)** — a Sigstore-bundle-derived, detached
signature format covering a directory tree (`skill.oms.sig`) — as the de-facto skill signing
format. Today a skill-guard signature cannot be verified by OMS tooling and vice versa. That
isolation is the project's biggest strategic risk. Meanwhile the prominent OMS implementation
is anchored to a vendor root of trust; a **vendor-neutral** one is genuinely missing.

### Scope
1. **OMS-compatible signer/verifier**
   - Emit `skill.oms.sig` alongside (not instead of) the existing SGMT-1 `.skillsig`.
   - Cover the whole skill bundle directory tree, not just `SKILL.md`.
   - Verify OMS signatures produced by other implementations; ensure signatures we produce
     verify under standard OMS/Sigstore verification.
2. **Sigstore keyless identity**
   - Fulcio for short-lived certs from OIDC identity; Rekor for transparency-log inclusion.
   - Support the standard CI identity path (GitHub Actions OIDC) so skills can be signed in a
     workflow with no long-lived key material.
   - Offline verification path: allow verifying against a pinned trust bundle / cached Rekor
     proof so air-gapped verification still works (principle #1).
3. **Trust model upgrade**
   - Keep the local trust roster for teams that want it.
   - Add identity-based trust policy: accept signatures from `repo:org/*` style OIDC
     identities, configured in `.skillguard.yaml`.
   - Multiple roots of trust configurable; **no hard-coded vendor root**.
4. **Migration/compat**
   - `verify` auto-detects signature type (SGMT-1 vs OMS) and reports which trust path was used.
   - Document SGMT-1 as legacy; do not remove it in this milestone.

### Hard parts / risks
- Sigstore Go dependency surface is non-trivial; keep it behind a build-tag or isolated
  package so the offline core stays lean.
- Directory-tree canonicalization must be exactly compatible (file ordering, path
  normalization, symlink and empty-dir handling) or cross-verification silently fails.
- Rekor availability must never be a hard requirement for `scan`.

### Done when
- A skill signed by skill-guard verifies with an independent OMS verifier, and an
  OMS-signed skill verifies with `skill-guard verify`.
- A GitHub Actions workflow signs a skill keylessly with zero stored secrets.
- Verification succeeds offline against a pinned trust bundle.

---

## M5 — Load-time verification hook + skill cards
**Priority:** high. **Size:** small → medium. **This is the differentiation vs. scanner-only rivals.**

### Why
Static pre-checks in CI are necessary but insufficient — the documented attacks are
install-time and load-time. The unmet ecosystem need is *verify at the moment a skill is
installed or loaded into an agent*, and a machine-readable trust artifact that downstream
tools can consume. Almost no OSS tool covers this.

### Scope
- **`verify --at-load` / embeddable gate**: a small, fast, dependency-light API in `pkg/verify`
  intended to be called from an agent loop or skill loader immediately before a skill enters
  the model's context. Latency budget: single-digit milliseconds for the cached path.
- **Install-time gate**: a mode suitable for wrapping skill installation (verify signature +
  policy threshold + optional scan) with clear allow/deny/warn outcomes.
- **Skill cards**: emit and verify machine-readable skill cards conforming to the
  agentskills.io / NVIDIA-style schema — declared capabilities, `content_hash`, risk tier,
  AST findings summary, signature status.
- **Caching**: verification results keyed by content hash so repeated loads are cheap.
- **Reference integration**: a worked example wiring the gate into a real skill loader.

### Done when
A reference integration demonstrates a malicious skill being blocked at load time, with a
skill card emitted for an approved skill and consumed by the gate on the next run.

---

## M6 — Taint analysis engine
**Priority:** medium-high. **Size:** medium → large. **Deterministic depth rivals' LLM passes lack.**

### Why
Pattern matching is explicitly called insufficient by the AST10 guidance. Taint analysis —
tracking data flow from untrusted sources to dangerous sinks — is the deterministic answer to
the "Lethal Trifecta" (sensitive-data access + untrusted content + external communication) and
raises precision without sacrificing offline determinism.

### Scope
- Source/sink/sanitizer model expressed in the existing data-driven YAML rule-pack style so
  the community can extend it without recompiling.
- Sources: skill inputs, fetched remote content, environment, files read.
- Sinks: network egress, shell/exec, file writes to sensitive paths, credential access.
- Analyze bundled scripts (start with shell + Python; design for pluggable language frontends)
  and instruction flows in `SKILL.md`.
- **Trifecta detector**: an explicit finding when all three legs co-occur in one flow.
- Confidence modifiers so taint findings integrate with existing scoring/threshold policy.

### Hard parts / risks
- Multi-language parsing scope creep — cap the initial language set deliberately.
- False-positive control; ship with conservative defaults and a `--strict` opt-in.
- Performance on large bundles.

### Done when
The trifecta detector fires on a curated corpus of known-malicious skill patterns with a
documented, measured false-positive rate on a known-good corpus.

---

## M7 — LLM / semantic analysis engine (opt-in plugin)
**Priority:** deliberately last. **Size:** medium.

### Why last
See §0. Building this first would be a me-too feature against better-resourced competitors and
would compromise the determinism moat. Built last, and correctly scoped, it becomes a genuine
augmentation instead of a liability.

### Non-negotiable constraints
- **Off by default.** Requires explicit flag/config plus a key. No network in the default path.
- **Never replaces** deterministic findings — it adds findings and may adjust confidence on
  existing ones, but a deterministic finding is never suppressed by an LLM verdict.
- **Pluggable backend interface** — support multiple providers (including Bedrock, given the
  target stack) behind one interface; no provider hard-coded.
- Deterministic reporting of non-determinism: record model + version + prompt hash in output
  so results are reproducible/auditable.
- Findings clearly tagged as LLM-derived in text/JSON/SARIF output.

### Scope
- Semantic intent analysis of `SKILL.md` instructions (obfuscated intent, social-engineering
  framing, instruction smuggling) where regex/AST cannot reach.
- Optional triage mode: rank/explain existing deterministic findings rather than generate new ones.

### Done when
Enabling the engine measurably improves detection on the evasion corpus from M8 without
changing any result when disabled.

---

## M8 — Hardening (parallel / ongoing)
**Size:** varies. These map to specific AST10 items that currently have no tooling.

- **Skill SBOM / dependency provenance (AST07 — Update Drift).** Emit an SBOM for a skill
  bundle; pin nested dependencies to immutable hashes; detect drift between a signed state
  and the current state.
- **Cross-platform reuse safety (AST10).** Detect constructs whose behavior differs across
  runtimes (Claude Code, Codex, Cursor, Gemini CLI, Goose) — differing tool permissions,
  frontmatter interpretation, `allowed-tools` semantics. No tooling exists here; this is a
  clean, ownable niche.
- **Evasion resistance.** Detect large-file padding (multi-MB README droppers), multi-layer
  encoding/obfuscation, zero-width and homoglyph tricks, and metadata that misrepresents
  bundle contents. Maintain an evasion corpus as a test fixture.
- **Over-privilege analysis (AST03).** Compare declared `allowed-tools` against capabilities
  actually exercised by the bundle; flag excess grants.

---

## 2. Cross-cutting engineering requirements

Apply to every milestone:

- **Backwards compatibility.** `scan`/`sign`/`verify` CLI surface and JSON output shape are
  contracts. Additive changes only until v1.0; breaking changes require a documented
  migration and a major-version bump.
- **Rule packs stay data-driven.** New detections should be expressible in YAML wherever
  possible, so contributors can add rules without Go changes.
- **AST10 traceability.** Every rule and finding keeps its `ast_references` mapping through
  every output format. This is a core differentiator — do not let it degrade.
- **Offline-first.** Any milestone that introduces a network dependency must ship an offline
  path in the same milestone.
- **Test corpora.** Maintain three fixture corpora: known-malicious, known-good, and evasion.
  Every detection milestone reports measured detection rate and false-positive rate against them.
- **Performance budget.** `scan` on a typical bundle stays well under a second; `verify`
  cached path stays in single-digit milliseconds.
- **Docs ship with the feature**, not after it. README currently lags the repo — closing that
  gap is part of the definition of done for each milestone.

---

## 3. Distribution track (runs in parallel from M3)

Capability is ahead of visibility. These are roadmap items, not afterthoughts:

1. **GitHub Action** published to the marketplace (lands with M3).
2. **Install paths**: Homebrew tap, `go install`, prebuilt binaries via existing GoReleaser
   setup, container image.
3. **Marketplace/registry listings** on skill marketplaces and awesome-lists in the
   MCP/Agent Skills ecosystem.
4. **A concrete writeup**: "Scanning and signing Agent Skills against OWASP AST10" — the
   AST10 mapping is a genuine differentiator and is currently undiscoverable.
5. **Standards engagement**: track AAIF / agentskills.io / OpenSSF work on skill signing and
   provenance. If an official standard ships, pivot immediately from bespoke format to best
   open implementation of that standard (M4 already positions for this).
6. **Reference integrations**: demonstrate the load-time gate inside at least one real
   agent runtime or skill loader.

---

## 4. Version targets

| Version | Contents |
|---|---|
| **v0.2** | M3 complete. SARIF, GitHub Action, CI docs. |
| **v0.3** | M4 complete. OMS-compatible signatures, Sigstore keyless, identity-based trust policy. |
| **v0.4** | M5 complete. Load-time gate, install-time gate, skill cards, reference integration. |
| **v0.5** | M6 complete. Taint analysis + trifecta detector, with measured detection/FP rates. |
| **v0.6** | M7 complete. Opt-in LLM engine behind pluggable backends. |
| **v1.0** | M8 items landed, output contracts frozen, docs complete, ≥1 external integration in the wild. |

---

## 5. Explicit non-goals

- **Do not** build a SaaS dashboard or hosted registry. The value proposition is a local,
  deterministic, embeddable binary + library.
- **Do not** invent additional bespoke formats. Prefer OMS, Sigstore, SARIF, skill cards.
- **Do not** make the LLM engine a dependency of core scanning.
- **Do not** execute skill code as part of the default scan path. Any dynamic analysis, if it
  ever ships, is a separate opt-in mode with explicit sandboxing.
- **Do not** hard-code any vendor's root of trust.

---

## 6. Instructions for the implementing agent

When planning from this document:

1. Start with **M3** — it is small, unblocks adoption, and its output format decisions
   (severity mapping, fingerprints, AST tags) constrain later milestones. Get them right.
2. Treat **M4** as the strategic centerpiece; if effort must be cut anywhere, cut M6/M7 scope,
   never M4.
3. Before implementing M4, **verify the current state of the OMS spec and Sigstore Go
   libraries** — this roadmap's assumptions about format details should be re-checked against
   primary sources at implementation time.
4. For each milestone, produce: a task breakdown, a proposed package layout, test-fixture
   requirements, and the acceptance criteria restated as executable checks.
5. Update README and docs as part of each milestone's work, and reconcile the README's
   self-reported version with actual release tags.
6. Where this roadmap and the repo disagree about current state, trust the repo and flag
   the discrepancy.
