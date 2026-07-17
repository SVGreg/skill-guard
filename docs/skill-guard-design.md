# skill-guard — Technical Design Document

> Security, signing & provenance toolchain for the Agent Skills (`SKILL.md`) standard.
> **Status:** Design v2 — ready for implementation. Supersedes v1 (fixes: signing byte-level spec, Merkle spec, rule-pack trust model, unified verdict model, OWASP-pivoted use cases).
> **Primary language:** Go (single static binary). **Also shipped as:** an embeddable library with Go, Python, TypeScript/Node, and Rust interfaces, plus a language-agnostic daemon (gRPC + JSON-RPC/stdio).

---

## 1. Purpose & scope

`skill-guard` is vendor-neutral trust infrastructure for the Agent Skills standard. The `SKILL.md` standard ships with **no signing, provenance, integrity-hash, or publisher-verification mechanism**; marketplaces perform zero security review; Snyk's ToxicSkills study found ~13.4% of scanned skills carry a critical issue. OWASP's Agentic Skills Top 10 prescribes the mitigations (ed25519 signing, `content_hash`, Merkle-root registry verification, registry scanning) but — by its own admission — does not specify the canonicalization or byte-level procedure. `skill-guard` implements those mitigations and **precisely specifies what OWASP leaves open**, so independent implementations interoperate.

It does three things:

1. **Scan** — statically analyze a skill bundle (`SKILL.md` front-matter + body + bundled scripts, configs, referenced assets) against an extensible ruleset mapped to the **OWASP Agentic Skills Top 10 (AST01–AST10)**.
2. **Sign / verify** — produce and verify cryptographic provenance in two interoperable forms: a detached **DSSE attestation** (`.skillsig`) and the OWASP **Universal Skill Format in-manifest fields** (`signature`, `content_hash`), both over the same SHA-256 Merkle root (byte-level spec in §7).
3. **Emit a skill card** — a machine-readable verdict (risk score/tier, permissions, findings digest, provenance) that agents, registries, and CI consume without re-scanning.

**What signing means (and does not).** An attestation proves **integrity** (bundle unchanged since signing) and **identity** (who signed). It does **not** prove safety — an attacker can sign their own malware. Safety comes from the scan verdict; trust comes from *whose* key signed. Consumers MUST treat `attestation.verified: true` as "authentic and untampered," never as "safe." Tooling output and docs repeat this distinction wherever the two appear together.

**Non-goals (v1):** not a runtime sandbox, not a network proxy, not a marketplace, not an LLM-as-judge service (LLM semantic analysis is an optional pluggable engine, off by default). `skill-guard` composes with those layers.

---

## 2. Research foundation & reference resources (verified)

Authoritative, license-checked sources the ruleset, use cases, and attestation format align to. All links verified July 2026.

### 2.1 Primary guidance — must-align

| Resource | URL | License | How we use it |
|---|---|---|---|
| **OWASP Agentic Skills Top 10** (project) | https://owasp.org/www-project-agentic-skills-top-10/ | CC-BY-SA-4.0 | Canonical risk taxonomy AST01–AST10; Universal Skill Format `signature`/`content_hash` fields; "Sign your skills: implement ed25519 signing before publication; include content_hash in your manifest (AST01/AST02)"; "signature and content_hash together enable Merkle-root registry verification (AST01/AST02)". |
| OWASP AST — Security Assessment **Checklist** | https://owasp.org/www-project-agentic-skills-top-10/checklist.html | CC-BY-SA-4.0 | Source of concrete per-risk automated checks (§5). |
| OWASP AST — **Skill Scanner Integration** guide | https://owasp.org/www-project-agentic-skills-top-10/skill-scanner-integration.html | CC-BY-SA-4.0 | **Pivot for our use cases (§3):** personas (developer / CI-CD / registry operator / security lead), integration scenarios (pre-commit, GitHub/GitLab CI, registry webhook, approval gates), SARIF multi-scanner composition conventions, 0–100 risk-score gating, best practices. |
| OWASP AST — **GitHub repo** (AST01…AST10 markdown) | https://github.com/OWASP/www-project-agentic-skills-top-10 | CC-BY-SA-4.0 | Per-risk detail + prescribed mitigations. |
| OWASP AST01 — Malicious Skills | https://owasp.org/www-project-agentic-skills-top-10/ast01 | CC-BY-SA-4.0 | Signing/attestation requirements. |
| OWASP AST05 — Untrusted External Instructions | https://github.com/OWASP/www-project-agentic-skills-top-10/blob/main/ast05.md | CC-BY-SA-4.0 | External-fetch inventory + reference-pinning checks. |

> **CC-BY-SA-4.0 note:** the AST text is copyleft for *documentation*. We implement the described checks freely (facts/ideas aren't copyrightable); where we quote or adapt AST prose in our docs we attribute OWASP and keep derived docs CC-BY-SA-4.0. Affects `docs/` text only — Go/rule code stays Apache-2.0.

> **OWASP signing gap we resolve:** OWASP's Universal Skill Format shows `signature: "ed25519:…"` and `content_hash: "sha256:…"` in the manifest but does **not** define which bytes are hashed/signed, whether the hash covers only `SKILL.md` or the whole bundle, or how the manifest is canonicalized given the signature lives inside the file it covers. §7 defines all of this normatively; if OWASP/AAIF later publish an official procedure, we add a compatibility emitter (§7.6) — the crypto core is format-agnostic.

### 2.2 Standard being secured

| Resource | URL | Notes |
|---|---|---|
| Agent Skills spec (Anthropic) | https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview | `SKILL.md` structure; required `name`/`description`; optional `license`/`compatibility`/`metadata`; experimental `allowed-tools`. |
| `SKILL.md` format spec | https://agentskills.io/specification | The open-standard spec (AAIF/Linux Foundation). Parser targets this; manifest schema validation pins to a spec version. |
| Anthropic public skills repo | https://github.com/anthropics/skills | Benign reference corpus for false-positive regression. |
| Anthropic engineering post | https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills | Design intent / triggering model. |

### 2.3 Prior-art scanners — rules reference & interop targets

| Resource | URL | License | Reusability |
|---|---|---|---|
| **NVIDIA SkillSpector** | https://github.com/NVIDIA/SkillSpector | **Apache-2.0** ✅ | 68 patterns / 17 categories, 0–100 risk score, SARIF output; OWASP's integration guide uses it as the reference scanner. We adopt its 0–100 score convention for gate compatibility, may port rule ideas, and merge its SARIF (AST08 multi-scanner). |
| Snyk **Agent Scan** / **mcp-scan** (Invariant Labs) | https://github.com/invariantlabs-ai/mcp-scan | **Apache-2.0** ✅ | Tool-poisoning / rug-pull detection for MCP + skills. Interop target and rule inspiration. |

### 2.4 Test corpus of malicious skills

| Resource | URL | License | Decision |
|---|---|---|---|
| Snyk **ToxicSkills** (`toxicskills-goof`) | https://github.com/snyk-labs/toxicskills-goof | **⚠️ No LICENSE file** | **Do NOT vendor** (no license = all rights reserved; repo says "educational only"). Reference only. `skill-guard corpus pull toxicskills` performs an opt-in clone into the user's own cache, **stored defanged** (§10.7): payload files zipped with a non-skill extension inside a `DO-NOT-LOAD.quarantine/` directory plus a marker file, so local agents' skill discovery and AV don't ingest live samples. Never redistributed in our repo or binary. Revisit if Snyk adds a permissive license. |
| Our own **fixtures** | `testdata/` (this repo) | Apache-2.0 | Synthetic malicious + benign skills; the primary CI regression corpus. |

**Supporting evidence in rationale** (not code dependencies): Snyk ToxicSkills study (https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/), SkillSieve triage framework (https://arxiv.org/html/2604.06550v1).

---

## 3. Use cases & UX flows

Pivoted on the OWASP Skill Scanner Integration guide's personas and scenarios. Each flow lists the actor, the exact commands, and the expected outcome. These flows are the acceptance criteria for the CLI UX.

### 3.1 Persona map (per OWASP integration guide)

| Persona | Integration point | skill-guard surface |
|---|---|---|
| **Skill author / developer** | Local dev, pre-commit hook | `scan`, `sign`, pre-commit hook |
| **CI/CD pipeline** | GitHub Actions / GitLab CI on PR & push | `scan --format sarif`, exit codes, GitHub Action |
| **Registry operator** | Publish-time webhook gate | daemon (`serve`) or CLI in webhook; `card`; `.skillsig` storage; transparency log |
| **Agent runtime / SDK integrator** | Pre-load guard before skill enters context | library `Guard()`, bindings, daemon |
| **Security lead / org admin** | Policy, trust roster, fleet inventory, multi-scanner review | `.skillguard.yaml` policy, `trust`, SARIF merge, skill-card inventory |
| **End user** (e.g., Claude Code user installing a marketplace skill) | Pre-install check | `skill-guard scan <git-url>` one-liner |

### 3.2 Flow A — Skill author: develop → scan → fix → sign → publish

```console
$ skill-guard scan ./my-skill
  SKILL.md:12  SG-INJ-001  high  Imperative override phrase ("ignore previous instructions")
  scripts/setup.sh:3  SG-NET-002  critical  curl piped to bash
  verdict: fail (fail-on: high)   risk score: 78/100 (L3)
$ ... fix findings ...
$ skill-guard scan ./my-skill
  verdict: pass   risk score: 4/100 (L0)
$ skill-guard keygen --out ~/.config/skill-guard/author.key       # once
$ skill-guard sign ./my-skill --key ~/.config/skill-guard/author.key
  wrote my-skill.skillsig  (merkle_root sha256:9f2b…, scan attached: pass @ core-packs 1.4.0)
$ skill-guard sign ./my-skill --key … --emit-manifest-fields      # optional USF compat (§7.5)
  updated my-skill/SKILL.md front-matter: content_hash, signature
$ git commit && publish to registry (bundle + .skillsig)
```

- `sign` **runs the default scan automatically** and embeds the result in the attestation; `--no-scan` produces an integrity-only attestation with `"scan": null` (explicitly rendered as "UNSCANNED" on verify). This resolves the sign↔scan ordering: sign never *requires* a prior scan, and signing a failing skill is allowed (signature ≠ safety, §1) but the failing verdict is recorded in the attestation and surfaces on every verify.
- Pre-commit hook (mirrors OWASP's pre-commit scenario): `repo: skill-guard`, `entry: skill-guard scan --fail-on high`, targeting `SKILL.md`, `*.md`, `*.yaml`, `*.json`, scripts.

### 3.3 Flow B — CI/CD: PR gate with SARIF (GitHub Actions / GitLab CI)

Per OWASP's approval-gate workflow: scan on PR → SARIF to code scanning → block merge over threshold.

```yaml
# .github/workflows/skill-guard.yml (shipped as a reusable action)
on:
  pull_request: { paths: ["skills/**"] }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: skill-guard/action@v1          # installs pinned skill-guard binary
        with: { path: skills/, fail-on: high, format: sarif, output: skill-guard.sarif }
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: skill-guard.sarif }
```

- SARIF `ruleId` = `SG-*` rule ID; each result carries `properties.ast: ["AST01",…]` and `properties.layer` (§3.6); artifacts carry `hashes["sha-256"]` so multi-scanner reports join per OWASP's composition convention.
- GitLab CI: same binary, `--format sarif --out gl-sast-report.json`-compatible emission, `rules: [merge_requests]`.
- Merge gate = exit code (§10.5): `1` blocks; risk score also emitted for orgs gating on OWASP's 0–100 threshold convention instead of severity.

### 3.4 Flow C — Registry operator: publish-time gate + provenance storage

Mirrors OWASP's Node.js webhook pattern, replacing ad-hoc scanning with a daemon call:

```
publish request ──► registry webhook ──► skill-guard daemon: Guard(bundle)
                                          │  verdict fail/critical ──► reject upload (show findings to author)
                                          │  verdict pass/warn ──► accept; store: bundle, .skillsig, skill-card
                                          └► append (merkle_root, keyid, card digest) to transparency log
serve to installers ──► bundle + .skillsig + skill-card   (installers re-verify locally; never trust registry scan alone)
```

- Registry policy examples: require attestation (`policy.attestation.required: true`), require publisher identity binding, reject `verdict: fail`, quarantine `warn` for human review.
- Re-scan on every version change (AST07): new upload = new merkle_root = full re-gate; no grandfathering.
- The registry stores the card so installers/browsers can display risk tier without re-scanning — but the card is advisory; local `verify` is the trust anchor.

### 3.5 Flow D — Agent runtime / SDK integrator: pre-load guard with rug-pull protection

Before a skill's instructions enter the context window or its scripts become executable:

```
discover skill dir ──► merkle_root := hash(bundle)
                       cached verdict for merkle_root? ──yes──► apply cached decision
                       └─no──► Guard(bundle, policy) ──► pass: load  / warn: load+log or ask  / fail: skip+log
on every session start / skill reload: recompute merkle_root; root changed ⇒ cache miss ⇒ full re-guard
```

- **Verdict cache is keyed by merkle_root**, so any content change (rug-pull, update drift — AST07) automatically forces re-evaluation, and unchanged skills cost one hash pass (~ms) per session.
- Concrete wiring per SDK in §11. Latency budget: static+secret+provenance guard on a typical skill ≤ 150 ms cold, ≤ 5 ms cached.

### 3.6 Flow E — Security lead: org policy, trust roster, fleet inventory, multi-scanner review

- **One policy file** (`.skillguard.yaml`, §10.4) distributed org-wide (repo, MDM, or `--policy https://…` pinned by hash): thresholds, waivers with expiry+justification, allowlists, and the **trust roster** (`trust:` section — accepted keys/identities, revocations). Policy and trust ship in one document to avoid the two-file confusion; `trust:` may alternatively `include:` a separate file.
- **Fleet inventory (AST09):** every guard/scan appends a JSONL audit record (skill name, merkle_root, verdict, policy version, timestamp, host) to a configurable sink; skill-cards aggregate into a central index — skill ID, version, hash, install date, installer identity, risk tier — satisfying the OWASP AST09 checklist fields.
- **Multi-scanner composition (AST08, per OWASP conventions):** `skill-guard report merge a.sarif b.sarif` joins runs by `artifacts[].hashes["sha-256"]`, partitions by `properties.layer` (`content` = instruction-layer findings, `code` = script findings, `provenance` = signature/hash findings, `drift` = change-detection), and preserves `run.tool.driver.name`+version per finding. SkillSpector/mcp-scan SARIF imports cleanly.

### 3.7 Flow F — End user: pre-install spot check

```console
$ skill-guard scan https://github.com/someone/cool-skill
  verdict: warn   risk score: 31/100 (L1)
  SKILL.md:44  SG-REF-002  medium  External reference not pinned to content hash
  1 medium, 2 low. Run with -v for details.
$ skill-guard verify https://github.com/someone/cool-skill
  attestation: present, signature VALID (key not in your trust roster — identity unverified)
  merkle root: MATCH   scan-at-signing: pass (core-packs 1.3.x)
```

Human-first output: verdict and score on line one, findings as `file:line id severity title`, remediation via `-v`. `--format json|sarif|skill-card` for machines. **Non-blocking by default for exploration** (OWASP best practice): `scan` without `--fail-on` prints everything and exits 0 unless findings reach the built-in default threshold (`high`, §10.5).

---

## 4. Architecture overview

```
                         ┌───────────────────────────────────────────────┐
                         │              skill-guard core (Go)            │
                         │                                               │
  SKILL.md bundle ──►    │  skill ──► scan ──► findings ──► report       │ ──► text / JSON / SARIF
  (dir, archive, git,    │   │         ▲          │            │         │ ──► skill-card.json
   single file, stdin)   │   │      rules ◄─ packs │         policy      │
                         │   ▼                     ▼            ▼        │
                         │  bundle ──► attest/verify (§7) ──► verdict    │ ──► .skillsig (DSSE)
                         │                 ▲                             │ ──► USF manifest fields
                         │              trust roster (in policy)         │
                         └───────────┬───────────────┬───────────────────┘
                                     │               │
             ┌───────────────────────┴─────┐   ┌─────┴────────────────────────────┐
             │  cmd/skill-guard (CLI)      │   │  embedding surfaces              │
             │  scan sign verify card ...  │   │  Go API · C-ABI · Py · TS · Rust │
             └─────────────────────────────┘   │  daemon: gRPC + JSON-RPC/stdio   │
                                               └──────────────────────────────────┘
```

**Design principles**

1. **Library-first.** The CLI is a thin shell over the public Go API; everything the CLI does, an embedder can do in-process.
2. **Deterministic core.** Static scan + provenance are reproducible: same bundle + same rule-pack versions ⇒ identical findings and identical **canonical card body** (§9 separates the reproducible card body from the emission envelope that carries timestamps). Non-deterministic engines (LLM, online CVE, dynamic) are opt-in and mark the card `nondeterministic: true`.
3. **Rules as data.** No attack signature hardcoded in Go control flow; all in loadable, versioned rule-packs with an explicit trust model (§8.2).
4. **Single static binary.** No runtime deps on the default path. Optional engines degrade gracefully.
5. **Standard outputs.** SARIF 2.1.0 with OWASP composition conventions; skill-card as the canonical machine verdict; USF manifest fields for registry compat.
6. **Practice what we scan for.** The daemon never binds publicly by default (§11.3); the corpus command quarantines samples (§2.4); secrets are redacted (§13).

---

## 5. Feature list — security checks (extensible catalog)

Each check is a **rule**: stable ID, AST mapping, default severity, engine. The catalog is **data, not code** — rules live in versioned YAML rule-packs (§8) and can be extended/overridden without recompiling. IDs: `SG-<domain>-<n>`.

Severity: `critical > high > medium > low > info`. Engines: `static` (regex/AST/structural), `secret` (entropy+pattern), `provenance` (hash/sig), `dynamic` (opt-in sandbox), `llm` (opt-in semantic).

> **Detection engineering:** the catalog below names *what* each rule detects. The companion **`rule-verification.md`** specifies, per rule, *how* to detect it with maximum coverage and minimum false positives — the widened pattern families, the FP carve-outs, the deterministic→LLM escalation ladder (T0–T3), confidence math, and the mandatory TP/FP fixtures. Every entry here is authored against its `rule-verification.md` section. Methodology and several rule classes are informed by NVIDIA SkillSpector (Apache-2.0) prior art.

### 5.1 Prompt injection, jailbreak & instruction-layer attacks → AST01, AST05
- **SG-INJ-001** Imperative override phrases in `SKILL.md` body (verb×scope×target family; catches paraphrase like "ignore any text written before"; T3 fallback). `static`(+`llm`), high.
- **SG-INJ-002** Hidden/obfuscated instructions: zero-width Unicode, bidi controls, Unicode-Tag ASCII smuggling, homoglyphs, instruction-bearing comments. `static`, critical.
- **SG-INJ-003** Base64 / hex / rot / gzip-encoded payload blocks (elevated when adjacent to a decode+exec sink). `static`, high.
- **SG-INJ-004** Writes to agent identity/config files (`SOUL.md`, `MEMORY.md`, `AGENTS.md`, `CLAUDE.md`, `.claude/`) outside the skill's own dir. `static`(+`llm`), critical.
- **SG-INJ-005** Description/name vs. observed-behavior mismatch. `static`+`llm`, medium.
- **SG-INJ-006** System-prompt / tool-schema exfiltration (direct, indirect, exfil-via-tool). `static`(+`llm`), high.
- **SG-MEM-001** Persistent context / memory poisoning — instructions to persist behavior across sessions or mutate memory state. `static`+`llm`, high.
- **SG-MEM-002** Context-window stuffing — oversized, low-entropy instruction blocks that displace real instructions/safety text. `static`, medium.
- **SG-ANTI-001** Anti-refusal / jailbreak framing — refusal suppression, disclaimer suppression, policy nullification (3 families). `static`(+`llm`), high.
- **SG-STEER-001** Subtle behavioral steering / covert bias or commercial nudging. `llm`+`static` seed, medium.

### 5.2 Data exfiltration & network egress → AST01, AST05
- **SG-NET-001** Outbound calls to pastebin/webhook/URL-shortener/raw-gist hosts. `static`, high.
- **SG-NET-002** `curl`/`wget`/`fetch` piped to a shell. `static`, critical.
- **SG-NET-003** Staged download: install/prepare step fetching a secondary payload at load time. `static`, critical.
- **SG-NET-004** Data POSTed to an external endpoint (env, files, clipboard). `static`, high.
- **SG-NET-005** Hardcoded IPs, non-allowlisted domains, DNS-exfil patterns. `static`, medium.
- **SG-NET-006** Bind to `0.0.0.0` / listener / reverse-shell idiom. `static`, high.

### 5.3 Secret & credential access → AST03, AST08
- **SG-SEC-001** Reads of sensitive paths: `~/.ssh/`, `~/.aws/`, `.env`, `**/credentials*`, `*.wallet`, browser profile/cookie stores, keychain (read sink required). `static`, critical.
- **SG-SEC-002** Embedded secrets in the bundle (keys, tokens) via provider regex + Shannon entropy (gitleaks/trufflehog-class; example-key denylist). `secret`, high.
- **SG-SEC-003** Environment harvesting — bulk `os.environ`/`process.env` enumeration or secret-named var reads. `static`, high.
- **SG-SEC-004 / SG-SSRF-001** Cloud metadata (`169.254.169.254`, `metadata.google.internal`) & SSRF (loopback/link-local/private, dynamic-host targets). `static`, high.
- **SG-AS-001** Agent-config / cross-skill snooping — reads of `.claude/`/`.codex/`/`.gemini/`, `mcp.json`, or peer skills' files. `static`, high.

### 5.4 Dangerous commands & code execution → AST01, AST04
- **SG-EXE-001** Dynamic eval/exec via real AST (`eval`, `exec`, `compile`, `getattr`-reflection, `subprocess(shell=True)`, `os.system`, `Function()`, `child_process`); high-confidence "exec-chain" when arg traces to a dynamic source. `static`, high.
- **SG-EXE-002** Destructive FS ops on broad/dynamic targets (`rm -rf /`/`$VAR`/`*`, recursive chmod/chown, disk wipes). `static`, high.
- **SG-EXE-003** Privilege escalation (`sudo`, `setuid`, `authorized_keys`/`sudoers` writes). `static`, high.
- **SG-EXE-004 / SG-ROGUE-002** Persistence (cron, systemd, launchd, shell-rc edits, login/git hooks). `static`, high.
- **SG-EXE-005** Anti-analysis / sandbox-detection / scanner-evasion logic. `static`, high.
- **SG-ROGUE-001** Self-modification — runtime rewrite of the skill's own SKILL.md/scripts/config or disabling its own checks. `static`, high.

### 5.5 Metadata & manifest integrity → AST04, AST03
- **SG-MTA-001** Unsafe YAML tags (`!!python/object`, `!!python/apply`, `!!python/name`) / deserialization gadgets. `static`, critical.
- **SG-MTA-002** Front-matter schema violation vs. the pinned agentskills.io schema version: missing `name`/`description`, malformed values. Unknown **top-level** keys → `low` (the spec evolves; `metadata.*` is open by spec and never flagged; USF reserved keys `signature`/`content_hash` and the `metadata.skillguard.*` extension are recognized). `static`, medium/low as above.
- **SG-MTA-003** `allowed-tools` over-broad (`Bash(*)`, unrestricted shell) or absent while scripts execute commands. `static`, high.
- **SG-MTA-004** Overly broad file globs in declared permissions (`**/*`). `static`, medium.
- **SG-MTA-005** Brand/trademark impersonation in `name`/`description`. `static`, medium.
- **SG-MTA-006** Declared risk tier inconsistent with observed permission scope. Declared tier is read from the optional `metadata.skillguard.risk_tier` extension key (spec-legal, since `metadata` is open); **rule is inactive when the key is absent.** `static`, medium.
- **SG-TRIG-001** Trigger abuse / shadowing — description/trigger engineered for over-activation (generic single-word triggers, "any/all/every request" claims) or shadowing a built-in/peer-skill trigger. `static`(+`llm`), medium.

### 5.6 Supply chain & dependencies → AST02, AST07
- **SG-DEP-001** Unpinned dependencies (ranges, `latest`, unhashed) in `requirements.txt`/`package.json`/`pyproject.toml`. `static`, medium.
- **SG-DEP-002** Dependency confusion / typosquat heuristics (edit distance to popular packages). `static`, medium.
- **SG-DEP-003** Known-CVE lookup for pinned deps (offline OSV DB; online optional ⇒ nondeterministic flag). `static`, high.
- **SG-DEP-004** Executable config treated as code: `.claude/settings.json`, git hooks, install/`postinstall` scripts. `static`, high.
- **SG-DEP-005** Missing/failed SBOM or content-hash coverage of bundle files. `provenance`, medium.
- **SG-DEP-006** Untrusted container image — content-trust disabled, `--insecure-registry`, unpinned `:latest`. `static`, medium.

### 5.7 External references → AST05
- **SG-REF-001** Inventory of all external URLs / remote refs in body + scripts. `static`, info (always emitted; feeds the card).
- **SG-REF-002** External reference (machine-loaded) not pinned to a content hash. `static`, medium.
- **SG-REF-003** Runtime fetch of instructions/docs outside a vetted allowlist ("external brain"). `static`(+`llm`), high.

### 5.8 Taint / dataflow correlation → AST01, AST05 (T2 behavioral)
Connect **sources** (env, credential reads, conversation, clipboard, network input) to **sinks** (network send, exec, external/identity file write). Correlation lets the single-signal rules above stay low-confidence (few FPs) while the *combination* fires high — the primary precision lever.
- **SG-TAINT-001** Source→sink with no validation between. `static`, high (0.7).
- **SG-TAINT-002** Source→sink via intermediate variable. `static`, medium (0.65).
- **SG-TAINT-003** Credential/env → network (high-confidence exfil). `static`, high (0.9).
- **SG-TAINT-004** File contents → network. `static`, high (0.85).
- **SG-TAINT-005** External input → exec (RCE/injection). `static`, high (0.9).

### 5.9 Provenance & signing → AST01, AST02, AST07, AST09
- **SG-PRV-001** No attestation present. `provenance`, medium; **promoted to a verification failure (exit 2) when `policy.attestation.required: true`** (§10.5).
- **SG-PRV-002** Signature invalid, or key not in the trust roster. `provenance`, critical.
- **SG-PRV-003** Merkle root mismatch — content changed since signing (tamper/rug-pull/drift). `provenance`, critical.
- **SG-PRV-004** Attestation expired or key revoked. `provenance`, high.
- **SG-PRV-005** Publisher identity unverified (no bound identity claim). `provenance`, medium.
- **SG-PRV-006** Attestation is integrity-only (`scan: null`, signed with `--no-scan`) — skill was never scanned at signing time. `provenance`, low.

### 5.10 Opt-in advanced engines
- **SG-YARA-\*** (`static`, opt-in) Bundled YARA signatures for known malware — reverse shells, webshells, C2 frameworks, info-stealers, crypto-miners, exploit tools. High precision, critical on match; versioned ruleset in the pack.
- **SG-DYN-\*** (`dynamic`) Sandboxed execution + behavioral diff (declared vs. observed FS/network/process); decodes SG-INJ-003 blobs, resolves SG-NET-003 staged fetches, proves SG-TAINT flows. Requires container runtime; findings marked `nondeterministic`.
- **SG-LLM-\*** (`llm`) Semantic adjudication (the T3 escalation target throughout `rule-verification.md`) — **only ever judges pre-filtered candidate spans**, re-scores confidence, always tagged `nondeterministic`. Pluggable provider.

> **Extensibility contract:** third parties add checks by supplying a rule-pack (§8); no fork required. The trust rules for third-party packs are in §8.2.
>
> **Deliberate non-adoptions** (from the SkillSpector coverage review): output-handling (unvalidated model-output injection) and the runtime half of excessive-agency (autonomous action without human-in-the-loop) are runtime/host concerns not statically decidable from a bundle. Their static shadows (broad tools, destructive ops, egress) are caught by SG-MTA-003/SG-EXE-\*/SG-NET-\*; the runtime enforcement is left to the agent layer and noted in the card rather than shipped as noisy rules.

### 5.11 OWASP AST → check coverage matrix

| AST | Risk | Covered by |
|---|---|---|
| AST01 | Malicious Skills | SG-INJ-\*, SG-MEM-\*, SG-ANTI-001, SG-NET-002/003, SG-EXE-\*, SG-ROGUE-\*, SG-MTA-001, SG-TAINT-\*, SG-YARA-\*, SG-PRV-\* |
| AST02 | Supply Chain Compromise | SG-DEP-001/002/004/005/006, SG-PRV-002/003 |
| AST03 | Over-Privileged Skills | SG-SEC-001/003, SG-AS-001, SG-MTA-003/004 |
| AST04 | Insecure Metadata | SG-MTA-\*, SG-INJ-002/003 |
| AST05 | Untrusted External Instructions | SG-REF-\*, SG-NET-003, SG-INJ-001, SG-STEER-001, SG-TRIG-001, SG-SSRF-001, SG-TAINT-\* |
| AST06 | Weak Isolation | SG-NET-006, SG-DYN-\* |
| AST07 | Update Drift | SG-DEP-001, SG-PRV-003/004; merkle-keyed re-guard (§3.5) |
| AST08 | Poor Scanning | SG-SEC-002, SG-YARA-\*, SG-LLM-\*, SG-DYN-\*, SARIF multi-scanner merge (§3.6) |
| AST09 | No Governance | audit JSONL + card inventory fields (§3.6), SG-PRV-005 |
| AST10 | Cross-Platform Reuse | manifest normalization, card `platforms[]`, cross-registry hash sharing |

AST06/AST09/AST10 are partly runtime/organizational: `skill-guard` supplies the artifacts (attestation, card, audit records, normalized manifest) those layers consume, and flags what static analysis can see.

---

## 6. Module design (Go packages)

```
skill-guard/
  cmd/skill-guard/           # CLI entrypoint (cobra)
  pkg/
    skill/                   # SKILL.md + bundle model, parsing, normalization
    rules/                   # rule-pack loader, engine registry, matching
    scan/                    # orchestration: bundle × rules -> findings
    secrets/                 # entropy + pattern secret detection
    attest/                  # Merkle (§7.1), DSSE (§7.3), USF fields (§7.5), signers
    verify/                  # attestation + trust verification
    trust/                   # trust roster (from policy), revocation, transparency-log client
    policy/                  # .skillguard.yaml: thresholds, waivers, allowlists, trust section
    card/                    # skill-card generation (§9)
    report/                  # formatters: text, json, sarif, skill-card; sarif merge
    engine/
      static/                # regex/AST/structural matchers
      dynamic/               # opt-in sandbox runner (interface + container impl)
      llm/                   # opt-in semantic engine (provider interface)
  api/                       # public library API facade + C-ABI (cgo) export
  proto/                     # gRPC service definitions (daemon)
  rulepacks/                 # built-in signed rule-packs (go:embed)
  bindings/{python,node,rust}
  testdata/                  # Apache-2.0 synthetic fixtures
  docs/
```

### 6.1 `skill` — bundle model & parser
- Input sources: local directory, `.tar/.tar.gz/.zip`, git URL/ref, single `SKILL.md` file, stdin (`-`). **Stdin accepts a single `SKILL.md` document only** (manifest+body checks run; file-tree, script, and provenance checks are skipped and reported as `skipped` in the card).
- Normalized model:
  ```go
  type Bundle struct {
      Root     string
      Manifest Manifest       // parsed YAML front-matter
      Body     string         // markdown body after front-matter
      Files    []File         // path (normalized, §7.1), mode, sha256, size, mediaType, role
      Scripts  []Script       // executable/interpretable files with detected language
      Configs  []File         // .claude/settings.json, hooks, dependency manifests
      Refs     []ExternalRef  // URLs & remote refs discovered
  }
  type Manifest struct {
      Name, Description, License string
      Compatibility any
      AllowedTools  []string          // experimental spec field
      Signature     string            // USF field, if present (§7.5)
      ContentHash   string            // USF field, if present (§7.5)
      Extra         map[string]any    // unknown keys preserved for SG-MTA-002
      Raw           []byte
  }
  ```
- **Hardened parsing:** safe YAML loader rejecting custom tags (feeds SG-MTA-001); nothing in the bundle is ever executed or resolved on the static path; file walk is symlink-safe, size- and depth-bounded; archive extraction is zip-slip guarded.
- Language detection (sh/bash, python, js/ts, ruby, powershell, …) enables language-aware rules.

### 6.2 `rules`, `scan`
- Rule-pack loading and trust: §8. Engine registry maps `engine:` → implementation; unknown engine ⇒ pack rejected (fail-closed).
- `scan` runs enabled rules over the bundle (worker pool, deterministic output order) and emits:
  ```go
  type Finding struct {
      RuleID     string
      AST        []string   // ["AST01","AST05"]
      Severity   Severity
      Engine     string
      Layer      string     // content | code | provenance | drift  (SARIF properties.layer, §3.6)
      Title      string
      File       string
      StartLine, EndLine int
      Excerpt    string     // secret-redacted
      Rationale  string
      Fix        string     // remediation guidance (OWASP best practice: actionable)
      Confidence float32
      Waived     bool       // excluded from counts/verdict; listed separately
  }
  ```

### 6.3 `attest`/`verify`/`trust` — see normative spec §7. `policy` — see §10.4. `card`/`report` — see §9, §3.6.

---

## 7. Provenance: normative signing & verification spec

This section is the interop contract. Independent implementations (per-language pure `verify`, registries) implement from this text alone. Requirement keywords per RFC 2119.

### 7.1 Bundle canonicalization & Merkle tree (`SGMT-1`)

**File set.** All regular files under the bundle root, **excluding**: the detached attestation (`*.skillsig`), `.git/`, `.DS_Store`, `Thumbs.db`, and paths matched by an optional `.skillguardignore` (which, if present, is itself **included** in the file set). Symlinks MUST be rejected (error, not skipped). Empty file set is invalid.

**Path normalization.** Paths are relative to the bundle root, use `/` as separator on all platforms (Windows `\` normalized), no leading `./`, no `.`/`..` segments, Unicode NFC-normalized, UTF-8 encoded. Duplicate post-normalization paths ⇒ error.

**Leaf hash** (domain-separated, RFC 6962-style):

```
leaf = SHA-256( 0x00 || uvarint(len(path)) || path || file_sha256 )
```
where `path` is the normalized UTF-8 path bytes and `file_sha256` is the raw 32-byte SHA-256 of the file content (for `SKILL.md`, of its **normalized form**, §7.5).

**Tree.** Leaves sorted by `path` bytewise ascending. Interior node = `SHA-256(0x01 || left || right)`. Odd node at any level is promoted unchanged to the next level (Bitcoin-style promotion, no duplication). Single file ⇒ root = its leaf. `merkle_root` is rendered `sha256:<lowercase-hex>`.

**Rationale:** domain separation prevents leaf/interior second-preimage confusion; sorted leaves make the root independent of walk order; per-file leaves let registries serve single-file inclusion proofs. (Note: the detached attestation also carries the full `files[]` list for convenience — the Merkle benefit materializes for registries and size-constrained verifiers that drop `files[]` and rely on proofs.)

### 7.2 Attestation statement

The signed payload is a JSON **statement** (no signature material inside):

```json
{
  "_type": "skillguard.dev/attestation/v1",
  "subject": {
    "name": "pdf-extractor",
    "merkle_root": "sha256:9f2b…",
    "file_count": 14,
    "manifest_sha256": "sha256:1a0c…"
  },
  "files": [ { "path": "SKILL.md", "sha256": "sha256:…" }, … ],
  "scan": {
    "rulepacks": [ { "name": "core-injection", "version": "1.4.0", "sha256": "…" } ],
    "verdict": "pass",
    "max_severity": "low",
    "risk_score": 4,
    "findings_digest": "sha256:…",
    "skillguard_version": "1.0.0"
  },
  "predicate": {
    "issued_at": "2026-07-16T00:00:00Z",
    "expires_at": "2027-07-16T00:00:00Z",
    "builder": "skill-guard@1.0.0",
    "reproducible": true
  },
  "publisher": { "identity": "oidc:author@example.com", "keyid": "author-2026" }
}
```

`scan` is `null` for integrity-only attestations (`--no-scan`; SG-PRV-006). `files[]` is sorted identically to the Merkle leaves.

### 7.3 Signature envelope — DSSE (`.skillsig`)

The detached attestation file is a **DSSE envelope** (https://github.com/secure-systems-lab/dsse), which removes any JSON-canonicalization requirement — the payload is opaque bytes:

```json
{
  "payloadType": "application/vnd.skillguard.attestation.v1+json",
  "payload": "<base64(statement JSON exactly as serialized at signing)>",
  "signatures": [ { "keyid": "author-2026", "sig": "<base64(ed25519 sig)>" } ]
}
```

**Signed bytes** = DSSE PAE: `"DSSEv1" || SP || len(payloadType) || SP || payloadType || SP || len(payload) || SP || payload` (lengths as ASCII decimals, payload = the raw decoded bytes). Ed25519 is the REQUIRED algorithm; the `Signer` abstraction (below) admits KMS/HSM/Sigstore backends producing Ed25519 (or ECDSA-P256 as OPTIONAL, negotiated by `keyid` metadata in the trust roster). Multiple `signatures[]` entries are allowed (co-signing: author + registry).

**Verification procedure (normative order):**
1. Parse envelope; decode payload; check `payloadType`.
2. Verify ≥1 signature against keys in the trust roster; record which identities verified. Unknown key ⇒ SG-PRV-002 (signature may still be *cryptographically* checked and reported as "valid, untrusted key", as in Flow F).
3. Check `predicate.expires_at` and roster revocations ⇒ SG-PRV-004.
4. Recompute SGMT-1 Merkle root over the local bundle; compare to `subject.merkle_root` ⇒ SG-PRV-003 on mismatch.
5. Optionally check transparency-log inclusion (Rekor interim).
6. Emit `VerifyResult` + SG-PRV findings; policy maps them to verdict/exit code (§10.5).

### 7.4 Signer & trust interfaces

```go
type Signer interface {
    KeyID() string
    Algorithm() string                     // "ed25519" | "ecdsa-p256"
    Sign(ctx context.Context, pae []byte) ([]byte, error)   // ctx: KMS calls are network calls
}
type TrustRoster interface {
    Lookup(keyid string) (PublicKey, Identity, bool)
    Revoked(ctx context.Context, keyid string) bool
}
```
Implementations: local encrypted keyfile (default; `skill-guard keygen`), AWS KMS, PKCS#11, Sigstore keyless (Fulcio cert → OIDC identity; Rekor entry recorded in `predicate`).

### 7.5 OWASP Universal Skill Format in-manifest fields (compat emitter)

OWASP's USF places `content_hash: "sha256:…"` and `signature: "ed25519:…"` **inside the manifest**, which creates a self-reference (the signature lives in the file it covers). OWASP does not resolve this; we do, normatively:

- **Normalized `SKILL.md`** = the file's raw bytes with the front-matter lines for the two reserved keys removed. Both keys MUST be written as single-line, top-level plain/quoted scalars (writer enforces; verifier rejects multi-line or nested forms). Removal is line-based: drop lines matching `^content_hash:` and `^signature:` inside the front-matter block only.
- **`content_hash`** = the SGMT-1 `merkle_root` computed with `SKILL.md`'s leaf using its **normalized** content hash. For a single-file skill this degenerates to the hash of the normalized `SKILL.md` — satisfying both readings of the OWASP text.
- **`signature`** = `"ed25519:" || base64(sig)` where the signed bytes are the DSSE PAE of §7.3 with `payloadType = "application/vnd.skillguard.usf-fields.v1"` and `payload = content_hash` string bytes. (Same crypto path, no second scheme.)
- Emitted by `sign --emit-manifest-fields`; verified whenever present. The detached `.skillsig` remains the richer, preferred artifact (carries scan results, expiry, identity); USF fields are the lowest-common-denominator for registries that only read the manifest. **"signature and content_hash together enable Merkle-root registry verification (AST01/AST02)"** — this design makes that sentence concretely implementable.

### 7.6 Format evolution

`attest` isolates statement-building from crypto. If AAIF/OWASP publish an official byte-level procedure, we add `--format aaif` as another emitter over the same Merkle core — additive, not a rewrite. An in-toto/SLSA exporter (`--format in-toto`) ships in v1 for supply-chain tool interop.

---

## 8. Rule-packs: format & trust model

### 8.1 Format (`rulepack.v1`)

```yaml
apiVersion: skillguard.dev/rulepack.v1
name: core-injection
version: 1.4.0
description: Prompt-injection and instruction-layer attacks.
rules:
  - id: SG-INJ-002
    title: Hidden or obfuscated instructions
    ast: [AST04, AST01]
    severity: critical
    engine: static
    layer: content
    confidence: 0.9
    languages: ["*"]
    targets: [body, scripts]        # body | scripts | configs | manifest | refs
    match:
      any:
        - unicode_category: [Cf]
        - bidi_control: true
        - regex: '(?i)ignore (all|previous) (instructions|prompts)'
        - homoglyph_ratio: { gt: 0.15 }
    rationale: >
      Obfuscated or non-printing instructions are invisible to human review
      but parsed by the agent (OWASP AST04/AST01).
    fix: Remove non-printing characters; keep instructions in plain text.
```

Matcher primitives (`static`): `regex` (RE2 only — no backtracking ReDoS), `substring`, `glob`, `unicode_category`, `bidi_control`, `homoglyph_ratio`, `entropy` (delegates to `secret`), `ast_call` (language-aware call match), `yaml_tag`, `json_path`, `url_host`, `dep_unpinned`; combinable via `any`/`all`/`not`. Later packs may `disable:` or re-`severity:` inherited rule IDs; policy waivers are separate and audited.

### 8.2 Trust model (resolves the third-party chicken-and-egg)

| Pack source | Signature requirement | Behavior |
|---|---|---|
| **Built-in** (`go:embed`) | Signed by the skill-guard project key (embedded) | Verified at startup; mismatch ⇒ hard error (binary tamper). |
| **Explicit flag** (`--rulepack PATH`) | None required | Loaded; if unsigned or key unknown, a startup notice names the pack and `provenance: unsigned` is recorded in the card. The explicit flag *is* the user's authorization. |
| **Auto-discovered** (`--rulepack-dir`, system/user dirs) | MUST be signed by a key in the trust roster | Unsigned/unknown-key packs in auto-load paths are **skipped with a warning** (fail-closed: a writable drop-in dir must not silently add rules — or silently *disable* them). |
| **Remote** (`--rulepack https://…`) | MUST be signed by a roster key AND pinned (`#sha256=` fragment) | Otherwise rejected. |

Third parties therefore ship packs by (a) telling users to pass `--rulepack`, or (b) publishing their signing key for users to add to their roster (`skill-guard trust add-pack-key …`). Pack signature = DSSE over the pack bytes, same §7.3 crypto.

---

## 9. skill-card (machine-readable verdict)

Two layers, resolving the determinism/timestamp conflict:

- **`card`** — the canonical, reproducible body. Byte-identical for same bundle + same rule-pack versions + same policy (default engines). This is what `findings_digest`-style hashing and registry dedup key on.
- **`envelope`** — emission metadata (timestamps, host, source URI), excluded from reproducibility claims.

```json
{
  "_type": "skillguard.dev/skill-card/v1",
  "card": {
    "name": "pdf-extractor",
    "description": "Extracts tables from PDFs.",
    "merkle_root": "sha256:9f2b…",
    "verdict": "pass",
    "risk_score": 4,
    "risk_tier": "L0",
    "max_severity": "low",
    "counts": { "critical": 0, "high": 0, "medium": 0, "low": 1, "info": 5 },
    "waived": 1,
    "skipped_checks": [],
    "ast_findings": ["AST05"],
    "platforms": ["claude-code", "generic"],
    "permissions": {
      "allowed_tools": ["Bash(pdftotext:*)", "Read"],
      "sensitive_reads": [],
      "network_egress": [],
      "external_refs": ["https://…/spec.pdf#sha256=…"]
    },
    "attestation": { "present": true, "signature_valid": true, "trusted": true,
                     "publisher": "oidc:author@example.com", "expires_at": "2027-07-16T00:00:00Z",
                     "scanned_at_signing": "pass" },
    "rulepacks": [ { "name": "core-injection", "version": "1.4.0", "provenance": "official" } ],
    "policy_digest": "sha256:…",
    "nondeterministic": false
  },
  "envelope": {
    "scanned_at": "2026-07-16T10:22:00Z",
    "source": "git+https://…@<sha>",
    "skillguard_version": "1.0.0"
  }
}
```

Semantics: `counts` **exclude waived** findings (`waived` is a separate total); `skipped_checks` lists rule domains not runnable for this input (e.g., stdin single-file mode); `ast_findings` lists AST categories with ≥1 non-waived finding (v1 renames ambiguous `ast_coverage`); `platforms[]` from `compatibility` normalization (AST10).

**Risk score & tier.** `risk_score` (0–100, SkillSpector-convention-compatible for OWASP-style threshold gates) is a documented deterministic function: base points per finding by severity (critical 40, high 15, medium 5, low 1, info 0), scaled by confidence, summed and capped at 100; provenance bonuses subtract (verified+trusted attestation −10, floor 0). Tiers: L0 = 0–9, L1 = 10–29, L2 = 30–59, L3 = 60–100. Weights live in policy (overridable) with these defaults frozen for the v1 line.

---

## 10. CLI specification

### 10.1 Commands

| Command | Purpose |
|---|---|
| `scan <path\|archive\|git-url\|->` | Scan; emit findings/card. Stdin = single SKILL.md (§6.1). |
| `sign <path>` | Scan (default) + Merkle + DSSE sign → `<bundle>.skillsig`. `--no-scan` for integrity-only; `--emit-manifest-fields` for USF (§7.5). |
| `verify <path>` | Full §7.3 verification; SG-PRV findings; exit per §10.5. |
| `card <path>` | Scan + verify, emit skill-card (card = f(scan ∪ verify); both always run here). |
| `guard <path>` | scan+verify+policy in one shot; the CLI twin of library `Guard()` — what agent-runtime shell integrations call. |
| `inspect <path>` | Dump parsed bundle model (debug). |
| `keygen` | Generate local Ed25519 keypair (encrypted at rest). |
| `rules {list\|show\|verify\|lint}` | Manage/validate rule-packs. |
| `trust {add\|add-pack-key\|list\|revoke}` | Manage the roster (edits the `trust:` section of policy). |
| `report merge <a.sarif> <b.sarif>…` | Multi-scanner SARIF merge (§3.6). |
| `corpus {pull\|list}` | Opt-in external corpora, quarantined (§2.4, §10.7). |
| `serve` | Daemon (§11.3). |
| `version` | Binary + built-in rule-pack versions. |

### 10.2 Common flags
`--format {text,json,sarif,skill-card,in-toto}` · `--out FILE` · `--policy PATH|URL#sha256=…` · `--rulepack PATH|URL#sha256=…` (repeatable) · `--rulepack-dir DIR` · `--engines static,secret,provenance[,dynamic,llm]` · `--fail-on {critical,high,medium,low}` · `--warn-on {…}` · `--offline` · `--show-secrets` · `--no-color` · `-q/-v`.

### 10.3 Verdict model (single definition, used everywhere)

Serialized verdict values are lowercase strings: **`pass` | `warn` | `fail`** (Go enum marshals to these; Python/TS bindings expose the same strings).

- `fail` — ≥1 non-waived finding with severity ≥ `fail_on` (default **high**), or a policy-required condition unmet.
- `warn` — no fail, and (≥1 finding ≥ `warn_on` (default **medium**), or attestation absent/untrusted while `policy.attestation.required: false` but `warn_if_missing: true` (default)).
- `pass` — otherwise.

### 10.4 Policy file (`.skillguard.yaml`) — one file, includes trust

```yaml
apiVersion: skillguard.dev/policy.v1
fail_on: high
warn_on: medium
attestation: { required: false, warn_if_missing: true }
waivers:
  - rule: SG-DEP-001
    path: "skills/legacy-*"
    reason: "vendored pin migration, ticket SEC-142"
    expires: 2026-10-01
allowlists: { domains: ["docs.example.com"], paths: [] }
scoring: {}                      # optional weight overrides (§9)
trust:                           # the roster — same file, no --trust-store flag to confuse
  include: []                    # optional: pull in a shared roster file/URL (hash-pinned)
  keys:
    - keyid: author-2026
      algorithm: ed25519
      public_key: "base64…"
      identity: "oidc:author@example.com"
  pack_keys: []                  # keys trusted to sign rule-packs (§8.2)
  revoked: []
```

### 10.5 Exit codes ↔ verdict

| Code | Meaning |
|---|---|
| `0` | `pass` — and `warn` by default (`--strict-warn` maps warn→1 for gates that want it) |
| `1` | `fail` (findings at/above threshold) |
| `2` | **Verification failure**: invalid signature, Merkle mismatch, revoked/expired key, or attestation absent while `policy.attestation.required: true`. Distinct from `1` so CI can distinguish "risky content" from "broken provenance". |
| `3` | Usage/config error (bad flags, unloadable policy, rejected rule-pack) |
| `4` | Internal error |

### 10.6 Output & DX conventions (OWASP best-practices alignment)
- Human `text`: verdict + risk score first line; findings as `file:line  RULE  severity  title`; `-v` adds rationale + fix (actionable remediation, per OWASP guidance).
- Exploration is non-blocking: plain `scan` prints all findings; gating is explicit via `--fail-on`/CI.
- Version tracking: every output embeds binary + rule-pack versions (OWASP: "version tracking of scanner and rule updates").

### 10.7 Corpus quarantine
`corpus pull` writes to `~/.cache/skill-guard/corpus/<name>.quarantine/`: samples stored inside a single zip with extension `.sgquar` (not extracted), plus `DO-NOT-LOAD.md` marker. Scans read members through the zip reader — live `SKILL.md` files never sit on disk where an agent's skill discovery or a backup/indexer could pick them up. Loud red warning on pull.

---

## 11. Embedding surfaces

### 11.1 Library API (Go, canonical)

```go
package skillguard

func LoadBundle(ctx context.Context, src Source) (*Bundle, error)

type Scanner struct{ /* rulepacks, engines, policy */ }
func NewScanner(opts ...Option) (*Scanner, error)
func (s *Scanner) Scan(ctx context.Context, b *Bundle) (*Report, error)

type Report struct {
    Findings    []Finding
    Waived      []Finding
    Verdict     Verdict      // marshals to "pass"|"warn"|"fail"
    RiskScore   int
    MaxSeverity Severity
    Card        *SkillCard
}

func Sign(ctx context.Context, b *Bundle, s Signer, opts ...SignOption) (*Envelope, error) // runs scan unless WithoutScan()
func Verify(ctx context.Context, b *Bundle, env *Envelope, tr TrustRoster) (*VerifyResult, error)

// One-shot: load + scan + verify + policy. The agent-loop entrypoint.
func Guard(ctx context.Context, src Source, opts ...Option) (*Report, error)

func WithRulePacks(refs ...string) Option
func WithEngines(names ...string) Option
func WithPolicy(p Policy) Option           // policy carries the trust roster (§10.4)
func WithVerdictCache(c Cache) Option      // merkle_root-keyed (§3.5)
```

Extension interfaces: `Engine`, `Signer` (§7.4), `TrustRoster` (§7.4), `Provider` (LLM backend) — all pluggable without forking.

### 11.2 Agent SDK integration (illustrative — wiring points are SDK-specific)

> Agent SDKs do not (as of this writing) expose an official "before skill load" callback; the honest v1 mechanisms are the three below. If/when SDKs add loader hooks, the same `guard()` call drops in.

**(a) Staging-directory filter (works with every SDK today, including Anthropic's Agent SDK):** guard skills *before* the session sees them —

```python
from skillguard import guard        # PyPI wheel (FFI) or daemon client — same API
import shutil, pathlib

def stage_safe_skills(src: pathlib.Path, dst: pathlib.Path, policy: str) -> None:
    dst.mkdir(exist_ok=True)
    for skill_dir in src.iterdir():
        r = guard(skill_dir, policy=policy)          # verdict cached by merkle_root
        if r.verdict == "fail":
            log.warning("skill-guard blocked %s: %s", skill_dir.name, r.findings[:3])
            continue
        shutil.copytree(skill_dir, dst / skill_dir.name, dirs_exist_ok=True)

stage_safe_skills(Path("skills-inbox"), Path("skills"), "org.skillguard.yaml")
# then point the agent/SDK at "skills" as its skills directory
```

**(b) Harness hook (e.g., Claude Code `PreToolUse`/session-start hook):** shell out to `skill-guard guard "$SKILL_DIR" --format json`; block on exit code 1/2.

**(c) Custom loader wrap:** runtimes that own their skill loader call `Guard()` inline (TypeScript shown):

```ts
import { guard } from "@skillguard/node";
const r = await guard(skillPath, { policy: "org.skillguard.yaml" });
if (r.verdict === "fail") { audit.block(skillPath, r); return; }
loadSkill(skillPath);
```

**Rug-pull protection in all three:** the verdict cache is keyed by `merkle_root` (§3.5); any content change forces re-guard, satisfying AST07 continuously rather than only at install.

### 11.3 Daemon (`skill-guard serve`) — language-agnostic, secure by default

- **gRPC** (`proto/skillguard.proto`): `Scan`, `Sign`, `Verify`, `Card`, `Guard`.
- **JSON-RPC over stdio** (`serve --stdio`): MCP-style framing, zero FFI for any host that can spawn a subprocess.
- **Binding policy (we pass our own SG-NET-006):** default transport is a **Unix domain socket** (0600) on macOS/Linux and a named pipe on Windows. TCP requires explicit `--listen 127.0.0.1:PORT` and generates a bearer token (`--token-file`); non-loopback binds additionally require `--allow-remote` **and** TLS flags. No unauthenticated network surface, ever.

### 11.4 Multi-language strategy

| Tier | Mechanism | Languages | Notes |
|---|---|---|---|
| **A. Native** | Go module `skillguard` | Go | Canonical, in-process. |
| **B. FFI over C-ABI** | cgo `libskillguard` + idiomatic wrappers | **Python** (cffi wheel: manylinux/macOS/Windows), **Node** (napi-rs; WASM build for verify-only edge), **Rust** (bindgen crate) | One audited core; wrappers add types + the guard helper. |
| **C. Daemon/RPC** | §11.3 | Any (Java, C#, Ruby, PHP, shell…) | No native code; process isolation is a security plus; recommended default for SDK integrations. |

Rationale: duplicating rule evaluation per language multiplies attack surface and drift; one audited Go core with thin bindings is the trust-correct split. **Verify-only** is additionally specified for pure per-language reimplementation (§7 is self-contained) so load-time verification can be dependency-free where FFI is unacceptable.

Packaging: GoReleaser (CLI + shared libs, linux/macos/windows × amd64/arm64), PyPI `skill-guard`, npm `@skillguard/node`, crates.io `skillguard`, GitHub Action `skill-guard/action@v1`, pre-commit hook repo.

---

## 12. Performance, safety & determinism

- **Inert parsing:** nothing in a bundle is executed on the static path; safe YAML; zip-slip/symlink-guarded, size/depth-capped extraction.
- **RE2 only** (no backtracking ReDoS from hostile packs or inputs).
- **Bounded:** per-file size/time limits; worker pool; deterministic ordering.
- **Reproducible:** default-engine scan + card **body** + Merkle are byte-reproducible given pinned rule-pack versions and policy (`card.policy_digest` + `card.rulepacks[]` make the inputs auditable); timestamps live only in the envelope (§9).
- **Secret hygiene:** matched secrets redacted in every output (text/JSON/SARIF/card) except behind `--show-secrets`.
- **Fail-closed:** unknown engine, unsigned auto-discovered pack, unverifiable built-in pack, or required-but-absent attestation ⇒ warning/skip/error per §8.2/§10.5 — never silent.
- **Guard latency budget:** ≤150 ms cold / ≤5 ms cached per skill (§3.5), so pre-load gating is viable inside agent startup.

---

## 13. Testing strategy

- **Unit:** parser (malformed/hostile front-matter), every matcher primitive, SGMT-1 vectors (published test vectors in `docs/sgmt1-vectors.json` so third-party implementations can conform), DSSE round-trip, USF field emit/strip/verify round-trip, roster & revocation, verdict/exit-code mapping.
- **Rule regression:** golden findings over `testdata/`; benign corpus mirrored from `anthropics/skills` guards the false-positive rate.
- **Corpus (opt-in, nightly):** `corpus pull toxicskills` (quarantined) measures true-positive rate over time; never in the repo.
- **Fuzzing:** `go test -fuzz` on front-matter parser, archive extractor, DSSE/USF parsers.
- **Interop:** SARIF schema validation; SkillSpector + mcp-scan SARIF merge fixtures (§3.6 join/partition conventions).
- **Cross-language:** Python/Node/Rust wrappers + daemon must return findings byte-identical to the Go core on shared fixtures; verify-only reimplementation conformance via SGMT-1 vectors.
- **Self-test:** the repo's own examples and the daemon config pass `skill-guard scan` (dogfood; guards §11.3's promise).

---

## 14. Milestones (research LOE: medium — 4–8 weeks to strong v1)

1. **M1 — Core scan (wk 1–2):** `skill` parser, rule loader + `static` engine (T0/T1 with confidence math §1.2 of `rule-verification.md`), SG-INJ/MEM/ANTI/STEER + NET + EXE/ROGUE + MTA/TRIG + SEC/AS + REF + DEP packs, text+json reports, CLI `scan`, TP/FP fixtures, verdict model (§10.3).
2. **M2 — Provenance (wk 2–4):** SGMT-1 + vectors, DSSE sign/verify, USF fields (§7.5), `keygen`/`trust`, SG-PRV rules, exit-code 2 path, in-toto exporter.
3. **M3 — Cards, secrets, SARIF, policy (wk 4–5):** `secret` engine (SG-SEC-002), AST-based SG-EXE-001 + SG-TAINT-\* correlation engine, skill-card (card/envelope split), risk score, SARIF + `report merge`, policy/waivers + per-rule FP-ceiling demotion, GitHub Action + pre-commit, `guard` CLI.
4. **M4 — Embedding (wk 5–7):** C-ABI, Python + Node wrappers, daemon (UDS/gRPC/stdio), verdict cache, SDK staging-filter examples (Py + TS), audit JSONL.
5. **M5 — Advanced + hardening (wk 7–8):** opt-in `dynamic`/`llm`/`SG-YARA-*` engines (T3 escalation §6 of `rule-verification.md`), KMS/Sigstore signers, SG-DEP-003 OSV/CVE pack, fuzzing, docs, Rust binding, release.

**Post-v1 pivots (tracked):** AAIF/OWASP official signing procedure ships → add `--format aaif` emitter (additive, §7.6). OWASP publishes `@owasp/ast10-scanner` or a normative rule catalog → map/merge rule IDs.

---

## 15. Resolved decisions & remaining open questions

**Resolved in this revision (were open in v1):**
- Signature payload: DSSE/PAE — no JSON canonicalization dependence (§7.3).
- Merkle: full SGMT-1 spec incl. domain separation, path normalization, `.skillsig` exclusion, odd-node rule, test vectors (§7.1).
- sign↔scan ordering: sign auto-scans; `--no-scan` ⇒ `scan: null` + SG-PRV-006; signing failing skills allowed and recorded (§3.2, §7.2).
- Rule-pack trust: four-source model (§8.2).
- Verdict: `pass|warn|fail` lowercase everywhere; `warn` defined; `--strict-warn` (§10.3, §10.5).
- Policy vs trust: one file, `trust:` section (§10.4).
- Determinism vs timestamps: card/envelope split (§9).
- `risk_tier` declaration: optional `metadata.skillguard.risk_tier`; SG-MTA-006 inactive when absent (§5.5).
- USF in-manifest signing semantics: normalized-SKILL.md rule (§7.5).
- Daemon security, corpus quarantine, stdin semantics, waived counts, `Signer` context, `platforms[]`.

**Still open (decide before the affected milestone):**
1. **Default `fail_on` for `Guard()` in agent loops** — recommend `high` (same as CLI default) — confirm before M4.
2. **Encrypted keyfile format** — age vs. NaCl secretbox + scrypt — before M2.
3. **Risk-score weight freeze** — the §9 defaults ship as v1-frozen unless tuning against the ToxicSkills corpus (nightly job) shows gross miscalibration — before M3.
4. **Transparency log** — client interface in v1, Rekor as interim backend; hosted skill-log out of scope until an ecosystem log exists.
