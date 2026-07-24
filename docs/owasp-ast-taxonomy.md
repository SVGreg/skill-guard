# OWASP Agentic Skills Top 10 — Taxonomy & skill-guard Mapping

**Status:** reference. Source of truth for how skill-guard rule IDs map to OWASP
Agentic Skills Top 10 risks (`AST01`–`AST10`).

This document consolidates, per risk: the OWASP definition, what is **in scope**,
where the **boundary** with neighbouring risks lies, the **distinguishing
signal**, and the official **Check / Evidence** items from the OWASP checklist.
It then records the reconciled rule→AST mapping and the principles used to derive
it.

Sources (fetched 2026-07-19):
- Checklist — <https://owasp.org/www-project-agentic-skills-top-10/checklist.html>
- Per-risk detail — `https://owasp.org/www-project-agentic-skills-top-10/astNN.html`

> **Why this matters.** skill-guard is a **static scanner of a skill's own
> bundle** (`SKILL.md` front-matter + body + bundled scripts/configs). The OWASP
> boundaries are precise about *where* a risk lives — in the skill's own content,
> its metadata, an external reference, the registry, the runtime sandbox, or the
> organisation. A finding must be filed under the risk that owns *that location
> and mechanism*, not a superficially-similar neighbour. Several original
> mappings conflated these (e.g. a `rm -rf` tagged `AST04 Insecure Metadata`);
> this document is the correction.

---

## How to read the AST boundaries (cheat-sheet)

The single most useful axis is **where the dangerous thing lives**:

| Where it lives / how it acts | Risk |
|---|---|
| Malice authored into the skill's **own code or `SKILL.md` prose** (reverse shell, credential theft, destructive op, persistence, injected instructions, exfil) | **AST01** Malicious Skills |
| How the skill **entered** — registry/dependency/config-file/account compromise, unpinned/unsigned distribution | **AST02** Supply Chain Compromise |
| Skill **holds or reaches** more capability/credential/file than its stated function needs | **AST03** Over-Privileged Skills |
| Deception or executable payload in the skill's **own metadata/definition files**, acting at **parse/load** (unsafe YAML, steganography, spoofed fields) | **AST04** Insecure Metadata |
| Danger arrives in **external content fetched at runtime** and followed as instructions | **AST05** Untrusted External Instructions |
| The **containment boundary** is missing/bypassable — host-mode, no sandbox, network exposure | **AST06** Weak Isolation |
| The skill's **version has drifted** from its known-good state (unpatched, silent auto-update, rollback, hot-reload) | **AST07** Update Drift |
| The **detection mechanism** itself fails or is evaded (obfuscation, embedded-secret scan gaps, scanner injection) | **AST08** Poor Scanning |
| Absence of **inventory/approval/audit/revocation** around skills | **AST09** No Governance |
| Security metadata **lost when ported** across platforms/registries | **AST10** Cross-Platform Reuse |

Two boundaries do most of the disambiguation work for a static content scanner:

- **AST01 vs AST05** — text that steers the agent is **AST01** when it is authored
  *inside the skill*, **AST05** only when the skill *fetches it from an external
  reference at runtime*. AST05 needs only instruction-following; no code execution.
- **AST01/AST03 vs AST04** — AST04 is **strictly** the metadata/definition layer at
  parse time (unsafe deserialization, steganography, deceptive fields). Runtime
  actions in scripts — eval, `rm -rf`, `sudo`, egress — are **never** AST04.

---

## The ten risks

### AST01 — Malicious Skills · *Critical*

**Definition.** A skill that appears legitimate but carries hidden malicious
payloads or instructions authored with intent — exploiting **both** the code
layer (scripts) **and** the natural-language layer (`SKILL.md` prose).

**In scope.** Credential theft (API keys, SSH, wallets, browser data); reverse
shells and backdoors embedded in skill code; social-engineering instructions in
markdown; typosquatting; ClickFix / fake "setup required" prompts; persistence
via agent identity files (`SOUL.md`, `MEMORY.md`, `AGENTS.md`); memory poisoning;
identity cloning/exfiltration; WebSocket C2; shadow features; `curl` to unknown
endpoints; pipe-to-shell of remote payloads; zero-click exfiltration through a
rendered markdown/HTML image or link whose URL interpolates conversation or
secret data (EchoLeak, CVE-2025-32711); destructive operations authored in
the skill.

**Boundary.** Compromised *delivery* → AST02. Excess *permissions* on an
otherwise-legitimate skill → AST03. Deception at the *metadata* layer → AST04.
Payload in an *external URL* keeping the body clean → AST05. Failure to *detect*
it → AST08.

**Distinguishing signal.** The malicious intent is authored directly into the
skill's own content — its code or its prose.

**Checklist — Check:** verified/trusted source; behavioral (not just pattern)
analysis; signature verification; scripts *and* NL instructions reviewed for
malicious patterns; canary-tested; avoids writing to identity files.
**Evidence:** publisher confirmed / not a typosquat; scan evaluates intent;
valid ed25519 signature + matching `content_hash`; no encoded payloads / no
`curl` to unknown endpoints / no credential access beyond function; dynamic
behavior matches declared; no identity-file writes unless justified.

### AST02 — Supply Chain Compromise · *Critical*

**Definition.** Exploiting the absence of provenance controls in the channels
through which skills are published, distributed, and installed. About **how a
skill (or a nested dependency/config/source) enters** the environment.

**In scope.** Registry flooding; dependency confusion in *nested* deps;
config-file hijacking (hooks, `.claude/settings.json`, env overrides executing on
open); maintainer account takeover; SkillJacking (re-registering deleted
accounts / expired domains); missing signing, transparency logs, pinning,
recursive dependency scanning, revocation.

**Boundary.** The malicious *behavior* once running → AST01. Unpinnable *external
instruction docs* → AST05. Mutable *version updates* → AST07.

**Distinguishing signal.** The problem is the unverified/compromised
*distribution channel*, not what the skill does once running.

**Checklist — Check:** publisher identity vs signing key; version pinned to an
immutable `sha256:`; nested deps pinned; SBOM generated; repo config files gated
as executable code; recursive dependency scan; pre-mutation receipt.
**Evidence:** verified identity (`did:web:`, verified org); no version ranges
(`^`/`~`); locked lockfiles; CycloneDX/SPDX SBOM; config reviewed not
auto-executed; transitive scan; privacy-safe mutation plan.

### AST03 — Over-Privileged Skills · *High*

**Definition.** A skill granted or holding broader permissions than its stated
function requires — either no permission manifest, or blanket acceptance. The
agentic wrinkle: a permission checked at the tool-call level (`SELECT`) can be
prompt-injected into abuse (`DELETE`) because intent isn't checked.

**In scope.** Excessive DB/admin access enabling destructive ops; shared
agent-level API keys instead of per-skill scoped credentials; **reading files or
credentials beyond stated function** (`~/.ssh`, `~/.aws`, `.env`, `**/credentials*`,
`*.wallet`, browser data, cloud-metadata credential endpoints); write access to
agent identity files (elevated-review); over-broad `allowed-tools` / permission
globs / `network: true`; host-mode granting shell+fs+net+cron.

**Boundary.** Malicious *code* → AST01. Deceptive *declaration* of permissions →
AST04. Missing *sandbox* → AST06. Missing *review process* → AST09.

**Distinguishing signal.** The harm is the **breadth of the grant or reach**
itself — the skill touches more than its function needs.

**Checklist — Check:** scoped permission manifest; minimized permissions; no
`shell: true`; file paths scoped (no `**/*`); per-skill scoped credentials;
identity-file writes flagged; network as domain allowlist; no access to
credential stores beyond function.
**Evidence:** enumerated permissions; no access beyond function; `shell: false`;
explicit paths; isolated/rotated credentials; default-deny egress; **no reads to
`~/.ssh/`, `~/.aws/`, `.env`, `**/credentials*`, `*.wallet`, browser data unless
required.**

### AST04 — Insecure Metadata · *High*

**Definition.** The skill's metadata/definition files (`name`, `description`,
`permissions`, `risk_tier`, and their YAML/JSON/Markdown containers) are
attacker-controlled inputs the loader reads with little validation. Two layers: a
**semantic** layer (fields deceive the installer) and a **parsing** layer
(unsafe deserialization executes code *at load*, before the skill runs).

**In scope.** Malicious metadata field values; unsafe YAML/JSON deserialization
(`!!python/object`, `!!python/apply`, `__proto__` prototype pollution);
steganographic injection in metadata/instructions (zero-width Unicode, base64,
ASCII smuggling); brand impersonation; understated permissions; spoofed
`risk_tier`; `requirements.txt`/`package.json`/`pyproject.toml` treated as
untrusted.

**Boundary — the sharp one.** AST04 executes/deceives from the skill's **own
files at parse time**; **AST05** covers instructions **loaded from external
references**. Excessive *actual* permission → AST03. Host-mode amplification →
AST06. Scanner evasion → AST08. **Runtime actions in scripts (eval, `rm`, `sudo`,
egress) are NOT AST04.**

**Distinguishing signal.** The deception or executable payload lives in the
skill's own metadata/definition files and acts during parsing/loading.

**Checklist — Check:** description matches functionality; scanned for ASCII
smuggling / zero-width / base64; secure defaults; validated against a security
schema; `risk_tier` consistent with scope; brand impersonation checked; safe YAML
loaders; parsed in isolation; key allowlist; deserialization at minimum
privilege.
**Evidence:** no hidden capabilities; no steganographic content in `SKILL.md` /
manifest; no default-open permissions; schema validation passed; no unsafe YAML
tags (`!!python/object`, `!!python/apply`); sandboxed deserialization; undeclared
fields rejected.

### AST05 — Untrusted External Instructions · *High*

**Definition.** A skill references external documentation/URLs/remote files **at
runtime** and consumes the fetched text as *instructions* — followed with the
agent's full permissions. That content lives outside the trust boundary: mutable,
unpinnable, poisonable by whoever controls the source.

**In scope.** Runtime fetch of external docs treated as instructions;
mutable/unpinnable references; author rug-pull (edit the doc after review);
reviewer bait-and-switch (clean to scanners, malicious to agents); transitive
reference chains; hosts that could lapse or be taken over.

**Boundary.** Payload in the skill *itself* → AST01. Pinnable *code* dependencies
→ AST02. Requires *code execution* / lives in metadata → AST04. *Version* updates
of the skill → AST07. **Instruction text authored inside `SKILL.md` is AST01, not
AST05** — AST05 requires the instructions to come from an external fetch.

**Distinguishing signal.** The dangerous behavior originates in **mutable
external content the skill fetches and follows** as instructions.

**Checklist — Check:** references external docs/URLs at runtime; each pinned to a
content hash and re-verified; inlined where possible; fetches restricted to a
vetted allowlist; references followed transitively; fleet-wide visibility.
**Evidence:** inventory of every external reference; pin recorded, load refuses
drift; inlined copies preferred; egress allowlist enforced; full reference graph
reviewed.

### AST06 — Weak Isolation · *High*

**Definition.** Skills execute in the host agent's security context — full
filesystem, shell, and network — because sandboxing is unavailable, optional, or
off by default. The **containment boundary itself** is missing or bypassable.

**In scope.** Host-mode execution; no container/seccomp/AppArmor; host
persistence surviving uninstall; unrestricted egress enabling lateral
movement/C2; skill shadowing via hot-reload precedence; locally-bound control
interfaces (WebSocket, `0.0.0.0` binds) reachable by other processes.

**Boundary.** The malicious *payload* → AST01. The permission *grants* → AST03.
Deployment *oversight* → AST09. Isolation is the **enabling condition**, not the
originating risk.

**Distinguishing signal.** The skill runs with host-level reach regardless of
intent or granted permissions; the sandbox is absent or escapable.

**Checklist — Check:** runs in a sandbox not host-mode; filesystem scoped;
network controlled (localhost+auth, not `0.0.0.0`); seccomp/AppArmor applied;
per-skill namespacing; WebSocket rate-limited+authed; hot-reload restricted in
prod. **Evidence:** container isolation confirmed; no out-of-scope access; auth
on control interfaces; profile attached; process isolation; workspace overrides
require confirmation.

### AST07 — Update Drift · *Medium*

**Definition.** Installed skills fall out of sync with known-good versions —
unpatched (known vulns stay open) or blindly auto-updated (upstream change may be
malicious). Root cause: no immutable pinning + no automated update verification.

**In scope.** Patch-lag; malicious auto-updates; rollback/downgrade attacks;
hot-reload abuse (mid-session directory change); fake "patch" versions lacking
cryptographic pinning.

**Boundary.** The malicious *code* → AST01. The broader *supply chain* → AST02.
Forged update *metadata* → AST04. External *reference* changing without a version
bump → AST05. Failure to *re-scan* after update → AST08.

**Distinguishing signal.** The gap is that the skill's **version has drifted**
from its known-good state.

**Checklist — Check:** pinned to immutable `sha256:`; auto-update disabled/gated;
updates signed by original publisher; updates trigger re-scan; hot-reload off in
prod; advisory subscription. **Evidence:** hash recorded not a mutable tag; human
approval before deploy; signature on every update; scan on every version change;
`SkillsWatcher` disabled in prod; CVE alerts configured.

### AST08 — Poor Scanning · *Medium*

**Definition.** Security scanners built for traditional code are ineffective
against skills, which blend natural-language instructions with code and defeat
pattern-matching/regex/signature detection. About the inadequacy of the
**detection mechanism** itself.

**In scope.** Natural-language obfuscation with no code signature; encoding
evasion (base64, zero-width, ASCII smuggling, `.pyc`, archives); context-dependent
malice (safe under test, active in prod); scanner impersonation; prompt injection
against the scanner's own LLM; file-truncation padding; **missing
credential-detection scanning (embedded API keys/tokens/passwords/PII in skill
files).**

**Boundary.** *What* the malicious skill is → AST01. Metadata-specific bypasses →
AST04. External content absent at scan time → AST05. Not re-scanning updates →
AST07.

**Distinguishing signal.** The core problem is that **detection failed or is
evadable** — including a skill shipping secrets that a credential scan should
catch.

**Checklist — Check:** behavioral/semantic analysis; code **and** NL layers
scanned independently; credential detection (Gitleaks/TruffleHog); isolated scan
env; dynamic behavioral testing; skill-based scanners advisory only;
skill-aware scanner before install. **Evidence:** intent-aware scan; separate
code vs `SKILL.md` results; **clean scan for API keys/tokens/passwords/PII**;
tamper-proof scan env; observed-behavior log; no single-scanner reliance;
pre-install report below threshold.

### AST09 — No Governance · *Medium*

**Definition.** Organisations lack the inventories, policies, review processes,
and audit trails to manage skills at scale — a "shadow AI" layer with no SOC
visibility, approval workflow, or revocation. Traditional SAM tools have no
concept of skills.

**In scope.** No centralized inventory; no approval/review workflow; no SOC
visibility; no revocation/deprovisioning; missing agentic-identity controls;
inadequate audit logging; disconnection from CMDB/ITSM/CASB/IAM.

**Boundary.** The malicious skill → AST01; excess permissions → AST03; isolation
failure → AST06; uncontrolled updates → AST07. AST09 is the **absence of
oversight** itself.

**Distinguishing signal.** The finding is about the lack of an inventory,
approval gate, audit trail, or revocation path — not a flaw in the skill's code,
permissions, isolation, or updates.

**Checklist — Check:** in centralized inventory; risk tier assigned; approval
record; invocations logged; review cadence; revocation process; agent identities
as scoped/rotated NHIs. **Evidence:** inventory entry (name/version/hash/date/
installer/scan status); documented tier; approval workflow; detailed logs;
scheduled reassessment; lifecycle-linked removal; NHI registered in IAM.

### AST10 — Cross-Platform Reuse · *Medium*

**Definition.** Skills ported across platforms (OpenClaw → Claude Code → Cursor →
VS Code) without translating security properties. Controls encoded in one
ecosystem's metadata format don't exist in another's and are silently dropped.

**In scope.** Loss of security metadata during porting; inconsistent format
standards; silent dropping of risk indicators; absence of unified cross-ecosystem
governance; cross-registry arbitrage / trust-signal laundering.

**Boundary.** Protocol standardization is **MCP's** concern, not AST10 — "this is
not a protocol problem; it is a behavioral abstraction problem." Malicious
authorship → AST01.

**Distinguishing signal.** The vulnerability arises from a skill **moving between
platforms/registries and losing its security metadata** in translation.

**Checklist — Check:** validated per platform; security properties consistent
across versions; per-target gap assessment; consistent credential handling;
cross-registry threat-intel sharing; uses a Universal Skill Format.
**Evidence:** per-platform test results; no silent property loss; gap analysis;
per-platform credential verification; shared scan/incident reports; normalized
manifest with all security fields.

---

## Reconciliation principles

skill-guard statically inspects a skill's own bundle, so a finding is filed by
**where the pattern lives and how it acts**:

- **P1 — In-skill text that steers the agent → AST01, never AST05.** AST05 is only
  for instructions *fetched from an external reference at runtime*. Imperative
  overrides, jailbreak framing, memory-poisoning prose authored in `SKILL.md` are
  AST01.
- **P2 — Exfil / egress / C2 → AST01** (malicious behavior), not AST05. AST05
  applies only when the network op *fetches external instructions the agent
  follows*.
- **P3 — Runtime execution in scripts (eval, destructive fs, `sudo`, persistence)
  → AST01, never AST04.** AST04 is the metadata/parse layer only.
- **P4 — Deception or unsafe deserialization / steganography in the skill's own
  definition files → AST04.**
- **P5 — Reaching credentials/files/env/metadata endpoints beyond stated function
  → AST03.**
- **P6 — Embedded secrets and scanner-evasion → AST08** (the credential-detection
  and detection-mechanism checks live here).
- **P7 — Reverse shell / bind-all listener → AST01 (backdoor) + AST06 (network
  exposure).**
- **P8 — Provenance / signing / tamper (SG-PRV-\*) → AST01 + AST02** (supply-chain
  trust). Handled by `verify`, not the static packs.

## Reconciled rule → AST mapping (implemented rule packs)

| Rule | Title | Was | Now | Change & rationale |
|---|---|---|---|---|
| `SG-EXE-001` | Dynamic eval / exec | AST01, AST04 | **AST01** | −AST04 (P3: eval in a script is not metadata parsing) |
| `SG-EXE-002` | Destructive filesystem operation | AST04 | **AST01** | AST04→AST01 (P3: `rm -rf` is a malicious action, not metadata) |
| `SG-EXE-003` | Privilege escalation | AST03 | **AST01** | AST03→AST01 (actively acquiring privilege is an attack action, not an over-broad grant) |
| `SG-EXE-004` | Persistence mechanism | AST01 | **AST01** | unchanged |
| `SG-ROGUE-001` | Skill self-modification | AST01 | **AST01** | unchanged (malicious self-modification to evade the reviewed baseline) |
| `SG-INJ-001` | Imperative instruction override | AST01, AST05 | **AST01** | −AST05 (P1: authored in `SKILL.md`, not fetched) |
| `SG-INJ-002` | Hidden or obfuscated instructions | AST04, AST01 | **AST04, AST01** | unchanged (P4: steganography in metadata/instructions is the defining AST04 case) |
| `SG-INJ-004` | Write to agent identity/config file | AST01 | **AST01, AST03** | +AST03 (checklist files identity-file writes under both AST01 and AST03) |
| `SG-ANTI-001` | Anti-refusal / jailbreak framing | AST01, AST05 | **AST01** | −AST05 (P1) |
| `SG-INJ-006` | System-prompt / tool-schema exfiltration | AST01 | **AST01** | unchanged |
| `SG-MTA-001` | Unsafe YAML/deserialization tag | AST04 | **AST04** | unchanged (P4: `!!python/object` at load) |
| `SG-MTA-003` | Over-broad allowed-tools | AST03 | **AST03** | unchanged (over-broad grant) |
| `SG-NET-001` | Egress to suspicious host | AST01, AST05 | **AST01** | −AST05 (P2: exfil/C2, not instruction fetch) |
| `SG-NET-002` | Pipe-to-shell execution | AST01 | **AST01** | unchanged (`curl … \| bash` of remote code) |
| `SG-NET-006` | Listener / reverse-shell idiom | AST06 | **AST01, AST06** | +AST01 primary (P7: backdoor is malicious content; AST06 kept for the network-exposure dimension) |
| `SG-NET-007` | Rendered-image/link data exfiltration | AST01 | **AST01** | unchanged (P2: exfil authored into the skill's own prose; the URL carries the data, so it is not an AST05 instruction fetch) |
| `SG-REF-003` | Runtime instruction fetch (external brain) | AST05 | **AST05, AST01** | +AST01 — the fetched content is followed as instructions, so the injection dimension applies alongside the external-fetch dimension (AST05 primary) |
| `SG-SSRF-001` | Cloud metadata / SSRF endpoint access | AST05 | **AST03, AST01** | AST05→AST03,AST01 (P5: reaching a cloud-credential endpoint beyond scope; not an external-instruction fetch) |
| `SG-SEC-001` | Sensitive-path read | AST03 | **AST03** | unchanged (P5: `~/.ssh`, `~/.aws`, `.env` — the AST03 evidence list) |
| `SG-SEC-002` | Embedded secret | AST03, AST08 | **AST08** | −AST03 (P6: an embedded secret is the AST08 credential-scan check, not access-over-privilege) |
| `SG-SEC-003` | Environment harvesting | AST03 | **AST03** | unchanged (P5: mass env read to harvest credentials) |
| `SG-AS-001` | Agent-config / cross-skill snooping | AST03 | **AST03** | unchanged (P5: reading beyond own scope) |

**Provenance (`verify`, not a static pack):** `SG-PRV-001…006` → **AST01, AST02**
(P8) — signature/trust/tamper failures are supply-chain + malicious-skill risks.

## Coverage: which ASTs a static bundle scan can reach

| AST | Covered by skill-guard `scan`? | Notes |
|---|---|---|
| AST01 Malicious Skills | **Yes** — primary | code + `SKILL.md` prose patterns |
| AST02 Supply Chain | Partial via `sign`/`verify` | provenance/attestation, not the static packs |
| AST03 Over-Privileged | **Yes** | credential/file/env reach, over-broad `allowed-tools` |
| AST04 Insecure Metadata | **Yes** | unsafe YAML, steganography in `SKILL.md`/manifest |
| AST05 Untrusted External Instr. | Partial | `SG-REF-003` (runtime instruction fetch / "external brain") implemented; the reference-inventory (`SG-REF-001`) and unpinned-ref (`SG-REF-002`) rules remain planned |
| AST06 Weak Isolation | Weak/partial | only visible signals (bind-all listeners); the sandbox itself is a runtime property |
| AST07 Update Drift | No (runtime/registry) | addressed by pinning + `verify` re-scan, not static content |
| AST08 Poor Scanning | Partial | embedded-secret detection; skill-guard is itself an AST08 mitigation |
| AST09 No Governance | No | organisational; out of a single-bundle scan's scope |
| AST10 Cross-Platform Reuse | No | multi-registry/platform; out of scope |

A clean `scan` therefore speaks mainly to AST01/AST03/AST04. It is **not** a
statement about AST02/06/07/09/10, which require provenance, runtime, or
organisational controls a static scan cannot observe.
