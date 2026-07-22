# Planned rules backlog

The single actionable backlog of **designed-but-unimplemented** detections. It consolidates the
planned-rule entries that were previously scattered across `docs/skill-guard-design.md §5`,
`docs/rule-verification.md §7`, and `docs/owasp-ast-taxonomy.md`.

- **`sg-threat-research`** appends new gaps here (one row per candidate rule).
- **`sg-rule-implement`** consumes the highest-priority `planned` row, ships it, and flips its
  status to `implemented` (linking the PR).
- **`sg-issue-triage`** appends notable `must-have`/`useful` issues here.

Status values: `planned` · `in-progress` · `implemented` · `wont-do`.
Priority: `P0` (security gap, do next) · `P1` (roadmap-aligned) · `P2` (nice-to-have).

Keep this file the source of truth. When you implement a row, don't delete it — set status to
`implemented` and add the PR link, so the history stays auditable.

## Backlog

| ID | AST | Threat | Priority | Status | Source / notes |
|----|-----|--------|----------|--------|----------------|
| SG-REF-001 | AST05 | Skill body instructs the agent to fetch and follow instructions from an external URL/file (untrusted external instructions). | P0 | planned | design §5, owasp-ast-taxonomy AST05 row (marked "planned") |
| SG-REF-002 | AST05 | Skill references an external ruleset/config the agent is told to obey at runtime. | P1 | planned | rule-verification §7 |
| SG-REF-003 | AST05 | Skill embeds a remote include / `@import`-style directive pulling instructions at use time. | P1 | planned | rule-verification §7 |
| SG-DEP-001 | AST02 | Declares an install step pulling an unpinned dependency (no version/hash). | P0 | planned | design §5 supply-chain; owasp-ast-taxonomy AST02 |
| SG-DEP-002 | AST02 | `pip install`/`npm install`/`curl \| sh` bootstrap in body or scripts. | P0 | planned | design §5 |
| SG-DEP-003 | AST02 | Dependency sourced from a raw git URL / arbitrary archive rather than a registry. | P1 | planned | design §5 |
| SG-DEP-004 | AST02 | Typosquat-shaped package name (near-miss of a popular package). | P2 | planned | design §5 |
| SG-DEP-005 | AST02 | Post-install / lifecycle hook that runs arbitrary code. | P1 | planned | design §5 |
| SG-DEP-006 | AST02 | Fetches a binary/blob and marks it executable. | P1 | planned | design §5 |
| SG-TAINT-001 | AST01 | Data-flow: untrusted input reaches a shell/exec sink. | P1 | planned | design §5 taint family; deferred to M3 |
| SG-TAINT-002 | AST01 | Data-flow: secret/env reaches a network sink (exfil path). | P1 | planned | design §5 |
| SG-TAINT-003 | AST01 | Data-flow: fetched content reaches a file-write sink. | P2 | planned | design §5 |
| SG-TAINT-004 | AST01 | Data-flow: user/agent context reaches an outbound request body. | P2 | planned | design §5 |
| SG-TAINT-005 | AST01 | Data-flow: decoded/deobfuscated blob reaches an exec sink. | P1 | planned | design §5 |
| SG-MEM-001 | AST01/AST03 | Instructs the agent to persist instructions into long-term memory across sessions. | P1 | planned | design §5 memory family |
| SG-MEM-002 | AST01/AST03 | Instructs the agent to silently re-load persisted state that alters future behavior. | P2 | planned | design §5 |
| SG-STEER-001 | AST01 | Steering/priming that reshapes the agent persona toward compliance without an override verb. | P2 | planned | design §5 |
| SG-NET-003 | AST01/AST06 | Connects to a raw IP literal (bypasses host allowlist / DNS review). | P1 | planned | design §5 network |
| SG-NET-004 | AST01 | DNS-exfiltration shaped hostname (data encoded in subdomain labels). | P2 | planned | design §5 |
| SG-NET-005 | AST06 | Opens a reverse shell / bind listener to a remote host. | P0 | planned | design §5 |
| SG-MTA-004 | AST04 | Manifest declares broad filesystem write scope beyond the skill dir. | P1 | planned | design §5 metadata |
| SG-MTA-005 | AST03/AST04 | Manifest requests credentials/env scope unrelated to its stated purpose. | P1 | planned | design §5 |
| SG-MTA-006 | AST04 | Description/trigger mismatch — metadata over-claims to widen activation. | P2 | planned | design §5 |
| SG-INJ-003 | AST01 | Conditional/time-bomb instruction (behaves differently under a hidden trigger). | P1 | planned | design §5 injection |
| SG-INJ-005 | AST01 | Role-confusion: text forged to look like a system/operator turn. | P1 | planned | design §5 |
| SG-TRIG-001 | AST04 | Over-broad activation trigger designed to fire on unrelated tasks. | P2 | planned | design §5 trigger |
| SG-NET-007 | AST01 | Data-exfil via a rendered markdown/HTML image or link whose URL embeds captured/secret/context data to an attacker host the client auto-fetches (zero-click). Complements SG-NET-001, which only fires on a fixed bad-host allowlist — this technique uses any attacker domain. | P0 | planned | Research (OWASP): EchoLeak CVE-2025-32711 (M365 Copilot); embracethered markdown-image exfil |

## SG-LLM-* (opt-in semantic engine — M5, engine not yet built)

Notes accumulated by `sg-llm-polish` for when the T3 semantic engine ships (`docs/rule-verification.md §6`,
`docs/skill-guard-design.md §M5`). Nothing here is a static rule; these guide the eventual prompt.

- **Escalation invariant**: never send raw bundle text to T3; escalate only a redacted, structured
  question. Any T3 finding is tagged `nondeterministic: true`.
- **Prompt-injection safety of the analyzer itself**: scanned skill content is *data to classify*,
  never instructions to the classifier. Collect real hijack attempts found during research as
  regression cases here.
- (Add discovered cases below as research finds them.)
