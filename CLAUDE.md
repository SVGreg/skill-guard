# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`skill-guard` scans, signs, and verifies Agent Skills (`SKILL.md` bundles) against the
**OWASP Agentic Skills Top 10** (`AST01`–`AST10`). It ships as a CLI and as a reusable Go
library. Nothing in a scanned skill is ever executed — a bundle is parsed into an inert
model and matched against static rules. Requires **Go 1.26+**; deps are only `cobra` and
`yaml.v3`, everything else stdlib.

## Commands

```sh
go build -o skill-guard ./cmd/skill-guard   # build the binary
go build ./...                              # build everything
go test ./...                               # full test suite
go test ./pkg/scan/ -run TestScan -v        # single package / single test
gofmt -l .                                  # formatting check (must be empty)
go vet ./...                                # static checks

# end-to-end smoke test against fixtures (also the exit-code contract)
go run ./cmd/skill-guard scan testdata/malicious   # verdict: fail, exit 1
go run ./cmd/skill-guard scan testdata/benign      # verdict: pass, exit 0
```

Exit codes are part of the contract and are asserted in the smoke test: `0` ok · `1` scan
verdict fail · `2` verification failed (bad signature / tampered content) · `3` usage error
· `4` internal error. They are produced via `exitErr{code,msg}` in `cmd/skill-guard/main.go` —
return one from a command rather than calling `os.Exit` directly.

> `testdata/malicious/setup.sh` is an exfiltration/injection corpus used **only** as scanner
> input. Never run it.

## Architecture

The CLI (`cmd/skill-guard`) is a thin cobra wrapper; all logic lives in `pkg/*`. Data flows
in one direction through the scan pipeline:

```
skill.LoadBundle(path)      →  parse SKILL.md front-matter + body + scripts/configs into an inert Bundle
rules.Builtin()             →  load + compile embedded YAML rule packs
scan.New(rules, policy)     →  evaluate every rule × every target → dedup → verdict, risk score, skill-card
report.*                    →  render text / json / skill-card
```

Signing/verifying is a parallel flow: `attest` computes an SGMT-1 Merkle root over the bundle
and writes a detached DSSE Ed25519 attestation (`SKILL.md.skillsig`); `verify` recomputes the
root, checks the signature, and consults the policy's trust roster.

Package responsibilities:

| Package | Responsibility |
|---------|----------------|
| `pkg/skill` | parse a `SKILL.md` bundle into an inert model (nothing executed); file walk + language detection |
| `pkg/rules` | rule-pack schema, YAML loader, matcher primitives, confidence/context math |
| `pkg/scan` | orchestrate rules → findings, dedup, waivers, verdict, risk score, skill-card |
| `pkg/policy` | `.skillguard.yaml` model, thresholds, waivers, allowlists, trust roster |
| `pkg/attest` | SGMT-1 Merkle root, DSSE signing, USF fields, Ed25519 keygen |
| `pkg/verify` | attestation verification, Merkle integrity, trust → `SG-PRV-*` findings |
| `pkg/report` | text / JSON / skill-card formatters |
| `pkg/model` | shared core types: `Severity`, `Verdict`, `Finding`, `Counts` |

### Rules are data, not code

Built-in rule packs are **YAML in `pkg/rules/packs/*.yaml`**, compiled into the binary via
`//go:embed` (`pkg/rules/builtin.go`). Adding or tuning a detection is a YAML edit, not a code
change. A rule's `match` is a tree of composite (`any`/`all`/`not`) and leaf primitives (regex,
substring, unicode-category, bidi-control, tag-block, url-host). The regex engine is Go's RE2 —
**no lookaround or backreferences** (`(?<`, `(?=`, `(?!`); they won't compile. External packs
load at runtime via `--rulepack` (repeatable).

Packs map to OWASP IDs: `core-injection`, `core-network`, `core-exec`, `core-secret`,
`core-metadata`, `core-supply` (AST02 supply-chain). Every finding carries `ast` ids resolved
through an `ast_references` map so tooling never hard-codes the taxonomy.

### Confidence, context modifiers, verdict, risk

Not every pattern hit becomes a finding. Each candidate starts at the rule's base confidence,
then **context modifiers** adjust it (`pkg/rules/rules.go`): matches inside fenced/indented code
blocks or near documentary words ("example", "e.g.", "do not") are down-weighted (−0.4) to cut
false positives; front-matter/body and tool-description matches are up-weighted. A candidate must
clear `EmitThreshold` (0.5) to emit. *Structural* leaves (bidi/unicode/tag/url-host) are exempt
from the documentary penalty — an invisible char in "documentation" is still an invisible char.

- **Risk score** = Σ (base points per severity × confidence), capped at 100; tiers L0–L3
  (`riskScore`/`tier` in `pkg/scan/scan.go`).
- **Verdict** = pass/warn/fail by comparing max finding severity to the policy's `fail_on`/`warn_on`.
- Findings are deduped by `file|line|rule` keeping the highest-confidence hit.

### Line-offset mapping (a subtle invariant)

The manifest front-matter and body are sub-spans of `SKILL.md`, so a rule's target-local line
number is **not** the true file line. `pkg/skill` records a `LineOffset`/`BodyLineOffset` per
target and `scan.Scan` adds it back (`f.StartLine += t.lineOffset`) so findings report true
`SKILL.md` line numbers. Preserve this whenever you touch parsing or target assembly.

### Trust model (important, and deliberate)

Trust is **local and decentralized** — there is no key server or identity authority. The
`--identity` passed to `sign` is a self-asserted label. A signature only "verifies" when the
consumer has added the signing key to `trust.keys` in *their* `.skillguard.yaml`. `verify`
reports states as `SG-PRV-*` findings (unverified / invalid / revoked / merkle-mismatch). See
the README's "Publisher identity & trust" section — don't reintroduce assumptions of a global
authority.

## Evaluation methodology (`evaluation/`)

`evaluation/` is a reproducible quality harness that runs `skill-guard scan` over a corpus of
**real Agent Skills** and rolls the results into stats + human reports. It uses only the built-in
rulepacks with **no policy/waivers**, so results reflect out-of-the-box behavior.

**Corpus** (each subfolder is one real skill bundle, provenance in its `_manifest.json`):

| Folder | Source | Count |
|--------|--------|------:|
| `clawhub/` | Top skills #1–200 by downloads from the ClawHub registry | 200 |
| `anthropic/` | Example skills from `github.com/anthropics/skills` | 17 |

**Pipeline** (`evaluation/scripts/`):

1. `fetch_clawhub.py` — pull top-N skills by download count from `clawhub.ai` (env: `WANT`,
   `OUTDIR`, `SKIP_DIRS`); only bundles containing a `SKILL.md` are kept.
2. `run_scans.sh [PARALLELISM]` — discover every dir containing a `SKILL.md` and scan it in
   parallel to `reports/<RAW_DIR>/<source>__<slug>.json`, each annotated with `_source`,
   `_slug`, `_exit`, `_path` (env: `CORPUS_DIRS`, `RAW_DIR`).
3. `aggregate.py` — roll raw JSON into `stats.json` + `REPORT.md` (env: `RAW_DIR`,
   `REPORT_NAME`, `STATS_NAME`, `REPORT_TITLE`).

The env vars let one script set produce multiple scoped reports (e.g. the standalone
`clawhub_more` run reuses the same scripts with `CORPUS_DIRS`/`RAW_DIR` overrides).

**Reports** (`evaluation/reports/`): `REPORT.md` (clawhub + anthropic), `REPORT_clawhub_more.md`
(the 100 new skills), and `CROSS_VERIFICATION.md` — a per-finding false-positive audit. The two
`REPORT*.md` reflect the **tuned** ruleset after the FP fixes from `CROSS_VERIFICATION.md`
(289 → 73 findings, no detection loss); the audit records the before/after. When you change a
rule pack, regenerate the affected report and sanity-check against the cross-verification audit
so a "fix" doesn't silently drop true positives. See `evaluation/README.md` for the full
reproduce recipe.

Interpretation caveat baked into the design: static analysis flags **capability and pattern, not
confirmed intent**. A `pass` is not a safety guarantee; a `fail` is an invitation to review.

## Reference docs

- `docs/skill-guard-design.md` — full design + roadmap; source code comments cite its sections (`design §X`).
- `docs/rule-verification.md` — the detection approach and confidence math behind each rule.
- `PROGRESS.md` — implementation status/handoff; M1 (scan) + M2 (sign/verify) are done.
