---
name: sg-rule-implement
description: Implement one planned detection rule from the skill-guard backlog — take the highest-priority planned entry, write it as a pack rule plus tests and docs, verify it, and open a PR. Use when asked to implement a new rule, ship a planned detection, or when the maintenance loop selects rule implementation.
---

# Implement one planned rule

Goal: turn one `planned` entry from `docs/planned-rules.md` into a working, tested detection and a
reviewable PR. One rule, one PR — no Go code change is needed to add a detection.

## Guardrails

All `sg-maintain` global guardrails apply. Attack strings you add to fixtures are inert test data.

## 1. Pick the entry

Read `docs/planned-rules.md`. Choose the highest-priority `planned` row (`P0` before `P1` before
`P2`; break ties by table order). If a caller named a specific `SG-ID`, use that. Set its status to
`in-progress` in the doc as you start (so a concurrent cycle doesn't grab it).

## 2. Design the detection

- Read the entry's threat description and source, plus its section (if any) in
  `docs/rule-verification.md` and `docs/skill-guard-design.md §5`.
- Decide the **layer** (`content` vs `code`), **targets** (`body`/`manifest`/`scripts`/`configs`/`refs`),
  **severity**, base **confidence**, and the **match tree**: composite (`any`/`all`/`not`) over leaf
  primitives (`regex`, `substring`, `unicode_category`, `bidi_control`, `tag_block`, `url_host`).
- Regex is **RE2** — no lookaround/backreferences. Model the shape on an existing rule in the same
  pack. Pick real signals; plan the false-positive `suppress` carve-outs up front.

## 3. Add the rule to a pack

Add the rule block to the pack that matches its family (`core-injection`, `core-network`,
`core-exec`, `core-secret`, `core-metadata`) — or create a new `pkg/rules/packs/<name>.yaml`
(auto-loaded via the `packs/*.yaml` embed glob). Required fields: `id`, `title`, `ast`, `severity`,
`engine: static`, `layer`, `confidence`, `targets`, `match`, `rationale`, `fix`. Add `suppress`
patterns for known benign phrasings.

**Bump the pack's `version:` (line 3) in the same commit** — a new rule id is a **minor** bump
(`1.4.0` → `1.5.0`); a brand-new pack file starts at `1.0.0`. Rules for the other levels:
`docs/skill-guard-design.md §8.1`.

## 4. Test it

- **Rule-level table test** in `pkg/rules/rules_test.go` (model:
  `TestInjectionOverrideCoversParaphrase`): fetch the new rule by ID from `Builtin()`, assert
  `{malicious → true}` and `{benign near-miss → false}` rows via `rule.Evaluate(...)`.
- **Fixture** — add a representative malicious snippet to `testdata/malicious/SKILL.md` and (if it
  should stay clean) a near-miss to `testdata/benign/SKILL.md`; assert in `pkg/scan/scan_test.go`
  as needed. Respect the line-offset invariant — findings report true `SKILL.md` line numbers.

```sh
go test ./pkg/rules/ ./pkg/scan/ -v
```

## 5. Verify end-to-end

Standard preflight is `sg-maintain` §Ship it step 1. Beyond it, this cycle owes one thing:

- Regenerate evaluation and confirm the new rule's corpus hits are ones you can defend, with no
  movement in the other rules' counts (git-ignored, local sanity check):
  `go build -o skill-guard ./cmd/skill-guard && evaluation/scripts/run_scans.sh && python3 evaluation/scripts/aggregate.py`
  — mind the parallelism cap in `CLAUDE.md`.

## 6. Update docs and backlog

- Add the rule's detection notes to `docs/rule-verification.md` (Signals / carve-outs / fixtures).
- Update the AST coverage note in `docs/owasp-ast-taxonomy.md` if this rule changes a row's status.
- In `docs/planned-rules.md`, set the entry's status to `implemented` and add the PR link. **Do not
  delete the row** — the history stays auditable.

## 7. Open the PR

Ship per **`sg-maintain` §Ship it**, with:

- **branch** `rule/<SG-ID>-<slug>` · **label** `rule-implement` (+ `research` when the backlog row
  was filed by `sg-threat-research`)
- **paths** `pkg/rules/ testdata/ docs/`
- **commit** `feat(rules): add <SG-ID> — <threat> (AST0X)`
- **evidence** for the body: what the rule detects and why that shape, the new tests, and the
  corpus result — hits, and a defence of each one, or an explicit "0 hits on the corpus".

**Close the tracking issue.** If the backlog entry came from a GitHub issue, `Closes #<n>` in the
body is **mandatory** — it auto-closes the tracking issue on merge. Report the PR link and mark the
cycle done.
