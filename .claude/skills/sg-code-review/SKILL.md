---
name: sg-code-review
description: Perform a cold code review of one rotating area of the skill-guard codebase — hunt for correctness bugs, security issues, and performance/efficiency problems, then fix what fits in one PR. Use when asked to review the code, audit for bugs, do a security or performance pass, or when the maintenance loop selects code review.
---

# Cold code review of one area

Goal: review one slice of the codebase with fresh eyes across three lenses — **correctness**,
**security**, **performance/efficiency** — and land the fixes that fit in a single focused PR.

## Guardrails

All `sg-maintain` global guardrails apply. If a fix is risky, large, or changes behavior in a way
that needs a decision, **don't force it into this cycle** — file it to `docs/planned-rules.md` or a
GitHub issue and move on. Small, correct, reviewable increments only.

## 1. Pick the area (rotate)

Load state from `.claude/maintenance/state.json` → `review_area_cursor`. Rotate through the areas:

```
 0 pkg/skill        1 pkg/rules       2 pkg/scan        3 pkg/policy
 4 pkg/attest       5 pkg/verify      6 pkg/report      7 cmd/skill-guard
 8 pkg/attest/oms   9 pkg/guard      10 keyless/       11 hooks/
```

Advance to the next area each cycle. A caller may name a specific path instead.

**Slots 8–11 were added after those areas shipped, and had never been reviewed.** Keep this list
current: a rotation that silently omits a package means the newest, least-exercised code — which
here includes signature parsing, certificate handling and the load-time gate — is the code nobody
looks at. When a new top-level package or module appears, add a slot in the same PR.

Two of them need care:

- **`keyless/` is a separate Go module.** Build and test it from its own directory
  (`cd keyless && go vet ./... && go test ./...`); `go test ./...` at the repo root does not
  reach it. Never let its dependency graph leak into the core module — CI asserts this, and
  breaking it defeats the reason the module exists (`keyless/README.md`).
- **`hooks/` is Python**, not Go: review it with `python3 -m unittest discover hooks/tests` and read
  it as a security boundary — it decides whether a skill reaches the model.

## 2. Review across three lenses

Read the area's code closely. Then bring in the repo's own reviewers where they help:

- **Correctness** — run `/code-review` on the working diff or reason directly about the target
  files: edge cases, error handling, the line-offset invariant (`f.StartLine += t.lineOffset` in
  `pkg/scan`), exit-code contract (`exitErr{code,msg}` in `cmd/skill-guard/main.go`), dedup/verdict
  math, RE2 assumptions.
- **Security** — run `/security-review`. This project parses untrusted bundles: check for ReDoS-y
  patterns, unbounded reads, path traversal in the file walk, panics on malformed input, and the
  invariant that **nothing in a scanned bundle is ever executed**.
- **Performance/efficiency** — repeated compilation, quadratic scans over large bundles, needless
  allocations in the per-line hot path, redundant file reads.

Collect concrete findings with `file:line` references and a failure scenario for each.

## 3. Fix what fits

Pick the findings that are clearly correct and self-contained. Apply the fixes. Add or extend a
test that fails before and passes after — especially for correctness/security fixes. Prefer the
smallest change that fixes the root cause; match surrounding style.

Defer the rest: append larger items to `docs/planned-rules.md` (or open a GitHub issue labeled
`maintenance` + the appropriate lens) so nothing is lost.

## 4. Verify

Standard preflight is `sg-maintain` §Ship it step 1. Beyond it: if you changed a rule pack, the
`version:` bump is normally a **patch** for a review fix (`docs/skill-guard-design.md §8.1`), and
you must regenerate evaluation and cross-check the corpus deltas (see `sg-rule-polish` §7).

## 5. Open the PR

Ship per **`sg-maintain` §Ship it**, with:

- **branch** `review/<area>-<slug>` · **label** `code-review` · **paths** `-A`
- **commit** `<fix|perf|refactor>(<area>): <what was wrong and the fix>`
- **evidence** for the body: each finding with its `file:line` and failure scenario, the fix, and
  the regression test that fails before and passes after. Name the deferred findings and where they
  were filed.

Update `state.json` → advance `review_area_cursor` (wrap mod 8). Report the PR link and list any
deferred findings.
