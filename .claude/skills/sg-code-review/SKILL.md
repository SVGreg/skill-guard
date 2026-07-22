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

Load state from `.claude/maintenance/state.json` → `review_area_cursor`. Rotate through the packages:

```
0 pkg/skill    1 pkg/rules    2 pkg/scan     3 pkg/policy
4 pkg/attest   5 pkg/verify   6 pkg/report   7 cmd/skill-guard
```

Advance to the next area each cycle. A caller may name a specific path instead.

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

- `gofmt -l .` empty · `go vet ./...` · `go test ./...` green.
- Exit-code smoke: `scan testdata/malicious`→1, `scan testdata/benign`→0.
- Dogfood any skill you touched: `go run ./cmd/skill-guard scan .claude/skills/<name>`.
- If you changed a rule pack, regenerate evaluation and cross-check (see `sg-rule-polish` §6).

## 5. Open the PR

```sh
git checkout -b review/<area>-<slug>
git add -A
git commit -m "<fix|perf|refactor>(<area>): <what was wrong and the fix>"
git push -u origin HEAD
gh pr create --label automated --label maintenance \
  --title "<fix|perf>(<area>): <short>" \
  --body "Automated code-review cycle over <area>. Findings + fixes with regression tests. Deferred items filed to backlog/issues. Bot-generated; needs review."
```

Update `state.json` → advance `review_area_cursor` (wrap mod 8). Report the PR link and list any
deferred findings.
