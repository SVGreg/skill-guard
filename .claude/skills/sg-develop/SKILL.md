---
name: sg-develop
description: Run one skill-guard development cycle — reconcile the plan with merged PRs, pick the next ready task from docs/v1-dev-plan.md, implement it end-to-end with tests and docs, and open one PR. Progress is tracked in the plan file so consecutive sessions resume without context. Use when asked to continue development, implement the next roadmap task, work on a milestone, or when the development loop fires on a schedule.
---

# Run one development cycle

Goal: move `docs/v1-dev-plan.md` forward by **exactly one task**, in **exactly one PR**, leaving
`main` green and the plan file an accurate picture of where the work stands. This is the executor
half of the pair — `/sg-plan` writes the plan, this skill burns it down.

Wire it up with:

```
/loop 6h /sg-develop
```

Invocation forms: `/sg-develop` (next ready task) · `/sg-develop M3-04` (that task specifically).

## Guardrails

All `sg-maintain` global guardrails apply — one activity per cycle, one PR per cycle, never
self-merge a code PR, never execute scanned or generated attack content, preflight before every PR,
start from fresh `main`. Plus:

- **One task per cycle.** A deep plan is answered with more cycles, never a bigger cycle. If the
  task turns out to be two tasks, implement the first and file the second as a new plan row.
- **Never plan here.** If the milestone has no expanded cards, stop and hand off to `/sg-plan`
  (§2). Do not invent tasks not in the plan; do not reorder milestones.
- **Contracts are frozen.** `scan`/`sign`/`verify` CLI surface, JSON shape, and exit codes are
  additive-only until v1.0. A breaking change needs a documented migration and the owner's call —
  raise it in the PR rather than shipping it.
- **Label.** This skill's PRs extend guardrail 4a's type-label set with `develop`.
  Create it once: `gh label create develop -c 0e8a16 -d "roadmap implementation" --force`.

## 0. Sync and reconcile the plan

```sh
git checkout main && git pull --ff-only
```

Read `docs/v1-dev-plan.md`. Before selecting anything, **reconcile status with reality** — this is
what makes the tracker survive across sessions:

1. For every row marked `in-progress` with a PR link: `gh pr view <n> --json state,mergedAt`.
   Merged → set the row to `done`. Closed unmerged → back to `todo` with a change-log line.
2. For every `in-progress` row **without** a PR: check for an existing branch
   (`git branch -a | grep <TASK-ID>`) — an interrupted cycle. Resume it (§3) rather than starting
   something new.
3. If a row claims `todo` but the functionality demonstrably already exists in the repo, mark it
   `done` with a change-log line instead of re-implementing it.

Reconciliation edits ride along in this cycle's PR. If reconciliation is the *only* thing that
changed and no task is startable, ship it as a docs-only PR and stop.

## 1. Load cycle state

State lives in `.claude/development/` (per-machine, git-ignored — create on first run):

- `.claude/development/state.json`:
  ```json
  { "cycle": 0, "last_task": "", "consecutive_noops": 0 }
  ```
- `.claude/development/log.md` — append-only human log, newest last.

The **plan file is the source of truth** for task status; `state.json` only records cadence.

## 2. Select exactly one task

In order:

1. A task the caller named explicitly, if it is `todo` or resumable.
2. A resumable `in-progress` task from §0.2.
3. Otherwise the **first `todo` task, in plan order** (milestone order, then table order) whose
   `Deps` are all `done`.

Skip `blocked`, `owner`, and `dropped` rows — never work them, but **report them** at the end so
the owner sees what is waiting on them.

**Hand off instead of guessing** when: the current milestone is titles-only, or every remaining
`todo` is dependency-blocked, or the next task's card has no executable acceptance check. Say so,
run nothing else, and tell the user to run `/sg-plan <milestone>`. A clean hand-off is a good
cycle; bump `consecutive_noops` and log it.

Mark the chosen row `in-progress` as you start, so a concurrent cycle does not grab it.

## 3. Implement it

- Re-read the task card **and** the source section of `docs/v1-dev-roadmap.md` it came from, plus
  the design authority for the area: `docs/skill-guard-design.md` for architecture,
  `docs/rule-verification.md` for what an `SG-` id means, `CLAUDE.md` for invariants.
- **Match the surrounding code.** Package responsibilities in `CLAUDE.md` are the map: parsing in
  `pkg/skill`, matching in `pkg/rules`, orchestration in `pkg/scan`, output in `pkg/report`,
  signing in `pkg/attest`/`pkg/verify`. The CLI stays a thin cobra wrapper returning
  `exitErr{code,msg}` — never `os.Exit`.
- **Preserve the invariants** the task touches: the line-offset mapping (findings report true
  `SKILL.md` line numbers), `refs` as a sub-kind of `body`, no code execution anywhere in the scan
  path, no hard-coded vendor root of trust, `ast_references` carried through every output format.
- **Detections are data.** Anything expressible as a rule-pack YAML edit does not become Go code;
  bump the pack's `version:` in the same commit.
- **Tests with the change, not after it.** Table tests in the owning package; golden files where
  the deliverable is an output format; a fixture in `testdata/` where the deliverable is a
  detection. Attack strings in fixtures are inert test data — never run them.
- **Offline path in the same task** for anything that introduces a network dependency, and keep
  heavy dependencies behind a build tag or an isolated package so the default binary stays lean.
- **Docs in the same PR** — README section, `docs/` page, or both, per the task card.

If the task proves materially harder or different than its card, do not silently redefine it:
implement the part that is right, and amend the card (or add a follow-up row) in the same PR with a
change-log line saying what changed and why.

## 4. Verify

Standard preflight is `sg-maintain` §Ship it step 1: `gofmt -l .` empty · `go vet ./...` ·
`go test ./...` · exit-code smoke (`scan testdata/malicious` → 1, `scan testdata/benign` → 0) ·
`scan` any skill bundle you touched · pack `version:` bumped if you edited a pack.

Beyond it, this cycle owes:

1. **The task card's acceptance check, run verbatim**, with its output pasted into the PR body.
2. The cross-cutting checklist in `docs/v1-dev-plan.md §2`, ticked honestly.
3. If the change can move findings — any rule pack, matcher, scoring, or target change —
   regenerate evaluation and confirm no unexplained movement in the corpus counts:
   `go build -o skill-guard ./cmd/skill-guard && evaluation/scripts/run_scans.sh && python3 evaluation/scripts/aggregate.py`
   — **mind the parallelism cap in `CLAUDE.md`**; never pass more than the machine's core count.
4. If the change touches performance-sensitive paths, confirm the budget: `scan` well under a
   second on a typical bundle, cached `verify` in single-digit ms.

## 5. Update the tracker

In the same commit as the code:

- Set the task's row to `in-progress` and (after the PR exists) fill its **PR** column — a short
  follow-up commit on the same branch, `docs(plan): link <TASK-ID> to #<n>`, is the normal way.
  The row flips to `done` at the *next* cycle's reconciliation, when the PR is actually merged.
- Append one line to the plan's **Change log** if the card itself changed.
- Append to `.claude/development/log.md`:
  ```
  ## cycle <N> — <ISO timestamp>
  - task: <TASK-ID> — <title>
  - result: <PR #, or "hand-off: <reason>", or "no-op: <reason>">
  - notes: <what the next cycle should know — surprises, follow-ups filed, owner-blocked rows>
  ```
- Update `state.json`: bump `cycle`, set `last_task`, reset `consecutive_noops` to 0 on real work.

## 6. Ship

Ship per **`sg-maintain` §Ship it**, with:

- **branch** `dev/<TASK-ID>-<slug>` · **label** `develop`
- **paths** the files the task touched, plus `docs/v1-dev-plan.md`
- **commit** conventional, scoped to the change — e.g.
  `feat(report): emit SARIF 2.1.0 from scan (M3-01)`. Put the task ID in the subject so the plan
  and the git history stay linkable.
- **evidence** for the PR body: the task ID and its goal, what was built, the **acceptance check
  command and its output**, the cross-cutting checklist, and any card amendment or follow-up row.
  `Closes #<n>` when the task has a tracking issue.

A task PR touches `pkg/`/`cmd/`/`testdata/`, so it is a **code PR** — leave it open for the owner
(guardrail 4). A docs-only task (a spike like `M4-01`, a docs task, a reconciliation-only cycle) is
merged right away once CI is green.

Then report: the task, the PR link, what the next cycle will pick, and any `blocked`/`owner` rows
the owner needs to clear.

## Notes

- A milestone is complete when every one of its rows is `done`, `dropped`, or `owner` — say so in
  the log and let the next cycle's `/sg-plan` expand the following milestone.
- If a cycle errors out mid-way, log the failure and leave the branch un-PR'd; §0.2 resumes it.
- Skill bundles under `.claude/skills/` are signed: editing one staleness its `.skillsig`, which
  this machine cannot fix. List every touched bundle under a "needs re-signing" line in the PR body
  (guardrail 5) — never keygen or re-sign with a substitute key.
