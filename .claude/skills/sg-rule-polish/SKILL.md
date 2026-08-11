---
name: sg-rule-polish
description: Polish one existing skill-guard detection rule — pick the least-recently-tuned rule, audit its real false positives against the evaluation corpus, generate realistic real-world attack test cases for its threat class, then widen the match tree where it misses and narrow it where it over-matches. Opens a PR. Use when asked to polish, harden, tune, improve coverage of, or reduce false positives on an existing rule, or when the maintenance loop selects rule polishing.
---

# Polish one detection rule

Goal: improve one existing rule on **both** axes — catch real-world variants it currently misses
(recall), and stop firing on benign content it should never have flagged (precision) — without
losing true positives. One rule, one PR.

Every cycle starts at step 3 — what the rule does to the real corpus today — before touching
anything. A rule can carry false positives from the day it shipped: it was written against synthetic
fixtures, and the corpus has only ever been checked for *regressions*, never audited.

Read `docs/rule-verification.md` for the detection approach and confidence math behind each rule.
(Pack layout and the RE2 constraint are in `CLAUDE.md`.)

## Guardrails

Generated attack payloads are **inert test data only** — never execute them. All the global
guardrails from `sg-maintain` apply.

## 1. Pick the rule

Load state from `.claude/maintenance/state.json` → `rule_last_polished`. List the rule IDs across the packs:

```sh
grep -h 'id: SG-' pkg/rules/packs/*.yaml
```

Choose the rule with the **oldest** (or missing) `rule_last_polished` timestamp. If a caller named
a specific rule, use that instead.

## 2. Understand its current coverage

- Open the rule's YAML block: its `match` tree, `confidence`, `suppress` list, `targets`.
- Read its section in `docs/rule-verification.md` (Signals / FP carve-outs / Fixtures).
- Note what it already matches and, importantly, its documented **false-positive carve-outs** —
  new test cases must respect these, and step 3 will tell you whether they actually hold in the wild.
- Check whether a previous cycle already recorded an FP audit for this rule (the "Corpus precision"
  note step 8 writes). If so, that is your baseline: look for what changed, not the same ground.

## 3. Audit its real false positives on the corpus

The `evaluation/` corpus is **real, unlabeled** skills (current count is reported by
`aggregate.py`). Almost none of them are attacks, so essentially every hit the rule produces there
is a false-positive candidate until you read it.

Make sure the raw reports reflect current `main` (they are git-ignored, so they may be stale or
absent). Regenerate only if needed — a full run takes several minutes:

```sh
go build -o skill-guard ./cmd/skill-guard
CORPUS_DIRS="clawhub anthropic orgs skillsmp" evaluation/scripts/run_scans.sh
python3 evaluation/scripts/aggregate.py
```

Then pull every hit for your rule:

```sh
evaluation/scripts/rule_findings.py <RULE-ID>            # summary + a sample
evaluation/scripts/rule_findings.py <RULE-ID> --all      # every hit, to judge exhaustively
```

Read the output for three things:

- **Repeated excerpts.** The tool tallies them because a repeat is almost always *one* systematic
  cause, not N independent mistakes — fix the cause and the whole cluster goes.
- **Concentration.** 50 hits in 2 bundles is a different problem from 50 hits across 50 authors.
  Heavy concentration in security-tooling skills (denylists, jailbreak catalogs, `safe-exec`-style
  docs) is the known benign-but-flagged class: those files genuinely contain attack strings.
- **Target file type.** Hits on `.md` prose vs `.py`/`.sh` code often need different fixes — the
  confidence modifiers already treat those registers differently (`docs/rule-verification.md §1.2`).

Now judge each hit — **true positive**, **false positive**, or **ambiguous** — and write the tally
into your working notes. Be honest about ambiguity: skill-guard's stated reading is "capability and
pattern, not confirmed intent", so a skill that really does ship a pipe-to-shell installer is a
true positive even if its author meant well. A false positive is a match on something that is *not*
the pattern — a license phrase, a variable name, prose describing the attack rather than
committing it.

If the rule has **zero** corpus hits, say so and move on: there is no precision evidence either way,
and widening in step 6 must then be extra conservative since nothing will catch over-matching.

### Propose the narrowing

For each FP cluster, pick the **narrowest** mechanism that kills it without touching true positives:

| FP shape | Mechanism |
|---|---|
| One recurring benign phrase (an MIT-license clause; a delete scoped to a variable) | `suppress:` regex on that line |
| Match is real code but in the wrong register (prose *about* an attack) | rely on / adjust the documentary modifier; check the target list |
| Leaf is too generic (a bare command name; a vague "applies to everything" phrase) | tighten the regex — require an argument, a flag, a command position |
| Right pattern, wrong file kind | narrow `targets:` |
| Signal is genuinely weak on its own | drop its `confidence` below the 0.5 emit threshold, or pair it in an `all:` composite |

Prefer `suppress` and tighter leaves over lowering severity — severity drives the verdict contract,
and muting a real signal to fix a display problem is the wrong trade. If an FP cannot be fixed
without losing true positives, **say so explicitly and leave it**, with the reasoning in the PR.
A known, documented FP beats a silent recall loss.

## 4. Generate realistic attack cases

Write 5–10 **new** payloads that a real attacker/skill might use for this rule's threat class, as
close to observed real-world threats as possible — paraphrases, spacing/casing variants, and
plausible obfuscations the current pattern may not reach. Draw on:

- the OWASP AST class the rule maps to,
- variants seen in the `evaluation/` corpus scan output,
- public write-ups (via `sg-threat-research` notes if available).

Also include **negative** cases: benign near-misses that must NOT match, mirroring the rule's
carve-outs (e.g. documentation phrasing). This is what keeps polishing from causing false positives.

**Seed the negatives from step 3.** Every false positive you confirmed on the corpus is a
real-world negative case — use the actual excerpt, not an invented paraphrase.

Keep the literal payload strings inside fenced code blocks in your working notes so they stay inert
and don't trip the scanner on this skill itself.

## 5. Add the cases as tests

Two harnesses (see `pkg/rules/rules_test.go` and `pkg/scan/scan_test.go`):

- **Rule-level table test** (fast, isolated) — the model is `TestInjectionOverrideCoversParaphrase`
  in `pkg/rules/rules_test.go`: fetch the rule by ID from `Builtin()`, then a table of
  `{text string; want bool}` cases evaluated with `rule.Evaluate("body", c.text)`. Add a
  `Test<Rule>Cover…` function (or extend the existing one) with your new `{payload, true}` and
  `{near-miss, false}` rows.
- **Fixture pipeline test** (only when target assignment / line mapping matters) — add the snippet
  to `testdata/malicious/SKILL.md` and assert the rule ID appears in the scan findings, following
  `TestMaliciousFails` in `pkg/scan/scan_test.go`.

Confirmed corpus false positives go in as `{excerpt, false}` rows in the same table, so the
recall and precision cases are pinned by one test and can't drift apart.

Run them:

```sh
go test ./pkg/rules/ ./pkg/scan/ -run <YourTest> -v
```

## 6. Tune the match tree — widen where it misses, narrow where it over-matches

If a realistic payload slips through, extend the rule's `match` tree in the pack YAML:

- Add or broaden a `regex`/`substring` leaf, or add an `any`-branch alternative.
- Prefer a **new alternative** over rewriting a working pattern — smaller blast radius.
- Set a per-pattern `confidence` appropriate to how specific the signal is.
- Add a `suppress` entry for any benign phrasing your change now over-matches.
- Keep RE2-compatible (no lookaround). Confirm it compiles: `go test ./pkg/rules/` runs
  `TestBuiltinPacksLoad`, which fails on a bad pattern.
- **Bump the pack's `version:` (line 3) in the same commit**: **minor** if you widened anything
  (new branch/leaf/target, raised severity or confidence), **patch** if the cycle was precision-only
  (`suppress`, tightened regex, lowered confidence). A cycle that does both takes the minor. Levels:
  `docs/skill-guard-design.md §8.1`.

If step 3 found false positives, apply the narrowing you proposed there in the **same** edit, so
the widening and the tightening are measured together rather than one masking the other.

A cycle where the rule already catches everything and the only change is an FP fix is a **complete,
successful polish** — precision work needs no widening to justify it. Equally, if the rule is clean
on both axes, make no change: record the audit result, update `state.json`, and skip the PR. Do not
invent a widening to have something to ship.

Re-run the tests until every `want:true` matches and every `want:false` doesn't.

## 7. Guard against regressions

Standard preflight is `sg-maintain` §Ship it step 1. This cycle owes two things beyond it:

- **If you changed a pack**, re-run the corpus and measure the change on **both** axes. You already
  have the step-3 numbers as your before; save them first so the comparison is real:
  ```sh
  cp evaluation/reports/stats.json /tmp/stats_before.json
  go build -o skill-guard ./cmd/skill-guard
  CORPUS_DIRS="clawhub anthropic orgs skillsmp" evaluation/scripts/run_scans.sh
  python3 evaluation/scripts/aggregate.py
  evaluation/scripts/rule_findings.py <RULE-ID> --all      # what survives
  ```
  Then state, for this rule: hits before → after, which FP clusters are gone, and **name which true
  positives are still caught** — a drop in the count is only good if you can say what left, since a
  "fix" must not silently drop detections. (`evaluation/` is git-ignored; regeneration is a local
  sanity check, not part of the PR.)
- Check the **other** rules' counts too: a shared leaf, a `suppress` line, or a target change can
  move a rule you weren't touching. Any non-zero delta outside your rule is either explained or
  reverted.

## 8. Open the PR

Ship per **`sg-maintain` §Ship it**, with:

- **branch** `polish/<rule-id>-<slug>` · **label** `rule-polish`
- **paths** `pkg/rules/ testdata/ docs/rule-verification.md`
- **commit** `fix(rules): <widen|narrow> <RULE-ID> — <what>`

The PR body must report **both axes with numbers**, since that is the evidence a reviewer needs:

- **Precision:** corpus hits before → after, each FP cluster you removed (with a real excerpt) and
  the mechanism used, plus any FP you deliberately left and why.
- **Recall:** the new real-world payloads now caught, and confirmation that previously-caught true
  positives still are — named, not just counted.
- Note that these are **real, unlabeled** skills, so the FP judgments are your reading of them; a
  reviewer may disagree with a specific call and the PR should make that easy to check.

Also record the audit in `docs/rule-verification.md` under the rule's section — the FP carve-outs
there are what the *next* polish cycle reads in step 2, so an unrecorded audit gets repeated.

Update `state.json` → set `rule_last_polished["<RULE-ID>"]` to now. Report the PR link.

If the audit found the rule clean on both axes, there is no PR: record the result in the cycle log
and `state.json` so the next cycle picks a different rule, and report that outcome instead.
