---
name: sg-rule-polish
description: Polish one existing skill-guard detection rule — pick the least-recently-tuned rule, generate realistic real-world attack test cases for its threat class, verify the rule catches them, and widen the rule's match tree if it misses. Opens a PR. Use when asked to polish, harden, tune, or improve coverage of an existing rule, or when the maintenance loop selects rule polishing.
---

# Polish one detection rule

Goal: make one existing rule catch real-world variants it currently misses, **without** losing
true positives or adding false positives. One rule, one PR.

Rules are data: `pkg/rules/packs/*.yaml`, compiled via `//go:embed`. Regex is Go **RE2** — no
lookaround/backreferences (`(?<`, `(?=`, `(?!`) — they won't compile. Read `docs/rule-verification.md`
for the detection approach and confidence math behind each rule.

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
  new test cases must respect these.

## 3. Generate realistic attack cases

Write 5–10 **new** payloads that a real attacker/skill might use for this rule's threat class, as
close to observed real-world threats as possible — paraphrases, spacing/casing variants, and
plausible obfuscations the current pattern may not reach. Draw on:

- the OWASP AST class the rule maps to,
- variants seen in the `evaluation/` corpus scan output,
- public write-ups (via `sg-threat-research` notes if available).

Also include **negative** cases: benign near-misses that must NOT match, mirroring the rule's
carve-outs (e.g. documentation phrasing). This is what keeps polishing from causing false positives.

Keep the literal payload strings inside fenced code blocks in your working notes so they stay inert
and don't trip the scanner on this skill itself.

## 4. Add the cases as tests

Two harnesses (see `pkg/rules/rules_test.go` and `pkg/scan/scan_test.go`):

- **Rule-level table test** (fast, isolated) — the model is `TestInjectionOverrideCoversParaphrase`
  in `pkg/rules/rules_test.go`: fetch the rule by ID from `Builtin()`, then a table of
  `{text string; want bool}` cases evaluated with `rule.Evaluate("body", c.text)`. Add a
  `Test<Rule>Cover…` function (or extend the existing one) with your new `{payload, true}` and
  `{near-miss, false}` rows.
- **Fixture pipeline test** (only when target assignment / line mapping matters) — add the snippet
  to `testdata/malicious/SKILL.md` and assert the rule ID appears in the scan findings, following
  `TestMaliciousFails` in `pkg/scan/scan_test.go`.

Run them:

```sh
go test ./pkg/rules/ ./pkg/scan/ -run <YourTest> -v
```

## 5. Widen the rule if it misses

If a realistic payload slips through, extend the rule's `match` tree in the pack YAML:

- Add or broaden a `regex`/`substring` leaf, or add an `any`-branch alternative.
- Prefer a **new alternative** over rewriting a working pattern — smaller blast radius.
- Set a per-pattern `confidence` appropriate to how specific the signal is.
- Add a `suppress` entry for any benign phrasing your change now over-matches.
- Keep RE2-compatible (no lookaround). Confirm it compiles: `go test ./pkg/rules/` runs
  `TestBuiltinPacksLoad`, which fails on a bad pattern.

Re-run the tests until every `want:true` matches and every `want:false` doesn't.

## 6. Guard against regressions

- `go test ./...` — full suite green.
- Exit-code smoke: `go run ./cmd/skill-guard scan testdata/malicious` → exit 1;
  `... scan testdata/benign` → exit 0.
- **If you changed a pack**, regenerate the evaluation and check for lost true positives:
  ```sh
  go build -o skill-guard ./cmd/skill-guard
  evaluation/scripts/run_scans.sh 8 && python3 evaluation/scripts/aggregate.py
  ```
  Compare against `evaluation/reports/CROSS_VERIFICATION.md` — a "fix" must not silently drop
  detections. (Note: `evaluation/` is git-ignored; regeneration is a local sanity check, not part
  of the PR.)
- Dogfood: `go run ./cmd/skill-guard scan .claude/skills/sg-rule-polish` still passes.

## 7. Open the PR

```sh
git checkout -b polish/<rule-id>-<slug>
git add pkg/rules/ testdata/ docs/rule-verification.md
git commit -m "fix(rules): widen <RULE-ID> to cover <what>"
git push -u origin HEAD
gh pr create --label automated --label maintenance \
  --title "fix(rules): polish <RULE-ID> — <short>" \
  --body "Automated rule-polish cycle. New real-world cases + match widening for <RULE-ID>; no lost true positives (cross-verified). Bot-generated; needs review."
```

Update `state.json` → set `rule_last_polished["<RULE-ID>"]` to now. Report the PR link.
