# SARIF 2.1.0 mapping

How skill-guard concepts land in a SARIF log (`scan --format sarif`), and which
of those choices are contracts a consumer may rely on.

The emitter lives in [`pkg/report/sarif.go`](../pkg/report/sarif.go); the wire
format is pinned by golden files and validated against the vendored official
schema in `pkg/report/testdata/` (offline — the test suite never needs the
network).

---

## Document shape

```
sarifLog
└── runs[0]
    ├── tool.driver         name, version, informationUri, rules[]
    ├── taxonomies[0]       OWASP Agentic Skills Top 10 (AST01–AST10)
    ├── originalUriBaseIds  SRCROOT → the scanned path
    ├── results[]           one per finding, waived ones included but suppressed
    └── properties          verdict, risk_score, risk_tier, counts
```

One run per scan. No timestamps are emitted anywhere: two scans of an unchanged
bundle produce byte-identical logs, so a diff always means a real change.

## Severity → `level`

SARIF has three levels; skill-guard has five severities. The raw value is kept
in `properties.severity` so nothing is lost.

| skill-guard | SARIF `level` |
|---|---|
| `critical` | `error` |
| `high` | `error` |
| `medium` | `warning` |
| `low` | `note` |
| `info` | `note` |

`results[].level` is the severity of **that hit** — after any context demotion.
`rules[].defaultConfiguration.level` is the rule's own severity, undemoted, and
is the worst severity that rule reached in the run. A demoted hit also carries
`properties.demoted_by` and `properties.original_severity`, so a reader sees
the judgment rather than a quietly lower number.

## Findings → `results[]`

| SARIF | Source |
|---|---|
| `ruleId` / `ruleIndex` | `Finding.RuleID`, resolved against the sorted `rules[]` |
| `message.text` | `Finding.Title` |
| `locations[].physicalLocation.artifactLocation.uri` | `Finding.File`, **bundle-relative**, with `uriBaseId: "SRCROOT"` |
| `locations[].physicalLocation.region.startLine` / `endLine` | `Finding.StartLine` / `EndLine` (`endLine` omitted when equal) |
| `properties.severity`, `.confidence`, `.engine`, `.layer`, `.ast` | the finding's own fields |

`rules[]` is built from the findings themselves — they carry title, rationale,
fix and AST ids — so an external `--rulepack` needs no special handling, and the
array is sorted by id and deduplicated.

`rules[].helpUri` points at the OWASP page for the rule's first AST id;
`fullDescription` is the rule's rationale and `help` its suggested fix.

## `partialFingerprints`

Key `skillGuard/v1`, value the first 8 bytes of
`sha256(ruleId | file | whitespace-normalized excerpt)`.

**The line number is deliberately excluded.** Inserting a paragraph above a
finding must not close its alert and open an identical one. Reflowing the
matched text is likewise ignored, since whitespace is normalized out. Two
identical hits in the same file are disambiguated by a deterministic occurrence
counter, so they stay two alerts rather than collapsing into one.

The key is versioned: a change to how the fingerprint is computed will land as
`skillGuard/v2` rather than silently re-opening every existing alert.

## OWASP taxonomy

`runs[].taxonomies[0]` describes all ten risks (`isComprehensive: true`) with a
fixed GUID, populated from `model.ASTAll()` — the single place the catalog is
defined.

- `rules[].relationships[]` → `kinds: ["relevant"]`, targeting the taxa the rule maps to.
- `results[].taxa[]` → the same references, per finding.
- `rules[].properties.tags` → `["security", "AST01", …]`. The `security` tag is
  what makes GitHub treat the alert as a security finding; the ids are there for
  consumers that ignore `taxonomies[]`.

An id outside the catalog (possible via `--rulepack`) stays visible in `tags`
but is not given a taxa reference, so no index ever dangles.

## Waivers → `suppressions`

A finding waived by `.skillguard.yaml` policy is **emitted, not dropped**:

```json
"suppressions": [{ "kind": "external", "justification": "reviewed: internal mirror" }]
```

`external` is SARIF's value for "suppressed outside the tool's own
configuration", which is what a policy waiver is. The justification is the
waiver's `reason`. Run-level `counts` continue to exclude waived findings, so
gating behavior is unchanged — the waiver is visible to review without
re-entering the verdict.

## Run properties

`runs[].properties` carries `verdict` (`pass`/`warn`/`fail`), `risk_score`,
`risk_tier`, and `counts` (waived excluded).

## Exit codes and CI gating

The format never changes the verdict; `--format sarif` exits exactly as `text`
and `json` do.

| Code | Meaning | In CI |
|---|---|---|
| `0` | pass or warn | job proceeds |
| `1` | verdict **fail** | gate the build here |
| `3` | usage error | fix the workflow — not a finding |
| `4` | internal error | fix or report — not a finding |

Because `1` is a *finding* and `3`/`4` are *broken workflows*, treat them
differently: the bundled GitHub Action uploads the SARIF and then fails on `1`,
but fails immediately on `3`/`4` rather than reporting a clean scan. If you wire
it by hand, put `continue-on-error: true` on the scan step, upload, then assert
the outcome — otherwise a failing scan never delivers the findings that explain
the failure.

## Known limitation — artifact URIs

`Finding.File` is relative to the **scanned bundle**, not the repository root, so
a bundle scanned at `./skills/foo` reports `SKILL.md`. The scanned path is
recorded in `originalUriBaseIds.SRCROOT`, which is the SARIF-standard way to
resolve it, but whether GitHub's uploader honours that base is unconfirmed —
tracked as **M3-09** in `docs/v1-dev-plan.md`. Scanning from the repository root
avoids the question entirely.
