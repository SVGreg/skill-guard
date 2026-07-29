# skill-guard — Quality Evaluation Session

A reproducible security evaluation that runs `skill-guard scan` against a corpus
of **real Agent Skills** and aggregates the results into a stats report.

## Corpus

Four sources, chosen for complementary coverage — a download-ranked registry, a
GitHub index, org/vendor repos, and Anthropic's examples — so the false-positive
picture reflects many independent authors, not one house style.

| Folder | Source | Skills |
|--------|--------|------:|
| `clawhub/` | Top skills by download count from the [ClawHub](https://clawhub.ai) registry (500 distinct publishers) | 500 |
| `skillsmp/` | GitHub-indexed skills from [SkillsMP](https://skillsmp.com), `sort=recent` for author diversity, ≤5 per repo | ~200 |
| `orgs/` | Organization/vendor repos surfaced by [skills.rest](https://skills.rest) — `trailofbits`, `stripe`, `supabase`, `tinybird` | 111 |
| `anthropic/` | Example skills from [`github.com/anthropics/skills`](https://github.com/anthropics/skills) | 17 |

Each skill can ship sub-skills that carry their own `SKILL.md`; every one is
discovered and scanned independently, so the scanned-bundle count runs a little
above the skill count. These are **real, unlabeled** skills: an excellent
false-positive corpus, but recall/true-positive coverage still relies on the
synthetic `testdata/malicious` fixtures. Registry/GitHub content overlaps across
sources — the fetchers dedup by slug, but a content-hash dedup is worth a pass
before quoting a headline finding rate.

## Reports

| Report | Scope |
|--------|-------|
| [`reports/REPORT.md`](reports/REPORT.md) | combined — `clawhub` (223 bundles) + `anthropic` (17) = 240 |
| [`reports/REPORT_clawhub200.md`](reports/REPORT_clawhub200.md) | standalone — the ClawHub top 200 only (223 bundles) |

Each report has a machine-readable sibling (`reports/stats.json`,
`reports/stats_clawhub200.json`). Each subfolder under a corpus dir is one skill
bundle (a `SKILL.md` plus its scripts/assets), exactly as it ships. Provenance for
every bundle is recorded in the `_manifest.json` in each corpus folder (ClawHub
owner handle + download count; Anthropic source commit).

## Layout

```
evaluation/
  clawhub/<slug>/          fetched skill bundles  (+ _manifest.json)
  skillsmp/<owner__repo__skill>/  GitHub-indexed bundles (+ _manifest.json)
  orgs/<org__repo__skill>/ vendor-repo bundles    (+ _manifest.json)
  anthropic/<slug>/        copied skill bundles   (+ _manifest.json)
  scripts/
    fetch_clawhub.py       pull top-N skills by downloads from clawhub.ai
    fetch_skillsmp.py      pull skills via the SkillsMP API -> GitHub bundles (gh)
    fetch_orgs.sh          clone vendor repos (skills.rest set) -> orgs/
    run_scans.sh           scan every bundle in parallel -> reports/<RAW_DIR>/*.json
    aggregate.py           roll raw JSON up into stats.json + REPORT.md
    rule_findings.py       every corpus hit for one rule, for FP auditing
  reports/
    raw/<source>__<slug>.json           combined-run scan results (one per bundle)
    raw_clawhub200/<source>__<slug>.json standalone clawhub-200 run
    stats.json / stats_clawhub200.json   aggregated statistics
    REPORT.md / REPORT_clawhub200.md     the human-readable evaluation reports
```

## Reproduce

```sh
# 1. build the scanner
go build -o skill-guard ./cmd/skill-guard

# 2. load the corpus
WANT=500 python3 evaluation/scripts/fetch_clawhub.py                      # ClawHub top-500 -> clawhub/
WANT=200 SKIP_DIRS=clawhub,anthropic,orgs \
  python3 evaluation/scripts/fetch_skillsmp.py                            # SkillsMP (recent) -> skillsmp/
evaluation/scripts/fetch_orgs.sh                                         # vendor repos -> orgs/
git clone --depth 1 https://github.com/anthropics/skills /tmp/anthropic-skills
#   then copy /tmp/anthropic-skills/skills/*/  into evaluation/anthropic/

# 3a. combined report (all four sources) -> reports/REPORT.md + stats.json
CORPUS_DIRS="clawhub skillsmp orgs anthropic" evaluation/scripts/run_scans.sh 8
python3 evaluation/scripts/aggregate.py

# 3b. standalone report over just one source (e.g. ClawHub)
CORPUS_DIRS="clawhub" RAW_DIR="raw_clawhub" evaluation/scripts/run_scans.sh 8
RAW_DIR="raw_clawhub" REPORT_NAME="REPORT_clawhub.md" \
  STATS_NAME="stats_clawhub.json" \
  REPORT_TITLE="skill-guard — ClawHub Security Evaluation" \
  python3 evaluation/scripts/aggregate.py

# 3c. audit one rule's precision — every hit it produced, to judge TP vs FP
#     (these are real, unlabeled skills, so each hit is an FP candidate until read)
evaluation/scripts/rule_findings.py SG-INJ-001            # summary + sample
evaluation/scripts/rule_findings.py SG-INJ-001 --all      # every hit
```

> **Growing / consolidating a source.** Each fetcher writes only the entries it
> fetched into its own `_manifest.json`. To grow ClawHub without re-downloading,
> fetch into a temp `OUTDIR` with `SKIP_DIRS=clawhub`, then move the new bundles
> into `clawhub/` and take the **union** of the two manifests — that is how the
> 200→500 expansion was consolidated into the single `clawhub/` folder.
> `fetch_skillsmp.py` dedups via `SKIP_DIRS` and caps `MAX_PER_REPO`;
> `fetch_orgs.sh` slugs each bundle by its repo-relative path so same-named skill
> folders across a repo don't collide.

## Notes

- The scan uses only the built-in rulepacks — no custom policy or waivers — so the
  numbers reflect skill-guard's out-of-the-box behavior.
- Static analysis flags **capability and pattern**, not confirmed intent. A `pass`
  is not a safety guarantee and a `fail` is an invitation to review — see the
  "Methodology & caveats" section of the report.
- Results are a **snapshot**: registry rankings and skill contents change over time.
