# skill-guard — Quality Evaluation Session

A reproducible security evaluation that runs `skill-guard scan` against a corpus
of **real Agent Skills** and aggregates the results into a stats report.

## Corpus

| Folder | Source | Skills |
|--------|--------|------:|
| `clawhub/` | Top skills #1–200 by download count from the [ClawHub](https://clawhub.ai) registry | 200 |
| `anthropic/` | Example skills from [`github.com/anthropics/skills`](https://github.com/anthropics/skills) | 17 |

The 200 ClawHub skills expand to **223 scanned bundles** — some skills ship
sub-skills that carry their own `SKILL.md`, and each is discovered and scanned
independently.

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
  anthropic/<slug>/        copied skill bundles   (+ _manifest.json)
  scripts/
    fetch_clawhub.py       pull top-N skills by downloads from clawhub.ai
    run_scans.sh           scan every bundle in parallel -> reports/<RAW_DIR>/*.json
    aggregate.py           roll raw JSON up into stats.json + REPORT.md
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
WANT=200 python3 evaluation/scripts/fetch_clawhub.py                      # ClawHub #1–200 -> clawhub/
git clone --depth 1 https://github.com/anthropics/skills /tmp/anthropic-skills
#   then copy /tmp/anthropic-skills/skills/*/  into evaluation/anthropic/

# 3a. combined report (clawhub + anthropic) -> reports/REPORT.md + stats.json
evaluation/scripts/run_scans.sh 8
python3 evaluation/scripts/aggregate.py

# 3b. standalone report over just the ClawHub top 200
CORPUS_DIRS="clawhub" RAW_DIR="raw_clawhub200" evaluation/scripts/run_scans.sh 8
RAW_DIR="raw_clawhub200" REPORT_NAME="REPORT_clawhub200.md" \
  STATS_NAME="stats_clawhub200.json" \
  REPORT_TITLE="skill-guard — ClawHub Top 200 Security Evaluation" \
  python3 evaluation/scripts/aggregate.py
```

> `fetch_clawhub.py` writes only the entries it fetched into `clawhub/_manifest.json`.
> To grow the corpus incrementally without re-downloading, fetch into a temp
> `OUTDIR` with `SKIP_DIRS=clawhub`, then move the new bundles into `clawhub/` and
> merge the manifests.

## Notes

- The scan uses only the built-in rulepacks — no custom policy or waivers — so the
  numbers reflect skill-guard's out-of-the-box behavior.
- Static analysis flags **capability and pattern**, not confirmed intent. A `pass`
  is not a safety guarantee and a `fail` is an invitation to review — see the
  "Methodology & caveats" section of the report.
- Results are a **snapshot**: registry rankings and skill contents change over time.
