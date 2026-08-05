# skill-guard — Quality Evaluation Session

A reproducible security evaluation that runs `skill-guard scan` against a corpus
of **real Agent Skills** and aggregates the results into a stats report.

## Corpus

Five sources, chosen for complementary coverage — a download-ranked registry, a
GitHub index, org/vendor repos, Anthropic's examples, and a security-research
sample — so the false-positive picture reflects many independent authors, not one
house style.

| Folder | Source | Skills |
|--------|--------|------:|
| `clawhub/` | Top skills by download count from the [ClawHub](https://clawhub.ai) registry (500 distinct publishers) | 500 |
| `skillsmp/` | GitHub-indexed skills from [SkillsMP](https://skillsmp.com), `sort=recent` for author diversity, ≤5 per repo | ~200 |
| `orgs/` | Organization/vendor repos surfaced by [skills.rest](https://skills.rest) — `trailofbits`, `stripe`, `supabase`, `tinybird` | 111 |
| `anthropic/` | Example skills from [`github.com/anthropics/skills`](https://github.com/anthropics/skills) | 17 |
| `skillject/` | `data/skills_sample` from [SkillJect](https://github.com/jiaxiaojunQAQ/SkillJect), a malicious-skill research framework | 100 |

### About `skillject/`

SkillJect is an agent-security evaluation framework that injects shell payloads
into skill content and measures whether a coding agent executes them. The
`data/skills_sample` bundles it ships are the **carriers**, not the attacks: real,
community-authored skills (71 of the 100 carry an upstream `source_url` in their
`skill-report.json`) that the framework mutates *at run time*. The payload corpus
lives separately in `data/bash_scripts/` and is **not** vendored here.

So this folder behaves like the other four — an unlabeled real-world set, useful
for false positives — with the caveat that it is the exact carrier population a
published attack framework targets, which makes it worth re-scanning whenever
injection rules change. Each bundle also ships a registry-generated
`skill-report.json` (a third-party audit artifact absent from the other corpora);
it produced zero findings in the first run, so it does not skew the comparison.
One slug, `skill-finder`, collides by name with a `clawhub/` bundle.

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
| [`reports/REPORT.md`](reports/REPORT.md) | combined — every corpus dir |
| [`reports/REPORT.html`](reports/REPORT.html) | the combined report as a self-contained interactive page |
| [`reports/REPORT_skillject.md`](reports/REPORT_skillject.md) | standalone — the SkillJect sample (100 bundles) |
| [`reports/REPORT_skillject.html`](reports/REPORT_skillject.html) | the SkillJect report as a self-contained interactive page |

Each report has a machine-readable sibling (`reports/stats.json`,
`reports/stats_skillject.json`). Each subfolder under a corpus dir is one skill
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
  skillject/<slug>/        SkillJect carrier bundles (+ _manifest.json)
  scripts/
    fetch_clawhub.py       pull top-N skills by downloads from clawhub.ai
    fetch_skillsmp.py      pull skills via the SkillsMP API -> GitHub bundles (gh)
    fetch_orgs.sh          clone vendor repos (skills.rest set) -> orgs/
    run_scans.sh           scan every bundle in parallel -> reports/<RAW_DIR>/*.json
    aggregate.py           roll raw JSON up into stats.json + REPORT.md
    report_html.py         render a stats.json into a self-contained HTML page
    rule_findings.py       every corpus hit for one rule, for FP auditing
  reports/
    raw/<source>__<slug>.json           combined-run scan results (one per bundle)
    raw_skillject/<source>__<slug>.json standalone SkillJect run
    stats.json / stats_skillject.json   aggregated statistics
    REPORT.md / REPORT_skillject.md     the human-readable evaluation reports
    REPORT.html / REPORT_skillject.html the same reports as interactive pages
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
git clone --depth 1 https://github.com/jiaxiaojunQAQ/SkillJect /tmp/skillject
#   then copy /tmp/skillject/data/skills_sample/*/ into evaluation/skillject/
#   (_manifest.json is built from each bundle's skill-report.json "meta" block)

# 3a. combined report (all five sources) -> reports/REPORT.md + stats.json
# (parallelism defaults to nproc; pass a number to override, but keep it at or
# below your core count — oversubscribing has hung the workstation before)
CORPUS_DIRS="clawhub skillsmp orgs anthropic skillject" evaluation/scripts/run_scans.sh
python3 evaluation/scripts/aggregate.py
python3 evaluation/scripts/report_html.py                 # -> reports/REPORT.html

# 3b. standalone report over just one source (e.g. SkillJect)
CORPUS_DIRS="skillject" RAW_DIR="raw_skillject" evaluation/scripts/run_scans.sh
RAW_DIR="raw_skillject" REPORT_NAME="REPORT_skillject.md" \
  STATS_NAME="stats_skillject.json" \
  REPORT_TITLE="skill-guard — SkillJect Sample Corpus Evaluation" \
  python3 evaluation/scripts/aggregate.py
STATS_NAME="stats_skillject.json" HTML_NAME="REPORT_skillject.html" \
  REPORT_TITLE="skill-guard — SkillJect Sample Corpus Evaluation" \
  python3 evaluation/scripts/report_html.py

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
