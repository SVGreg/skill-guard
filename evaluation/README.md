# surfaceguard — Quality Evaluation Session

A reproducible security evaluation that runs `surfaceguard scan` against a corpus
of **real Agent Skills** and aggregates the results into a stats report.

## Corpus

Six sources, chosen for complementary coverage — a download-ranked registry, an
install-ranked registry, a GitHub index, org/vendor repos, Anthropic's examples,
and a security-research sample — so the false-positive picture reflects many
independent authors, not one house style.

| Folder | Source | Skills |
|--------|--------|------:|
| `clawhub/` | Top skills by download count from the [ClawHub](https://clawhub.ai) registry (500 distinct publishers) | 500 |
| `skillssh/` | Top skills by **install count** from the [skills.sh](https://skills.sh) registry | ~200 |
| `skillsmp/` | GitHub-indexed skills from [SkillsMP](https://skillsmp.com), `sort=recent` for author diversity, ≤5 per repo | ~200 |
| `orgs/` | Organization/vendor repos surfaced by [skills.rest](https://skills.rest) — `trailofbits`, `stripe`, `supabase`, `tinybird` — plus [`vercel-labs/agent-skills`](https://github.com/vercel-labs/agent-skills), the official collection behind skills.sh | 120 |
| `aws/` | The AWS Agent Toolkit — every skill in [`aws/agent-toolkit-for-aws`](https://github.com/aws/agent-toolkit-for-aws) | 159 |
| `anthropic/` | Example skills from [`github.com/anthropics/skills`](https://github.com/anthropics/skills) | 17 |
| `skillject/` | `data/skills_sample` from [SkillJect](https://github.com/jiaxiaojunQAQ/SkillJect), a malicious-skill research framework | 100 |

### About `aws/`

One vendor repo, ~160 bundles, written to a single house style: every skill ships
`references/*.md` under progressive disclosure, links AWS documentation heavily, and
describes cloud primitives — IMDS, IAM policy documents, `sudo` installs, `~/.aws`
credential paths, per-model prompt templates — that the ruleset also treats as risk
signals. That combination makes it the corpus's densest **false-positive proving
ground**, and it plays the same regression-anchor role as `orgs/` (a finding is an FP
until proven otherwise) at five times the size.

It is scanned as its own corpus dir so it can be read alone:

```sh
evaluation/scripts/fetch_aws.sh
CORPUS_DIRS=aws RAW_DIR=raw_aws evaluation/scripts/run_scans.sh 4
RAW_DIR=raw_aws REPORT_NAME=REPORT_aws.md STATS_NAME=stats_aws.json \
  REPORT_TITLE="surfaceguard — AWS Agent Toolkit corpus" \
  evaluation/scripts/aggregate.py
```

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

### Two roles: pinned baseline and rolling sweep

A corpus is a **snapshot**, and the population it samples turns over continuously —
new publishers, new install rankings, new idioms. So the corpus does two different
jobs, and conflating them is how a scanner silently drifts out of calibration:

| Role | What it is | What it answers |
|---|---|---|
| **Pinned baseline** | the vendored dirs above, fetched once with a commit pinned per bundle in `_manifest.json` | "did this rule change break anything that used to pass?" |
| **Rolling sweep** | a fresh slice fetched into quarantine each maintenance cycle by `sg-corpus-sweep`, scanned, mined, then deleted | "what do skills look like *now*, and where is the scanner wrong about them?" |

Sweep reports are **internal and git-ignored** — `reports/sweeps/<date>-<source>.md`,
alongside the raw scan output they summarise. They carry counts, rule ids and escaped
excerpts, never fetched bundle content, and they stay out of git because a sweep is a
point-in-time reading of other people's skills, not a project document. What gets
published is what the sweep files: issues describing patterns, and backlog rows. The
sweep tooling is
`sweep_diff.py` (per-bundle hit-rate movement between two `stats.json` files) and
`sweep_gaps.py` (bundles the scanner scored clean that still carry a risky primitive —
the counter-signal to false-positive auditing). `run_scans.sh` takes `CORPUS_ROOT`
so a sweep can be scanned from a quarantine directory outside the repo.

Sweeps do not re-measure the same slice: `corpus_ledger.py` remembers what was
fetched and skips it next time unless the rule packs moved, the source repo gained
commits, or the TTL lapsed — so successive sweeps walk down the ranking, and a
bundle that *is* refetched gets its `content_hash` compared against the last one,
which is how drift surfaces.

`skillssh/_manifest.json` records a `fetched_at` per bundle and every manifest pins a
source commit, so any set can be re-fetched and compared rather than trusted
indefinitely. Treat a corpus older than a few weeks as a regression baseline, not as
evidence about what skills look like today; re-run the fetcher before quoting a rate.

## Reports

| Report | Scope |
|--------|-------|
| [`reports/REPORT.md`](reports/REPORT.md) | combined — every corpus dir |
| [`reports/REPORT.html`](reports/REPORT.html) | the combined report as a self-contained interactive page |
| [`reports/REPORT_aws.md`](reports/REPORT_aws.md) | standalone — the AWS Agent Toolkit (159 bundles) |
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
  skillssh/<owner__repo__skill>/  install-ranked skills.sh bundles (+ _manifest.json)
  skillsmp/<owner__repo__skill>/  GitHub-indexed bundles (+ _manifest.json)
  orgs/<org__repo__skill>/ vendor-repo bundles    (+ _manifest.json)
  aws/<org__repo__skill>/  AWS Agent Toolkit bundles (+ _manifest.json)
  anthropic/<slug>/        copied skill bundles   (+ _manifest.json)
  skillject/<slug>/        SkillJect carrier bundles (+ _manifest.json)
  scripts/
    fetch_clawhub.py       pull top-N skills by downloads from clawhub.ai
    fetch_skillssh.py      pull top-N skills by installs from skills.sh -> skillssh/
    fetch_skillsmp.py      pull skills via the SkillsMP API -> GitHub bundles (gh)
    fetch_orgs.sh          clone vendor repos (skills.rest set) -> orgs/
    fetch_aws.sh           clone aws/agent-toolkit-for-aws -> aws/
    run_scans.sh           scan every bundle in parallel -> reports/<RAW_DIR>/*.json
    aggregate.py           roll raw JSON up into stats.json + REPORT.md
    report_html.py         render a stats.json into a self-contained HTML page
    rule_findings.py       every corpus hit for one rule, for FP auditing
    sweep_diff.py          hit-rate movement between two sweeps of one source
    sweep_gaps.py          clean bundles that still carry a risky primitive
    corpus_ledger.py       what a sweep already saw; skip/revisit rules + drift
    multi_parity.py        one-process `scan <corpus>` vs run_scans.sh: same findings? latency
  reports/
    raw/<source>__<slug>.json           combined-run scan results (one per bundle)
    raw_skillject/<source>__<slug>.json standalone SkillJect run
    stats.json / stats_skillject.json   aggregated statistics
    REPORT.md / REPORT_skillject.md     the human-readable evaluation reports
    REPORT.html / REPORT_skillject.html the same reports as interactive pages
```

## One process vs one process per bundle

`surfaceguard scan <folder>` (M9) scans a whole corpus in one process.
`multi_parity.py` runs that and `run_scans.sh` over the same corpus with the same
binary, then checks that every bundle both runs scanned has identical findings,
waivers, verdict and risk score:

```sh
CORPUS=clawhub evaluation/scripts/multi_parity.py   # exit 1 if any bundle differs
```

Measured on 2026-09-27 over `clawhub/`, on 4 cores, with parallelism at the core count for both runs:

| | one process | per bundle (`run_scans.sh -P4`) |
|---|--:|--:|
| bundles scanned | 500 | 532 |
| bundles in both, differing | **0** | — |
| wall clock | 542 s | 542 s |
| peak RSS | 141 MiB (whole run) | ≤ 71 MiB (largest single scan) |

The one-process run is a **parity** result, not a speed-up. Per-bundle scanning
dominates the wall clock, and the ~0.1 s of rule compilation a fresh process pays
(M5-09) is small beside it. Both runs also overlapped with an unrelated test run
on the same machine, so read the timings as equal rather than as precise.

The 32 extra per-bundle bundles are `SKILL.md` directories that sit **inside**
another bundle. `run_scans.sh` scans each of those on its own, while `scan
<folder>` treats them as part of the outer skill, which is what `LoadBundle`
reads. None of the 32 are one-process-only.

## Reproduce

```sh
# 1. build the scanner
go build -o surfaceguard ./cmd/surfaceguard

# 2. load the corpus
WANT=500 python3 evaluation/scripts/fetch_clawhub.py                      # ClawHub top-500 -> clawhub/
WANT=200 SKIP_DIRS=clawhub,anthropic,orgs \
  python3 evaluation/scripts/fetch_skillssh.py                            # skills.sh top-200 by installs -> skillssh/
WANT=200 SKIP_DIRS=clawhub,anthropic,orgs,skillssh \
  python3 evaluation/scripts/fetch_skillsmp.py                            # SkillsMP (recent) -> skillsmp/
evaluation/scripts/fetch_orgs.sh                                         # vendor repos -> orgs/
evaluation/scripts/fetch_aws.sh                                          # AWS Agent Toolkit -> aws/
git clone --depth 1 https://github.com/anthropics/skills /tmp/anthropic-skills
#   then copy /tmp/anthropic-skills/skills/*/  into evaluation/anthropic/
git clone --depth 1 https://github.com/jiaxiaojunQAQ/SkillJect /tmp/skillject
#   then copy /tmp/skillject/data/skills_sample/*/ into evaluation/skillject/
#   (_manifest.json is built from each bundle's skill-report.json "meta" block)

# 3a. combined report (all six sources) -> reports/REPORT.md + stats.json
# (parallelism defaults to nproc; pass a number to override, but keep it at or
# below your core count — oversubscribing has hung the workstation before)
CORPUS_DIRS="clawhub skillssh skillsmp orgs aws anthropic skillject" evaluation/scripts/run_scans.sh
python3 evaluation/scripts/aggregate.py
python3 evaluation/scripts/report_html.py                 # -> reports/REPORT.html

# 3b. standalone report over just one source (e.g. SkillJect)
CORPUS_DIRS="skillject" RAW_DIR="raw_skillject" evaluation/scripts/run_scans.sh
RAW_DIR="raw_skillject" REPORT_NAME="REPORT_skillject.md" \
  STATS_NAME="stats_skillject.json" \
  REPORT_TITLE="surfaceguard — SkillJect Sample Corpus Evaluation" \
  python3 evaluation/scripts/aggregate.py
STATS_NAME="stats_skillject.json" HTML_NAME="REPORT_skillject.html" \
  REPORT_TITLE="surfaceguard — SkillJect Sample Corpus Evaluation" \
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
  numbers reflect surfaceguard's out-of-the-box behavior.
- Static analysis flags **capability and pattern**, not confirmed intent. A `pass`
  is not a safety guarantee and a `fail` is an invitation to review — see the
  "Methodology & caveats" section of the report.
- Results are a **snapshot**: registry rankings and skill contents change over time.
