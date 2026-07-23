#!/usr/bin/env python3
"""Aggregate evaluation/reports/raw/*.json into stats.json + REPORT.md."""
import glob
import json
import os
from collections import Counter, defaultdict

HERE = os.path.dirname(__file__)
RAW = os.path.join(HERE, "..", "reports", os.environ.get("RAW_DIR", "raw"))
OUT = os.path.join(HERE, "..", "reports")
REPORT_NAME = os.environ.get("REPORT_NAME", "REPORT.md")
STATS_NAME = os.environ.get("STATS_NAME", "stats.json")
TITLE = os.environ.get("REPORT_TITLE",
                       "skill-guard — Skill Corpus Security Evaluation")

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def load():
    rows = []
    for f in sorted(glob.glob(os.path.join(RAW, "*.json"))):
        d = json.load(open(f))
        rows.append(d)
    return rows


def summarize(rows):
    stats = {
        "total_skills": len(rows),
        "by_source": {},
        "verdicts": Counter(),
        "severity_totals": Counter(),
        "rule_hits": Counter(),
        "rule_titles": {},
        "ast_hits": Counter(),
        "ast_titles": {},
        "risk_tiers": Counter(),
        "clean_skills": 0,
    }
    per_source = defaultdict(lambda: {"n": 0, "pass": 0, "fail": 0,
                                      "findings": 0, "risk_sum": 0,
                                      "sev": Counter()})
    skills = []
    for d in rows:
        src = d.get("_source", "?")
        verdict = d.get("verdict", "error")
        score = d.get("risk_score", 0) or 0
        tier = d.get("risk_tier", "?")
        counts = d.get("counts", {}) or {}
        findings = d.get("findings", []) or []
        stats["verdicts"][verdict] += 1
        stats["risk_tiers"][tier] += 1
        ps = per_source[src]
        ps["n"] += 1
        ps["risk_sum"] += score
        ps["findings"] += len(findings)
        if verdict == "pass":
            ps["pass"] += 1
        else:
            ps["fail"] += 1
        if not findings:
            stats["clean_skills"] += 1
        for sev in SEV_ORDER:
            stats["severity_totals"][sev] += counts.get(sev, 0)
            ps["sev"][sev] += counts.get(sev, 0)
        for fdg in findings:
            rid = fdg.get("rule_id", "?")
            stats["rule_hits"][rid] += 1
            stats["rule_titles"][rid] = fdg.get("title", "")
            for a in (fdg.get("ast") or []):
                stats["ast_hits"][a] += 1
        for a, meta in (d.get("ast_references") or {}).items():
            stats["ast_titles"][a] = meta.get("title", "")
        top = [{"rule_id": f.get("rule_id"), "title": f.get("title"),
                "severity": f.get("severity"), "file": f.get("file"),
                "line": f.get("start_line"), "ast": f.get("ast") or [],
                "excerpt": (f.get("excerpt") or "").strip()[:90]}
               for f in findings]
        skills.append({
            "source": src, "slug": d.get("_slug", "?"),
            "verdict": verdict, "risk_score": score, "risk_tier": tier,
            "max_severity": d.get("max_severity", "info"),
            "counts": counts, "n_findings": len(findings),
            "findings": top,
        })
    for src, ps in per_source.items():
        stats["by_source"][src] = {
            "n": ps["n"], "pass": ps["pass"], "fail": ps["fail"],
            "pass_rate": round(100 * ps["pass"] / ps["n"], 1) if ps["n"] else 0,
            "total_findings": ps["findings"],
            "avg_risk": round(ps["risk_sum"] / ps["n"], 1) if ps["n"] else 0,
            "severity": dict(ps["sev"]),
        }
    stats["skills"] = sorted(skills, key=lambda s: (-s["risk_score"], s["source"], s["slug"]))
    # jsonify counters
    for k in ["verdicts", "severity_totals", "rule_hits", "ast_hits", "risk_tiers"]:
        stats[k] = dict(stats[k])
    return stats


def bar(n, total, width=24):
    if total == 0:
        return ""
    fill = int(round(width * n / total))
    return "█" * fill + "·" * (width - fill)


def md(stats):
    L = []
    A = L.append
    A(f"# {TITLE}\n")
    A(f"_Static scan of **{stats['total_skills']} real Agent Skills** "
      "against the skill-guard ruleset (OWASP Agentic Skills Top 10)._\n")
    SRC_DESC = {
        "clawhub": "top skills by download count from the ClawHub registry (`clawhub.ai`)",
        "clawhub_more": "ClawHub skills ranked #41–140 by download count (`clawhub.ai`)",
        "anthropic": "the official `github.com/anthropics/skills` example skills",
    }
    A("| Corpus | Source |")
    A("|---|---|")
    for src in sorted(stats["by_source"]):
        A(f"| **{src}** | {SRC_DESC.get(src, 'skill bundles')} |")
    A("")

    # headline
    v = stats["verdicts"]
    npass = v.get("pass", 0)
    nfail = v.get("fail", 0)
    A("## Headline\n")
    A(f"- **{stats['total_skills']}** skills scanned "
      f"— **{npass} pass**, **{nfail} fail** "
      f"({round(100*nfail/stats['total_skills'],1)}% fail rate).")
    A(f"- **{stats['clean_skills']}** skills produced **zero findings**.")
    tot = stats["severity_totals"]
    A(f"- **{sum(tot.values())}** findings total — "
      f"crit {tot.get('critical',0)}, high {tot.get('high',0)}, "
      f"med {tot.get('medium',0)}, low {tot.get('low',0)}, info {tot.get('info',0)}.")
    A("")

    # by source
    A("## By corpus\n")
    A("| Corpus | Skills | Pass | Fail | Pass rate | Findings | Avg risk | crit | high | med | low |")
    A("|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|")
    for src in sorted(stats["by_source"]):
        s = stats["by_source"][src]
        sv = s["severity"]
        A(f"| {src} | {s['n']} | {s['pass']} | {s['fail']} | {s['pass_rate']}% | "
          f"{s['total_findings']} | {s['avg_risk']} | {sv.get('critical',0)} | "
          f"{sv.get('high',0)} | {sv.get('medium',0)} | {sv.get('low',0)} |")
    A("")

    # risk tiers
    A("## Risk tier distribution\n")
    A("| Tier | Skills | |")
    A("|---|--:|:--|")
    order = ["L0", "L1", "L2", "L3"]
    tiers = stats["risk_tiers"]
    tt = sum(tiers.values())
    for t in order + [x for x in tiers if x not in order]:
        if t in tiers:
            A(f"| {t} | {tiers[t]} | {bar(tiers[t], tt)} |")
    A("\n_L0 clean · L1 low · L2 elevated · L3 high-risk._\n")

    # top rules
    A("## Most-triggered rules\n")
    A("| Rule | Title | Hits |")
    A("|---|---|--:|")
    for rid, n in sorted(stats["rule_hits"].items(), key=lambda x: -x[1])[:15]:
        A(f"| `{rid}` | {stats['rule_titles'].get(rid,'')} | {n} |")
    A("")

    # AST breakdown
    A("## OWASP Agentic Skills Top 10 coverage\n")
    A("| AST | Category | Findings |")
    A("|---|---|--:|")
    for a, n in sorted(stats["ast_hits"].items(), key=lambda x: -x[1]):
        A(f"| {a} | {stats['ast_titles'].get(a,'')} | {n} |")
    A("")

    # worst offenders
    A("## Highest-risk skills\n")
    A("| # | Corpus | Skill | Verdict | Risk | Tier | Max sev | Findings |")
    A("|--:|---|---|---|--:|---|---|--:|")
    ranked = [s for s in stats["skills"] if s["risk_score"] > 0][:15]
    for i, s in enumerate(ranked, 1):
        A(f"| {i} | {s['source']} | `{s['slug']}` | {s['verdict']} | "
          f"{s['risk_score']} | {s['risk_tier']} | {s['max_severity']} | {s['n_findings']} |")
    A("")

    # full table
    A("<details><summary>Full per-skill results (all "
      f"{stats['total_skills']})</summary>\n")
    A("| Corpus | Skill | Verdict | Risk | Tier | crit | high | med | low |")
    A("|---|---|---|--:|---|--:|--:|--:|--:|")
    for s in stats["skills"]:
        c = s["counts"]
        A(f"| {s['source']} | `{s['slug']}` | {s['verdict']} | {s['risk_score']} | "
          f"{s['risk_tier']} | {c.get('critical',0)} | {c.get('high',0)} | "
          f"{c.get('medium',0)} | {c.get('low',0)} |")
    A("\n</details>\n")

    A("## Notable cases (top findings per high-risk skill)\n")
    A("What actually tripped the scanner on the riskiest skills. These are "
      "**capability signals** mapped to OWASP AST, not proof of malice — skill-guard "
      "is a static pre-load gate so a human or policy can decide.\n")
    for s in [x for x in stats["skills"] if x["risk_score"] > 0][:8]:
        A(f"**`{s['slug']}`** ({s['source']}) — risk {s['risk_score']} "
          f"({s['risk_tier']}), {s['n_findings']} findings")
        # de-dup findings by (rule, excerpt) and show up to 4
        seen, shown = set(), 0
        for f in s["findings"]:
            key = (f["rule_id"], f["excerpt"])
            if key in seen:
                continue
            seen.add(key)
            loc = f"{f['file']}:{f['line']}"
            ex = f["excerpt"].replace("\n", " ")
            A(f"  - `{f['rule_id']}` {f['severity']} — {f['title']} "
              f"— `{loc}` — `{ex}`")
            shown += 1
            if shown >= 4:
                break
        extra = s["n_findings"] - shown
        if extra > 0:
            A(f"  - …and {extra} more.")
        A("")
    A("## Methodology & caveats\n")
    corpus_bits = ", ".join(f"{stats['by_source'][s]['n']} {s}"
                            for s in sorted(stats["by_source"]))
    A(f"- **Corpus**: {corpus_bits}. ClawHub slugs are resolved to each slug's "
      "top publisher by download count; provenance in each corpus's `_manifest.json`.")
    A("- **Scan**: `skill-guard scan <bundle> --format json`, the built-in "
      "rulepacks only (no custom policy/waivers), run in parallel.")
    A("- **Static only**: findings indicate *capability and pattern*, not confirmed "
      "intent or runtime behavior. A `pass` is not a safety guarantee; a `fail` is a "
      "prompt for review, waiver, or signing — not automatic condemnation.")
    A("- **Snapshot**: registry download counts and skill contents drift; results "
      "reflect the fetch date recorded in the manifests.")
    A("")

    A("---\n_Reproduce: `evaluation/scripts/fetch_clawhub.py`, "
      "`git clone anthropics/skills`, `evaluation/scripts/run_scans.sh`, "
      "`evaluation/scripts/aggregate.py`._")
    return "\n".join(L)


def main():
    rows = load()
    stats = summarize(rows)
    json.dump(stats, open(os.path.join(OUT, STATS_NAME), "w"), indent=2)
    open(os.path.join(OUT, REPORT_NAME), "w").write(md(stats))
    print(f"wrote {OUT}/{STATS_NAME} and {OUT}/{REPORT_NAME}")
    print(f"  {stats['total_skills']} skills, "
          f"{stats['verdicts'].get('pass',0)} pass / "
          f"{stats['verdicts'].get('fail',0)} fail")


if __name__ == "__main__":
    main()
