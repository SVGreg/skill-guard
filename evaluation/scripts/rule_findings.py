#!/usr/bin/env python3
"""Pull every corpus finding for one rule, for false-positive auditing.

The evaluation corpus is real, unlabeled skills, so every hit a rule produces
there is a false-positive candidate until a human reads it. `aggregate.py` gives
per-rule *counts*; this gives the individual hits with enough context to judge
them — path, line, confidence, and the matched excerpt.

Usage:
    evaluation/scripts/rule_findings.py SG-INJ-001
    evaluation/scripts/rule_findings.py SG-INJ-001 --all
    evaluation/scripts/rule_findings.py SG-INJ-001 --sample 5 --group-by bundle

Env:
    RAW_DIR   raw report dir under evaluation/reports/ (default: "raw")

Exit status is 0 even with no hits — "this rule fires nowhere in the corpus" is
a valid and useful answer.
"""

import argparse
import collections
import json
import os
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def load(raw_dir):
    """Yield (report, bundle_path, source) for every scan report.

    Yields one item per *report*, not per finding: a bundle that produced no
    findings still has to count toward the denominator, or the hit rate is
    measured against "bundles that tripped some rule" instead of the corpus.
    """
    d = ROOT / "evaluation" / "reports" / raw_dir
    if not d.is_dir():
        sys.exit(
            f"no raw reports at {d}\n"
            "  run: go build -o skill-guard ./cmd/skill-guard && "
            "evaluation/scripts/run_scans.sh 8"
        )
    files = sorted(d.glob("*.json"))
    if not files:
        sys.exit(f"{d} has no scan reports; run evaluation/scripts/run_scans.sh first")
    for p in files:
        try:
            rep = json.load(open(p))
        except Exception as e:  # a truncated report should not abort the audit
            print(f"warning: cannot parse {p.name}: {e}", file=sys.stderr)
            continue
        yield rep, rep.get("_path", p.stem), rep.get("_source", "?")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rule", help="rule id, e.g. SG-INJ-001")
    ap.add_argument("--all", action="store_true", help="print every hit, not a sample")
    ap.add_argument("--sample", type=int, default=12, help="hits to show (default 12)")
    ap.add_argument(
        "--group-by",
        choices=("bundle", "file", "excerpt"),
        default="excerpt",
        help="what to tally (default: excerpt — the fastest way to spot a systematic FP)",
    )
    ap.add_argument("--seed", type=int, default=0, help="sampling seed, for reproducibility")
    args = ap.parse_args()

    rule = args.rule.upper()
    raw_dir = os.environ.get("RAW_DIR", "raw")

    hits, bundles, scanned = [], set(), set()
    for rep, path, source in load(raw_dir):
        scanned.add(path)
        for f in rep.get("findings") or []:
            if (f.get("rule_id") or "").upper() != rule:
                continue
            hits.append(
                {
                    "bundle": os.path.basename(path),
                    "source": source,
                    "file": f.get("file", ""),
                    "line": f.get("start_line"),
                    "confidence": f.get("confidence"),
                    "severity": f.get("severity"),
                    "excerpt": (f.get("excerpt") or "").strip(),
                }
            )
            bundles.add(path)

    n_scanned = len(scanned)
    print(f"{rule}: {len(hits)} findings across {len(bundles)} of {n_scanned} corpus bundles")
    if not hits:
        print("\nNo corpus hits. Nothing to audit for false positives — but note this")
        print("also means the corpus gives no evidence about this rule's precision.")
        return

    pct = 100.0 * len(bundles) / n_scanned if n_scanned else 0.0
    print(f"bundle hit rate: {pct:.1f}%")

    # Concentration matters: a rule firing 50 times in 2 bundles is a different
    # problem from one firing 50 times across 50 authors.
    per_bundle = collections.Counter(h["bundle"] for h in hits)
    top = per_bundle.most_common(5)
    print(f"\nmost-affected bundles ({len(per_bundle)} total):")
    for name, c in top:
        print(f"  {c:>4}  {name}")
    if len(per_bundle) > 5:
        share = 100.0 * sum(c for _, c in top) / len(hits)
        print(f"  (top 5 hold {share:.0f}% of all hits)")

    print(f"\nby target file type:")
    for ext, c in collections.Counter(
        os.path.splitext(h["file"])[1].lower() or "(none)" for h in hits
    ).most_common(10):
        print(f"  {c:>4}  {ext}")

    key = {"bundle": lambda h: h["bundle"], "file": lambda h: h["file"]}.get(
        args.group_by, lambda h: h["excerpt"][:80]
    )
    print(f"\nrepeated {args.group_by}s (a repeat is usually one systematic cause):")
    for val, c in collections.Counter(key(h) for h in hits).most_common(10):
        if c > 1:
            print(f"  {c:>4}  {val!r}")

    shown = hits if args.all else random.Random(args.seed).sample(hits, min(args.sample, len(hits)))
    label = "all hits" if args.all else f"sample of {len(shown)}"
    print(f"\n--- {label} (judge each: true positive, false positive, or ambiguous) ---")
    for h in sorted(shown, key=lambda h: (h["bundle"], h["file"], h["line"] or 0)):
        print(f"\n{h['bundle']}/{h['file']}:{h['line']}  conf={h['confidence']} sev={h['severity']}")
        print(f"  | {h['excerpt'][:200]}")


if __name__ == "__main__":
    main()
