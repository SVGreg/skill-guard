#!/usr/bin/env python3
"""One-process corpus scan vs per-bundle scans: same findings? how much faster?

Runs the same corpus two ways with the same freshly built binary:

  1. per bundle — evaluation/scripts/run_scans.sh, one process per bundle
     (the pipeline every evaluation report is built from);
  2. one process — `surfaceguard scan <corpus> --format json` (M9 multi mode).

and reports, for every bundle both runs scanned, whether the findings,
verdict and risk score are identical, plus wall-clock and peak RSS of each
run. Parallelism is the machine's core count for both — never more
(CLAUDE.md: oversubscribed scans have hung low-core hosts).

The two runs do not discover exactly the same set, by design: run_scans.sh
treats every directory holding a SKILL.md as a bundle, including one nested
inside another bundle and one inside a vendored tree, while `scan <folder>`
treats a nested SKILL.md as part of its outer bundle and skips vendored
trees. Those bundles are listed separately; only bundles in both runs can
"differ".

Env: CORPUS (default clawhub), RAW_DIR (default raw_parity, under
evaluation/reports/). Nothing from a scanned bundle is executed; only the
scanner's JSON is read. Exit 1 if any common bundle differs.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORPUS = os.environ.get("CORPUS", "clawhub")
RAW_DIR = os.environ.get("RAW_DIR", "raw_parity")
BIN = os.path.join(ROOT, "surfaceguard")


# RUSAGE_CHILDREN is a running maximum over every descendant this process has
# waited for, so measuring two runs from one process would report the larger
# of the two for both. Each run gets its own wrapper process instead.
_WRAP = ("import resource, subprocess, sys; subprocess.run(sys.argv[1:]); "
         "print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)")


def timed(cmd, **kw):
    """Run cmd; return (wall seconds, peak RSS in MiB of its largest process)."""
    t0 = time.monotonic()
    out = subprocess.run([sys.executable, "-c", _WRAP, *cmd], check=False,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, **kw)
    wall = time.monotonic() - t0
    rss_kib = int(out.stdout.strip().splitlines()[-1])
    return wall, rss_kib / 1024


def key(path):
    return os.path.realpath(path)


def comparable(rep):
    return {
        "findings": rep.get("findings") or [],
        "waived": rep.get("waived") or [],
        "verdict": rep.get("verdict"),
        "risk_score": rep.get("risk_score"),
    }


def main():
    cores = os.cpu_count() or 1
    print(f"building {BIN} ...")
    subprocess.run(["go", "build", "-o", BIN, "./cmd/surfaceguard"], cwd=ROOT, check=True)

    # 1. one process
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        multi_out = tmp.name
    corpus = os.path.join(ROOT, "evaluation", CORPUS)
    print(f"one process: scan {corpus} ...")
    multi_wall, multi_rss = timed(
        [BIN, "scan", corpus, "--format", "json", "--out", multi_out, "--quiet"])
    with open(multi_out) as f:
        multi = json.load(f)
    os.unlink(multi_out)
    one = {key(b["path"]): b for b in multi["bundles"]}

    # 2. per bundle. Its peak RSS is the largest single bundle's scan, since
    # each bundle is its own process.
    print(f"per bundle: run_scans.sh with -P{cores} ...")
    env = dict(os.environ, CORPUS_DIRS=CORPUS, RAW_DIR=RAW_DIR)
    per_wall, per_rss = timed(
        [os.path.join(ROOT, "evaluation", "scripts", "run_scans.sh"), str(cores)],
        env=env)
    raw = os.path.join(ROOT, "evaluation", "reports", RAW_DIR)
    per = {}
    for name in os.listdir(raw):
        if name.endswith(".json"):
            with open(os.path.join(raw, name)) as f:
                d = json.load(f)
            per[key(d["_path"])] = d

    common = sorted(set(one) & set(per))
    only_per = sorted(set(per) - set(one))
    only_one = sorted(set(one) - set(per))
    differ = [k for k in common
              if one[k].get("error") or comparable(one[k]) != comparable(per[k])]

    print()
    print(f"corpus            {CORPUS}  ({cores} cores)")
    print(f"bundles           one-process {len(one)}   per-bundle {len(per)}   common {len(common)}")
    print(f"differing         {len(differ)}")
    print(f"per-bundle only   {len(only_per)}  (nested inside another bundle, or in a vendored tree)")
    print(f"one-process only  {len(only_one)}")
    print(f"wall clock        one-process {multi_wall:.1f}s   per-bundle {per_wall:.1f}s")
    print(f"peak RSS          one-process {multi_rss:.0f} MiB   per-bundle (largest single scan) ≤ {per_rss:.0f} MiB")
    for k in differ[:20]:
        print(f"  DIFFERS  {os.path.relpath(k, ROOT)}")
    for k in only_one[:20]:
        print(f"  ONLY-ONE {os.path.relpath(k, ROOT)}")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
