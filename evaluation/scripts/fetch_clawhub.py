#!/usr/bin/env python3
"""Fetch the most-downloaded ClawHub skills into <OUTROOT>/<OUTDIR>/<slug>.

Pipeline:
  1. GET /api/v1/skills?sort=downloads  -> ranked slugs (paged via nextCursor)
  2. For each slug, resolve the publisher via /api/v1/search (exact slug,
     highest download count wins) -> ownerHandle
  3. GET /api/v1/download?slug=..&ownerHandle=..  -> zip, extracted to disk

Only bundles that actually contain a SKILL.md are kept.

Env:
  WANT          number of NEW bundles to save                 (default 40)
  OUTROOT       root the corpus dir lives under               (default evaluation/)
  OUTDIR        corpus dir name under OUTROOT                 (default clawhub)
  SKIP_DIRS     comma-separated pinned corpus dirs (under evaluation/) to skip
  LEDGER_SOURCE when set (e.g. "clawhub"), consult the sweep ledger and skip
                bundles already seen — see corpus_ledger.py. ClawHub bundles have
                no source repo to ls-remote, so a seen bundle is revisited only
                when the rule packs moved or the TTL lapsed.

OUTROOT and LEDGER_SOURCE were silently ignored before #321: a sweep that
followed sg-corpus-sweep §2 verbatim wrote 150 third-party bundles into the
pinned evaluation/clawhub/ corpus instead of its quarantine, and re-fetched the
head of the ranking every time.
"""
import io
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import corpus_ledger  # noqa: E402  (same directory, not a package)

REGISTRY = "https://clawhub.ai"
OUT_ROOT = os.environ.get("OUTROOT") or os.path.join(HERE, "..")
OUT_NAME = os.environ.get("OUTDIR", "clawhub")
OUT_DIR = os.path.join(OUT_ROOT, OUT_NAME)
LEDGER_SOURCE = os.environ.get("LEDGER_SOURCE") or None
WANT = int(os.environ.get("WANT", "40"))
# Comma-separated corpus dirs whose slugs should be skipped (already loaded).
SKIP_DIRS = [d for d in os.environ.get("SKIP_DIRS", "").split(",") if d]


def get(url, timeout=25):
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "surfaceguard-eval/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def get_json(url):
    return json.loads(get(url))


def ranked_slugs(want):
    """Return [(slug, downloads)] sorted by downloads desc, up to `want`."""
    out, cursor = [], None
    while len(out) < want:
        url = f"{REGISTRY}/api/v1/skills?limit=50&sort=downloads"
        if cursor:
            url += f"&cursor={urllib.parse.quote(cursor)}"
        d = get_json(url)
        for it in d.get("items", []):
            st = it.get("stats") or {}
            out.append((it["slug"], st.get("downloads") or 0))
        cursor = d.get("nextCursor")
        if not cursor:
            break
    return out[:want]


def resolve_owner(slug):
    """Owner handle of the most-downloaded publisher for an exact slug."""
    try:
        d = get_json(f"{REGISTRY}/api/v1/search?q={urllib.parse.quote(slug)}")
    except Exception:
        return None
    best, best_dl = None, -1
    for r in d.get("results", []):
        if r.get("slug") == slug and (r.get("downloads") or 0) > best_dl:
            best, best_dl = r.get("ownerHandle"), r.get("downloads") or 0
    return best


def download_bundle(slug, owner, dest):
    url = f"{REGISTRY}/api/v1/download?slug={urllib.parse.quote(slug)}&ownerHandle={urllib.parse.quote(owner)}"
    raw = get(url, timeout=40)
    zf = zipfile.ZipFile(io.BytesIO(raw))
    names = zf.namelist()
    if not any(n.split("/")[-1] == "SKILL.md" for n in names):
        return False
    os.makedirs(dest, exist_ok=True)
    for n in names:
        if n.endswith("/"):
            continue
        # guard against path traversal
        target = os.path.normpath(os.path.join(dest, n))
        if not target.startswith(os.path.normpath(dest)):
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as f:
            f.write(zf.read(n))
    return True


def load_skip():
    """Slugs already present in other corpus dirs (SKIP_DIRS)."""
    skip = set()
    for d in SKIP_DIRS:
        base = os.path.join(HERE, "..", d)
        if os.path.isdir(base):
            for name in os.listdir(base):
                if os.path.exists(os.path.join(base, name, "SKILL.md")):
                    skip.add(name)
    return skip


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    skip = load_skip()
    # Over-fetch the ranked pool so we still reach WANT *new* skills after
    # removing already-loaded slugs and any bundles that lack a SKILL.md.
    pool = WANT + len(skip) + 40
    led = packs = None
    if LEDGER_SOURCE:
        # Most of the top of the ranking is already in the ledger, so the sweep
        # walks *down* it — that only works if the pool reaches far enough down.
        pool = max(pool, WANT * 8)
        led = corpus_ledger.load()["skills"]
        packs = corpus_ledger.pack_versions()
        print(f"[*] ledger: {len(led)} skills known, "
              f"{sum(1 for k in led if k.startswith(LEDGER_SOURCE + '/'))} from this source",
              flush=True)
    print(f"[*] ranking {pool} skills by downloads; want {WANT} new "
          f"(skipping {len(skip)} already loaded) -> {OUT_DIR}", flush=True)
    ranked = ranked_slugs(pool)
    manifest = []
    ok = skipped = 0
    for i, (slug, dl) in enumerate(ranked, 1):
        if ok >= WANT:
            break
        if slug in skip:
            continue
        why = ""
        if led is not None:
            # No source repo to ls-remote, so "deferred" (seen, packs unchanged,
            # within TTL) is final here: the bundle is skipped.
            fetch, why = corpus_ledger.decide(f"{LEDGER_SOURCE}/{slug}", led.get(f"{LEDGER_SOURCE}/{slug}"),
                                              packs, repo_head=None, source=LEDGER_SOURCE)
            if not fetch:
                skipped += 1
                continue
        owner = resolve_owner(slug)
        if not owner:
            print(f"[{i:>2}] {slug:<32} SKIP (no owner resolved)")
            continue
        dest = os.path.join(OUT_DIR, slug)
        try:
            got = download_bundle(slug, owner, dest)
        except Exception as e:
            print(f"[{i:>2}] {slug:<32} ERROR {e}")
            continue
        if not got:
            print(f"[{i:>2}] {slug:<32} SKIP (no SKILL.md)")
            continue
        ok += 1
        manifest.append({"slug": slug, "owner": owner, "downloads": dl,
                         "ref": f"@{owner}/{slug}", "dir": f"{OUT_NAME}/{slug}"})
        print(f"[{i:>2}] {slug:<32} OK  @{owner}  ({dl:,} downloads)"
              + (f"  [{why}]" if why else ""))
        time.sleep(0.15)
    with open(os.path.join(OUT_DIR, "_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    tail = f", {skipped} skipped as already-seen-and-unchanged" if LEDGER_SOURCE else ""
    print(f"\n[done] {ok}/{len(ranked)} bundles saved{tail} -> {OUT_DIR}")
    if LEDGER_SOURCE:
        print("[*] record the results afterwards: "
              f"corpus_ledger.py record --source {LEDGER_SOURCE} --raw-dir <RAW_DIR> "
              f"--manifest {os.path.join(OUT_DIR, '_manifest.json')}")


if __name__ == "__main__":
    main()
