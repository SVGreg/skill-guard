#!/usr/bin/env python3
"""Fetch the most-downloaded ClawHub skills into evaluation/clawhub/<slug>.

Pipeline:
  1. GET /api/v1/skills?sort=downloads  -> ranked slugs (paged via nextCursor)
  2. For each slug, resolve the publisher via /api/v1/search (exact slug,
     highest download count wins) -> ownerHandle
  3. GET /api/v1/download?slug=..&ownerHandle=..  -> zip, extracted to disk

Only bundles that actually contain a SKILL.md are kept.
"""
import io
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import zipfile

REGISTRY = "https://clawhub.ai"
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", os.environ.get("OUTDIR", "clawhub"))
WANT = int(os.environ.get("WANT", "40"))
# Comma-separated corpus dirs whose slugs should be skipped (already loaded).
SKIP_DIRS = [d for d in os.environ.get("SKIP_DIRS", "").split(",") if d]


def get(url, timeout=25):
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "skill-guard-eval/0.1"})
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
        base = os.path.join(os.path.dirname(__file__), "..", d)
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
    print(f"[*] ranking {pool} skills by downloads; want {WANT} new "
          f"(skipping {len(skip)} already loaded) -> {OUT_DIR}", flush=True)
    ranked = ranked_slugs(pool)
    manifest = []
    ok = 0
    for i, (slug, dl) in enumerate(ranked, 1):
        if ok >= WANT:
            break
        if slug in skip:
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
                         "ref": f"@{owner}/{slug}", "dir": f"clawhub/{slug}"})
        print(f"[{i:>2}] {slug:<32} OK  @{owner}  ({dl:,} downloads)")
        time.sleep(0.15)
    with open(os.path.join(OUT_DIR, "_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n[done] {ok}/{len(ranked)} bundles saved -> {OUT_DIR}")


if __name__ == "__main__":
    main()
