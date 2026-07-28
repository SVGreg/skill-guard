#!/usr/bin/env python3
"""Fetch Agent Skills indexed by SkillsMP (skillsmp.com) into evaluation/skillsmp/.

SkillsMP is a GitHub-indexer: its REST API returns, per skill, the GitHub
`owner/repo/branch` and the path to the skill's `SKILL.md`. We resolve each to
its bundle *directory* and download the whole directory (recursively) via the
authenticated GitHub contents API — `gh` avoids the raw.githubusercontent rate
limit that anonymous fetches hit.

Why this source: unlike ClawHub (download-ranked, its own registry) SkillsMP spans
many public GitHub repos and authors, which is exactly the author diversity a
false-positive corpus wants. Because it is star-ranked and dominated by a few
mega-repos, MAX_PER_REPO caps how many skills any single repo contributes so one
project can't skew the corpus.

Env:
  WANT          number of NEW skill bundles to save            (default 200)
  OUTDIR        output dir under evaluation/                   (default skillsmp)
  SKIP_DIRS     comma-separated corpus dirs whose skills to skip (dedup)
  MAX_PER_REPO  cap of skills taken from any one GitHub repo   (default 5)
  SORT          SkillsMP sort key                              (default recent)
                — `recent` spans many small repos (author diversity); `stars`
                collapses to ~5 mega-repos (affaan-m/ecc alone is ~894 skills).

Only bundles that actually contain a SKILL.md are kept. Requires `gh` on PATH and
authenticated (`gh auth status`).
"""
import base64
import json
import os
import subprocess
import time
import urllib.request

API = "https://skillsmp.com/api/skills"
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", os.environ.get("OUTDIR", "skillsmp"))
WANT = int(os.environ.get("WANT", "200"))
MAX_PER_REPO = int(os.environ.get("MAX_PER_REPO", "5"))
SORT = os.environ.get("SORT", "recent")
SKIP_DIRS = [d for d in os.environ.get("SKIP_DIRS", "").split(",") if d]

UA = "Mozilla/5.0 (X11; Linux x86_64) skill-guard-eval/0.1"


def api_page(page, limit=50):
    url = f"{API}?page={page}&limit={limit}&sortBy={SORT}"
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def gh_api(path):
    """Call the GitHub API via `gh` (authenticated). Returns parsed JSON or None."""
    try:
        out = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=40)
        if out.returncode != 0:
            return None
        return json.loads(out.stdout)
    except Exception:
        return None


def download_dir(owner, repo, ref, path, dest, depth=0):
    """Recursively download a repo directory into dest. Returns files written."""
    if depth > 4:
        return 0
    items = gh_api(f"repos/{owner}/{repo}/contents/{path}?ref={ref}")
    if not isinstance(items, list):
        return 0
    written = 0
    for it in items:
        name = it.get("name", "")
        typ = it.get("type")
        if typ == "dir":
            written += download_dir(owner, repo, ref, it["path"], os.path.join(dest, name), depth + 1)
        elif typ == "file":
            # Skip huge/binary blobs; the scanner reads text bundles.
            if (it.get("size") or 0) > 1_000_000:
                continue
            content = it.get("content")
            if content is None:
                blob = gh_api(f"repos/{owner}/{repo}/contents/{it['path']}?ref={ref}")
                content = (blob or {}).get("content")
            if not content:
                continue
            try:
                raw = base64.b64decode(content)
            except Exception:
                continue
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, name), "wb") as f:
                f.write(raw)
            written += 1
    return written


def load_skip():
    skip = set()
    for d in SKIP_DIRS:
        base = os.path.join(os.path.dirname(__file__), "..", d)
        if os.path.isdir(base):
            for name in os.listdir(base):
                if os.path.exists(os.path.join(base, name, "SKILL.md")):
                    skip.add(name.lower())
    return skip


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    skip = load_skip()
    manifest, ok, per_repo, page = [], 0, {}, 1
    print(f"[*] fetching {WANT} new SkillsMP skills (sort={SORT}, max {MAX_PER_REPO}/repo, "
          f"skipping {len(skip)} already-loaded) -> {OUT_DIR}", flush=True)
    while ok < WANT and page <= 200:
        try:
            d = api_page(page)
        except Exception as e:
            print(f"[page {page}] API error {e}")
            break
        skills = d.get("skills", [])
        if not skills:
            break
        for s in skills:
            if ok >= WANT:
                break
            r = s.get("route") or {}
            owner, repo = r.get("ownerSlug"), r.get("repoSlug")
            skill_path = r.get("sourceSkillPath") or s.get("path")
            branch = s.get("branch") or "main"
            if not (owner and repo and skill_path and skill_path.endswith("SKILL.md")):
                continue
            repo_key = f"{owner}/{repo}"
            if per_repo.get(repo_key, 0) >= MAX_PER_REPO:
                continue
            name = s.get("name") or os.path.basename(os.path.dirname(skill_path))
            slug = f"{owner}__{repo}__{name}".replace("/", "_")
            if name.lower() in skip or slug.lower() in skip:
                continue
            skill_dir = os.path.dirname(skill_path)
            dest = os.path.join(OUT_DIR, slug)
            n = download_dir(owner, repo, branch, skill_dir, dest)
            if n == 0 or not os.path.exists(os.path.join(dest, "SKILL.md")):
                continue
            ok += 1
            per_repo[repo_key] = per_repo.get(repo_key, 0) + 1
            manifest.append({"slug": slug, "name": name, "owner": owner, "repo": repo,
                             "branch": branch, "skill_path": skill_path, "stars": s.get("stars"),
                             "github": s.get("githubUrl"), "dir": f"skillsmp/{slug}", "files": n})
            print(f"[{ok:>3}] {slug:<48} ({n} files, {s.get('stars')}★)")
            time.sleep(0.1)
        page += 1
    with open(os.path.join(OUT_DIR, "_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n[done] {ok} bundles saved -> {OUT_DIR}")


if __name__ == "__main__":
    main()
