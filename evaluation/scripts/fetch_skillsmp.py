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
  OUTROOT       root the corpus dir lives under                (default evaluation/)
  OUTDIR        corpus dir name under OUTROOT                  (default skillsmp)
  LEDGER_SOURCE when set (e.g. "skillsmp"), consult the sweep ledger and skip
                bundles already seen and unchanged — packs moved, source repo has
                new commits (one `git ls-remote` per repo), or TTL lapsed.
                OUTROOT and LEDGER_SOURCE were silently ignored before #321.
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
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import corpus_ledger  # noqa: E402  (same directory, not a package)

API = "https://skillsmp.com/api/skills"
OUT_ROOT = os.environ.get("OUTROOT") or os.path.join(HERE, "..")
OUT_NAME = os.environ.get("OUTDIR", "skillsmp")
OUT_DIR = os.path.join(OUT_ROOT, OUT_NAME)
LEDGER_SOURCE = os.environ.get("LEDGER_SOURCE") or None
WANT = int(os.environ.get("WANT", "200"))
MAX_PER_REPO = int(os.environ.get("MAX_PER_REPO", "5"))
# Files taken from any one bundle. One GitHub API call per file means an
# uncapped bundle can stall an entire sweep. 400 is chosen from the vendored
# skillsmp corpus's own distribution: 75 bundles, **median 2** files and mean
# 57 — a mean inflated by a single 1,738-file outlier, which is precisely the
# shape that stalls a run. The cap sits far above every ordinary skill and
# clips only the tail.
MAX_FILES_PER_BUNDLE = int(os.environ.get("MAX_FILES_PER_BUNDLE", "400"))
SORT = os.environ.get("SORT", "recent")
SKIP_DIRS = [d for d in os.environ.get("SKIP_DIRS", "").split(",") if d]

UA = "Mozilla/5.0 (X11; Linux x86_64) surfaceguard-eval/0.1"


def api_page(page):
    """Fetch one listing page.

    No client-side `limit`: the API caps the page size server-side (12 as of
    2026-09-15, reported back in `pagination.limit`) and **rejects** a larger
    value with HTTP 400 rather than clamping it. This fetcher used to ask for
    50, which turned every page request into a 400 and every sweep into zero
    bundles. Taking whatever page size the server offers means a future change
    to the cap cannot break it again.
    """
    url = f"{API}?page={page}&sortBy={SORT}"
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


def download_dir(owner, repo, ref, path, dest, depth=0, budget=None):
    """Recursively download a repo directory into dest. Returns files written.

    `budget` caps the files taken from one bundle. This costs one GitHub API
    call per file, so an uncapped bundle with a vendored tree can stall a whole
    sweep on a single skill — observed on 2026-09-15, where the run sat on one
    bundle for minutes with the rate limit untouched. fetch_skillssh.py has had
    a file-count cap for the same reason; this brings the two into line.
    """
    if depth > 4:
        return 0
    if budget is None:
        budget = [MAX_FILES_PER_BUNDLE]
    if budget[0] <= 0:
        return 0
    items = gh_api(f"repos/{owner}/{repo}/contents/{path}?ref={ref}")
    if not isinstance(items, list):
        return 0
    written = 0
    for it in items:
        if budget[0] <= 0:
            print(f"    [cap] {owner}/{repo}: stopped at {MAX_FILES_PER_BUNDLE} files", flush=True)
            break
        name = it.get("name", "")
        typ = it.get("type")
        if typ == "dir":
            written += download_dir(owner, repo, ref, it["path"], os.path.join(dest, name), depth + 1, budget)
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
            budget[0] -= 1
    return written


def load_skip():
    skip = set()
    for d in SKIP_DIRS:
        base = os.path.join(HERE, "..", d)
        if os.path.isdir(base):
            for name in os.listdir(base):
                if os.path.exists(os.path.join(base, name, "SKILL.md")):
                    skip.add(name.lower())
    return skip


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    skip = load_skip()
    manifest, ok, per_repo, page, skipped = [], 0, {}, 1, 0
    led = packs = None
    heads = {}  # repo -> HEAD sha, one `git ls-remote` per repo per run
    if LEDGER_SOURCE:
        led = corpus_ledger.load()["skills"]
        packs = corpus_ledger.pack_versions()
        print(f"[*] ledger: {len(led)} skills known, "
              f"{sum(1 for k in led if k.startswith(LEDGER_SOURCE + '/'))} from this source",
              flush=True)
    print(f"[*] fetching {WANT} new SkillsMP skills (sort={SORT}, max {MAX_PER_REPO}/repo, "
          f"skipping {len(skip)} already-loaded) -> {OUT_DIR}", flush=True)
    while ok < WANT and page <= 200:
        try:
            d = api_page(page)
        except Exception as e:
            # Page 1 failing means the listing API is unreachable or its
            # contract moved, and there is nothing to salvage. Later pages
            # failing just truncates the sweep, which is recoverable.
            print(f"[page {page}] API error {e}", flush=True)
            if page == 1:
                raise SystemExit(f"[fatal] SkillsMP listing API failed on the first page: {e}")
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
            if led is not None:
                # One `ls-remote` per repo per run: it is both the drift check for
                # bundles already seen and the commit recorded for new ones, so a
                # later sweep can tell whether the repo moved.
                if repo_key not in heads:
                    heads[repo_key] = corpus_ledger.repo_head(repo_key)
                key = f"{LEDGER_SOURCE}/{slug}"
                fetch, _ = corpus_ledger.decide(key, led.get(key), packs,
                                                repo_head=heads[repo_key], source=LEDGER_SOURCE)
                if not fetch:
                    skipped += 1
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
                             "github": s.get("githubUrl"), "dir": f"{OUT_NAME}/{slug}", "files": n,
                             # read by `corpus_ledger.py record` as repo / repo_commit
                             "source": repo_key, "commit": heads.get(repo_key)})
            # flush: this fetcher makes one GitHub API call per file, so a
            # 150-bundle run takes tens of minutes. Without flushing, the
            # progress lines sit in the buffer and the run looks hung — which
            # is exactly how the 2026-09-15 breakage first presented.
            print(f"[{ok:>3}] {slug:<48} ({n} files, {s.get('stars')}★)", flush=True)
            time.sleep(0.1)
        page += 1
    with open(os.path.join(OUT_DIR, "_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    tail = f", {skipped} skipped as already-seen-and-unchanged" if LEDGER_SOURCE else ""
    print(f"\n[done] {ok} bundles saved{tail} -> {OUT_DIR}")
    if LEDGER_SOURCE:
        print("[*] record the results afterwards: "
              f"corpus_ledger.py record --source {LEDGER_SOURCE} --raw-dir <RAW_DIR> "
              f"--manifest {os.path.join(OUT_DIR, '_manifest.json')}")
    # A sweep that fetched nothing is a failure, not an empty result. Exiting 0
    # here let the 2026-09-15 cycle's `limit=50` breakage read as "[done] 0
    # bundles saved" and flow straight into run_scans.sh, which then had nothing
    # to scan and also succeeded.
    if ok == 0:
        raise SystemExit("[fatal] no bundles fetched — the listing contract or the filters moved")


if __name__ == "__main__":
    main()
