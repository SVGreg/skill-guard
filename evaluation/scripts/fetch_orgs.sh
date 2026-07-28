#!/usr/bin/env bash
# Fetch organization-authored Agent Skills into evaluation/orgs/.
#
# These are the vendor/org repositories surfaced by the skills.rest directory —
# professionally-authored skills (a security firm, a payments API, a database
# vendor) that form a distinct, higher-signal slice of the corpus than the
# download/star-ranked registries. Each is a public GitHub repo, so `git clone`
# is reproducible and the license is visible.
#
# For each repo we shallow-clone, find every SKILL.md, and copy its containing
# directory into evaluation/orgs/<org>__<repo>__<skill>/ exactly as it ships.
#
# Env:
#   ORG_REPOS   space-separated owner/repo list (default: the skills.rest set)
#   OUTDIR      output dir under evaluation/ (default: orgs)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-orgs}"
DEST="$HERE/../$OUTDIR"
ORG_REPOS="${ORG_REPOS:-trailofbits/skills stripe/agent-toolkit supabase/agent-skills tinybirdco/tinybird-agent-skills}"

mkdir -p "$DEST"
MANIFEST="$DEST/_manifest.json"
echo "[" > "$MANIFEST"
first=1
count=0

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for repo in $ORG_REPOS; do
  org="${repo%%/*}"
  name="${repo##*/}"
  echo "[*] cloning $repo ..." >&2
  if ! git clone --depth 1 --quiet "https://github.com/$repo" "$tmp/$name" 2>/dev/null; then
    echo "    SKIP (clone failed)" >&2
    continue
  fi
  sha="$(git -C "$tmp/$name" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  # Each SKILL.md marks a bundle; copy its directory.
  while IFS= read -r skillmd; do
    dir="$(dirname "$skillmd")"
    # Relative path of the bundle dir within the repo, so two skills whose
    # containing folders share a basename don't collide onto one slug.
    rel="${dir#"$tmp/$name"}"
    rel="${rel#/}"
    [ -z "$rel" ] && rel="root"
    slug="${org}__${name}__${rel}"
    slug="${slug//[^A-Za-z0-9_.-]/_}"
    out="$DEST/$slug"
    rm -rf "$out"
    cp -r "$dir" "$out"
    [ $first -eq 0 ] && echo "," >> "$MANIFEST"
    first=0
    printf '  {"slug": "%s", "org": "%s", "repo": "%s", "commit": "%s", "dir": "%s/%s"}' \
      "$slug" "$org" "$repo" "$sha" "$OUTDIR" "$slug" >> "$MANIFEST"
    count=$((count + 1))
  done < <(find "$tmp/$name" -name SKILL.md -not -path '*/.git/*')
  echo "    ok ($sha)" >&2
done

echo "" >> "$MANIFEST"
echo "]" >> "$MANIFEST"
echo "[done] $count org skill bundles saved -> $DEST" >&2
