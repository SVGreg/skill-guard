#!/usr/bin/env bash
# Scan skill bundles in parallel and write one JSON report per skill.
#
# Usage: evaluation/scripts/run_scans.sh [PARALLELISM]
# Env:
#   CORPUS_DIRS  space-separated corpus dirs under evaluation/ (default: "clawhub anthropic")
#   RAW_DIR      output dir for raw JSON, relative to evaluation/reports/ (default: "raw")
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/skill-guard"
RAW="$ROOT/evaluation/reports/${RAW_DIR:-raw}"
JOBS="${1:-8}"
CORPUS_DIRS="${CORPUS_DIRS:-clawhub anthropic}"

[ -x "$BIN" ] || { echo "building skill-guard ..."; (cd "$ROOT" && go build -o skill-guard ./cmd/skill-guard) || exit 1; }

rm -rf "$RAW"; mkdir -p "$RAW"

# Discover skill bundle dirs: any directory directly containing a SKILL.md.
LIST="$(mktemp)"
CORPUS_PATHS=""
for c in $CORPUS_DIRS; do CORPUS_PATHS="$CORPUS_PATHS $ROOT/evaluation/$c"; done
find $CORPUS_PATHS \
  -name SKILL.md -not -path '*/.git/*' -exec dirname {} \; | sort -u > "$LIST"

echo "found $(wc -l < "$LIST" | tr -d ' ') skill bundles; scanning with -P$JOBS ..."

scan_one() {
  local dir="$1" bin="$2" raw="$3" root="$4"
  local rel="${dir#"$root"/evaluation/}"      # e.g. clawhub/github
  local source="${rel%%/*}"                    # clawhub | anthropic
  local slug="${rel#*/}"; slug="${slug//\//_}" # nested-safe
  local out="$raw/${source}__${slug}.json"
  "$bin" scan "$dir" --format json --no-color >"$out" 2>"$out.err"
  local code=$?
  # annotate with source/slug/exit for the aggregator
  python3 - "$out" "$source" "$slug" "$code" "$dir" <<'PY'
import json, sys
out, source, slug, code, path = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
try:
    d = json.load(open(out))
except Exception as e:
    d = {"_parse_error": str(e), "findings": [], "verdict": "error"}
d["_source"] = source
d["_slug"] = slug
d["_exit"] = code
d["_path"] = path
json.dump(d, open(out, "w"), indent=1)
PY
  printf '  %-9s %-34s exit=%s\n' "$source" "$slug" "$code"
}
export -f scan_one

tr '\n' '\0' < "$LIST" | xargs -0 -P"$JOBS" -I{} bash -c 'scan_one "$@"' _ {} "$BIN" "$RAW" "$ROOT"
rm -f "$LIST"

echo "raw reports written to $RAW ($(ls "$RAW"/*.json | wc -l | tr -d ' ') files)"
