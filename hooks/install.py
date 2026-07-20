#!/usr/bin/env python3
"""Register (or remove) the skill-guard PreToolUse hook in a Claude Code settings file.

  python3 hooks/install.py            # add to .claude/settings.json (project)
  python3 hooks/install.py --user     # add to ~/.claude/settings.json (all projects)
  python3 hooks/install.py --uninstall

Idempotent: re-running will not create a duplicate hook entry. The settings file
is created if missing and existing keys are preserved.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
COMMAND = "python3 ${CLAUDE_PROJECT_DIR}/hooks/skillguard_hook.py"
MATCHER = "Skill"


def entry() -> dict:
    return {
        "matcher": MATCHER,
        "hooks": [{"type": "command", "command": COMMAND, "timeout": 30}],
    }


def load(path: str) -> dict:
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def save(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def is_ours(block: dict) -> bool:
    if block.get("matcher") != MATCHER:
        return False
    return any("skillguard_hook.py" in h.get("command", "")
               for h in block.get("hooks", []))


def install(path: str) -> str:
    data = load(path)
    hooks = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    if any(is_ours(b) for b in hooks):
        return "already installed"
    hooks.append(entry())
    save(path, data)
    return "installed"


def uninstall(path: str) -> str:
    data = load(path)
    pre = data.get("hooks", {}).get("PreToolUse", [])
    kept = [b for b in pre if not is_ours(b)]
    if len(kept) == len(pre):
        return "nothing to remove"
    data["hooks"]["PreToolUse"] = kept
    save(path, data)
    return "uninstalled"


def target_path(user: bool) -> str:
    if user:
        return os.path.join(os.path.expanduser("~"), ".claude", "settings.json")
    project = os.environ.get("CLAUDE_PROJECT_DIR") or os.path.dirname(HERE)
    return os.path.join(project, ".claude", "settings.json")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--user", action="store_true", help="write to ~/.claude/settings.json")
    ap.add_argument("--uninstall", action="store_true", help="remove the hook")
    args = ap.parse_args()

    path = target_path(args.user)
    action = uninstall if args.uninstall else install
    result = action(path)
    print(f"{result}: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
