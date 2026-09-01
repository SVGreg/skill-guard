#!/usr/bin/env python3
"""skill-guard PreToolUse hook for Claude Code.

Gate Agent Skill invocations at load time. When the model calls a skill via the
`Skill` tool, Claude Code fires a `PreToolUse` hook with `tool_name == "Skill"`
and `tool_input == {"skill": <name>, "args": ...}`. This script resolves that
skill name to a local bundle, runs `skill-guard guard --format json` against the
project policy, and either allows the call or denies it with a reason —
depending on the configured enforcement mode.

The hook asks the binary for a *decision*, not for a report. `guard` verifies
whichever signature formats the bundle carries, scans it, applies the policy and
answers `allow` / `warn` / `deny`; the hook maps that one field onto its mode.
It used to run `verify` and re-derive a decision by regexing SG-PRV-* ids out of
human-readable text, which was fragile in three ways this replaces: the text is
not a contract, only SGMT-1 signatures were noticed (an OMS-signed skill read as
*unsigned*), and nothing was scanned — so a malicious but correctly-signed skill
was allowed straight into the model's context.

Nothing in the skill is executed here: `guard` parses the bundle into an inert
model, hashes it, and matches static rules. The hook is pure stdlib (Python
3.8+) so it runs anywhere Claude Code does, with no install step.

Contract (see https://code.claude.com/docs/en/hooks):
  * stdin  = JSON with tool_name, tool_input, cwd, permission_mode, ...
  * stdout = JSON `{"hookSpecificOutput": {"permissionDecision": "deny", ...}}`
             to block; empty (exit 0) to let the call proceed normally.
We deliberately never emit permissionDecision "allow": that would auto-approve
and short-circuit every other permission check. "Not blocking" == exit 0 silent.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# Skills Claude Code / the harness provides that we can never sign or verify.
# They resolve to no local bundle; listing them keeps the audit log quiet and
# lets `enforce` mode allow first-party skills while still blocking unknown ones.
DEFAULT_BUILTIN_ALLOWLIST = [
    "artifact-design", "artifact-capabilities", "dataviz", "update-config",
    "keybindings-help", "verify", "code-review", "simplify", "loop", "schedule",
    "claude-api", "claude-in-chrome", "run", "init", "review", "security-review",
    "fewer-permission-prompts", "stock-sentiment-scan",
]

DEFAULT_CONFIG: Dict[str, Any] = {
    # "log" | "block-invalid" | "enforce"  (see decide() for exact semantics)
    "mode": "block-invalid",
    "skill_guard_bin": "skill-guard",
    # Trust roster (.skillguard.yaml). Relative paths resolve against the project.
    "policy": ".skillguard.yaml",
    # Where a skill name is resolved to a bundle dir, in priority order.
    "skill_dirs": [
        "${CLAUDE_PROJECT_DIR}/.claude/skills",
        "${HOME}/.claude/skills",
    ],
    "builtin_allowlist": DEFAULT_BUILTIN_ALLOWLIST,
    # Skill that resolves to no local bundle and is not built-in:
    #   "allow" | "warn" | "deny"
    "unresolved_action": "warn",
    # Hook/gate failure (binary missing, timeout, crash): "allow" | "deny".
    # Fail-open by default so a broken hook never bricks the agent; enforce
    # deployments should set this to "deny".
    "on_error": "allow",
    # Seconds to wait for `skill-guard guard`. The legacy key
    # "verify_timeout_seconds" is still honoured (see _timeout).
    "timeout_seconds": 20,
    # Decision cache directory. "-" means the user cache dir, "" disables it.
    # Decisions are keyed by the bundle's content hash and the policy, so a
    # changed byte or a changed policy is a miss by construction — the cache
    # cannot answer yesterday's question. It is what keeps the load path off
    # the ~270 ms cold scan on every skill call.
    "cache_dir": "-",
    "log_file": "${CLAUDE_PROJECT_DIR}/.claude/skillguard-hook.log",
    # Surface allow-with-warning / deny reasons to the user via systemMessage.
    "system_messages": True,
    # Tool names that carry a skill invocation. Kept configurable in case the
    # harness exposes skills under a different tool name.
    "trigger_tools": ["Skill"],
}

CONFIG_ENV = "SKILLGUARD_HOOK_CONFIG"
CONFIG_BASENAME = "skillguard-hook.config.json"


def load_config() -> Dict[str, Any]:
    """Merge the first config found (env → project → user) over defaults."""
    cfg = dict(DEFAULT_CONFIG)
    for path in _config_candidates():
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    cfg.update(json.load(fh))
            except (OSError, ValueError) as exc:  # pragma: no cover - defensive
                _stderr(f"skillguard-hook: ignoring bad config {path}: {exc}")
            break
    return cfg


def _config_candidates() -> List[str]:
    project = _project_dir()
    home = os.path.expanduser("~")
    return [
        os.environ.get(CONFIG_ENV, ""),
        os.path.join(project, ".claude", CONFIG_BASENAME),
        os.path.join(home, ".claude", CONFIG_BASENAME),
    ]


def _project_dir() -> str:
    return os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()


def expand(path: str) -> str:
    """Expand ${CLAUDE_PROJECT_DIR}, ${HOME}, ~ and other env vars in a path."""
    mapping = dict(os.environ)
    mapping.setdefault("CLAUDE_PROJECT_DIR", _project_dir())
    mapping.setdefault("HOME", os.path.expanduser("~"))

    def repl(match: "re.Match[str]") -> str:
        name = match.group(1) or match.group(2)
        return mapping.get(name, match.group(0))

    expanded = re.sub(r"\$\{(\w+)\}|\$(\w+)", repl, path)
    return os.path.expanduser(expanded)


# --------------------------------------------------------------------------- #
# Decision model
# --------------------------------------------------------------------------- #

# The three outcomes `skill-guard guard` returns. This is the whole of the
# gate's judgment: it has already weighed provenance against the scan verdict
# against the policy, so the hook reads one field instead of reconstructing that
# reasoning from finding ids.
ALLOW = "allow"
WARN = "warn"
DENY = "deny"
GUARD_OUTCOMES = (ALLOW, WARN, DENY)

# States the hook decides for itself, because they are about *the hook's* world
# — name resolution and subprocess failure — not about a bundle the gate saw.
UNRESOLVED = "unresolved"    # no local bundle found (and not a known built-in)
BUILTIN = "builtin"          # first-party skill on the allowlist
ERROR = "error"              # hook could not obtain a decision


@dataclass
class Decision:
    block: bool
    state: str
    skill: str
    reason: str = ""
    bundle: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Core logic (pure, unit-tested)
# --------------------------------------------------------------------------- #

def outcome_of(rc: int, out: str) -> Tuple[str, Dict[str, Any]]:
    """Read the outcome out of a `skill-guard guard --format json` run.

    Returns (state, decision). The decision is the parsed JSON, kept whole for
    the audit log and for the deny reason. `guard` exits 0 for allow and warn
    and 1 for deny, and prints the decision either way; 3 and 4 are usage and
    internal errors, where there is no decision to read.

    The one field this reads — `outcome` — is the contract. Everything the old
    text-parsing classify() inferred (which SG-PRV ids appeared, whether a
    signature file existed) is the binary's job, and the binary already did it.
    """
    try:
        decision = json.loads(out)
    except ValueError:
        return ERROR, {}
    if not isinstance(decision, dict):
        return ERROR, {}
    state = decision.get("outcome")
    if state not in GUARD_OUTCOMES:
        return ERROR, decision
    # A deny must arrive as exit 1 and an allow/warn as exit 0. A disagreement
    # means we are talking to something that is not this contract, and guessing
    # which half to believe is how a gate silently stops gating.
    if (state == DENY) != (rc == 1):
        return ERROR, decision
    return state, decision


# Which outcomes each mode blocks.
#
# `guard` folds provenance, the scan verdict and the policy into one answer, so
# the modes now differ only in how much of that answer they act on:
#
#   log            audit only, never blocks
#   block-invalid  block a denial — a signature that is present but compromised
#                  (tampered, invalid, revoked), or a failing scan verdict
#   enforce        additionally block a warning — an unsigned or unverified
#                  skill, or a warn-level verdict
#
# This preserves the old mapping for every provenance state (a compromised
# signature denies, a missing one warns under the default policy) and adds what
# the text-parsing version could not see at all: the scan. A malicious skill is
# now blocked at load in block-invalid, not just an unsigned one in enforce.
_BLOCKED_BY_MODE = {
    "log": set(),
    "block-invalid": {DENY},
    "enforce": {DENY, WARN},
}


def decide(state: str, mode: str, unresolved_action: str) -> Tuple[bool, str]:
    """Return (block, reason) for an outcome under a mode. Pure function."""
    if state in (ALLOW, BUILTIN):
        return False, ""
    if state == UNRESOLVED:
        if mode == "log":
            return False, ""
        if unresolved_action == "deny":
            return True, "no local bundle found to verify this skill"
        return False, ""  # allow / warn
    if state == ERROR:
        return False, ""  # error handling is applied by the caller via on_error
    return state in _BLOCKED_BY_MODE.get(mode, set()), ""


# --------------------------------------------------------------------------- #
# Skill resolution & verification (I/O)
# --------------------------------------------------------------------------- #

def resolve_bundle(skill: str, skill_dirs: List[str]) -> Optional[str]:
    """Find the bundle dir for a skill name (a dir containing SKILL.md)."""
    for base in skill_dirs:
        cand = os.path.join(expand(base), skill)
        if os.path.isfile(os.path.join(cand, "SKILL.md")):
            return cand
    return None


def _timeout(cfg: Dict[str, Any]) -> int:
    """Seconds to allow the gate. `verify_timeout_seconds` is the pre-guard name
    for this setting and is still honoured, so an existing config keeps working.
    """
    return int(cfg.get("timeout_seconds", cfg.get("verify_timeout_seconds", 20)))


def guard_command(cfg: Dict[str, Any], bundle: str) -> List[str]:
    """Build the `skill-guard guard` argv. Pure, so the tests can read it."""
    bin_path = shutil.which(expand(cfg["skill_guard_bin"])) or expand(cfg["skill_guard_bin"])
    # --mode load: this hook fires as a skill enters the model's context, which
    # is exactly the load gate. Install-time strictness belongs to whatever
    # installs the skill, not here.
    cmd = [bin_path, "guard", bundle, "--format", "json", "--mode", "load"]
    policy = expand(cfg.get("policy", ""))
    if policy and not os.path.isabs(policy):
        policy = os.path.join(_project_dir(), policy)
    if policy and os.path.isfile(policy):
        cmd += ["--policy", policy]
    cache_dir = expand(cfg.get("cache_dir", ""))
    if cache_dir:
        cmd += ["--cache-dir", cache_dir]
    return cmd


def run_guard(cfg: Dict[str, Any], bundle: str) -> Tuple[int, str, str]:
    """Run `skill-guard guard` on a bundle. Returns (rc, stdout, stderr).

    No .skillsig probe first: an unsigned bundle is a decision the gate makes
    under the policy, and probing for one signature format was how an OMS-signed
    skill came back "unsigned".
    """
    proc = subprocess.run(
        guard_command(cfg, bundle), capture_output=True, text=True,
        timeout=_timeout(cfg),
    )
    return proc.returncode, proc.stdout, proc.stderr


def evaluate(cfg: Dict[str, Any], skill: str) -> Decision:
    """Full pipeline: allowlist → resolve → guard → decide."""
    if skill in set(cfg.get("builtin_allowlist", [])):
        return Decision(block=False, state=BUILTIN, skill=skill)

    skill_dirs = cfg.get("skill_dirs", [])
    bundle = resolve_bundle(skill, skill_dirs)
    if bundle is None:
        block, reason = decide(UNRESOLVED, cfg["mode"], cfg["unresolved_action"])
        return Decision(block=block, state=UNRESOLVED, skill=skill, reason=reason)

    try:
        rc, out, err = run_guard(cfg, bundle)
    except FileNotFoundError:
        return _error_decision(cfg, skill, bundle, "skill-guard binary not found")
    except subprocess.TimeoutExpired:
        return _error_decision(cfg, skill, bundle, "skill-guard guard timed out")
    except OSError as exc:  # pragma: no cover - defensive
        return _error_decision(cfg, skill, bundle, f"guard failed: {exc}")

    state, gd = outcome_of(rc, out)
    if state == ERROR:
        detail = (err or out or "").strip().splitlines()
        why = f"no usable decision from guard (exit {rc})"
        if detail:
            why += f": {detail[0][:200]}"
        return _error_decision(cfg, skill, bundle, why)

    block, _ = decide(state, cfg["mode"], cfg["unresolved_action"])
    return Decision(
        block=block, state=state, skill=skill,
        # The reason is the gate's own, in the gate's words — it names the rule
        # or the provenance state that decided, which is what a human reading
        # the block message needs. Re-writing it here would only lose detail.
        reason=gd.get("reason", "") if block else "",
        bundle=bundle,
        detail={
            "guard_exit": rc,
            "verdict": gd.get("verdict", ""),
            "risk_score": gd.get("risk_score", 0),
            "content_hash": gd.get("content_hash", ""),
            "signature": gd.get("signature", {}),
            "cache_hit": bool(gd.get("cache_hit")),
            "gate_reason": gd.get("reason", ""),
            "rules": _rule_ids(gd),
        },
    )


def _rule_ids(gd: Dict[str, Any], limit: int = 5) -> List[str]:
    """The rule ids that drove the decision, for the audit log. Truncated: the
    log is a trail, not a report — `skill-guard scan` is where the full list is.
    """
    findings = gd.get("findings") or []
    ids = []
    for f in findings[:limit]:
        if isinstance(f, dict) and f.get("rule_id"):
            ids.append(f["rule_id"])
    return ids


def _error_decision(cfg: Dict[str, Any], skill: str, bundle: str, why: str) -> Decision:
    """Apply the on_error fail-open/closed policy."""
    block = cfg.get("on_error", "allow") == "deny"
    reason = f"{why} (on_error={cfg.get('on_error')})" if block else ""
    return Decision(block=block, state=ERROR, skill=skill, reason=reason,
                    bundle=bundle, detail={"error": why})


# --------------------------------------------------------------------------- #
# Emit / logging
# --------------------------------------------------------------------------- #

def audit_log(cfg: Dict[str, Any], payload: Dict[str, Any]) -> None:
    path = expand(cfg.get("log_file", ""))
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, separators=(",", ":")) + "\n")
    except OSError:  # pragma: no cover - never fail the hook on a log write
        pass


def emit(cfg: Dict[str, Any], d: Decision) -> None:
    """Write the hook's stdout decision and exit."""
    warn_states = {WARN, UNRESOLVED}
    if d.block:
        msg = f"skill-guard blocked skill '{d.skill}': {d.reason}"
        out: Dict[str, Any] = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": msg,
            }
        }
        if cfg.get("system_messages", True):
            out["systemMessage"] = msg
        print(json.dumps(out))
    else:
        # Not blocking. In non-log modes, still surface a heads-up for risky-but-
        # allowed states so the user is not silently trusting an unsigned skill.
        if (cfg.get("system_messages", True) and cfg.get("mode") != "log"
                and d.state in warn_states):
            note = d.detail.get("gate_reason") or (
                "no local bundle found to verify this skill"
                if d.state == UNRESOLVED else d.state)
            print(json.dumps({
                "systemMessage": f"skill-guard: skill '{d.skill}' allowed but {note}",
                "suppressOutput": True,
            }))
    sys.exit(0)


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> None:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        sys.exit(0)  # not our concern; let the call proceed

    cfg = load_config()
    tool_name = event.get("tool_name", "")
    if tool_name not in set(cfg.get("trigger_tools", ["Skill"])):
        sys.exit(0)

    tool_input = event.get("tool_input") or {}
    skill = tool_input.get("skill") or tool_input.get("name") or ""
    if not skill:
        sys.exit(0)

    decision = evaluate(cfg, skill)
    audit_log(cfg, {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "session": event.get("session_id"),
        "mode": cfg.get("mode"),
        "skill": decision.skill,
        "state": decision.state,
        "block": decision.block,
        "bundle": decision.bundle,
        "reason": decision.reason,
        **decision.detail,
    })
    emit(cfg, decision)


if __name__ == "__main__":
    main()
