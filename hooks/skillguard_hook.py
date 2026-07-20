#!/usr/bin/env python3
"""skill-guard PreToolUse hook for Claude Code.

Gate Agent Skill invocations on their skill-guard signature. When the model
calls a skill via the `Skill` tool, Claude Code fires a `PreToolUse` hook with
`tool_name == "Skill"` and `tool_input == {"skill": <name>, "args": ...}`. This
script resolves that skill name to a local bundle, runs `skill-guard verify`
against the project trust roster, and either allows the call or denies it with a
reason — depending on the configured enforcement mode.

Nothing in the skill is executed here: `skill-guard verify` only recomputes a
Merkle root and checks a detached Ed25519 signature. The hook is pure stdlib
(Python 3.8+) so it runs anywhere Claude Code does, with no install step.

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
    # Hook/verify failure (binary missing, timeout, crash): "allow" | "deny".
    # Fail-open by default so a broken hook never bricks the agent; enforce
    # deployments should set this to "deny".
    "on_error": "allow",
    "verify_timeout_seconds": 20,
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
# Verification result model
# --------------------------------------------------------------------------- #

# States, worst → best. Ordering matters for classification precedence.
TAMPERED = "tampered"        # SG-PRV-003: Merkle mismatch, content changed
INVALID = "invalid"          # SG-PRV-002: signature does not verify / untrusted key w/ roster
REVOKED = "revoked"          # SG-PRV-004: revoked key or expired attestation
UNVERIFIED = "unverified"    # SG-PRV-005: no roster or unknown key — identity unproven
UNSIGNED = "unsigned"        # no .skillsig at all
UNRESOLVED = "unresolved"    # no local bundle found (and not a known built-in)
BUILTIN = "builtin"          # first-party skill on the allowlist
TRUSTED = "trusted"          # valid signature from a trusted, non-revoked key
ERROR = "error"              # hook could not determine a state


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

def classify(rc: int, out: str, err: str, sig_exists: bool) -> str:
    """Map a `skill-guard verify` run to a verification state.

    Exit codes: 0 ok · 2 verification failed · 3 usage/no-attestation. We lean on
    the SG-PRV-* finding codes in the output for precise state, falling back to
    the exit code. See pkg/verify/verify.go for the source of these codes.
    """
    if not sig_exists:
        return UNSIGNED
    codes = set(re.findall(r"SG-PRV-\d+", (out or "") + "\n" + (err or "")))
    if "SG-PRV-003" in codes:
        return TAMPERED
    if "SG-PRV-002" in codes:
        return INVALID
    if "SG-PRV-004" in codes:
        return REVOKED
    if "SG-PRV-005" in codes:
        return UNVERIFIED
    if rc == 0:
        return TRUSTED
    return ERROR


# Which states each mode blocks. `log` blocks nothing; `block-invalid` blocks a
# signature that is present but compromised; `enforce` requires valid + trusted.
_BLOCKED_BY_MODE = {
    "log": set(),
    "block-invalid": {TAMPERED, INVALID, REVOKED},
    "enforce": {TAMPERED, INVALID, REVOKED, UNVERIFIED, UNSIGNED},
}

_REASONS = {
    TAMPERED: "bundle content changed since signing (Merkle root mismatch)",
    INVALID: "signature does not verify against any trusted key",
    REVOKED: "signature was made with a revoked key or an expired attestation",
    UNVERIFIED: "publisher identity is unverified (no trust roster / unknown key)",
    UNSIGNED: "skill is unsigned (no .skillsig attestation)",
}


def decide(state: str, mode: str, unresolved_action: str) -> Tuple[bool, str]:
    """Return (block, reason) for a state under a mode. Pure function."""
    if state in (TRUSTED, BUILTIN):
        return False, ""
    if state == UNRESOLVED:
        if mode == "log":
            return False, ""
        if unresolved_action == "deny":
            return True, "no local bundle found to verify this skill"
        return False, ""  # allow / warn
    if state == ERROR:
        return False, ""  # error handling is applied by the caller via on_error
    block = state in _BLOCKED_BY_MODE.get(mode, set())
    return block, _REASONS.get(state, state) if block else ""


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


def run_verify(cfg: Dict[str, Any], bundle: str) -> Tuple[int, str, str, bool]:
    """Run `skill-guard verify` on a bundle. Returns (rc, stdout, stderr, sig_exists)."""
    sig_exists = os.path.isfile(os.path.join(bundle, "SKILL.md.skillsig"))
    if not sig_exists:
        return 3, "", "no .skillsig", False

    bin_path = shutil.which(expand(cfg["skill_guard_bin"])) or expand(cfg["skill_guard_bin"])
    cmd = [bin_path, "verify", bundle, "--no-color"]
    policy = expand(cfg.get("policy", ""))
    if policy and not os.path.isabs(policy):
        policy = os.path.join(_project_dir(), policy)
    if policy and os.path.isfile(policy):
        cmd += ["--policy", policy]

    proc = subprocess.run(
        cmd, capture_output=True, text=True,
        timeout=cfg.get("verify_timeout_seconds", 20),
    )
    return proc.returncode, proc.stdout, proc.stderr, True


def evaluate(cfg: Dict[str, Any], skill: str) -> Decision:
    """Full pipeline: allowlist → resolve → verify → classify → decide."""
    if skill in set(cfg.get("builtin_allowlist", [])):
        return Decision(block=False, state=BUILTIN, skill=skill)

    skill_dirs = cfg.get("skill_dirs", [])
    bundle = resolve_bundle(skill, skill_dirs)
    if bundle is None:
        block, reason = decide(UNRESOLVED, cfg["mode"], cfg["unresolved_action"])
        return Decision(block=block, state=UNRESOLVED, skill=skill, reason=reason)

    try:
        rc, out, err, sig_exists = run_verify(cfg, bundle)
    except FileNotFoundError:
        return _error_decision(cfg, skill, bundle, "skill-guard binary not found")
    except subprocess.TimeoutExpired:
        return _error_decision(cfg, skill, bundle, "skill-guard verify timed out")
    except OSError as exc:  # pragma: no cover - defensive
        return _error_decision(cfg, skill, bundle, f"verify failed: {exc}")

    state = classify(rc, out, err, sig_exists)
    if state == ERROR:
        return _error_decision(cfg, skill, bundle, f"unexpected verify exit {rc}")

    block, reason = decide(state, cfg["mode"], cfg["unresolved_action"])
    return Decision(
        block=block, state=state, skill=skill, reason=reason, bundle=bundle,
        detail={"verify_exit": rc},
    )


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
    warn_states = {UNSIGNED, UNVERIFIED, REVOKED, UNRESOLVED}
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
            note = _REASONS.get(d.state, d.state)
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
