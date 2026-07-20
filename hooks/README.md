# skill-guard hooks

Gate **Agent Skill invocations on their skill-guard signature** at the moment an
agent tries to use them. When a model calls a skill, the hook resolves it to a
local bundle, runs `skill-guard verify` against your trust roster, and allows or
blocks the call based on the configured enforcement mode.

Nothing in the skill is executed to check it — `verify` only recomputes a Merkle
root and checks a detached Ed25519 signature. The hook is **pure Python stdlib**
(3.8+); there is nothing to `pip install`.

> **How skills reach the hook.** In current Claude Code the model invokes a skill
> through the built-in `Skill` tool, which fires a `PreToolUse` event with
> `tool_name == "Skill"` and `tool_input == {"skill": "<name>", ...}`. That is the
> interception point this hook uses. (User-typed `/slash-command` skills expand via
> `UserPromptExpansion` instead and are not tool calls — see
> [Other agents](#other-agents-cursor--the-agent-sdk) for covering those.)

## Files

| File | Purpose |
|------|---------|
| `skillguard_hook.py` | The `PreToolUse` hook. Reads the event on stdin, decides on stdout. |
| `config.example.json` | Copy to `.claude/skillguard-hook.config.json` and edit. |
| `settings.snippet.json` | The `hooks` block to paste into a Claude Code settings file. |
| `install.py` | Idempotently add/remove the hook entry in a settings file. |
| `tests/test_hook.py` | Unit tests for the decision logic (`python3 -m unittest`). |

## Quick start

```sh
# 1. Make sure the skill-guard binary is on PATH (see repo root install.sh),
#    or set "skill_guard_bin" in the config to an absolute path.
skill-guard version

# 2. Register the hook in this project's .claude/settings.json
python3 hooks/install.py               # or: --user for ~/.claude/settings.json

# 3. Configure it (optional — sensible defaults apply)
cp hooks/config.example.json .claude/skillguard-hook.config.json
```

`install.py` writes the same block found in `settings.snippet.json`; paste that
by hand instead if you prefer. Restart Claude Code so it reloads settings.

## Enforcement modes

Set `"mode"` in the config. Each mode maps a verification **state** to allow/deny:

| State (from `skill-guard verify`) | `log` | `block-invalid` | `enforce` |
|-----------------------------------|:-----:|:---------------:|:---------:|
| **trusted** — valid signature from a trusted key | allow | allow | allow |
| **unverified** — no trust roster / unknown key (`SG-PRV-005`) | allow | allow | **deny** |
| **unsigned** — no `.skillsig` at all | allow | allow | **deny** |
| **revoked / expired** (`SG-PRV-004`) | allow | **deny** | **deny** |
| **invalid** — signature does not verify (`SG-PRV-002`) | allow | **deny** | **deny** |
| **tampered** — Merkle mismatch, content changed (`SG-PRV-003`) | allow | **deny** | **deny** |

- **`log`** — audit only. Never blocks; every decision is written to the log file.
  Start here to see what *would* be blocked before you turn on enforcement.
- **`block-invalid`** — block a signature that is present but **compromised**
  (tampered, invalid, revoked). Unsigned and unverified skills still run. This is
  the "block when non-valid" outcome.
- **`enforce`** — require a **valid, trusted** signature; block everything else,
  including unsigned and unverified. This is the "block unless valid *and*
  trusted" outcome.

Two orthogonal knobs:

- **`unresolved_action`** (`allow` | `warn` | `deny`) — a skill with no local
  bundle to verify (and not on the built-in allowlist). `log` mode never blocks
  regardless.
- **`on_error`** (`allow` | `deny`) — what to do if the hook itself fails (binary
  missing, timeout). Default `allow` (fail-open) so a broken hook never bricks the
  agent; set `deny` (fail-closed) for hardened deployments.

`builtin_allowlist` names first-party skills the harness provides (e.g. `dataviz`)
that can't be signed — they are always allowed and kept out of the noise.

## Configuration

Resolution order (first found wins), merged over built-in defaults:

1. `$SKILLGUARD_HOOK_CONFIG`
2. `$CLAUDE_PROJECT_DIR/.claude/skillguard-hook.config.json`
3. `~/.claude/skillguard-hook.config.json`

See `config.example.json` for every field. Paths support `${CLAUDE_PROJECT_DIR}`,
`${HOME}`, `~`, and `$VAR`.

## The audit log

Every decision appends one JSON line to `log_file` (default
`.claude/skillguard-hook.log`) — `skill`, `state`, `block`, `bundle`, `reason`,
`mode`, `session`. This is your record in `log` mode and your forensics trail in
enforcing modes. It is `.gitignore`d.

## Other agents (Cursor & the Agent SDK)

The verification core (`skill-guard verify` → state → allow/deny) is agent-neutral.
The `evaluate()` / `classify()` / `decide()` functions in `skillguard_hook.py` are
pure and reusable. Ports:

- **Claude Agent SDK (Python/TS).** The SDK exposes the same `PreToolUse` hook
  contract *and* a `canUseTool` permission callback. Import `evaluate()` and return
  a deny decision from either — same logic, in-process, no subprocess parsing of
  the CLI. This is the tightest integration when you build your own agent.

- **Cursor.** Cursor has no per-tool-call pre-execution hook today, so verify at
  the boundaries you *do* control:
  - a **pre-commit / CI gate** (`skill-guard verify` over every bundle under
    `.cursor/` or your skills dir; fail the build on a bad state — reuse
    `enforce` semantics);
  - a **wrapper MCP server** that proxies skill/tool execution and calls
    `evaluate()` before forwarding;
  - a Cursor **Rule** that instructs the agent to run `skill-guard verify` before
    using any third-party skill (advisory, not enforced — weaker than a hook).

- **Any harness with shell hooks.** Point its pre-execution hook at
  `skillguard_hook.py`; if its event JSON differs, adjust `trigger_tools` and the
  small field lookups in `main()`.

## Testing

```sh
python3 -m unittest discover -s hooks/tests    # pure-logic unit tests
```

To exercise it end-to-end, sign a skill, add its key to a `.skillguard.yaml`
trust roster, then pipe a fake event in:

```sh
echo '{"tool_name":"Skill","tool_input":{"skill":"my-skill"}}' \
  | CLAUDE_PROJECT_DIR="$PWD" python3 hooks/skillguard_hook.py
```
