# skill-guard hooks

Gate **Agent Skill invocations** at the moment an agent tries to use them. When a
model calls a skill, the hook resolves it to a local bundle, runs
`skill-guard guard --format json` against your policy, and allows or blocks the
call based on the configured enforcement mode.

`guard` is the load-time gate: it verifies whichever signature formats the bundle
carries, scans it against the rule packs, applies your policy, and returns one
decision — `allow`, `warn` or `deny`. **The hook reads that one field.** It does
not re-derive a judgment from a report, which is what it used to do by regexing
`SG-PRV-*` ids out of `verify`'s human-readable text. That mattered: the text is
not a contract, only SGMT-1 signatures were noticed (an OMS-signed skill read as
*unsigned*), and nothing was ever scanned — so a malicious skill that happened to
be signed went straight into the model's context.

Nothing in the skill is executed to check it — the bundle is parsed into an inert
model, hashed, and matched against static rules. The hook is **pure Python
stdlib** (3.8+); there is nothing to `pip install`.

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

Set `"mode"` in the config. Each mode decides how much of the gate's answer to
act on:

| `guard` outcome | What produces it | `log` | `block-invalid` | `enforce` |
|-----------------|------------------|:-----:|:---------------:|:---------:|
| **allow** | valid trusted signature (or a policy that does not ask for one), clean scan | allow | allow | allow |
| **warn** | unsigned or unverified publisher under a policy that warns; a `warn` scan verdict | allow | allow | **deny** |
| **deny** | tampered content (`SG-PRV-003`), invalid signature (`SG-PRV-002`), revoked key or expired attestation (`SG-PRV-004`) — **or a failing scan verdict** | allow | **deny** | **deny** |

- **`log`** — audit only. Never blocks; every decision is written to the log file.
  Start here to see what *would* be blocked before you turn on enforcement.
- **`block-invalid`** (default) — block anything the gate denies: a signature that
  is present but **compromised**, and a skill whose **scan fails** your policy's
  `fail_on` threshold. Unsigned and unverified skills still run.
- **`enforce`** — additionally block warnings: require a valid, trusted signature
  and a clean scan.

> **This is stricter than it was before the hook called `guard`.** The old hook
> only ever looked at signatures, so an unsigned malicious skill was allowed in
> every mode short of `enforce` — and there it was blocked for being unsigned,
> not for being malicious. `block-invalid` now blocks it on the scan verdict.
> Run `log` mode for a session first if you are retrofitting this onto a machine
> with skills you have never scanned.

**Provenance outranks the verdict.** A signature that does not match its content
denies whatever the scan found — see `skill-guard guard --help`.

Two orthogonal knobs:

- **`unresolved_action`** (`allow` | `warn` | `deny`) — a skill with no local
  bundle to verify (and not on the built-in allowlist). `log` mode never blocks
  regardless.
- **`on_error`** (`allow` | `deny`) — what to do if the hook itself fails (binary
  missing, timeout, a decision it cannot read). Default `allow` (fail-open) so a
  broken hook never bricks the agent; set `deny` (fail-closed) for hardened
  deployments.
- **`cache_dir`** (default `"-"`, the user cache dir; `""` disables) — where
  decisions are cached. They are keyed by the bundle's **content hash** and the
  policy, so one changed byte or one changed setting is a miss by construction:
  the cache can never serve a stale allow. This is what keeps a skill call off
  the cold scan path (~270 ms) on every invocation.
- **`timeout_seconds`** (default 20) — how long to wait for the gate. The old
  name `verify_timeout_seconds` is still honoured.

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
`mode`, `session`, plus what the gate reported: `verdict`, `risk_score`,
`content_hash`, `signature`, `cache_hit`, and the first few `rules` that drove
the decision. The content hash is what ties a log line to exactly the bytes that
were judged. This is your record in `log` mode and your forensics trail in
enforcing modes. It is `.gitignore`d.

```json
{"ts":"2026-09-01T17:07:14+0300","mode":"block-invalid","skill":"evil-skill",
 "state":"deny","block":true,"reason":"scan verdict: fail (critical findings, risk 100/100)",
 "verdict":"fail","risk_score":100,"content_hash":"sha256:94fadb79…",
 "signature":{"present":false,"valid":false,"trusted":false},"cache_hit":false,
 "rules":["SG-NET-007","SG-INJ-002","SG-SEC-005","SG-EXE-006","SG-NET-002"]}
```

## Other agents (Cursor & the Agent SDK)

The gate (`skill-guard guard` → outcome → allow/deny) is agent-neutral. The
`evaluate()` / `outcome_of()` / `decide()` functions in `skillguard_hook.py` are
pure and reusable. Ports:

- **Claude Agent SDK (Python/TS).** The SDK exposes the same `PreToolUse` hook
  contract *and* a `canUseTool` permission callback. Import `evaluate()` and return
  a deny decision from either — same logic, in-process. In Go, skip the subprocess
  entirely and call `guard.Guard(path, guard.Options{…})` from `pkg/guard`, which
  is the same decision this hook shells out for.

- **Cursor.** Cursor has no per-tool-call pre-execution hook today, so verify at
  the boundaries you *do* control:
  - a **pre-commit / CI gate** (`skill-guard guard` over every bundle under
    `.cursor/` or your skills dir; a denial exits 1, so the build fails on it);
  - a **wrapper MCP server** that proxies skill/tool execution and calls
    `evaluate()` before forwarding;
  - a Cursor **Rule** that instructs the agent to run `skill-guard guard` before
    using any third-party skill (advisory, not enforced — weaker than a hook).

- **Any harness with shell hooks.** Point its pre-execution hook at
  `skillguard_hook.py`; if its event JSON differs, adjust `trigger_tools` and the
  small field lookups in `main()`.

## Testing

```sh
python3 -m unittest discover -s hooks/tests    # pure-logic unit tests
```

To exercise it end-to-end, pipe a fake event in. Using the repo's own fixtures as
installed skills, in the default `block-invalid` mode:

```sh
$ echo '{"tool_name":"Skill","tool_input":{"skill":"evil-skill"}}' \
    | CLAUDE_PROJECT_DIR="$PROJ" python3 hooks/skillguard_hook.py
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
 "permissionDecisionReason": "skill-guard blocked skill 'evil-skill': scan verdict: fail
 (critical findings, risk 100/100)"}, "systemMessage": "…"}

$ echo '{"tool_name":"Skill","tool_input":{"skill":"good-skill"}}' \
    | CLAUDE_PROJECT_DIR="$PROJ" python3 hooks/skillguard_hook.py
{"systemMessage": "skill-guard: skill 'good-skill' allowed but no attestation present",
 "suppressOutput": true}
```

The first call never reaches the model; the second proceeds with a heads-up. To
exercise the provenance half, sign a skill, add its key to a `.skillguard.yaml`
trust roster, then edit a byte of the bundle and call it again.
