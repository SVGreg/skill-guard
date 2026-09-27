# Where agents load skills from

> **Status:** M9-01 spike output, checked **2026-09-27** against each vendor's own documentation.
> This page is the source of truth for `pkg/locations/locations.yaml` (M9-06). Every registry
> entry must cite a row here, and every row cites a primary source. Vendor paths drift between
> releases, so re-check a row before changing the registry entry that cites it.

`surfaceguard scan --installed` (M9-07) audits the directories below. It only *reads* them: it
never runs an agent, never reads the agent's settings to decide what is "enabled", and never
touches the network. A location that doesn't exist on the machine is reported as absent, not
treated as an error.

## Conventions used below

- **Scope.** `user` is under the home directory. `project` is relative to the project directory
  (`--project-dir`, default cwd). `plugin` is a bundle-in-a-package location an installer manages.
  `admin` is a system-wide directory an organization deploys.
- **`~`** is `os.UserHomeDir()` (`%USERPROFILE%` on Windows). The docs write home-relative paths in
  POSIX form and don't give separate Windows paths, except where a row says otherwise.
- **Walk-up.** Some agents also load `project`-scope directories from every ancestor of the working
  directory up to the repository root. That is marked in the notes, and the registry records it as
  a flag rather than a list of paths.
- **Symlinks.** Whether the agent follows a symlinked skill directory. This matters because
  `LoadBundle` refuses a symlinked root. Discovery (M9-02) resolves the entry and loads the real
  path.

## Claude Code

Sources:
- [skills](https://code.claude.com/docs/en/skills)
- [plugin loading, "Find plugins on disk"](https://code.claude.com/docs/en/plugins/loading)
- [managed settings](https://code.claude.com/docs/en/managed-settings)

| Scope | Path | Override | Notes |
|---|---|---|---|
| user | `~/.claude/skills/<name>/SKILL.md` | `CLAUDE_CONFIG_DIR` replaces `~/.claude` | Symlinked skill dirs supported. Two links to one target load once. |
| user | `~/.claude/skills/synced/<name>/SKILL.md` | as above | Skills synced from claude.ai. `synced` is a reserved folder, so it's already covered by discovering under `~/.claude/skills`. |
| project | `.claude/skills/<name>/SKILL.md` | — | **Walk-up**: loads from parent directories up to the repo root, and from nested `<subdir>/.claude/skills` when files there are touched. |
| plugin | `<plugins-root>/cache/<marketplace>/<plugin>/<version>/skills/<name>/SKILL.md` | `CLAUDE_CODE_PLUGIN_CACHE_DIR` replaces `<plugins-root>` (default `~/.claude/plugins`) | The installed copy, one directory per version. A plugin can also put `SKILL.md` at its root. Old versions keep an `.orphaned_at` marker for 14 days. |
| plugin | `<plugins-root>/marketplaces/<name>/…` | as above | The marketplace **clone**. Relative-path plugins from a local-directory marketplace load in place, but a git-hosted marketplace's clone isn't what loads. Scan it as a superset, not as the installed set. |
| plugin | `<plugins-root>/synced/…` | as above | Plugins synced from claude.ai. |
| admin | `<managed-dir>/.claude/skills/<name>/SKILL.md` | — | `<managed-dir>` is `/etc/claude-code` (Linux/WSL), `/Library/Application Support/ClaudeCode` (macOS), or `C:\Program Files\ClaudeCode` (Windows). See the discrepancy below. |

Not a skill location: Claude Code doesn't scan a project's `.claude/plugins/`. Plugin directories
under `~/.claude/skills/` or `.claude/skills/` with a `.claude-plugin/plugin.json` load as
`@skills-dir` plugins, so discovery under those roots covers them already.

**Discrepancy.** The skills page gives Windows managed skills as
`C:\ProgramData\Anthropic\Claude Code\.claude\skills\`. The managed-settings page says the
system directory is `C:\Program Files\ClaudeCode\`, and that the `C:\ProgramData\ClaudeCode` path
is legacy and **no longer read**. The registry uses `C:\Program Files\ClaudeCode` and lists the
`ProgramData` form as a second candidate. Scanning a directory the agent doesn't read costs a stat,
while missing one it does read is a blind spot.

## Codex CLI

Source: [Codex — build skills](https://learn.chatgpt.com/docs/build-skills) (redirected from
`developers.openai.com/codex/skills`).

| Scope | Path | Override | Notes |
|---|---|---|---|
| project | `$CWD/.agents/skills` | — | **Walk-up**: also `$CWD/../.agents/skills` and `$REPO_ROOT/.agents/skills`. |
| user | `~/.agents/skills` | — | This is the shared convention (see [`.agents`](#the-shared-agents-convention)). |
| admin | `/etc/codex/skills` | — | System-wide organizational skills. |
| system | *(bundled in the binary)* | — | Not on disk as a bundle, so out of scope. |

Codex follows symlinked skill folders. `~/.codex/skills` doesn't appear in the current Codex doc.
It's kept as a **legacy** candidate because Cursor's docs still list it as a compatibility path
(below). `CODEX_HOME` is referenced only indirectly in the doc, so the registry doesn't key a skills
path on it until a source states that.

## Gemini CLI

Source: [Gemini CLI — skills](https://geminicli.com/docs/cli/skills/)

| Scope | Path | Notes |
|---|---|---|
| user | `~/.gemini/skills` | Alias: `~/.agents/skills`. Within a tier, `.agents` wins. |
| project | `.gemini/skills` | Alias: `.agents/skills`. |
| plugin | extension-bundled skills | The doc gives no on-disk path, so this is **not in the registry** until one is documented. |

The doc doesn't say how symlinks are handled.

## GitHub Copilot

Source: [About agent skills](https://docs.github.com/en/copilot/concepts/agents/about-agent-skills)
(covers the cloud agent, code review, Copilot CLI, the Copilot app, and agent mode in VS Code and
JetBrains).

| Scope | Path |
|---|---|
| project | `.github/skills`, `.claude/skills`, `.agents/skills` |
| user | `~/.copilot/skills`, `~/.agents/skills` |

The doc doesn't say which Copilot surface reads which path.

## Cursor

Source: [Cursor — skills](https://cursor.com/docs/context/skills)

| Scope | Path |
|---|---|
| project | `.agents/skills`, `.cursor/skills`, plus compatibility `.claude/skills` and `.codex/skills` |
| user | `~/.agents/skills`, `~/.cursor/skills`, plus compatibility `~/.claude/skills` and `~/.codex/skills` |

Cursor "walks the skills root recursively and picks up any `SKILL.md` it finds". That matches
M9-02's discovery, which descends through non-bundle directories.

## OpenCode

Source: [OpenCode — skills](https://opencode.ai/docs/skills/)

| Scope | Path | Notes |
|---|---|---|
| project | `.opencode/skills`, `.claude/skills`, `.agents/skills` | **Walk-up** from cwd to the git worktree root. |
| user | `~/.config/opencode/skills`, `~/.claude/skills`, `~/.agents/skills` | |

## Goose

Source: [goose — using skills](https://goose-docs.ai/docs/guides/context-engineering/using-skills/)
(the old `block.github.io/goose/...` URL returns 404).

| Scope | Path | Notes |
|---|---|---|
| user | `~/.agents/skills` | Recommended. |
| project | `.agents/skills` | Recommended. |
| plugin | `~/.agents/plugins/<plugin>/` | Skills shipped by installed plugins. |
| project | `.goose/skills`, `.claude/skills` | Backward compatibility. |
| user | `~/.claude/skills`, plus "platform-specific config directories" | The doc names no path for the config directory. Earlier Goose material names `~/.config/goose/skills`, which the registry keeps as a **legacy** candidate. |

## The shared `.agents` convention

Source: [agentskills.io — adding skills support](https://agentskills.io/client-implementation/adding-skills-support)

The Agent Skills site recommends that every client scan `<project>/.agents/skills/` and
`~/.agents/skills/` next to its own directory, and many do: Codex, Gemini, Copilot, Cursor,
OpenCode and Goose. For discovery it recommends:
- skip `.git/` and `node_modules/`
- bound depth (4–6) and directory count (~2000)
- treat project-level skills as untrusted input

M9-02's defaults are looser on depth (8) because they also serve `scan <repo>`, where a skill can
sit deeper than an installed-skills root.

**Consequence for the registry:** `~/.agents/skills` is **one location shared by several agents**,
not one per agent. The registry lists it once, under agent id `agents`, and every agent that reads
it names it in `reads_shared`. `scan --installed --agent codex` then includes it without scanning
the same bundle twice.

## What this means for M9-06

The registry schema needs everything below, and nothing more:

1. **Per-OS path templates** with `~` and `${ENV}` expansion, plus an **override variable** that
   replaces a prefix: `CLAUDE_CONFIG_DIR` for `~/.claude`, `CLAUDE_CODE_PLUGIN_CACHE_DIR` for
   `~/.claude/plugins`.
2. **Bounded globs**, for the Claude Code plugin cache
   (`cache/*/*/*/skills` plus the plugin root itself) and Goose plugins (`~/.agents/plugins/*`).
   Every other location is a fixed directory.
3. **A `walk_up` flag** for project-scope entries of agents that read ancestors up to the repo root
   (Claude Code, Codex, OpenCode).
4. **A `status` of `documented` / `legacy`**, so `locations` can show which candidates a vendor no
   longer documents. Legacy entries are still scanned.
5. **Shared locations**, meaning `~/.agents/skills` and `.agents/skills`, owned by the `agents`
   pseudo-agent and referenced from others by `reads_shared`.
6. **A `source`** on each entry, linking back to this page's row.

Out of scope, and deliberately so: reading `installed_plugins.json` or `enabledPlugins` to narrow
the set to what is *enabled*. That would parse agent config for a policy decision, so the audit
scans what is **on disk**, which is a superset of what loads.
