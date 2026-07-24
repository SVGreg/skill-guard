---
name: sg-release
description: Cut a skill-guard release — run preflight checks, determine the next version from conventional commits, push, then merge the release-please PR and verify the published binaries. Use when asked to release, cut/publish a version, or ship a release.
---

# Releasing skill-guard

Releases are driven by **release-please + GoReleaser** (`.github/workflows/release.yml`).
You never create tags or GitHub Releases by hand. The flow is:

```
conventional commits on main
  → release-please opens/updates a "release PR" (version bump + CHANGELOG)
  → merging that PR creates the vX.Y.Z tag + GitHub Release
  → the goreleaser job attaches cross-platform binaries + checksums.txt
```

All GitHub interaction uses `gh`. If `gh` is unauthenticated, export the keychain token
per-command: `GH_TOKEN=$(printf "protocol=https\nhost=github.com\n" | git credential fill | sed -n 's/^password=//p') gh ...`
Never print the token.

**Branch protection**: `main` is covered by the `protect-main` ruleset (direct pushes,
force pushes, and deletion are blocked; PRs need 1 approval). Only the repo owner
(admin role) bypasses it — that's who this skill assumes is running it, since step 3
pushes to `main` directly and step 4 merges the release PR without a review. If `git push
origin main` is rejected with a ruleset/protected-branch error, the invoking user is not
an admin bypass actor: push a feature branch and open a PR instead, and get an approval
before merging — don't try to work around the ruleset.

## 1. Preflight (all must pass before pushing anything)

Run from the repo root:

1. `git status --short` — working tree must be clean, or contain only the changes being
   released. Never release with unrelated uncommitted edits mixed in.
2. On `main` and synced: `git fetch && git status -sb` shows no divergence from `origin/main`.
3. `gofmt -l .` — empty output.
4. `go vet ./...` — clean.
5. `go test ./...` — all pass.
6. Exit-code smoke test (the release contract):
   `go run ./cmd/skill-guard scan testdata/malicious` exits **1**;
   `go run ./cmd/skill-guard scan testdata/benign` exits **0**.
7. Dogfood: `go run ./cmd/skill-guard scan .claude/skills/sg-release` must pass —
   skill-guard's own skills must survive skill-guard.

If any step fails, stop and fix before proceeding — the release workflow re-runs tests and
will refuse to publish otherwise.

## 2. Determine the expected version

release-please computes the version; your job is to **predict it, sanity-check it, and
override it only when justified**.

List unreleased commits:

```sh
last=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
git log ${last:+$last..}HEAD --pretty='%s'
```

Bump rules (from `release-please-config.json` — keep this table in sync if that changes):

| Commits since last tag | Pre-1.0 bump | Post-1.0 bump |
|---|---|---|
| `fix:` only | patch | patch |
| any `feat:` | patch | minor |
| any `!` / `BREAKING CHANGE:` | minor | major |

Overrides — only with explicit intent (e.g. first release, or graduating to 1.0.0): add an
empty commit with a `Release-As` footer:

```sh
git commit --allow-empty -m "chore: release X.Y.Z" -m "Release-As: X.Y.Z"
```

Commits that are not conventional-commit formatted are ignored by release-please. If the
work that must be released only has non-conventional messages, it won't trigger a release
PR — fix by adding a properly-typed empty commit describing the change.

## 3. Push and wait for the release PR

1. `git push origin main`.
2. Wait for the `release` workflow run on main to finish:
   `gh run list --workflow=release --branch=main --limit=1` then `gh run watch <id>`.
3. Find the release PR: `gh pr list --search "chore(main): release" --state open`.
   It is labeled `autorelease: pending`.
4. **Verify the version in the PR title matches your prediction from step 2.** If it
   doesn't, understand why before continuing (mis-typed commit? missing footer?).
5. Check CI is green on the PR: `gh pr checks <number>`.

If no release PR appears: check the workflow run logs. The most common cause is the repo
setting "Allow GitHub Actions to create and approve pull requests" being disabled
(Settings → Actions → General → Workflow permissions).

## 4. Trigger the release

Merge the release PR (squash keeps history clean):

```sh
gh pr merge <number> --squash
```

Then watch the resulting `release` workflow run on main — this time the
`release-please` job creates the tag + GitHub Release and the `goreleaser` job must also
run: `gh run watch <id>`.

## 5. Verify the release

1. `gh release view vX.Y.Z` — must exist, with changelog notes and **7 assets**:
   5 archives (linux/darwin × amd64/arm64 `.tar.gz`, windows-amd64 `.zip`) + `checksums.txt`
   + source archive behavior varies; the 6 named assets are what matters.
2. Install-path smoke test on this machine:
   ```sh
   VERSION=vX.Y.Z INSTALL_DIR=$(mktemp -d) sh install.sh
   ```
   It must print `Installed: skill-guard X.Y.Z` — this proves asset naming, checksums, and
   the ldflags version injection all line up.
3. Report the release URL to the user.

## Troubleshooting

- **Tag exists but no binaries**: the goreleaser job failed — `gh run view <id> --log-failed`.
  Fix, then re-run the job (`gh run rerun <id> --failed`); GoReleaser `release.mode:
  keep-existing` makes re-runs safe.
- **Wrong version released**: don't delete tags. Ship a corrective release with a
  `Release-As` footer.
- **Release PR stuck on old version**: release-please updates the PR on every push to main;
  force a refresh by re-running the release workflow.
