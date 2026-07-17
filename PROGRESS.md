# skill-guard — Implementation Progress & Handoff

**Goal of first runnable version:** M1 + M2 from `docs/skill-guard-design.md` §14 — an end-to-end
`skill-guard scan | sign | verify` CLI + library over a real bundle, with a static rule engine,
SGMT-1 Merkle + DSSE Ed25519 signing/verification, policy/trust, and TP/FP fixtures.

**Module:** `github.com/SVGreg/skill-guard` (rename later if a real org/remote is chosen).
**Toolchain:** Go 1.26.2. Deps: `gopkg.in/yaml.v3`, `github.com/spf13/cobra`. Everything else stdlib.

## Durability protocol
- `git init` done. Commit after each working increment (`go build` + `go test` green).
- This file is the handoff: on resume, read it, run `go build ./... && go test ./...`, continue at the next unchecked item.
- A scheduled cloud agent is set up to continue autonomously between interactive sessions.

## Status checklist
- [x] Repo scaffold: git, go.mod, .gitignore, PROGRESS.md
- [x] pkg/model — Severity/Verdict/Finding/Counts core types (written)
- [x] pkg/skill — SKILL.md front-matter + bundle parser, file walk, language detection (written)
- [x] pkg/rules — rule-pack schema, YAML loader, matcher primitives (RE2 etc.), confidence + context modifiers (written)
- [x] rulepacks/ — built-in packs: injection, network, exec, secret, metadata (written)
- [x] pkg/scan — orchestration, dedup, waivers, verdict + risk score, skill-card (written)
- [x] pkg/attest — SGMT-1 Merkle, DSSE, USF fields, Ed25519 signer, keygen (written)
- [x] pkg/verify + trust — attestation verification, SG-PRV findings (written)
- [x] pkg/policy — .skillguard.yaml model + defaults (incl. trust roster) (written)
- [x] pkg/report — text + json + skill-card formatters (written)
- [x] cmd/skill-guard — cobra CLI: scan, sign, verify, keygen, version (written)
- [x] testdata/ — benign + malicious fixtures (written); SGMT-1 vectors deferred
- [x] tests — rules smoke/paraphrase, attest merkle/normalize/roundtrip, scan benign/malicious (written)
- [x] **build/test/commit** — `go build ./...` clean, `go test ./...` green, `gofmt -l .` clean, `go vet ./...` clean.
- [x] End-to-end smoke verified on the built binary: exit codes 0 (benign pass), 1 (malicious fail),
      2 (verify tamper / Merkle mismatch), 3 (usage). keygen→sign→verify round-trips; trust roster
      flips untrusted→trusted; tamper flips MATCH→MISMATCH(SG-PRV-003); json + skill-card formatters work.
- [ ] scheduled cloud agent for continuation (optional; deferred)
- [x] First-runnable verification done — M1+M2 is runnable.

## RESUME STEPS (run these the moment Bash is available)
1. `cd /Users/sergii/Projects/skill-guard && go build ./... 2>&1 | head`
   - Fix any compile errors. Likely-fragile spots I could not verify by running:
     - RE2 rejects lookaround/backreferences — I removed the ones I found; re-grep packs for `(?<` `(?=` `(?!`.
     - Single-quoted YAML: bare `'` ends the scalar — I doubled `don''?t` (2 spots); re-check any new apostrophes.
     - `func min` in pkg/rules shadows the Go 1.21 builtin (intended; fine).
2. `go test ./... 2>&1 | tail -30` — expect: benign PASS, malicious FAIL(verdict), merkle deterministic,
   USF-field injection leaves root unchanged, SG-INJ-001 paraphrase cases.
3. `gofmt -l . ` and `go vet ./...` — clean up nits.
4. End-to-end smoke:
   `go run ./cmd/skill-guard version`
   `go run ./cmd/skill-guard scan testdata/malicious -v`      (expect verdict: fail, exit 1)
   `go run ./cmd/skill-guard scan testdata/benign`            (expect pass, exit 0)
   `go run ./cmd/skill-guard keygen --out /tmp/sg.key`
   `go run ./cmd/skill-guard sign testdata/benign --key /tmp/sg.key --identity oidc:me`
   `go run ./cmd/skill-guard verify testdata/benign`          (valid sig, merkle MATCH, key untrusted)
   then add the printed key to a policy trust roster and re-verify → trusted.
5. Commit: `git add -A && git commit -m "feat: M1+M2 scan/sign/verify core"` (branch first if needed).
6. Set up the scheduled cloud agent (schedule skill) for autonomous continuation.
7. Report first-runnable status to the user.

## Deferred to later milestones (explicitly NOT in first drop)
- SARIF output + `report merge` (M3), full skill-card envelope split (M3)
- `secret` entropy engine breadth, OSV/CVE (M3/M5), taint/dataflow SG-TAINT-* (M3)
- LLM (T3) + dynamic + YARA engines (M5)
- C-ABI / Python / Node / Rust bindings + daemon (M4)
- Rule-pack signing + external-pack trust enforcement (hardening)
- Keyfile encryption at rest (currently 0600 plaintext + warning) — decide age vs secretbox (M2 open q)
- git-URL / tar / zip bundle sources (parser currently: directory or single SKILL.md)

## Design decisions locked for the code
- SKILL.md normalized form (strip `signature:`/`content_hash:` front-matter lines) is used for BOTH
  the USF `content_hash` and the detached-attestation Merkle leaf, so adding manifest fields never
  changes the root. (design §7.1/§7.5)
- Verdict strings: `pass|warn|fail`. Exit codes: 0 pass/warn, 1 fail, 2 verification failure, 3 usage, 4 internal.
- Emit threshold after context modifiers: confidence ≥ 0.5.
