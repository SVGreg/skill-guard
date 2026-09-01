# skill-guard skill card — schema v1

**`_type: skillguard.net/skill-card/v1`** · emitted by `skill-guard scan --format skill-card`
· checked by `skill-guard verify --card <file>`

A skill card is skill-guard's machine-readable summary of one scanned bundle: what the skill
declares it can do, what the scan found, whether it is signed — and, uniquely, **which bundle
the card is about**, as a hash a verifier can recompute.

That last part is the reason this document exists. The M5-01 spike
([`skill-card-notes.md`](skill-card-notes.md)) went looking for a card schema to conform to and
found none: **agentskills.io** specifies the skill *format* and has no card, hash, or signature
concept at all, and **NVIDIA's "skill card"** is a CC0 prose disclosure template — owner,
licence, deployment geography, evaluation results — whose fields a scanner cannot honestly
derive. So this schema is our own, and its distinguishing property is that a card can be
**checked against its subject** instead of merely being well-formed.

## 1. Versioning

`_type` is the version marker. It changes when a consumer that understands the old version could
**misread** the new one:

| Change | `_type` |
|---|---|
| A field is added | unchanged — consumers must ignore unknown fields |
| A field's meaning or type changes, or a field is removed | `…/v2` |
| A field's *value set* widens (a new `risk_tier`, a new `verdict`) | unchanged |

`pkg/verify.ParseCard` rejects any `_type` this build does not know, rather than reading a
future card through v1 assumptions. Cards emitted before v1 gained `content_hash` are rejected
too: without it there is nothing to check.

## 2. The document

`scan --format skill-card` writes the card inside an emission envelope:

```json
{
  "card": { "_type": "skillguard.net/skill-card/v1", "...": "..." },
  "envelope": {
    "scanned_at": "2026-09-01T13:59:44Z",
    "skillguard_version": "0.2.1",
    "source": "testdata/benign"
  }
}
```

The split is deliberate: **the card is the reproducible part** — scan the same bytes with the
same rules and policy and you get the same card — while the envelope records when and by what
this particular emission happened, which necessarily differs run to run. `verify --card` accepts
either the whole document or a bare card body, since a consumer that has pulled the body out of
an envelope still holds a valid card.

## 3. Fields

| Field | Type | Meaning |
|---|---|---|
| `_type` | string | Schema id and version (§1). |
| `name` | string | The skill's declared `name`, from `SKILL.md` front-matter. Publisher-controlled. |
| `description` | string | The skill's declared `description`. Publisher-controlled. |
| `content_hash` | string | **The subject.** `sha256:<hex>` — the bundle's SGMT-1 Merkle root (§4). |
| `verdict` | string | `pass` · `warn` · `fail`, under the policy in force at emission. |
| `risk_score` | int | 0–100, Σ (severity points × confidence), capped. |
| `risk_tier` | string | `L0`–`L3`, the banded form of `risk_score`. |
| `max_severity` | string | Highest severity among emitted findings. |
| `counts` | object | Findings per severity: `critical`, `high`, `medium`, `low`, `info`. |
| `waived` | int | Findings a policy waiver suppressed. Non-zero means the verdict was influenced by local policy. |
| `ast_findings` | string[] | Sorted OWASP Agentic Skills ids (`AST01`…`AST10`) the findings map to. |
| `permissions.allowed_tools` | string[] | The manifest's declared `allowed-tools`. Never `null`. |
| `permissions.external_refs` | string[] | Distinct outbound URLs found anywhere in the bundle — the skill's outbound surface, one entry per destination. Never `null`. |
| `attestation` | object \| null | Signature summary (`present`, `signature_valid`, `trusted`, `publisher`) when a verifier filled it; `null` from a plain scan, which does not verify signatures. |
| `publisher_cards` | string[] | Bundle-relative paths of publisher-authored card documents shipped alongside the skill — `Skill Card.md`, `model-card.md`, `agent card.md`, `system_card.md` (case- and separator-insensitive, prose extensions only). Never `null`; **never parsed** (§5). |

Consumers must **ignore unknown fields**: v1 can gain fields without a version bump.

## 4. `content_hash` — what a card check proves

`content_hash` is the bundle's **SGMT-1 Merkle root** (`docs/skill-guard-design.md §7.1`) — the
same value a `.skillsig` attestation signs — recomputed by the card emitter whether or not a
signature exists, so it means the same thing either way. `SKILL.md` enters the tree in its
*normalized* form, so adding USF `content_hash`/`signature` front-matter fields with
`sign --emit-manifest-fields` does not invalidate a card emitted before signing.

```sh
skill-guard scan ./my-skill --format skill-card --out card.json
skill-guard verify ./my-skill --card card.json
```

```
card: "card.json"
subject: "./my-skill"
schema: skillguard.net/skill-card/v1
content hash: MATCH
  card:   sha256:df97944f0c4772c981608e5a728cd5c4e469b83f3de97d5df29afac0f9bf0854
  bundle: sha256:df97944f0c4772c981608e5a728cd5c4e469b83f3de97d5df29afac0f9bf0854
card claims: "pdf-table-extractor" — verdict "pass", risk 0/100 ("L0")
```

**What the check establishes:** this card describes *this* bundle, byte for byte. Change one
byte of any bundled file and the check fails with **`SG-PRV-007`** and exit code **2** — the same
class as a Merkle mismatch, because it is the same failure: a claim about content that the
content contradicts. A card therefore cannot be detached from a clean skill, edited, and
re-presented over a modified one.

**What it does not establish:**

- **Not authenticity.** A card is unsigned JSON; anyone can write one, including one whose
  `content_hash` is honestly computed over a malicious bundle. For "who says so", verify a
  signature (`skill-guard verify`) — the card check answers "about what?", not "from whom?".
  Card `name`/`description`/`verdict` are attacker-controlled strings and the CLI prints them
  quoted for that reason.
- **Not the verdict.** `verify --card` deliberately does **not** re-scan. A card's `verdict` and
  `risk_score` are products of the rule packs and policy in force when it was emitted;
  re-deriving them under the verifier's own policy would report a policy difference as a card
  defect. To re-judge a skill, scan it.

Exit codes: **0** the card describes the bundle · **2** it does not (`SG-PRV-007`) · **3** the
file is unreadable, is not a skill-guard card, is a schema version this build does not know, or
predates `content_hash`. A malformed document is a usage error, not a verification failure: it
makes no claim to be wrong about.

## 5. Publisher cards are noted, never parsed

If a bundle ships an NVIDIA-style prose card, `publisher_cards` records its path and nothing
else. Those fields — owner, licence, deployment geography, known risks, evaluation results — are
disclosures only the publisher can make. Deriving them from a static scan would be inventing
them, and a card that mixes derived facts with invented ones is worse than one that omits them.
A reviewer who sees a path here knows to go read it.

## 6. Related

- [`skill-card-notes.md`](skill-card-notes.md) — the M5-01 spike: what the ecosystem actually
  publishes, and why this schema is our own.
- [`skill-guard-design.md`](skill-guard-design.md) §7.1 (SGMT-1), §9 (the card), §10.5 (exit codes).
- [`rule-verification.md`](rule-verification.md) — `SG-PRV-001…007`.
- [`signature-formats.md`](signature-formats.md) — when to sign with SGMT-1 vs OMS.
