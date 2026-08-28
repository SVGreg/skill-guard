# Skill cards: what the ecosystem actually publishes (M5-01 spike)

The roadmap asks for skill cards "conforming to the agentskills.io / NVIDIA-style
schema — declared capabilities, `content_hash`, risk tier, AST findings summary,
signature status" (§M5). This is the primary-source check of that assumption,
run before committing `scan.Card` to a shape.

**Bottom line: neither source defines that artifact.** One publishes a *skill
format*, the other a *human-authored disclosure document*. The field list the
roadmap names is skill-guard's own card, and there is no external schema to
conform to. M5-06 is rewritten accordingly.

---

## Sources

| What | URL | Read |
|---|---|---|
| agentskills.io specification | `https://github.com/agentskills/agentskills/blob/main/docs/specification.mdx` | 2026-08-28 |
| agentskills.io repo tree | `https://github.com/agentskills/agentskills` | 2026-08-28 |
| NVIDIA skill card template | `https://github.com/NVIDIA/Trustworthy-AI/blob/main/Skill%20Card.md` | 2026-08-28 |
| NVIDIA verified agent skills | `https://developer.nvidia.com/blog/nvidia-verified-agent-skills-provide-capability-governance-for-ai-agents/` | 2026-08-28 |

## 1. agentskills.io defines the skill format, not a card

The specification covers the directory structure, the `SKILL.md` frontmatter
(`name`, `description`, and optional `license`, `compatibility`, `metadata`,
`allowed-tools`), `scripts/` `references/` `assets/`, progressive disclosure, and
validation rules.

It contains **no card, no provenance, no signature, and no hash concept** — a
search of the specification for "card", "sign", "hash", "verif", and "trust"
returns only Mintlify `<Card>` documentation components, which are page-layout
markup, not a schema.

So there is nothing at agentskills.io to conform *to*. What it does give us is
the authority for the frontmatter fields skill-guard already parses, which is
worth citing where we describe them.

## 2. NVIDIA's skill card is a prose disclosure document

The published template (CC0) is Markdown with human-filled placeholders:

> Description · Owner · License/Terms of Use · Use Case · Deployment Geography ·
> Requirements/Dependencies (credential type, "do not include secrets in
> prompts/logs") · **Known Risks and Mitigations** · References · Skill Output
> (type, format, parameters) · Evaluation Agent · Evaluation Tasks · Evaluation
> Metrics · Evaluation Results · Skill Version *(signing identifier)* · Ethical
> Considerations

It is a model-card-style transparency artifact: who built this, how is it
licensed, what could go wrong, how was it evaluated. There is **no
`content_hash`, no risk tier, no findings summary, and no signature status** —
"Skill Version: [Signing Identifier]" is a human-typed line, not a verification
result.

Crucially, it is **authored by the publisher**, not derived from the artifact. A
scanner cannot honestly generate "Deployment Geography" or "Evaluation Results";
inventing them would be worse than omitting them.

## 3. What NVIDIA *does* do machine-readably — and it is signing

The same programme signs skills as **`skill.oms.sig`**, an OpenSSF Model Signing
detached signature covering every file in the skill directory, verified with the
`model-signing` Python package against **`nv-agent-root-cert.pem`**, an NVIDIA
root certificate.

Three things follow, all corroborating M4:

- `skill.oms.sig` as a filename is the ecosystem convention, not just our choice
  (the OMS spec itself only asks for a `.sig` extension — see `oms-notes.md §3`).
- OMS-over-a-skill-directory is exactly the usage `oms-notes.md §7` flagged as
  unproven. It is now proven: a major vendor ships it.
- The trust anchor is **a vendor root**, which is precisely the gap the roadmap
  identified — and precisely what skill-guard's consumer-pinned `trust.roots`
  refuses to reproduce.

## 4. Compared with `scan.Card`

skill-guard's card already carries what the roadmap listed, minus one field:

| Roadmap field | `scan.Card` | Note |
|---|---|---|
| declared capabilities | `permissions.allowed_tools`, `permissions.external_refs` | ✅ |
| risk tier | `risk_tier`, plus `risk_score` | ✅ |
| AST findings summary | `ast_findings`, `counts`, `max_severity`, `verdict` | ✅ |
| signature status | `attestation{present,signature_valid,trusted,publisher}` | ✅ |
| `content_hash` | **absent** | ❌ the one real gap |

Without a content hash a card cannot be tied to the bundle it describes, which
makes "verify a card" impossible — so that is the substantive work in M5-06,
not schema translation.

## 5. Decision

1. **Keep our own shape.** There is no normative schema to adopt. `scan.Card`
   stays the emitted artifact, gains `content_hash`, and gets a documented,
   versioned schema of its own (`_type` already carries a version marker).
2. **Do not generate an NVIDIA-style card.** Its fields are publisher
   disclosures a scanner cannot derive. If a bundle *ships* one, note its
   presence in our card rather than parsing prose.
3. **Make cards verifiable**, which is the capability nobody else offers: check a
   card against the bundle it claims to describe, so a card cannot be detached
   from its subject, edited, and re-presented.
4. **Cite agentskills.io** as the authority for the frontmatter fields we read,
   since it *is* normative there.

## 6. Still unverified

- Whether agentskills.io intends to add provenance to the specification; nothing
  in the repo suggests work in progress, but the project is young.
- Whether NVIDIA publishes a machine-readable *schema* for the card at
  `docs.nvidia.com/skills` beyond the Markdown template. The template repo
  contains only prose templates (`Skill Card.md`, `Model Card++`, `Agent Card`,
  `System Card`), so any such schema is not in the public template repo.
