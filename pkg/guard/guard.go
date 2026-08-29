// Package guard answers one question — may this skill enter the model's
// context? — in a single call, for callers sitting in an agent loop or an
// install step.
//
// It is the entrypoint `docs/skill-guard-design.md §11.1` specifies. Everything
// it does is already available from pkg/skill, pkg/scan and pkg/verify; what
// this package adds is the *decision*, so every caller does not re-derive one
// from a scan report and a verification result. The existing Claude Code hook
// is the cautionary example: it parses `verify`'s text output to work out what
// the binary already knew.
//
// Nothing here executes anything from the bundle, and nothing touches the
// network.
package guard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/attest/oms"
	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/policy"
	"github.com/SVGreg/skill-guard/pkg/rules"
	"github.com/SVGreg/skill-guard/pkg/scan"
	"github.com/SVGreg/skill-guard/pkg/skill"
	"github.com/SVGreg/skill-guard/pkg/verify"
)

// Mode selects when the gate is being asked, which changes how a provenance
// warning is treated.
//
// The two modes differ by **escalation, never relaxation**: install mode turns
// provenance warnings into denials, and load mode is exactly as strict as it
// has always been. Making the load gate laxer than the install gate would be
// backwards — load is the moment untrusted content reaches the model — so the
// difference is that at install time a human is present, the fix is cheap
// (fetch a signed copy, add the key), and nothing is mid-session.
type Mode string

const (
	// ModeLoad is the default: a skill is about to enter a model's context.
	ModeLoad Mode = "load"
	// ModeInstall is a skill being added to a machine, where a provenance
	// warning is worth stopping for.
	ModeInstall Mode = "install"
)

// Outcome is the gate's answer.
type Outcome string

const (
	// Allow: nothing found that policy gates on.
	Allow Outcome = "allow"
	// Warn: proceed, but something is worth a human's attention — a warn-level
	// verdict, or an unsigned skill under a policy that only warns about that.
	Warn Outcome = "warn"
	// Deny: do not load. The scan verdict failed, or verification did.
	Deny Outcome = "deny"
)

// Decision is what a caller acts on. It carries the reason as text because the
// caller is usually about to show it to a human — a hook message, a CI log — and
// "denied" without a reason is not actionable.
type Decision struct {
	Outcome Outcome `json:"outcome"`
	Reason  string  `json:"reason"`
	Path    string  `json:"path"`

	// ContentHash identifies exactly what was judged: the bundle's SGMT-1
	// Merkle root. Two decisions with the same content hash are about the same
	// bytes, which is what makes caching sound (M5-03) and what a skill card
	// will bind to (M5-06).
	ContentHash string `json:"content_hash"`

	Verdict     model.Verdict `json:"verdict,omitempty"`
	RiskScore   int           `json:"risk_score,omitempty"`
	RiskTier    string        `json:"risk_tier,omitempty"`
	MaxSeverity string        `json:"max_severity,omitempty"`
	Counts      model.Counts  `json:"counts,omitempty"`

	// Signature reports provenance, whichever format the bundle carries.
	Signature SignatureState `json:"signature"`

	// Findings that drove a deny or warn, most severe first. Empty on a clean
	// allow. Never the whole report: a decision is not a scan.
	Findings []model.Finding `json:"findings,omitempty"`

	// Mode records which gate answered, since the same bundle and policy can
	// legitimately produce different outcomes at install and at load.
	Mode Mode `json:"mode"`

	// Capabilities is the skill's declared surface. A human approving an
	// install should see what they are admitting; it is reported rather than
	// judged, because a tool grant is not a finding.
	Capabilities Capabilities `json:"capabilities"`

	// Scanned is false when the caller opted out of scanning, so a consumer can
	// tell "nothing found" from "nothing looked".
	Scanned bool `json:"scanned"`

	// CacheHit reports that this decision was served from a cache rather than
	// recomputed. It is not part of the decision — the same bytes under the
	// same policy yield the same answer either way — but a caller measuring
	// latency, or debugging a surprise, needs to know.
	CacheHit bool `json:"cache_hit,omitempty"`
}

// Capabilities is what the bundle declares it may reach.
type Capabilities struct {
	AllowedTools []string `json:"allowed_tools,omitempty"`
	ExternalRefs []string `json:"external_refs,omitempty"`
}

// SignatureState summarizes provenance for the decision.
type SignatureState struct {
	Present   bool   `json:"present"`
	Format    string `json:"format,omitempty"` // sgmt-1 | oms | both
	Valid     bool   `json:"valid"`
	Trusted   bool   `json:"trusted"`
	Publisher string `json:"publisher,omitempty"`
}

// Options configure a Guard call. The zero value scans, uses the default
// policy, and denies on the same threshold the CLI does.
type Options struct {
	// Policy gates the decision. Zero value means policy.Default().
	Policy policy.Policy
	// PolicyDir resolves relative paths inside the policy (trust.roots).
	PolicyDir string
	// SkipScan returns a decision based on provenance alone. Faster, and
	// strictly weaker: use it only where something else has already scanned.
	SkipScan bool
	// Rules overrides the built-in rule set. Nil loads the built-ins.
	Rules    []*rules.Rule
	Contexts []*rules.ContextRule
	// Cache serves repeated decisions about unchanged bytes. Nil disables
	// caching entirely — the default, because a cache is a promise about
	// invalidation and the caller should opt into it.
	Cache Cache
	// Mode selects the gate. Zero value is ModeLoad.
	Mode Mode
}

// Guard loads, verifies and scans a skill, and returns one decision.
//
// The default fail threshold is the policy's, which is `high` — the same bar
// `skill-guard scan` applies (design §15 open question 1 recommends this, and a
// gate that disagreed with the CLI would mean a skill that passes CI is blocked
// at load, or worse, the reverse).
func Guard(path string, opt Options) (*Decision, error) {
	pol := opt.Policy
	if pol.APIVersion == "" && pol.FailOn == "" {
		pol = policy.Default()
	}

	// The bundle is loaded even on a cache hit: the content hash *is* the
	// bundle's contents, so there is no way to know whether an entry applies
	// without reading them. Loading is the cheap part — parsing and hashing a
	// few files — and scanning is what the cache actually saves.
	b, err := skill.LoadBundle(path)
	if err != nil {
		return nil, fmt.Errorf("guard: cannot read skill at %q: %w", path, err)
	}

	contentHash := attest.MerkleRoot(attest.BundleLeaves(b))
	var key string
	if opt.Cache != nil {
		key = CacheKey(contentHash, pol, opt)
		if cached, ok := opt.Cache.Get(key); ok {
			cached.CacheHit = true
			cached.Path = path
			return cached, nil
		}
	}

	d := &Decision{
		Path:         path,
		ContentHash:  contentHash,
		Outcome:      Allow,
		Reason:       "no gating findings",
		Mode:         mode(opt),
		Capabilities: capabilities(b),
	}

	sig, provenance := verifyProvenance(b, path, pol, opt.PolicyDir)
	d.Signature = sig

	if !opt.SkipScan {
		rs, cs := opt.Rules, opt.Contexts
		if rs == nil {
			packs, err := rules.Builtin()
			if err != nil {
				return nil, fmt.Errorf("guard: loading rules: %w", err)
			}
			rs, cs = rules.AllRules(packs), rules.AllContexts(packs)
		}
		rep := scan.New(rs, pol).WithContexts(cs).Scan(b)
		d.Scanned = true
		d.Verdict, d.RiskScore, d.RiskTier = rep.Verdict, rep.RiskScore, rep.RiskTier
		d.MaxSeverity, d.Counts = rep.MaxSeverity.String(), rep.Counts
		d.Findings = gatingFindings(rep.Findings, pol)
	}

	// Provenance findings go first: they are the stronger statement, and they
	// must survive the scan's assignment above — an earlier version assigned
	// the scan's findings over them, which silently dropped a tamper finding
	// whenever the bundle otherwise scanned clean.
	d.Findings = append(provenance, d.Findings...)

	decide(d, pol)

	if opt.Cache != nil {
		opt.Cache.Put(key, d)
	}
	return d, nil
}

// verifyProvenance checks whichever signatures the bundle carries. A verdict is
// not withheld when a signature is absent — that is what policy decides — but a
// signature that is present and *invalid* is a denial regardless of policy,
// since it means the bytes are not the bytes that were signed.
func verifyProvenance(b *skill.Bundle, path string, pol policy.Policy, policyDir string) (SignatureState, []model.Finding) {
	var st SignatureState
	var findings []model.Finding
	policyDir = resolvePolicyDir(policyDir)

	env, envErr := attest.ReadEnvelope(attest.SigPath(path))
	if envErr == nil && env != nil {
		res := verify.Verify(b, env, pol.Trust)
		applySignature(&st, res, verify.FormatSGMT1)
		findings = append(findings, gatingProvenance(res)...)
	}

	if data, err := os.ReadFile(oms.SigPath(b.Root)); err == nil {
		res := verify.VerifyOMSAt(b, data, pol.Trust, policyDir)
		applySignature(&st, res, verify.FormatOMS)
		findings = append(findings, gatingProvenance(res)...)
	}
	return st, findings
}

func applySignature(st *SignatureState, res *verify.Result, format string) {
	if !res.Present {
		return
	}
	switch {
	case !st.Present:
		st.Format = format
	case st.Format != format:
		st.Format = "both"
	}
	st.Present = true
	// Valid/Trusted are ORed across formats on purpose: one good signature is
	// provenance. A *bad* one still denies, via the SG-PRV findings collected
	// alongside — so "trusted by one format, forged in another" cannot pass.
	st.Valid = st.Valid || res.SignatureValid
	st.Trusted = st.Trusted || res.Trusted
	if res.Publisher != "" && st.Publisher == "" {
		st.Publisher = res.Publisher
	}
}

// gatingProvenance keeps the provenance findings that gate a decision.
// SG-PRV-002/003/004 are the ones `verify` exits 2 on; the informational ones
// (no attestation, no roster, no scan recorded) are policy's business, not
// automatic denials.
func gatingProvenance(res *verify.Result) []model.Finding {
	var out []model.Finding
	for _, f := range res.Findings {
		switch f.RuleID {
		case "SG-PRV-002", "SG-PRV-003", "SG-PRV-004":
			out = append(out, f)
		}
	}
	return out
}

func mode(opt Options) Mode {
	if opt.Mode == ModeInstall {
		return ModeInstall
	}
	return ModeLoad
}

// capabilities reads the declared surface straight off the bundle: the
// manifest's allowed-tools and the external references the parser found. It is
// disclosure, not judgement — the rules already flag over-broad grants, and
// repeating that here would double-report it.
func capabilities(b *skill.Bundle) Capabilities {
	c := Capabilities{AllowedTools: b.Manifest.AllowedTools}
	seen := map[string]bool{}
	for _, r := range b.Refs {
		if seen[r.URL] {
			continue
		}
		seen[r.URL] = true
		c.ExternalRefs = append(c.ExternalRefs, r.URL)
	}
	return c
}

func resolvePolicyDir(dir string) string {
	if dir == "" {
		return "."
	}
	return filepath.Clean(dir)
}

// gatingFindings keeps findings at or above the warn threshold, most severe
// first. A decision explains itself; it does not reproduce the report.
func gatingFindings(findings []model.Finding, pol policy.Policy) []model.Finding {
	warn := pol.WarnOnSeverity()
	var out []model.Finding
	for _, f := range findings {
		if f.Severity >= warn {
			out = append(out, f)
		}
	}
	return out
}

// decide turns the gathered state into an outcome. Provenance failures come
// first: a tampered or forged signature is a stronger statement than any scan
// verdict, and reporting "verdict: pass" over a broken signature would be
// actively misleading.
func decide(d *Decision, pol policy.Policy) {
	for _, f := range d.Findings {
		switch f.RuleID {
		case "SG-PRV-003":
			d.Outcome, d.Reason = Deny, "content does not match its signature (tamper or drift)"
			return
		case "SG-PRV-002":
			d.Outcome, d.Reason = Deny, "signature is invalid or does not verify"
			return
		case "SG-PRV-004":
			d.Outcome, d.Reason = Deny, "signing key is revoked, or the attestation has expired"
			return
		}
	}

	if pol.Attestation.Required && !d.Signature.Trusted {
		d.Outcome = Deny
		d.Reason = "policy requires a trusted attestation"
		if d.Signature.Present {
			d.Reason = "policy requires a trusted attestation; this signature is not from a trusted key"
		}
		return
	}

	if d.Scanned {
		switch d.Verdict {
		case model.Fail:
			d.Outcome = Deny
			d.Reason = fmt.Sprintf("scan verdict: fail (%s findings, risk %d/100)", d.MaxSeverity, d.RiskScore)
			return
		case model.Warn:
			d.Outcome = Warn
			d.Reason = fmt.Sprintf("scan verdict: warn (%s findings, risk %d/100)", d.MaxSeverity, d.RiskScore)
		}
	}

	if !d.Signature.Trusted && (pol.Attestation.WarnIfMissing || d.Mode == ModeInstall) {
		reason := "no attestation present"
		if d.Signature.Present {
			reason = "no trusted attestation: the signing key is not in the trust roster"
		}
		if d.Mode == ModeInstall {
			// Escalated, not relaxed: at install a human is present and the fix
			// is cheap — fetch a signed copy, or add the key to the roster.
			// Nothing is mid-session, so stopping costs little.
			d.Outcome = Deny
			d.Reason = reason + " (install mode requires provenance)"
			return
		}
		if d.Outcome == Allow {
			d.Outcome = Warn
		}
		d.Reason = reason
	}
}

// ErrNotFound is returned when the path holds no readable skill bundle.
var ErrNotFound = errors.New("guard: no skill bundle at that path")
