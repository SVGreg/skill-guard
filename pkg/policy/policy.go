// Package policy models .surfaceguard.yaml: gating thresholds, waivers, allowlists,
// and the trust roster (design §10.4). Trust and policy live in one document.
package policy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/SVGreg/surfaceguard/pkg/attest"
	"github.com/SVGreg/surfaceguard/pkg/model"
	"gopkg.in/yaml.v3"
)

// Policy is the loaded, defaulted configuration.
// APIVersion is the policy schema id written by `surfaceguard policy init`.
// Unlike a rule pack it is not gated: a policy is the *user's* file, and the
// field stays optional.
const APIVersion = "surfaceguard.svgreg.net/policy.v1"

type Policy struct {
	APIVersion  string          `yaml:"apiVersion"`
	FailOn      string          `yaml:"fail_on"`
	WarnOn      string          `yaml:"warn_on"`
	Attestation AttestationRule `yaml:"attestation"`
	Waivers     []Waiver        `yaml:"waivers"`
	Allowlists  Allowlists      `yaml:"allowlists"`
	Trust       Trust           `yaml:"trust"`

	// Scoring is the per-severity risk-score weight override from design §9.
	// Like Trust.Include/PackKeys it is documented (it appears in the §10.4
	// example policy) but **not implemented** — riskScore in pkg/scan hardcodes
	// the weights. The field exists so the documented example still parses, and
	// Load rejects it when non-empty rather than letting an override that
	// changes nothing look like it worked.
	Scoring map[string]float64 `yaml:"scoring"`
}

// AttestationRule controls provenance gating.
type AttestationRule struct {
	Required      bool `yaml:"required"`
	WarnIfMissing bool `yaml:"warn_if_missing"`
}

// Waiver suppresses a rule for matching paths until it expires.
//
// Path is a filepath.Match glob, which matches a **single path segment**: `*`
// does not cross `/`, so `scripts/*.sh` covers `scripts/setup.sh` but a bare
// `*` covers `SKILL.md` and NOT `scripts/setup.sh`. Leave Path empty to waive
// the rule bundle-wide — that, not `*`, is the "everywhere" form. `**` is not
// supported (it behaves as a single `*`).
//
// MerkleRoot pins a waiver to one exact version of one bundle: its SGMT-1 root,
// the `content_hash` a skill card and `guard` report. A pinned waiver may omit
// Rule, which waives **every** rule for that bundle — the "I authored this
// version" form a skill's own author needs when scanning their own work. It
// lives only in the consumer's policy, never in a bundle, and stops matching the
// moment one byte of the bundle changes, so it cannot silently cover a later
// rug-pull. Reason is mandatory for it. Bundle, when set, must also equal the
// manifest's name — a readability check, since the name is self-asserted and
// the root is what binds.
type Waiver struct {
	Rule       string `yaml:"rule"`
	Path       string `yaml:"path"`
	Reason     string `yaml:"reason"`
	Expires    string `yaml:"expires"` // YYYY-MM-DD
	Bundle     string `yaml:"bundle"`
	MerkleRoot string `yaml:"merkle_root"` // sha256:<64 hex>
}

// BundleID identifies the bundle a finding came from, for pinned waivers.
type BundleID struct {
	Name       string
	MerkleRoot string
}

var merkleRootRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// HasPinnedWaivers reports whether any waiver is pinned to a Merkle root, so a
// caller can skip computing the root when none could match.
func (p Policy) HasPinnedWaivers() bool {
	for _, w := range p.Waivers {
		if w.MerkleRoot != "" {
			return true
		}
	}
	return false
}

// Allowlists holds domains/paths exempt from certain rules. Like
// Trust.Include/PackKeys and Scoring it is part of the documented schema and is
// **not implemented**: nothing in pkg/ or cmd/ reads either field. Load rejects
// it when non-empty rather than letting it fail silently, because of the four
// unimplemented fields this is the one whose silence is most dangerous — it
// reads as a *suppression* control, so a consumer who allowlists their internal
// host and keeps seeing SG-NET-001 may conclude the findings are noise, while
// one who trusts the allowlist stops reading those findings altogether.
type Allowlists struct {
	Domains []string `yaml:"domains"`
	Paths   []string `yaml:"paths"`
}

// Trust is the roster (design §10.4).
//
// Include and PackKeys are part of the documented schema (design §10.4) but are
// **not implemented**: nothing reads them. They are kept as fields so a policy
// declaring them parses, and Load rejects them when non-empty rather than
// letting them fail silently — a silently-ignored `include:` means the org's
// roster was never loaded and every skill reports as unverified, which reads
// exactly like "the publisher didn't sign it".
type Trust struct {
	Include  []string `yaml:"include"`
	Keys     []Key    `yaml:"keys"`
	PackKeys []Key    `yaml:"pack_keys"`
	// Identities restricts which publisher identities are acceptable, on top of
	// the key roster. See IdentityRule and Allows.
	Identities []IdentityRule `yaml:"identities"`
	// Roots are the certificate authorities whose signing certificates may be
	// trusted, for keyless (certificate-bound) signatures. **Empty by design:**
	// surfaceguard ships no root of trust, vendor or otherwise. A consumer who
	// wants to accept Sigstore-issued certificates supplies the Fulcio roots
	// themselves, in their own file, and can pin any other CA the same way.
	Roots []Root `yaml:"roots"`
	// LogKeys are the transparency logs whose signed checkpoints are accepted.
	// Configuring any makes checkpoint verification **mandatory**: a bundle
	// whose checkpoint no configured key signs is not trusted. Leaving the
	// section out keeps the inclusion proof's arithmetic check (which proves
	// the entry is in *a* tree) without requiring proof of *whose*.
	LogKeys []LogKey `yaml:"log_keys"`
	// Revoked lists key ids **and** identities that are never trusted, whatever
	// else matches. One list rather than two because revocation is one decision
	// — "not this publisher, in any form" — and splitting it invites revoking a
	// key while leaving its identity admissible.
	Revoked []string `yaml:"revoked"`
}

// IdentityRule admits publisher identities by pattern rather than by key, which
// is how CI-signed skills are trusted: the signing key is short-lived and
// unknowable in advance, but the identity ("repo:org/repo") is stable.
//
// **The identity must be cryptographically bound to the signature** before a
// rule can admit it. Today that means a roster key's own identity field; the
// keyless path (M4-09) will supply certificate identities. A self-asserted
// identity from an attestation's publisher block is never sufficient — anyone
// can write any identity into a statement they sign with their own key.
//
// No issuer or root is built in. surfaceguard has no vendor root of trust and
// will not acquire one: the consumer decides who they trust, in their own file.
type IdentityRule struct {
	// Pattern is matched against the identity claim. `*` matches any run of
	// characters, including `/`, so "repo:acme/*" covers "repo:acme/tools" and
	// "repo:acme/tools/sub". An empty pattern is rejected at load: a rule that
	// matches everything is what having no rules already means.
	Pattern string `yaml:"pattern"`
	// Issuer, when set, must equal the OIDC issuer the identity came from. It
	// has no effect until certificate identities land (M4-09); it is accepted
	// now so a policy written today keeps its meaning then.
	Issuer string `yaml:"issuer"`
}

// Key is a trusted public key/identity.
type Key struct {
	KeyID     string `yaml:"keyid"`
	Algorithm string `yaml:"algorithm"`
	PublicKey string `yaml:"public_key"` // base64
	Identity  string `yaml:"identity"`
}

// Revokes reports whether the roster revokes this key id or identity. Both are
// checked against one list, so revoking "oidc:sam@example.com" also stops a
// signature whose key id is unknown but whose bound identity matches.
func (t Trust) Revokes(values ...string) bool {
	for _, r := range t.Revoked {
		for _, v := range values {
			if v != "" && r == v {
				return true
			}
		}
	}
	return false
}

// Allows reports whether a bound identity is admissible under the identity
// rules. With no rules configured it returns true — identity rules narrow an
// existing roster, they are not a second gate everyone must opt into, and
// making them mandatory would break every policy written before they existed.
//
// issuer is compared only against rules that specify one.
func (t Trust) Allows(identity, issuer string) bool {
	if len(t.Identities) == 0 {
		return true
	}
	for _, rule := range t.Identities {
		if rule.Issuer != "" && rule.Issuer != issuer {
			continue
		}
		if matchIdentity(rule.Pattern, identity) {
			return true
		}
	}
	return false
}

// matchIdentity implements the `*` glob. filepath.Match is deliberately not
// used: its `*` stops at `/`, which would make "repo:acme/*" fail to match
// "repo:acme/tools/sub" — the opposite of what a reader of that pattern
// expects. `?` and `[` are not special here, so an identity containing them is
// matched literally.
func matchIdentity(pattern, identity string) bool {
	if pattern == "" || identity == "" {
		return false
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == identity
	}
	rest := identity
	if !strings.HasPrefix(rest, parts[0]) {
		return false
	}
	rest = rest[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(rest, parts[i])
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(parts[i]):]
	}
	last := parts[len(parts)-1]
	return strings.HasSuffix(rest, last) && len(rest) >= len(last)
}

// LogKey is one trusted transparency log. KeyID is the base64 log id carried in
// the bundle's tlogEntries; PublicKey is base64 PKIX DER, as produced by
// `openssl x509 -pubkey` or Rekor's published key material.
type LogKey struct {
	Name      string `yaml:"name"`
	KeyID     string `yaml:"key_id"`
	PublicKey string `yaml:"public_key"`
}

// Root is one trusted certificate authority, given inline or by path. Exactly
// one of PEM and Path may be set.
type Root struct {
	Name string `yaml:"name"`
	PEM  string `yaml:"pem"`
	Path string `yaml:"path"`
}

// Default returns the built-in policy used when no file is present.
func Default() Policy {
	return Policy{
		APIVersion:  APIVersion,
		FailOn:      "high",
		WarnOn:      "medium",
		Attestation: AttestationRule{Required: false, WarnIfMissing: true},
	}
}

// Load reads a policy file, applying defaults for unset fields. An empty path
// returns Default().
//
// Decoding is **strict** (KnownFields) and the result is validated, because a
// policy file is a security control: every way it can be wrong must be loud.
// Silently dropping `failon:` (a typo for `fail_on:`) leaves the threshold at
// its default while the author believes they tightened it, and silently
// dropping `waiver:` (a typo for `waivers:`) leaves findings unwaived while the
// author believes they reviewed them. Both used to load without a word.
func Load(path string) (Policy, error) {
	p := Default()
	if path == "" {
		return p, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	// io.EOF is an empty (or comment-only) document: no overrides, not an error.
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return p, err
	}
	if p.FailOn == "" {
		p.FailOn = "high"
	}
	if p.WarnOn == "" {
		p.WarnOn = "medium"
	}
	if err := p.validate(); err != nil {
		return p, err
	}
	return p, nil
}

// validate rejects a policy that would misbehave silently. It is deliberately
// stricter than the accessors below: FailOnSeverity/WarnOnSeverity still fall
// back to a safe default, because Policy values are also built directly in
// code and by tests, but a policy *file* never reaches those fallbacks.
func (p Policy) validate() error {
	if _, err := model.ParseSeverity(p.FailOn); err != nil {
		return fmt.Errorf("fail_on %q is not a severity (valid: critical, high, medium, low, info)", p.FailOn)
	}
	if _, err := model.ParseSeverity(p.WarnOn); err != nil {
		return fmt.Errorf("warn_on %q is not a severity (valid: critical, high, medium, low, info)", p.WarnOn)
	}
	for i, w := range p.Waivers {
		if w.MerkleRoot != "" {
			if !merkleRootRe.MatchString(w.MerkleRoot) {
				return fmt.Errorf("waivers[%d]: merkle_root %q is not sha256:<64 lowercase hex> (copy it from `surfaceguard guard --format json` content_hash)", i, w.MerkleRoot)
			}
			if strings.TrimSpace(w.Reason) == "" {
				return fmt.Errorf("waivers[%d]: a waiver pinned to merkle_root must give a reason", i)
			}
		} else if w.Bundle != "" {
			return fmt.Errorf("waivers[%d]: bundle is only meaningful with merkle_root, which is what pins the waiver to content", i)
		}
		if w.Rule == "" && w.MerkleRoot == "" {
			return fmt.Errorf("waivers[%d]: rule is required (a waiver with no rule matches nothing); only a waiver pinned to merkle_root may omit it", i)
		}
		if w.Path != "" {
			// filepath.Match only reports a bad pattern once it is used, and
			// WaiverFor discards that error — so an unclosed `[` would make the
			// waiver silently inert forever. Catch it here instead.
			if _, err := filepath.Match(w.Path, "probe"); err != nil {
				return fmt.Errorf("waivers[%d] (rule %s): invalid path glob %q: %v", i, w.Rule, w.Path, err)
			}
		}
		if w.Expires != "" {
			if _, err := time.Parse("2006-01-02", w.Expires); err != nil {
				return fmt.Errorf("waivers[%d] (rule %s): expires %q is not a YYYY-MM-DD date", i, w.Rule, w.Expires)
			}
		}
	}
	seen := map[string]int{}
	for i, k := range p.Trust.Keys {
		if k.KeyID == "" {
			return fmt.Errorf("trust.keys[%d]: keyid is required", i)
		}
		// The roster is indexed by keyid (pkg/verify), so a duplicate silently
		// replaces the public key bound to that id — an append is enough to
		// re-point a trusted id at another key. Never resolve that quietly.
		if j, dup := seen[k.KeyID]; dup {
			return fmt.Errorf("trust.keys[%d]: duplicate keyid %q (already declared at trust.keys[%d]); the later entry would silently replace the earlier key", i, k.KeyID, j)
		}
		seen[k.KeyID] = i
		// A roster entry that cannot verify anything is worse than no entry at
		// all. pkg/verify keys the roster by keyid, so a malformed entry still
		// makes the key "known" — verifySignature then returns false, and
		// because len(roster.Keys) != 0 the caller reports **SG-PRV-002
		// "Invalid or untrusted signature" at critical** instead of the
		// SG-PRV-005 "no roster configured" it would report for an empty
		// roster. A typo in the consumer's own policy is therefore surfaced as
		// tampering by the publisher. The same reasoning the log_keys check
		// below already applies, on the roster that actually gates trust.
		if err := validateKeyMaterial(k); err != nil {
			return fmt.Errorf("trust.keys[%d] (keyid %s): %w", i, k.KeyID, err)
		}
	}
	for i, r := range p.Trust.Roots {
		switch {
		case r.PEM == "" && r.Path == "":
			return fmt.Errorf("trust.roots[%d]: needs either pem or path (a root with neither trusts nothing and would silently make every keyless signature unverifiable)", i)
		case r.PEM != "" && r.Path != "":
			return fmt.Errorf("trust.roots[%d]: set either pem or path, not both", i)
		}
	}
	for i, k := range p.Trust.LogKeys {
		if k.PublicKey == "" {
			return fmt.Errorf("trust.log_keys[%d]: public_key is required (an entry without one would make every checkpoint unverifiable while looking configured)", i)
		}
	}
	for i, rule := range p.Trust.Identities {
		if rule.Pattern == "" {
			return fmt.Errorf("trust.identities[%d]: pattern is required (an empty pattern matches nothing, and a rule matching everything is what omitting the section already means)", i)
		}
		if strings.ContainsAny(rule.Pattern, "?[") {
			return fmt.Errorf("trust.identities[%d]: pattern %q uses %q, which is matched literally here — only %q is a wildcard", i, rule.Pattern, "?[", "*")
		}
	}
	if len(p.Trust.Include) > 0 {
		return errors.New("trust.include is documented but not implemented — the listed rosters would be ignored and every signature would report as unverified; inline the keys under trust.keys for now")
	}
	if len(p.Trust.PackKeys) > 0 {
		return errors.New("trust.pack_keys is documented but not implemented — rule packs are not signature-checked, so the listed keys would be ignored; remove the section")
	}
	if len(p.Scoring) > 0 {
		return errors.New("scoring weights are documented but not implemented — pkg/scan hardcodes the per-severity points, so the override would change nothing; remove the section")
	}
	if len(p.Allowlists.Domains) > 0 || len(p.Allowlists.Paths) > 0 {
		return errors.New("allowlists are documented but not implemented — nothing reads allowlists.domains or allowlists.paths, so the listed hosts and paths would still be reported at full severity; use waivers (which carry a reason and an expiry) instead")
	}
	return nil
}

// validateKeyMaterial reports why a roster entry could never verify a
// signature. It mirrors pkg/verify.verifySignature, which is the authority:
// that function decodes public_key as base64, dispatches on a lower-cased,
// trimmed algorithm, and requires an Ed25519 key to be exactly
// ed25519.PublicKeySize bytes. Anything it would reject is checked here so the
// policy author hears about it at load time instead of reading a critical
// finding about someone else's signature.
//
// The ECDSA key is deliberately only base64-checked, not parsed: parsing PKIX
// DER here would duplicate the crypto dispatch rather than mirror a constraint,
// and the failure it would catch (valid base64 that is not a P-256 key) is far
// rarer than the two this does catch — an omitted field and a mistyped
// algorithm.
func validateKeyMaterial(k Key) error {
	alg := strings.ToLower(strings.TrimSpace(k.Algorithm))
	switch alg {
	case "", attest.AlgEd25519, attest.AlgECDSAP256:
	default:
		return fmt.Errorf("algorithm %q is not recognized (valid: %s, %s; empty means %s) — an unrecognized algorithm verifies nothing",
			k.Algorithm, attest.AlgEd25519, attest.AlgECDSAP256, attest.AlgEd25519)
	}
	if strings.TrimSpace(k.PublicKey) == "" {
		return errors.New("public_key is required (an entry with a keyid but no key verifies nothing, while still making the keyid \"known\" to the roster)")
	}
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil {
		return fmt.Errorf("public_key is not valid base64: %v", err)
	}
	if alg == "" || alg == attest.AlgEd25519 {
		if len(raw) != ed25519PublicKeySize {
			return fmt.Errorf("public_key decodes to %d bytes, but an %s key is %d (a truncated or partially-pasted key)",
				len(raw), attest.AlgEd25519, ed25519PublicKeySize)
		}
	}
	return nil
}

// ed25519PublicKeySize mirrors ed25519.PublicKeySize. It is spelled out rather
// than imported so this package keeps no crypto dependency for one constant.
const ed25519PublicKeySize = 32

// FailOnSeverity resolves the fail threshold.
func (p Policy) FailOnSeverity() model.Severity {
	s, err := model.ParseSeverity(p.FailOn)
	if err != nil {
		return model.SevHigh
	}
	return s
}

// WarnOnSeverity resolves the warn threshold.
func (p Policy) WarnOnSeverity() model.Severity {
	s, err := model.ParseSeverity(p.WarnOn)
	if err != nil {
		return model.SevMedium
	}
	return s
}

// WaiverFor returns a non-empty reason if an unexpired waiver covers rule+file.
// Waivers pinned to a Merkle root never match here: without the bundle's
// identity there is nothing to pin against. Use WaiverForBundle.
func (p Policy) WaiverFor(ruleID, file string) string {
	return p.WaiverForBundle(ruleID, file, BundleID{})
}

// WaiverForBundle is WaiverFor with the bundle's identity, which a waiver
// pinned to merkle_root must match exactly. A pinned waiver with no rule
// covers every rule in that bundle.
func (p Policy) WaiverForBundle(ruleID, file string, id BundleID) string {
	for _, w := range p.Waivers {
		if w.MerkleRoot != "" {
			if id.MerkleRoot == "" || w.MerkleRoot != id.MerkleRoot {
				continue
			}
			if w.Bundle != "" && w.Bundle != id.Name {
				continue
			}
		}
		if w.Rule != "" && w.Rule != ruleID {
			continue
		}
		if w.Expires != "" {
			exp, err := time.Parse("2006-01-02", w.Expires)
			if err != nil {
				// A malformed expiry cannot bound the waiver. Fail closed: do not
				// honor it, so the suppressed finding surfaces rather than being
				// silently waived forever by a typo in the date.
				continue
			}
			if time.Now().After(exp) {
				continue // expired waiver no longer applies
			}
		}
		if w.Path == "" {
			return orReason(w.Reason)
		}
		if ok, _ := filepath.Match(w.Path, file); ok {
			return orReason(w.Reason)
		}
	}
	return ""
}

func orReason(s string) string {
	if s == "" {
		return "waived"
	}
	return s
}
