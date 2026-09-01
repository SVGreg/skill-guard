package verify

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/SVGreg/skill-guard/pkg/attest"
	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/scan"
	"github.com/SVGreg/skill-guard/pkg/skill"
)

// Errors a card document can fail with before it can be checked against
// anything. These are malformed *input*, not a failed verification: a file that
// is not a skill-guard card cannot make a false claim about a bundle, so the
// caller reports them as usage errors rather than as tampering.
var (
	ErrNotACard          = errors.New("not a skill-guard skill card")
	ErrUnsupportedSchema = errors.New("unsupported skill-card schema version")
	ErrNoContentHash     = errors.New("card has no content_hash (emitted before v1 gained one)")
)

// CardResult is the outcome of checking a card against the bundle it claims to
// describe: does this card's subject exist, and is it this one?
type CardResult struct {
	// Card is the parsed card, for a caller that wants to show its claims.
	Card *scan.Card
	// CardHash is the content hash the card asserts; BundleHash is the root
	// recomputed from the bundle on disk. Match reports whether they agree —
	// the whole point of the check.
	CardHash   string
	BundleHash string
	Match      bool
	Findings   []model.Finding
}

// cardEnvelope is what `scan --format skill-card` writes: the card body under
// "card", emission metadata under "envelope". A caller may hand us either that
// document or a bare card, and both are ordinary things to have on disk — the
// envelope is what the command emits, the bare card is what a consumer gets
// after picking the body out of one — so both are accepted.
type cardEnvelope struct {
	Card json.RawMessage `json:"card"`
}

// ParseCard reads a card document, accepting either the emitted envelope or a
// bare card body. It validates only what must hold for the card to be checkable
// at all: it is a skill-guard card, of a version this build understands, and it
// carries a content hash.
func ParseCard(data []byte) (*scan.Card, error) {
	var env cardEnvelope
	body := data
	if err := json.Unmarshal(data, &env); err == nil && len(env.Card) > 0 {
		body = env.Card
	}
	var card scan.Card
	if err := json.Unmarshal(body, &card); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotACard, err)
	}
	if card.Type == "" {
		return nil, fmt.Errorf("%w: no _type field", ErrNotACard)
	}
	if card.Type != scan.CardType {
		return nil, fmt.Errorf("%w: %q (this build understands %q)", ErrUnsupportedSchema, card.Type, scan.CardType)
	}
	if card.ContentHash == "" {
		return nil, ErrNoContentHash
	}
	return &card, nil
}

// VerifyCard checks a parsed card against a bundle. The comparison is the
// bundle's SGMT-1 Merkle root — the same value an attestation signs — so a card
// verifies exactly when it describes this bundle, byte for byte, and stops
// verifying the moment one file changes.
//
// This is deliberately *not* a re-scan. A card's verdict and risk score are
// products of the policy in force when it was emitted; re-deriving them under
// the verifier's own policy would report a policy difference as a card defect.
// What a card can honestly be held to is its subject.
func VerifyCard(b *skill.Bundle, card *scan.Card) *CardResult {
	res := &CardResult{
		Card:       card,
		CardHash:   card.ContentHash,
		BundleHash: attest.MerkleRoot(attest.BundleLeaves(b)),
	}
	res.Match = res.CardHash == res.BundleHash
	if !res.Match {
		// prv() attributes provenance findings to "<attestation>"; this one is
		// about the card document, so it says so.
		f := prv("SG-PRV-007", model.SevCritical,
			"Skill card does not describe this bundle",
			fmt.Sprintf("The card claims content_hash %s; the bundle hashes to %s. The card was either "+
				"emitted for a different skill, or the skill changed after the card was written.",
				res.CardHash, res.BundleHash),
			"Re-emit the card for this bundle: skill-guard scan <path> --format skill-card --out card.json.")
		f.File = "<skill-card>"
		res.Findings = append(res.Findings, f)
	}
	return res
}

// CardVerificationFailed decides exit code 2 for a card check. A mismatch is a
// claim that has been shown false, which is the same class as SG-PRV-003.
func CardVerificationFailed(res *CardResult) bool { return !res.Match }
