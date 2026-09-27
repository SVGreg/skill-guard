package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/SVGreg/surfaceguard/pkg/attest"
	"github.com/SVGreg/surfaceguard/pkg/attest/oms"
	"github.com/SVGreg/surfaceguard/pkg/policy"
	"github.com/SVGreg/surfaceguard/pkg/report"
	"github.com/SVGreg/surfaceguard/pkg/skill"
	sgverify "github.com/SVGreg/surfaceguard/pkg/verify"
)

// Provenance states for one bundle in a multi-bundle verify, worst first.
// Only the first five fail verification (exit 2): unverified and unsigned
// are states the consumer has not decided on yet, exactly as single-bundle
// verify reports them — unless the policy requires an attestation.
var verifyStates = []string{"error", "merkle-mismatch", "invalid", "revoked", "expired", "unverified", "unsigned", "verified"}

func stateRank(s string) int {
	for i, v := range verifyStates {
		if v == s {
			return i
		}
	}
	return len(verifyStates)
}

// verifyRow is one bundle's line in the multi-bundle table.
type verifyRow struct {
	path, state, formats, signer string
	failed                       bool
}

// stateOf names what one format's result says about the bundle.
func stateOf(res *sgverify.Result) string {
	has := func(id string) bool {
		for _, f := range res.Findings {
			if f.RuleID == id {
				return true
			}
		}
		return false
	}
	switch {
	case !res.Present:
		return "unsigned"
	case has("SG-PRV-003"):
		return "merkle-mismatch"
	case res.Revoked:
		return "revoked"
	case res.Expired:
		return "expired"
	case has("SG-PRV-002") || has("SG-PRV-004"):
		return "invalid"
	case res.Trusted:
		return "verified"
	}
	return "unverified"
}

// verifyOne checks every signature a discovered bundle carries and folds
// them into one row: the worst state across formats. A bundle that cannot be
// loaded fails closed — an audit that cannot read a skill cannot vouch for it.
func verifyOne(c skill.Candidate, pol policy.Policy, policyDir string) verifyRow {
	row := verifyRow{path: c.Path, state: "unsigned", formats: "-", signer: "-"}
	b, err := skill.LoadBundle(c.RealPath)
	if err != nil {
		row.state, row.failed, row.signer = "error", true, err.Error()
		return row
	}
	var results []*sgverify.Result
	var formats []string
	if env, err := attest.ReadEnvelope(attest.SigPath(c.RealPath)); err == nil && env != nil {
		results = append(results, sgverify.Verify(b, env, pol.Trust))
		formats = append(formats, sgverify.FormatSGMT1)
	} else if _, statErr := os.Stat(attest.SigPath(c.RealPath)); statErr == nil {
		// Present but unreadable: malformed, not unsigned.
		row.state, row.failed, row.formats, row.signer = "invalid", true, sgverify.FormatSGMT1, "unreadable attestation"
		return row
	}
	if data, err := os.ReadFile(oms.SigPath(b.Root)); err == nil {
		results = append(results, sgverify.VerifyOMSAt(b, data, pol.Trust, policyDir))
		formats = append(formats, sgverify.FormatOMS)
	}
	if len(results) == 0 {
		row.failed = pol.Attestation.Required
		return row
	}
	row.formats = strings.Join(formats, "+")
	row.state = "verified"
	for _, res := range results {
		if s := stateOf(res); stateRank(s) < stateRank(row.state) {
			row.state = s
		}
		if res.Publisher != "" && row.signer == "-" {
			row.signer = res.Publisher
		}
		row.failed = row.failed || verificationFailed(res, pol)
	}
	return row
}

// runMultiVerify verifies every bundle discovered under roots and prints one
// table. Exit 2 if any bundle fails verification, as for a single bundle.
func runMultiVerify(roots []string, policyPath string) error {
	cands, derrs, err := skill.Discover(roots, skill.DiscoverOptions{})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fail(3, "%v\n  every <path> must exist: a skill directory, a SKILL.md file, or a folder to search.", err)
		}
		return fail(3, "%v", err)
	}
	if len(cands) == 0 {
		return fail(3, "no skills found under %s", strings.Join(quoteAll(roots), ", "))
	}
	pol, err := policy.Load(policyPath)
	if err != nil {
		return fail(3, "cannot use policy %q: %v\n  expected a valid .surfaceguard.yaml file with a trust roster.", policyPath, err)
	}
	policyDir := "."
	if policyPath != "" {
		policyDir = filepath.Dir(policyPath)
	}

	rows := make([]verifyRow, len(cands))
	tally := map[string]int{}
	failed := 0
	for i, c := range cands {
		rows[i] = verifyOne(c, pol, policyDir)
		tally[rows[i].state]++
		if rows[i].failed {
			failed++
		}
	}
	// Worst first, path as the tiebreak, so the order is total.
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0; j-- {
			a, b := rows[j-1], rows[j]
			if stateRank(a.state) < stateRank(b.state) || (a.state == b.state && a.path <= b.path) {
				break
			}
			rows[j-1], rows[j] = b, a
		}
	}

	var parts []string
	for _, s := range verifyStates {
		if tally[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", tally[s], s))
		}
	}
	fmt.Printf("verify: %d skills — %s — %d failed verification\n\n", len(rows), strings.Join(parts, ", "), failed)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATE\tFORMAT\tSIGNER\tPATH")
	for _, r := range rows {
		// No colour: escape codes would count toward tabwriter's column
		// widths and misalign the table. The state words carry the meaning.
		// The signer comes from the attestation (or a load error naming the
		// bundle's own paths) and is attacker-controlled until verified, so it
		// is sanitized like every other scanned string.
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.state, r.formats, report.Sanitize(r.signer), report.Sanitize(r.path))
	}
	_ = tw.Flush()
	for _, d := range derrs {
		fmt.Printf("  note: %s\n", report.Sanitize(d.Error()))
	}
	if failed > 0 {
		return exitErr{code: 2, msg: "verification failed"}
	}
	return nil
}
