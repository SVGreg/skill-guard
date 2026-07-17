package attest

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/skillguard/skill-guard/pkg/skill"
)

// USFPayloadType is the DSSE payloadType for the USF manifest-field signature.
const USFPayloadType = "application/vnd.skillguard.usf-fields.v1"

// USFFields computes the OWASP Universal Skill Format fields (design §7.5):
// content_hash = SGMT-1 root (normalized SKILL.md), signature = ed25519 over the
// PAE of content_hash. Same crypto path as the detached attestation.
func USFFields(ctx context.Context, b *skill.Bundle, signer Signer) (contentHash, signature string, err error) {
	contentHash = MerkleRoot(BundleLeaves(b))
	if contentHash == "" {
		return "", "", fmt.Errorf("empty bundle")
	}
	sig, err := signer.Sign(ctx, PAE(USFPayloadType, []byte(contentHash)))
	if err != nil {
		return "", "", err
	}
	return contentHash, "ed25519:" + base64.StdEncoding.EncodeToString(sig), nil
}

// WriteUSFFields inserts content_hash and signature into the SKILL.md
// front-matter at skillMDPath, replacing any existing reserved lines.
func WriteUSFFields(skillMDPath, contentHash, signature string) error {
	content, err := os.ReadFile(skillMDPath)
	if err != nil {
		return err
	}
	m := fmBlockRe.FindSubmatchIndex(content)
	if m == nil {
		return fmt.Errorf("%s has no front-matter block", skillMDPath)
	}
	open := content[m[2]:m[3]]
	body := reservedLine.ReplaceAll(content[m[4]:m[5]], nil)
	closeD := content[m[6]:m[7]]
	rest := content[m[1]:]

	var out []byte
	out = append(out, open...)
	out = append(out, fmt.Sprintf("content_hash: %q\n", contentHash)...)
	out = append(out, fmt.Sprintf("signature: %q\n", signature)...)
	out = append(out, body...)
	out = append(out, closeD...)
	out = append(out, rest...)
	return os.WriteFile(skillMDPath, out, 0o644)
}
