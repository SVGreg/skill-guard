package attest

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SVGreg/surfaceguard/pkg/skill"
)

// USFPayloadType is the DSSE payloadType for the USF manifest-field signature.
// This namespace must stay disjoint from PayloadType: the USF signature is
// published in plaintext in SKILL.md front-matter, and the payloadType is what
// stops it being replayed as a full attestation.
const USFPayloadType = "application/vnd.surfaceguard.usf-fields.v1"

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
//
// SKILL.md is the skill's source of truth and nothing surfaceguard holds can
// regenerate it, so it is rewritten atomically: the new bytes go to a temp file
// in the same directory, which is renamed over the original only once fully
// written. The old in-place os.WriteFile truncated first, so a crash, a full
// disk or a signal mid-write left the skill truncated (issue #140). The rename
// also keeps the file's mode — os.WriteFile's perm applied only on creation, so
// an existing SKILL.md always kept its own mode, and a rename must not silently
// normalize it to the temp file's 0600. A symlinked SKILL.md is refused, as for
// every other write in this package.
func WriteUSFFields(skillMDPath, contentHash, signature string) error {
	if err := refuseSymlink(skillMDPath); err != nil {
		return err
	}
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
	return replaceFile(skillMDPath, out)
}

// replaceFile atomically replaces the regular file at path with data, keeping
// its permission bits. The temp file is created beside path so the rename never
// crosses a filesystem, and it is removed on any failure.
func replaceFile(path string, data []byte) (err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(fi.Mode().Perm()); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
