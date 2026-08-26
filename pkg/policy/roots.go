package policy

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// CertPool builds the trusted-root pool for keyless verification.
//
// baseDir resolves relative `path` entries — a policy file names roots relative
// to itself, not to whatever directory the command happens to run in.
//
// An empty roster returns (nil, nil): no roots configured means keyless
// signatures cannot be verified, which is a reportable state, not an error.
// skill-guard has no fallback root to quietly substitute.
func (t Trust) CertPool(baseDir string) (*x509.CertPool, error) {
	if len(t.Roots) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	for i, r := range t.Roots {
		pem := []byte(r.PEM)
		if r.Path != "" {
			path := r.Path
			if !filepath.IsAbs(path) {
				path = filepath.Join(baseDir, path)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("trust.roots[%d] (%s): %w", i, rootName(r, i), err)
			}
			pem = data
		}
		if !pool.AppendCertsFromPEM(pem) {
			// Silently ignoring an unparseable root would leave the consumer
			// believing they had pinned a CA they had not.
			return nil, fmt.Errorf("trust.roots[%d] (%s): no PEM certificates could be parsed", i, rootName(r, i))
		}
	}
	return pool, nil
}

func rootName(r Root, i int) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("root %d", i)
}
