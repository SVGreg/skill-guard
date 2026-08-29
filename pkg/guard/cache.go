package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/SVGreg/skill-guard/pkg/model"
	"github.com/SVGreg/skill-guard/pkg/policy"
)

// Verdict caching for the load-time path.
//
// The point is latency: an agent loop may load the same skills on every turn,
// and re-scanning unchanged bytes to reach the same answer is waste. The
// hazard is the mirror image — answering a question nobody asked, because the
// bundle or the policy has moved since the entry was written. The key below is
// built so that cannot happen: everything a decision depends on is in it.

// Cache stores decisions by key. Implementations must be safe for concurrent
// use; an agent loop is the expected caller.
//
// A miss returns (nil, false). An implementation that cannot answer — a
// corrupt file, an unreadable directory — must report a miss rather than an
// error: a cache is an optimization, and a broken one should cost time, never
// correctness.
type Cache interface {
	Get(key string) (*Decision, bool)
	Put(key string, d *Decision)
}

// CacheKey identifies a decision by everything that could change it: the
// bundle's content hash, a digest of the policy, and the options that alter
// what is even examined.
//
// SkipScan is in the key because a decision made without scanning is not the
// same answer as one made with it — reusing the cheap answer for a full request
// would silently downgrade the gate.
func CacheKey(contentHash string, pol policy.Policy, opt Options) string {
	h := sha256.New()
	fmt.Fprintf(h, "v1\x00%s\x00%t\x00%s\x00", contentHash, opt.SkipScan, mode(opt))
	h.Write(policyDigest(pol))
	// A caller supplying its own rules is not running the built-in set, so its
	// decisions must not be served to a caller who is. The count is a weak
	// discriminator, but the alternative — hashing every compiled rule — costs
	// more than the lookup saves; callers overriding rules are rare and can
	// pass their own cache.
	fmt.Fprintf(h, "rules:%d,ctx:%d", len(opt.Rules), len(opt.Contexts))
	return hex.EncodeToString(h.Sum(nil))
}

// policyDigest hashes the policy. The whole struct is marshalled rather than a
// hand-picked subset: a subset means remembering to update this function every
// time policy grows a field, and forgetting once yields a cache that ignores
// the new setting. encoding/json sorts map keys, so the result is stable.
func policyDigest(pol policy.Policy) []byte {
	data, err := json.Marshal(pol)
	if err != nil {
		// Unhashable policy: return a unique value so nothing is ever served
		// from cache, rather than colliding every such policy onto one key.
		return []byte(err.Error())
	}
	sum := sha256.Sum256(data)
	return sum[:]
}

// MemoryCache is an in-process cache. Suitable for an agent that loads skills
// repeatedly within one run; it holds decisions, which are small.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]Decision
}

// NewMemoryCache returns an empty in-process cache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{entries: make(map[string]Decision)}
}

func (c *MemoryCache) Get(key string) (*Decision, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	d, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	// Copied out: a caller that mutates the returned decision must not corrupt
	// what the next caller sees.
	out := d
	out.Findings = append([]model.Finding(nil), d.Findings...)
	return &out, true
}

func (c *MemoryCache) Put(key string, d *Decision) {
	if d == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	stored := *d
	stored.Findings = append([]model.Finding(nil), d.Findings...)
	c.entries[key] = stored
}

// Len reports how many decisions are held, for tests and diagnostics.
func (c *MemoryCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// FileCache persists decisions as JSON under a directory, so a short-lived
// process (a hook, a CLI invocation) still benefits. Off unless a caller asks
// for it: writing verdicts to disk is a decision about the user's filesystem,
// not one to make on their behalf.
type FileCache struct {
	dir string
}

// NewFileCache prepares a cache directory, creating it if needed. Pass an empty
// path to use the user cache dir (os.UserCacheDir + /skill-guard/verdicts).
func NewFileCache(dir string) (*FileCache, error) {
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("guard: no cache directory available: %w", err)
		}
		dir = filepath.Join(base, "skill-guard", "verdicts")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("guard: cannot create cache directory: %w", err)
	}
	return &FileCache{dir: dir}, nil
}

// Dir reports where the cache writes, so a caller can tell the user.
func (c *FileCache) Dir() string { return c.dir }

func (c *FileCache) Get(key string) (*Decision, bool) {
	data, err := os.ReadFile(c.path(key))
	if err != nil {
		return nil, false
	}
	var d Decision
	if err := json.Unmarshal(data, &d); err != nil {
		// A corrupt entry is a miss, not a failure. Remove it so the next run
		// does not pay the same read.
		_ = os.Remove(c.path(key))
		return nil, false
	}
	return &d, true
}

func (c *FileCache) Put(key string, d *Decision) {
	if d == nil {
		return
	}
	data, err := json.Marshal(d)
	if err != nil {
		return
	}
	// Written via a temp file and renamed: a half-written entry read by a
	// concurrent process would be a corrupt decision, and rename is atomic on
	// every platform this runs on.
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	if err := os.Rename(tmpName, c.path(key)); err != nil {
		_ = os.Remove(tmpName)
	}
}

// path maps a key to a file. Keys are hex from CacheKey, so they are already
// safe as filenames; the check is belt-and-braces against a caller passing
// something else straight through to the filesystem.
func (c *FileCache) path(key string) string {
	if len(key) != 64 || !isHex(key) {
		sum := sha256.Sum256([]byte(key))
		key = hex.EncodeToString(sum[:])
	}
	return filepath.Join(c.dir, key+".json")
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ErrNoCache is returned by helpers that require a cache and were given none.
var ErrNoCache = errors.New("guard: no cache configured")
