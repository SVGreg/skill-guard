package skill

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Discovery limits. DefaultMaxDepth is deeper than the 4–6 agentskills.io
// suggests for an installed-skills root because Discover also serves
// `scan <repo>`, where a skill can sit under e.g. plugins/x/skills/y. The
// bundle cap bounds a scan pointed at $HOME by mistake; it is reported, never
// silently applied.
const (
	DefaultMaxDepth   = 8
	DefaultMaxBundles = 5000
)

// Discovery conditions reported in a DiscoverError, testable with errors.Is.
var (
	ErrMaxDepth           = errors.New("directories below the depth limit were not searched")
	ErrMaxBundles         = errors.New("bundle limit reached; discovery stopped early")
	ErrSymlinkNotFollowed = errors.New("symlinked directory is not a bundle; not followed")
)

// vendoredDirs are directory names discovery never descends into: dependency
// trees and caches hold other people's code, not the skills a user installed,
// and can be enormous. This governs *discovery* only — whether the loader
// should also exclude them from a bundle it reads is issue #293's call.
var vendoredDirs = map[string]bool{
	"node_modules": true, "bower_components": true, "vendor": true,
	".venv": true, "venv": true, "site-packages": true, "__pycache__": true,
	".cache": true,
}

// DiscoverOptions bounds a Discover call. Zero values take the defaults.
type DiscoverOptions struct {
	MaxDepth   int
	MaxBundles int
}

// Candidate is one skill bundle found by Discover.
type Candidate struct {
	Path     string   `json:"path"`           // as reached from its root; what a user recognises
	RealPath string   `json:"real_path"`      // symlinks resolved; what LoadBundle is given
	Root     string   `json:"root"`           // the discovery root that reached Path
	Via      string   `json:"via,omitempty"`  // set when Path is a symlink to the bundle
	Also     []string `json:"also,omitempty"` // other paths reaching the same RealPath
	File     bool     `json:"file,omitempty"` // a single SKILL.md file named directly as a root
}

// DiscoverError is a non-fatal problem met while discovering: an unreadable
// directory, a limit hit, or a symlink that was deliberately not followed.
type DiscoverError struct {
	Path string `json:"path"`
	Err  error  `json:"-"`
}

func (e DiscoverError) Error() string { return e.Path + ": " + e.Err.Error() }
func (e DiscoverError) Unwrap() error { return e.Err }

// Discover finds skill bundles under roots. It reads directory listings and
// stats `SKILL.md`; it reads no file content and executes nothing.
//
//   - A directory holding SKILL.md is one bundle; discovery does not descend
//     into it (its subtree belongs to it, which is what LoadBundle reads).
//   - A root is resolved through symlinks — the user named it. Below a root,
//     a symlink is followed only when its target directly is a bundle, never
//     for descent, so a link cycle cannot be walked. The bundle is reported
//     once per real path; every other path to it lands in Also.
//   - Vendored dependency directories (vendoredDirs) and .git are skipped.
//
// The error return is for unusable roots (missing, unreadable); everything
// met during the walk is a DiscoverError. Output is sorted by Path.
func Discover(roots []string, opt DiscoverOptions) ([]Candidate, []DiscoverError, error) {
	if opt.MaxDepth <= 0 {
		opt.MaxDepth = DefaultMaxDepth
	}
	if opt.MaxBundles <= 0 {
		opt.MaxBundles = DefaultMaxBundles
	}
	d := &discoverer{opt: opt, byReal: map[string]*reachSet{}, seenDir: map[string]bool{}}
	for _, root := range roots {
		real, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, nil, fmt.Errorf("discover: %w", err)
		}
		info, err := os.Stat(real)
		if err != nil {
			return nil, nil, fmt.Errorf("discover: %w", err)
		}
		if !info.IsDir() {
			// A file named directly is single-file mode, exactly as LoadBundle
			// treats it; there is nothing to discover.
			d.add(reach{path: root, real: real, root: root, file: true})
			continue
		}
		d.walk(root, real, root, 0)
		if d.stopped {
			break
		}
	}
	return d.result(), d.errs, nil
}

type reach struct {
	path, real, root, via string
	file                  bool
}

type reachSet struct{ all []reach }

type discoverer struct {
	opt     DiscoverOptions
	byReal  map[string]*reachSet
	order   []string // RealPaths in first-seen order, for the bundle cap
	seenDir map[string]bool
	errs    []DiscoverError
	pruned  map[string]int // root → directories not searched for depth
	stopped bool
}

func (d *discoverer) add(r reach) {
	if s, ok := d.byReal[r.real]; ok {
		s.all = append(s.all, r)
		return
	}
	if len(d.order) >= d.opt.MaxBundles {
		if !d.stopped {
			d.stopped = true
			d.errs = append(d.errs, DiscoverError{Path: r.root, Err: fmt.Errorf("%w (%d)", ErrMaxBundles, d.opt.MaxBundles)})
		}
		return
	}
	d.byReal[r.real] = &reachSet{all: []reach{r}}
	d.order = append(d.order, r.real)
}

// isBundleDir reports whether dir holds a SKILL.md that is not a directory.
// A symlinked SKILL.md still counts: the bundle is found, and LoadBundle then
// rejects it — an audit must surface that as a load error, not skip it.
func isBundleDir(dir string) bool {
	fi, err := os.Lstat(filepath.Join(dir, "SKILL.md"))
	return err == nil && !fi.IsDir()
}

// walk visits path (as reached) whose symlink-free location is real.
func (d *discoverer) walk(path, real, root string, depth int) {
	if d.stopped || d.seenDir[real] {
		return
	}
	d.seenDir[real] = true
	if isBundleDir(real) {
		d.add(reach{path: path, real: real, root: root})
		return
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		d.errs = append(d.errs, DiscoverError{Path: path, Err: err})
		return
	}
	for _, e := range entries { // ReadDir sorts by name
		if d.stopped {
			return
		}
		name := e.Name()
		childPath, childReal := filepath.Join(path, name), filepath.Join(real, name)
		switch {
		case e.Type()&os.ModeSymlink != 0:
			d.symlink(childPath, childReal, root)
		case e.IsDir():
			if skipNames[name] || vendoredDirs[name] {
				continue
			}
			if depth+1 > d.opt.MaxDepth {
				if d.pruned == nil {
					d.pruned = map[string]int{}
				}
				d.pruned[root]++
				continue
			}
			d.walk(childPath, childReal, root, depth+1)
		}
	}
}

// symlink follows link only when its target directly is a bundle directory.
// Links to files and dangling links are ignored as any other file is; a link
// to a non-bundle directory is reported, so an audit shows what it skipped.
func (d *discoverer) symlink(path, link, root string) {
	target, err := filepath.EvalSymlinks(link)
	if err != nil {
		return
	}
	fi, err := os.Stat(target)
	if err != nil || !fi.IsDir() {
		return
	}
	if !isBundleDir(target) {
		d.errs = append(d.errs, DiscoverError{Path: path, Err: ErrSymlinkNotFollowed})
		return
	}
	d.add(reach{path: path, real: target, root: root, via: path})
}

func (d *discoverer) result() []Candidate {
	roots := make([]string, 0, len(d.pruned))
	for r := range d.pruned {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	for _, r := range roots {
		d.errs = append(d.errs, DiscoverError{Path: r, Err: fmt.Errorf("%w (%d directories, limit %d)", ErrMaxDepth, d.pruned[r], d.opt.MaxDepth)})
	}
	out := make([]Candidate, 0, len(d.order))
	for _, real := range d.order {
		all := d.byReal[real].all
		// The lexically-first path is primary, so the result does not depend
		// on which root or link happened to be walked first.
		sort.Slice(all, func(i, j int) bool { return all[i].path < all[j].path })
		p := all[0]
		c := Candidate{Path: p.path, RealPath: p.real, Root: p.root, Via: p.via, File: p.file}
		prev := p.path
		for _, r := range all[1:] {
			if r.path != prev {
				c.Also = append(c.Also, r.path)
				prev = r.path
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
