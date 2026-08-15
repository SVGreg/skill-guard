// Package skill parses a SKILL.md bundle into a normalized, inert model.
// Nothing in a bundle is ever executed or resolved here (design §6.1).
package skill

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// File is one regular file in the bundle.
type File struct {
	Path      string      `json:"path"` // normalized, relative, '/'-separated
	Mode      fs.FileMode `json:"-"`
	SHA256    string      `json:"sha256"` // "sha256:<hex>" of raw content
	Size      int64       `json:"size"`
	MediaType string      `json:"media_type,omitempty"`
	Role      string      `json:"role,omitempty"` // manifest | script | config | doc | asset
	Language  string      `json:"language,omitempty"`
	Content   []byte      `json:"-"`
}

// Script is a File classified as executable/interpretable.
type Script struct {
	File
}

// ExternalRef is a URL or remote reference discovered in the bundle.
type ExternalRef struct {
	URL  string `json:"url"`
	File string `json:"file"`
	Line int    `json:"line"`
}

// Manifest is the parsed SKILL.md YAML front-matter.
type Manifest struct {
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	License       string         `json:"license,omitempty"`
	Compatibility any            `json:"compatibility,omitempty"`
	AllowedTools  []string       `json:"allowed_tools,omitempty"`
	Signature     string         `json:"signature,omitempty"`    // USF field (§7.5)
	ContentHash   string         `json:"content_hash,omitempty"` // USF field (§7.5)
	Extra         map[string]any `json:"extra,omitempty"`        // unknown keys (SG-MTA-002)
	Raw           []byte         `json:"-"`                      // raw front-matter bytes
	Present       bool           `json:"-"`                      // false if no front-matter found
	LineOffset    int            `json:"-"`                      // file line of Raw's first line, minus 1
}

// Bundle is the normalized, inert representation of a skill.
type Bundle struct {
	Root           string        `json:"root"`
	Manifest       Manifest      `json:"manifest"`
	Body           string        `json:"-"` // markdown body after front-matter
	BodyLineOffset int           `json:"-"` // file line of Body's first line, minus 1
	SkillMDRaw     []byte        `json:"-"` // raw SKILL.md bytes
	Files          []File        `json:"files"`
	Scripts        []Script      `json:"-"`
	Configs        []File        `json:"-"`
	Docs           []File        `json:"-"` // bundled prose read by the agent (progressive disclosure)
	Refs           []ExternalRef `json:"refs,omitempty"`
	SingleFile     bool          `json:"single_file"` // stdin / single SKILL.md mode
}

var (
	frontMatterRe = regexp.MustCompile(`(?s)\A\x{FEFF}?---\r?\n(.*?)\r?\n---\r?\n?`)
	urlRe         = regexp.MustCompile(`https?://[^\s"'` + "`" + `)\]<>]+`)
)

// Skipped file/dir names excluded from the walk (and from the Merkle set).
var skipNames = map[string]bool{".git": true, ".DS_Store": true, "Thumbs.db": true}

const maxFileSize = 16 << 20 // 16 MiB per-file cap (DoS guard)

// maxBundleSize caps the *sum* of the bytes a single bundle may load.
//
// The per-file cap alone leaves memory unbounded: every file's Content is
// retained for the lifetime of the scan, so a bundle of N files just under
// maxFileSize costs ~N × 16 MiB of RSS with no ceiling. skill-guard exists to
// parse untrusted bundles, so that input is attacker-controlled by definition,
// and the batch/registry-side scanning use case is where it bites.
//
// The ceiling is a fixed value rather than a .skillguard.yaml knob on purpose.
// Everything in the policy file answers "how should I judge this skill?"
// (fail_on, warn_on, waivers, trust); this answers "how much of it am I willing
// to read", which must hold before and independent of any judgment — and
// pkg/skill deliberately imports no policy, keeping the pipeline's one-way data
// flow. Its sibling maxFileSize is a constant for the same reason; making one
// of the pair configurable would be incoherent.
//
// 256 MiB is ~11× the largest bundle in the 777-bundle evaluation corpus
// (23.3 MiB; p99 1.8 MiB, median 16.5 KiB), so no plausible real skill is
// blocked, while a hostile one is bounded to something any CI runner survives.
//
// It is a var, not a const, only so tests can lower it — writing a quarter of a
// gigabyte to exercise the guard would be a slow test, not a better one.
var maxBundleSize int64 = 256 << 20

// LoadBundle loads a bundle from a directory or a single SKILL.md file.
// git-URL / tar / zip sources are deferred (see PROGRESS.md).
func LoadBundle(src string) (*Bundle, error) {
	// Lstat, not Stat: Stat resolves the link, so the ModeSymlink check below
	// could never fire and single-file mode silently followed symlinks (§7.1).
	info, err := os.Lstat(src)
	if err != nil {
		return nil, fmt.Errorf("load bundle: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("load bundle: %s is a symlink (rejected)", src)
	}
	if !info.IsDir() {
		// The directory walk caps every file it reads; single-file mode must
		// apply the same DoS guard rather than reading an arbitrary blob.
		if info.Size() > maxFileSize {
			return nil, fmt.Errorf("file %s exceeds size cap", src)
		}
		return loadSingleFile(src)
	}
	return loadDir(src)
}

func loadSingleFile(path string) (*Bundle, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b := &Bundle{Root: filepath.Dir(path), SingleFile: true}
	b.SkillMDRaw = content
	parseSkillMD(b, content)
	b.Files = []File{fileFrom("SKILL.md", content, 0o644)}
	b.Files[0].Role = "manifest"
	return b, nil
}

func loadDir(root string) (*Bundle, error) {
	b := &Bundle{Root: root}
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != root && skipNames[name] {
				return fs.SkipDir
			}
			return nil
		}
		if skipNames[name] {
			return nil
		}
		// Reject symlinks rather than follow them (design §7.1).
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle contains symlink %s (rejected)", p)
		}
		if strings.HasSuffix(name, ".skillsig") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxFileSize {
			return fmt.Errorf("file %s exceeds size cap", p)
		}
		// Check the running total *before* reading, so the cap bounds what is
		// actually allocated rather than being noticed one file too late.
		total += info.Size()
		if total > maxBundleSize {
			return fmt.Errorf("bundle %s exceeds total size cap of %d MiB", root, maxBundleSize>>20)
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel := normalizePath(root, p)
		f := fileFrom(rel, content, info.Mode())
		classify(&f)
		b.Files = append(b.Files, f)
		if rel == "SKILL.md" {
			b.SkillMDRaw = content
			parseSkillMD(b, content)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if b.SkillMDRaw == nil {
		return nil, fmt.Errorf("no SKILL.md found in %s", root)
	}
	// Group scripts/configs and gather external refs.
	for _, f := range b.Files {
		switch f.Role {
		case "script":
			b.Scripts = append(b.Scripts, Script{File: f})
		case "config":
			b.Configs = append(b.Configs, f)
		case "doc":
			b.Docs = append(b.Docs, f)
		}
	}
	b.Refs = gatherRefs(b)
	return b, nil
}

func fileFrom(rel string, content []byte, mode fs.FileMode) File {
	sum := sha256.Sum256(content)
	return File{
		Path:    rel,
		Mode:    mode,
		SHA256:  "sha256:" + hex.EncodeToString(sum[:]),
		Size:    int64(len(content)),
		Content: content,
	}
}

// parseSkillMD splits front-matter from body and maps the manifest.
func parseSkillMD(b *Bundle, content []byte) {
	m := frontMatterRe.FindSubmatchIndex(content)
	if m == nil {
		b.Body = string(content)
		b.BodyLineOffset = 0
		b.Manifest = Manifest{Present: false}
		return
	}
	fmBytes := content[m[2]:m[3]]
	b.Body = string(content[m[1]:])
	// Line offsets so findings can be reported at true file line numbers:
	// the front-matter content starts after the opening "---\n", and the body
	// starts after the closing "---\n".
	b.BodyLineOffset = bytes.Count(content[:m[1]], []byte("\n"))

	var raw map[string]any
	// yaml.v3 is memory-safe (no code execution on unmarshal, unlike PyYAML).
	// A parse error leaves Extra empty; SG-MTA rules still see Raw bytes.
	_ = yaml.Unmarshal(fmBytes, &raw)

	man := Manifest{Raw: fmBytes, Present: true, Extra: map[string]any{},
		LineOffset: bytes.Count(content[:m[2]], []byte("\n"))}
	for k, v := range raw {
		switch strings.ToLower(k) {
		case "name":
			man.Name, _ = v.(string)
		case "description":
			man.Description, _ = v.(string)
		case "license":
			man.License, _ = v.(string)
		case "compatibility":
			man.Compatibility = v
		case "allowed-tools", "allowed_tools":
			man.AllowedTools = toStringSlice(v)
		case "signature":
			man.Signature, _ = v.(string)
		case "content_hash":
			man.ContentHash, _ = v.(string)
		default:
			man.Extra[k] = v
		}
	}
	b.Manifest = man
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		// `allowed-tools: Read, Write` is a plain scalar, and Fields alone would
		// yield "Read," with the comma welded on — which then reaches the
		// skill-card's permissions list verbatim. Split on commas too.
		return strings.FieldsFunc(t, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})
	}
	return nil
}

// normalizePath returns a bundle-relative, '/'-separated, cleaned path.
func normalizePath(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		rel = p
	}
	rel = filepath.ToSlash(rel)
	rel = strings.TrimPrefix(rel, "./")
	return rel
}

// scriptExt maps extensions to a language for language-aware rules.
var scriptExt = map[string]string{
	".sh": "bash", ".bash": "bash", ".zsh": "bash",
	".py": "python", ".js": "javascript", ".mjs": "javascript",
	".ts": "typescript", ".rb": "ruby", ".pl": "perl",
	".ps1": "powershell", ".php": "php",
}

var configNames = map[string]bool{
	"requirements.txt": true, "package.json": true, "pyproject.toml": true,
	"settings.json": true, "mcp.json": true, "Makefile": true,
}

// docExt marks prose formats — bundled reference material the agent is told to
// read and follow. Progressive disclosure is the documented Agent Skills
// pattern: SKILL.md stays short and points at `references/*.md`, so these files
// reach the model exactly like the body does and must be scanned like it.
//
// Deliberately prose only. Extension-less files are *not* included even though
// some carry text: across the 777-bundle evaluation corpus every one of the 49
// such files is packaging metadata or license text (LICENSE, WHEEL, RECORD,
// METADATA, Dockerfile) — none is instruction surface, so admitting them buys
// no detection and costs false positives. Data formats (.json, .yaml, .csv)
// stay out too: the ones that matter are already the `config` role.
var docExt = map[string]bool{
	".md": true, ".markdown": true, ".mdx": true,
	".txt": true, ".rst": true, ".text": true,
}

func classify(f *File) {
	base := filepath.Base(f.Path)
	ext := strings.ToLower(filepath.Ext(f.Path))
	switch {
	case base == "SKILL.md":
		f.Role = "manifest"
		f.MediaType = "text/markdown"
	case scriptExt[ext] != "":
		f.Role = "script"
		f.Language = scriptExt[ext]
	case configNames[base] || strings.Contains(f.Path, ".claude/") || strings.Contains(f.Path, ".git/hooks/"):
		f.Role = "config"
	case docExt[ext] && !looksBinary(f.Content):
		// Checked after config so requirements.txt stays a config despite ".txt".
		f.Role = "doc"
		if ext == ".md" || ext == ".markdown" || ext == ".mdx" {
			f.MediaType = "text/markdown"
		} else {
			f.MediaType = "text/plain"
		}
	default:
		f.Role = "asset"
		if lang := shebangLanguage(f.Content); lang != "" {
			f.Role = "script"
			f.Language = lang
		}
	}
}

// shebangLanguage returns the interpreter language named in a leading shebang
// line, or "" if the file has none. It lets classify() recognize an executable
// script shipped *without* a telltale extension — a common way to slip a payload
// past extension-based classification, and the only reason a bundled `perl`/`php`
// one-liner would otherwise land as an inert `asset` and skip every code-layer
// rule. It covers the same interpreters as scriptExt so classification is
// consistent whether or not the file carries an extension, and it reports the
// actual language instead of assuming bash (a python shebang used to be labeled
// bash, hiding it from language-gated rules). "sh" is checked last because it is
// a substring of many interpreter names.
func shebangLanguage(content []byte) string {
	if !bytes.HasPrefix(content, []byte("#!")) {
		return ""
	}
	line := content
	if i := bytes.IndexByte(content, '\n'); i >= 0 {
		line = content[:i]
	}
	switch {
	case bytes.Contains(line, []byte("python")):
		return "python"
	case bytes.Contains(line, []byte("node")):
		return "javascript"
	case bytes.Contains(line, []byte("ruby")):
		return "ruby"
	case bytes.Contains(line, []byte("perl")):
		return "perl"
	case bytes.Contains(line, []byte("php")):
		return "php"
	case bytes.Contains(line, []byte("sh")):
		return "bash"
	}
	return ""
}

// looksBinary reports whether content is not plausibly text. A NUL byte is the
// standard heuristic (git uses it too) and only the head is inspected, which is
// enough to keep a mislabeled binary out of the `doc` role without paying a
// full scan for it.
func looksBinary(content []byte) bool {
	head := content
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// refKey identifies one (file, URL) pair. A struct rather than a concatenated
// string because both operands can legally contain any delimiter — a file named
// "a|b" referencing "c" would otherwise collide with file "a" referencing "b|c"
// and silently drop one entry. Same reasoning as pkg/scan.dedupKey.
type refKey struct{ file, url string }

func gatherRefs(b *Bundle) []ExternalRef {
	var refs []ExternalRef
	seen := map[refKey]bool{}
	for _, f := range b.Files {
		if f.Role == "asset" {
			continue
		}
		// FindAllIndex yields matches in increasing offset order, so the line
		// number advances with one forward pass over the file. Counting newlines
		// from offset 0 for every match instead is O(matches × size) — measured
		// on a synthetic doc, 1 MiB took 2.1 s, 2 MiB 8.3 s and 4 MiB 37.4 s
		// (doubling the input quadrupled the time), which at the 16 MiB per-file
		// cap is minutes for a single attacker-supplied file.
		line, prev := 1, 0
		for _, loc := range urlRe.FindAllIndex(f.Content, -1) {
			line += bytes.Count(f.Content[prev:loc[0]], []byte("\n"))
			prev = loc[0]
			u := string(f.Content[loc[0]:loc[1]])
			key := refKey{f.Path, u}
			if seen[key] {
				continue
			}
			seen[key] = true
			refs = append(refs, ExternalRef{URL: u, File: f.Path, Line: line})
		}
	}
	return refs
}
