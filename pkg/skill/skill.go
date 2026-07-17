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

	"gopkg.in/yaml.v3"
)

// File is one regular file in the bundle.
type File struct {
	Path      string      `json:"path"` // normalized, relative, '/'-separated
	Mode      fs.FileMode `json:"-"`
	SHA256    string      `json:"sha256"` // "sha256:<hex>" of raw content
	Size      int64       `json:"size"`
	MediaType string      `json:"media_type,omitempty"`
	Role      string      `json:"role,omitempty"` // manifest | script | config | asset
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

// LoadBundle loads a bundle from a directory or a single SKILL.md file.
// git-URL / tar / zip sources are deferred (see PROGRESS.md).
func LoadBundle(src string) (*Bundle, error) {
	info, err := os.Stat(src)
	if err != nil {
		return nil, fmt.Errorf("load bundle: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("load bundle: %s is a symlink (rejected)", src)
	}
	if !info.IsDir() {
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
		return strings.Fields(t)
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
	default:
		f.Role = "asset"
		if hasShebangScript(f.Content) {
			f.Role = "script"
			f.Language = "bash"
		}
	}
}

func hasShebangScript(content []byte) bool {
	if !bytes.HasPrefix(content, []byte("#!")) {
		return false
	}
	line := content
	if i := bytes.IndexByte(content, '\n'); i >= 0 {
		line = content[:i]
	}
	return bytes.Contains(line, []byte("sh")) || bytes.Contains(line, []byte("python")) ||
		bytes.Contains(line, []byte("node")) || bytes.Contains(line, []byte("ruby"))
}

func gatherRefs(b *Bundle) []ExternalRef {
	var refs []ExternalRef
	seen := map[string]bool{}
	for _, f := range b.Files {
		if f.Role == "asset" {
			continue
		}
		for _, loc := range urlRe.FindAllIndex(f.Content, -1) {
			u := string(f.Content[loc[0]:loc[1]])
			key := f.Path + "|" + u
			if seen[key] {
				continue
			}
			seen[key] = true
			refs = append(refs, ExternalRef{URL: u, File: f.Path, Line: lineAt(f.Content, loc[0])})
		}
	}
	return refs
}

func lineAt(content []byte, off int) int {
	if off > len(content) {
		off = len(content)
	}
	return bytes.Count(content[:off], []byte("\n")) + 1
}
