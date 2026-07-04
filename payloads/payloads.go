// Package payloads loads the external payload database (paths, headers,
// unicode, byte-quirks) that drives bypass403's mutation modules.
//
// Design goal: payloads should be editable without recompiling. Every file
// is embedded as a compiled-in fallback (so the binary still works
// standalone), but at runtime we always prefer a matching file from an
// on-disk directory if one is present — either the caller-supplied
// -payloads-dir flag, or a ./payloads directory next to the binary/cwd.
package payloads

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed defaults/*.json
var embedded embed.FS

type PathEntry struct {
	ID          string `json:"id"`
	Value       string `json:"value,omitempty"`
	Desc        string `json:"desc"`
	RequiresRaw bool   `json:"requires_raw"`
	Source      string `json:"source,omitempty"`
	Depth       int    `json:"depth,omitempty"`
}

type PathsDB struct {
	EndPaths    []PathEntry `json:"end_paths"`
	MidPaths    []PathEntry `json:"mid_paths"`
	RawEncoding []PathEntry `json:"raw_encoding_strategies"`
}

type OverrideHeader struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	ValueIsPath bool   `json:"value_is_path,omitempty"`
	Desc        string `json:"desc"`
}

type StaticHeader struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Desc   string `json:"desc"`
	Source string `json:"source,omitempty"`
}

type HeadersDB struct {
	IPHeaders       []string         `json:"ip_headers"`
	IPValues        []string         `json:"ip_values"`
	PortHeaders     []string         `json:"port_headers"`
	PortValues      []string         `json:"port_values"`
	OverrideHeaders []OverrideHeader `json:"override_headers"`
	StaticHeaders   []StaticHeader   `json:"static_headers"`
	UserAgents      []string         `json:"user_agents"`
	DebugParams     []string         `json:"debug_params"`
}

type NormalizePair struct {
	ASCII   string `json:"ascii"`
	Unicode string `json:"unicode"`
	Desc    string `json:"desc"`
}

type TruncateChar struct {
	TargetASCII string `json:"target_ascii"`
	Byte        string `json:"byte"`
	Desc        string `json:"desc"`
}

type UnicodeDB struct {
	NormalizePairs  []NormalizePair `json:"normalize_pairs"`
	TruncateChars   []TruncateChar  `json:"truncate_chars"`
	ApplyToSegments []string        `json:"apply_to_segments"`
}

type FrameworkBytes struct {
	Name      string   `json:"name"`
	Desc      string   `json:"desc"`
	Bytes     []string `json:"bytes"`
	Positions []string `json:"positions"`
	Note      string   `json:"note,omitempty"`
}

type ByteQuirksDB struct {
	Frameworks  []FrameworkBytes `json:"frameworks"`
	EncodeForms []string         `json:"encode_forms"`
}

// DB is the full loaded payload set.
type DB struct {
	Paths      PathsDB
	Headers    HeadersDB
	Unicode    UnicodeDB
	ByteQuirks ByteQuirksDB
	LoadedFrom map[string]string // filename -> "disk:<path>" or "embedded"
}

// Load reads the four payload files. dir is an optional on-disk override
// directory (pass "" to only use ./payloads next to the cwd, falling back
// to the compiled-in defaults). Missing/invalid files fall back silently
// per-file to the embedded copy so a typo in one JSON file doesn't break
// the whole scan.
func Load(dir string) (*DB, error) {
	db := &DB{LoadedFrom: map[string]string{}}
	candidates := []string{}
	if dir != "" {
		candidates = append(candidates, dir)
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".config", "bypass403"))
	}
	candidates = append(candidates, "payloads")

	if err := loadFile(db, candidates, "paths.json", &db.Paths); err != nil {
		return nil, err
	}
	if err := loadFile(db, candidates, "headers.json", &db.Headers); err != nil {
		return nil, err
	}
	if err := loadFile(db, candidates, "unicode.json", &db.Unicode); err != nil {
		return nil, err
	}
	if err := loadFile(db, candidates, "bytequirks.json", &db.ByteQuirks); err != nil {
		return nil, err
	}
	return db, nil
}

func loadFile(db *DB, dirs []string, filename string, target interface{}) error {
	for _, d := range dirs {
		p := filepath.Join(d, filename)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if err := json.Unmarshal(data, target); err != nil {
			return fmt.Errorf("parsing %s: %w", p, err)
		}
		db.LoadedFrom[filename] = "disk:" + p
		return nil
	}
	// Fall back to embedded default.
	data, err := embedded.ReadFile("defaults/" + filename)
	if err != nil {
		return fmt.Errorf("no on-disk %s found and no embedded default: %w", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("parsing embedded %s: %w", filename, err)
	}
	db.LoadedFrom[filename] = "embedded"
	return nil
}
