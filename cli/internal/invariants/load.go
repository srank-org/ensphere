package invariants

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultDir is the invariant directory relative to the source path.
const DefaultDir = ".ensphere/invariants"

// DefaultSurfaceMap is the system map relative to the source path.
const DefaultSurfaceMap = ".ensphere/surfaces.yaml"

// Load reads every *.yaml and *.yml file in dir, sorted by filename. A file
// that does not parse is an Issue; only an unreadable directory is an error.
func Load(dir string) ([]Invariant, []Issue, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read invariant directory: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yaml" || ext == ".yml" {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	var invs []Invariant
	var issues []Issue
	for _, name := range names {
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			issues = append(issues, newIssue("invariant_yaml_invalid", path, fmt.Sprintf("read file: %v", err)))
			continue
		}
		var inv Invariant
		if err := decodeStrictYAML(raw, &inv); err != nil {
			if errors.Is(err, io.EOF) {
				err = errors.New("file is empty")
			}
			issues = append(issues, newIssue("invariant_yaml_invalid", path, err.Error()))
			continue
		}
		inv.Path = path
		invs = append(invs, inv)
	}
	return invs, issues, nil
}

// ResolveSurfaces returns the surface ids of the system map at mapPath, or of
// <sourcePath>/.ensphere/surfaces.yaml when mapPath is empty and that file
// exists. It returns nil when there is no map, which turns the surface check off.
func ResolveSurfaces(sourcePath, mapPath string) ([]string, error) {
	if mapPath == "" {
		candidate := filepath.Join(sourcePath, DefaultSurfaceMap)
		if _, err := os.Stat(candidate); err != nil {
			return nil, nil
		}
		mapPath = candidate
	}
	raw, err := os.ReadFile(mapPath)
	if err != nil {
		return nil, fmt.Errorf("read surface map: %w", err)
	}
	var doc struct {
		Surfaces []struct {
			ID string `yaml:"id"`
		} `yaml:"surfaces"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse surface map %s: %w", mapPath, err)
	}
	ids := make([]string, 0, len(doc.Surfaces))
	for _, s := range doc.Surfaces {
		if s.ID != "" {
			ids = append(ids, s.ID)
		}
	}
	return ids, nil
}

// HasErrors reports whether any issue has error severity.
func HasErrors(issues []Issue) bool {
	for _, issue := range issues {
		if issue.Severity == SeverityError {
			return true
		}
	}
	return false
}

// UnknownIDs returns the ids in only that no invariant in invs carries.
func UnknownIDs(invs []Invariant, only []string) []string {
	known := make(map[string]bool, len(invs))
	for _, inv := range invs {
		known[inv.ID] = true
	}
	var unknown []string
	for _, id := range only {
		if !known[id] {
			unknown = append(unknown, id)
		}
	}
	return unknown
}

func newIssue(code, path, message string) Issue {
	return Issue{Severity: SeverityError, Code: code, Path: path, Message: message}
}

func decodeStrictYAML(raw []byte, destination any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple YAML documents are not allowed")
		}
		return err
	}
	return nil
}
