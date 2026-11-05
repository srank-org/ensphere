// Package sysmap reads and validates the system map, the committed inventory
// of a target's surfaces at <source_path>/.ensphere/surfaces.yaml, and
// computes which surfaces changed since a git commit. It records which files
// implement each surface and which sessions own its checks; it judges nothing.
package sysmap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const RelativePath = ".ensphere/surfaces.yaml"

// Path returns the system map path for a source tree.
func Path(sourcePath string) string {
	return filepath.Join(sourcePath, filepath.FromSlash(RelativePath))
}

type Map struct {
	Version      int       `json:"version" yaml:"version"`
	ReconciledAt string    `json:"reconciled_at" yaml:"reconciled_at"`
	Stack        *Stack    `json:"stack,omitempty" yaml:"stack,omitempty"`
	Surfaces     []Surface `json:"surfaces" yaml:"surfaces"`
}

// Stack mirrors the keys of the runner's stack profile so a recon stack block
// can be copied into the map unchanged.
type Stack struct {
	Languages              []string `json:"languages,omitempty" yaml:"languages,omitempty"`
	Frameworks             []string `json:"frameworks,omitempty" yaml:"frameworks,omitempty"`
	DataLayers             []string `json:"data_layers,omitempty" yaml:"data_layers,omitempty"`
	AuthProviders          []string `json:"auth_providers,omitempty" yaml:"auth_providers,omitempty"`
	Hosting                []string `json:"hosting,omitempty" yaml:"hosting,omitempty"`
	Storage                []string `json:"storage,omitempty" yaml:"storage,omitempty"`
	Edge                   []string `json:"edge,omitempty" yaml:"edge,omitempty"`
	BillingExposedServices []string `json:"billing_exposed_services,omitempty" yaml:"billing_exposed_services,omitempty"`
	Clients                []string `json:"clients,omitempty" yaml:"clients,omitempty"`
	EvidenceRefs           []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
}

// Surface is one entry of the map. Files are relative to the source path;
// Sessions are the session ids that own the surface's checks.
type Surface struct {
	ID       string   `json:"id" yaml:"id"`
	Kind     string   `json:"kind" yaml:"kind"`
	Name     string   `json:"name" yaml:"name"`
	Role     string   `json:"role" yaml:"role"`
	Identity string   `json:"identity,omitempty" yaml:"identity,omitempty"`
	Files    []string `json:"files" yaml:"files"`
	Sessions []string `json:"sessions" yaml:"sessions"`
	Checks   []string `json:"checks,omitempty" yaml:"checks,omitempty"`
	Notes    string   `json:"notes,omitempty" yaml:"notes,omitempty"`
}

// Issue is one validation problem. Path locates it inside the map, such as
// surfaces[2].files[0].
type Issue struct {
	Severity string `json:"severity" yaml:"severity"`
	Code     string `json:"code" yaml:"code"`
	Path     string `json:"path,omitempty" yaml:"path,omitempty"`
	Message  string `json:"message" yaml:"message"`
}

// Validation is the result of ensphere map validate.
type Validation struct {
	Path     string  `json:"path" yaml:"path"`
	Valid    bool    `json:"valid" yaml:"valid"`
	Surfaces int     `json:"surfaces" yaml:"surfaces"`
	Issues   []Issue `json:"issues" yaml:"issues"`
}

// Kinds is the surface kind vocabulary.
var Kinds = []string{"bucket", "client", "config", "endpoint", "function", "job", "table", "workflow"}

// Roles is the snake_case form of the roles in fundamentals.md, sorted.
var Roles = []string{
	"audit_trail",
	"authorization_decision",
	"billed_operation",
	"browser_boundary",
	"cryptographic_operation",
	"data_store",
	"entry_point",
	"identity",
	"limiter",
	"object_storage",
	"outbound_call",
	"parser",
	"platform_configuration",
	"query_construction",
	"render_context",
	"secret",
	"workflow",
}

var surfaceIDPattern = regexp.MustCompile(`^SURF-[0-9]{3,}$`)

// Load reads a map with strict YAML decoding: unknown fields and multiple
// documents are errors.
func Load(path string) (*Map, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read system map: %w", err)
	}
	var m Map
	if err := decodeStrictYAML(raw, &m); err != nil {
		return nil, fmt.Errorf("parse system map %s: %w", path, err)
	}
	return &m, nil
}

// ValidateFile loads the map at path and validates it. The error is non-nil
// only when the file cannot be read or parsed.
func ValidateFile(path, sourcePath string, sessionIDs []string) (*Validation, *Map, error) {
	m, err := Load(path)
	if err != nil {
		return nil, nil, err
	}
	issues := Validate(m, sourcePath, sessionIDs)
	return &Validation{
		Path:     path,
		Valid:    !HasErrors(issues),
		Surfaces: len(m.Surfaces),
		Issues:   issues,
	}, m, nil
}

// Validate checks the map's structure and that every claimed file exists
// under sourcePath. Issues are sorted by path, then code.
func Validate(m *Map, sourcePath string, sessionIDs []string) []Issue {
	issues := []Issue{}
	add := func(severity, code, path, message string) {
		issues = append(issues, Issue{Severity: severity, Code: code, Path: path, Message: message})
	}
	if m.Version != 1 {
		add("error", "map_version_invalid", "version", fmt.Sprintf("version %d must be 1", m.Version))
	}
	if strings.TrimSpace(m.ReconciledAt) == "" {
		add("error", "map_reconciled_missing", "reconciled_at", "reconciled_at must name the commit the map was last reconciled against")
	}
	knownSessions := toSet(sessionIDs)
	seen := map[string]bool{}
	for i, surface := range m.Surfaces {
		ref := fmt.Sprintf("surfaces[%d]", i)
		id := strings.TrimSpace(surface.ID)
		switch {
		case !surfaceIDPattern.MatchString(id):
			add("error", "surface_id_invalid", ref+".id", fmt.Sprintf("surface id %q must look like SURF-001", surface.ID))
		case seen[id]:
			add("error", "surface_id_duplicate", ref+".id", fmt.Sprintf("duplicate surface id %s", id))
		default:
			seen[id] = true
		}
		if !contains(Kinds, strings.TrimSpace(surface.Kind)) {
			add("error", "surface_kind_invalid", ref+".kind", fmt.Sprintf("surface kind %q must be one of %s", surface.Kind, strings.Join(Kinds, ", ")))
		}
		if strings.TrimSpace(surface.Name) == "" {
			add("error", "surface_name_missing", ref+".name", "surface name is required")
		}
		if !contains(Roles, strings.TrimSpace(surface.Role)) {
			add("error", "surface_role_invalid", ref+".role", fmt.Sprintf("surface role %q must be one of %s", surface.Role, strings.Join(Roles, ", ")))
		}
		if len(surface.Files) == 0 {
			add("error", "surface_files_missing", ref+".files", "a surface lists at least one source file")
		}
		for j, file := range surface.Files {
			if problem := fileProblem(sourcePath, file); problem != "" {
				add("error", "surface_file_missing", fmt.Sprintf("%s.files[%d]", ref, j), fmt.Sprintf("file %q %s", file, problem))
			}
		}
		if len(surface.Sessions) == 0 {
			add("error", "surface_session_invalid", ref+".sessions", "a surface names at least one session that owns its checks")
		}
		for j, session := range surface.Sessions {
			if !knownSessions[strings.TrimSpace(session)] {
				add("error", "surface_session_invalid", fmt.Sprintf("%s.sessions[%d]", ref, j), fmt.Sprintf("session %q must be one of %s", session, strings.Join(sessionIDs, ", ")))
			}
		}
		if len(surface.Checks) == 0 {
			add("warning", "surface_checks_empty", ref+".checks", fmt.Sprintf("surface %s names no checks", displayID(id)))
		}
	}
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Path != issues[j].Path {
			return issues[i].Path < issues[j].Path
		}
		return issues[i].Code < issues[j].Code
	})
	return issues
}

// HasErrors reports whether any issue has severity error.
func HasErrors(issues []Issue) bool {
	for _, issue := range issues {
		if issue.Severity == "error" {
			return true
		}
	}
	return false
}

// IDs returns the set of non-empty surface ids in the map.
func IDs(m *Map) map[string]bool {
	ids := map[string]bool{}
	for _, surface := range m.Surfaces {
		if id := strings.TrimSpace(surface.ID); id != "" {
			ids[id] = true
		}
	}
	return ids
}

func fileProblem(sourcePath, file string) string {
	file = strings.TrimSpace(file)
	if file == "" {
		return "is empty"
	}
	if filepath.IsAbs(file) || strings.HasPrefix(file, "/") || strings.HasPrefix(file, `\`) || (len(file) >= 2 && file[1] == ':') {
		return "must be relative to the source path"
	}
	for _, segment := range strings.FieldsFunc(file, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == ".." {
			return `must not contain ".."`
		}
	}
	if _, err := os.Stat(filepath.Join(sourcePath, filepath.FromSlash(file))); err != nil {
		return "does not exist under " + sourcePath
	}
	return ""
}

func decodeStrictYAML(raw []byte, destination any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple YAML documents are not allowed")
		}
		return err
	}
	return nil
}

func toSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[strings.TrimSpace(value)] = true
	}
	return set
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func displayID(id string) string {
	if id == "" {
		return "<missing-id>"
	}
	return id
}
