package sysmap

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var testSessions = []string{"02", "03", "04", "05", "06", "07", "08", "08.5", "08.7"}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func validMap() *Map {
	return &Map{
		Version:      1,
		ReconciledAt: "9f1c2d3e",
		Surfaces: []Surface{
			{
				ID:       "SURF-001",
				Kind:     "endpoint",
				Name:     "POST /api/auth/otp",
				Role:     "billed_operation",
				Identity: "anonymous",
				Files:    []string{"routes/otp.ts", "lib/otp"},
				Sessions: []string{"03", "08.5"},
				Checks:   []string{"auth_control", "rate_limit_burst"},
			},
		},
	}
}

func validSource(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "routes/otp.ts", "export {}\n")
	writeFile(t, root, "lib/otp/send.ts", "export {}\n")
	return root
}

func codes(issues []Issue) []string {
	var out []string
	for _, issue := range issues {
		out = append(out, issue.Code)
	}
	return out
}

func TestRolesAreSorted(t *testing.T) {
	for i := 1; i < len(Roles); i++ {
		if Roles[i-1] >= Roles[i] {
			t.Fatalf("Roles must be sorted and unique: %q before %q", Roles[i-1], Roles[i])
		}
	}
}

func TestValidateAcceptsCorrectMap(t *testing.T) {
	root := validSource(t)
	if issues := Validate(validMap(), root, testSessions); len(issues) != 0 {
		t.Fatalf("expected no issues, got %+v", issues)
	}
}

func TestValidateReportsEachErrorCode(t *testing.T) {
	root := validSource(t)
	cases := []struct {
		code   string
		mutate func(m *Map)
	}{
		{"map_version_invalid", func(m *Map) { m.Version = 2 }},
		{"map_reconciled_missing", func(m *Map) { m.ReconciledAt = " " }},
		{"surface_id_invalid", func(m *Map) { m.Surfaces[0].ID = "SURF-1" }},
		{"surface_id_duplicate", func(m *Map) { m.Surfaces = append(m.Surfaces, m.Surfaces[0]) }},
		{"surface_kind_invalid", func(m *Map) { m.Surfaces[0].Kind = "route" }},
		{"surface_name_missing", func(m *Map) { m.Surfaces[0].Name = "" }},
		{"surface_role_invalid", func(m *Map) { m.Surfaces[0].Role = "billed-operation" }},
		{"surface_files_missing", func(m *Map) { m.Surfaces[0].Files = nil }},
		{"surface_file_missing", func(m *Map) { m.Surfaces[0].Files = []string{"routes/gone.ts"} }},
		{"surface_file_missing", func(m *Map) { m.Surfaces[0].Files = []string{"/etc/passwd"} }},
		{"surface_file_missing", func(m *Map) { m.Surfaces[0].Files = []string{"routes/../routes/otp.ts"} }},
		{"surface_session_invalid", func(m *Map) { m.Surfaces[0].Sessions = nil }},
		{"surface_session_invalid", func(m *Map) { m.Surfaces[0].Sessions = []string{"09"} }},
	}
	for _, tc := range cases {
		m := validMap()
		tc.mutate(m)
		issues := Validate(m, root, testSessions)
		if !reflect.DeepEqual(codes(issues), []string{tc.code}) {
			t.Fatalf("%s: expected exactly that code, got %+v", tc.code, issues)
		}
		if issues[0].Severity != "error" || !HasErrors(issues) {
			t.Fatalf("%s: expected an error issue, got %+v", tc.code, issues)
		}
	}
}

func TestValidateNamesTheMissingFileAndWarnsOnEmptyChecks(t *testing.T) {
	root := validSource(t)
	m := validMap()
	m.Surfaces[0].Files = []string{"routes/otp.ts", "routes/gone.ts"}
	m.Surfaces[0].Checks = nil
	issues := Validate(m, root, testSessions)
	if !reflect.DeepEqual(codes(issues), []string{"surface_checks_empty", "surface_file_missing"}) {
		t.Fatalf("expected checks warning then missing file, sorted by path, got %+v", issues)
	}
	if issues[0].Severity != "warning" || issues[0].Path != "surfaces[0].checks" {
		t.Fatalf("unexpected warning: %+v", issues[0])
	}
	if issues[1].Path != "surfaces[0].files[1]" || !strings.Contains(issues[1].Message, "routes/gone.ts") {
		t.Fatalf("missing file issue must name the file: %+v", issues[1])
	}
}

func TestLoadIsStrict(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, RelativePath, "version: 1\nreconciled_at: abc\nsurfaces: []\nextra: true\n")
	if _, err := Load(Path(root)); err == nil {
		t.Fatal("expected an unknown field to fail")
	}
	writeFile(t, root, RelativePath, "version: 1\nreconciled_at: abc\nsurfaces: []\n---\nversion: 1\n")
	if _, err := Load(Path(root)); err == nil {
		t.Fatal("expected a second document to fail")
	}
	writeFile(t, root, RelativePath, `version: 1
reconciled_at: abc
stack:
  languages: [typescript]
  billing_exposed_services: [stripe]
surfaces:
  - id: SURF-001
    kind: endpoint
    name: "GET /"
    role: entry_point
    files: [index.ts]
    sessions: ["08"]
`)
	m, err := Load(Path(root))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if m.Stack == nil || m.Stack.BillingExposedServices[0] != "stripe" || m.Surfaces[0].Sessions[0] != "08" {
		t.Fatalf("unexpected map: %+v", m)
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestChangedJoinsGitDiffToSurfaces(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	git(t, root, "init", "-q")
	writeFile(t, root, "routes/otp.ts", "v1\n")
	writeFile(t, root, "lib/otp/send.ts", "v1\n")
	writeFile(t, root, "routes/items.ts", "v1\n")
	writeFile(t, root, "db/schema.sql", "v1\n")
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "base")
	base := git(t, root, "rev-parse", "HEAD")

	m := &Map{
		Version:      1,
		ReconciledAt: base,
		Surfaces: []Surface{
			{ID: "SURF-001", Kind: "endpoint", Name: "POST /api/auth/otp", Role: "billed_operation", Files: []string{"routes/otp.ts", "lib/otp"}, Sessions: []string{"08.5", "03"}},
			{ID: "SURF-002", Kind: "endpoint", Name: "GET /items", Role: "entry_point", Files: []string{"routes/items.ts"}, Sessions: []string{"04", "08"}},
			{ID: "SURF-003", Kind: "table", Name: "items", Role: "data_store", Files: []string{"db/schema.sql"}, Sessions: []string{"02"}},
		},
	}

	writeFile(t, root, "lib/otp/send.ts", "v2\n")
	git(t, root, "commit", "-q", "-am", "edit limiter")
	if err := os.Remove(filepath.Join(root, "routes", "items.ts")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	writeFile(t, root, "routes/admin.ts", "new\n")
	writeFile(t, root, RelativePath, "version: 1\n")
	writeFile(t, root, ".ensphere/map.md", "# Map\n")
	writeFile(t, root, ".ensphere/invariants/x.yaml", "id: INV-001\n")
	writeFile(t, root, "ensphere-pentest/config.md", "# Assessment Configuration\n")

	set, err := Changed(m, root, "")
	if err != nil {
		t.Fatalf("changed: %v", err)
	}
	if set.Since != base || set.Head == "" || set.Head == base {
		t.Fatalf("since must default to reconciled_at and head must be the new commit: %+v", set)
	}
	if want := []string{"lib/otp/send.ts", "routes/admin.ts", "routes/items.ts"}; !reflect.DeepEqual(set.ChangedFiles, want) {
		t.Fatalf("changed_files = %v, want %v", set.ChangedFiles, want)
	}
	want := []ChangedSurface{
		{ID: "SURF-001", Name: "POST /api/auth/otp", Kind: "endpoint", Sessions: []string{"03", "08.5"}, ChangedFiles: []string{"lib/otp/send.ts"}},
		{ID: "SURF-002", Name: "GET /items", Kind: "endpoint", Sessions: []string{"04", "08"}, ChangedFiles: []string{"routes/items.ts"}},
	}
	if !reflect.DeepEqual(set.ChangedSurfaces, want) {
		t.Fatalf("changed_surfaces = %+v, want %+v", set.ChangedSurfaces, want)
	}
	if !reflect.DeepEqual(set.UnmappedChangedFiles, []string{"routes/admin.ts"}) {
		t.Fatalf("unmapped_changed_files = %v", set.UnmappedChangedFiles)
	}
	if !reflect.DeepEqual(set.MissingFiles, []MissingFile{{SurfaceID: "SURF-002", File: "routes/items.ts"}}) {
		t.Fatalf("missing_files = %+v", set.MissingFiles)
	}
	if !reflect.DeepEqual(set.SessionsAffected, []string{"03", "04", "08", "08.5"}) {
		t.Fatalf("sessions_affected = %v", set.SessionsAffected)
	}

	explicit, err := Changed(m, root, "HEAD")
	if err != nil {
		t.Fatalf("changed since HEAD: %v", err)
	}
	if explicit.Since != "HEAD" || len(explicit.ChangedSurfaces) != 1 || explicit.ChangedSurfaces[0].ID != "SURF-002" {
		t.Fatalf("an explicit since must override reconciled_at: %+v", explicit)
	}
}

func TestChangedReportsGitFailures(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	git(t, root, "init", "-q")
	writeFile(t, root, "a.txt", "a\n")
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "base")

	_, err := Changed(&Map{Version: 1, ReconciledAt: "no-such-ref"}, root, "")
	if err == nil || !strings.Contains(err.Error(), "no-such-ref") {
		t.Fatalf("expected a git error naming the bad ref with stderr, got %v", err)
	}
	if _, err := Changed(&Map{Version: 1}, root, ""); err == nil {
		t.Fatal("expected an error when neither since nor reconciled_at is set")
	}
	if _, err := Changed(&Map{Version: 1}, root, "--output=x"); err == nil {
		t.Fatal("expected an option-shaped ref to be refused")
	}
}
