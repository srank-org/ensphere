package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const cliTestMap = `version: 1
reconciled_at: "%s"
surfaces:
  - id: SURF-001
    kind: endpoint
    name: "POST /api/auth/otp"
    role: billed_operation
    files: [routes/otp.ts]
    sessions: ["03", "08.5"]
    checks: [rate_limit_burst]
  - id: SURF-002
    kind: table
    name: "items"
    role: data_store
    files: [db/schema.sql]
    sessions: ["02"]
`

type mapValidateOutput struct {
	Path     string `json:"path"`
	Valid    bool   `json:"valid"`
	Surfaces int    `json:"surfaces"`
	Issues   []struct {
		Severity string `json:"severity"`
		Code     string `json:"code"`
		Path     string `json:"path"`
	} `json:"issues"`
}

func writeMapSource(t *testing.T, root, reconciledAt string) {
	t.Helper()
	for rel, content := range map[string]string{
		"routes/otp.ts":           "v1\n",
		"db/schema.sql":           "v1\n",
		".ensphere/surfaces.yaml": strings.Replace(cliTestMap, "%s", reconciledAt, 1),
	} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
}

func gitIn(t *testing.T, dir string, args ...string) string {
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

func TestCLIMapValidate(t *testing.T) {
	source := t.TempDir()
	writeMapSource(t, source, "9f1c2d3e")

	result := runCLISplit(t, "map", "validate", "--source-path", source)
	if result.code != 0 {
		t.Fatalf("valid map exit %d stderr=%s stdout=%s", result.code, result.stderr, result.stdout)
	}
	var out mapValidateOutput
	decodeJSON(t, result.stdout, &out)
	if !out.Valid || out.Surfaces != 2 || out.Path != filepath.Join(source, ".ensphere", "surfaces.yaml") {
		t.Fatalf("unexpected output: %+v", out)
	}
	if len(out.Issues) != 1 || out.Issues[0].Code != "surface_checks_empty" || out.Issues[0].Severity != "warning" {
		t.Fatalf("expected only the empty-checks warning, got %+v", out.Issues)
	}

	if err := os.Remove(filepath.Join(source, "db", "schema.sql")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	result = runCLISplit(t, "map", "validate", "--source-path", source)
	if result.code != 1 {
		t.Fatalf("invalid map must exit 1, got %d stderr=%s", result.code, result.stderr)
	}
	out = mapValidateOutput{}
	decodeJSON(t, result.stdout, &out)
	if out.Valid || out.Issues[1].Code != "surface_file_missing" || out.Issues[1].Path != "surfaces[1].files[0]" {
		t.Fatalf("expected surface_file_missing, got %+v", out)
	}

	result = runCLISplit(t, "map", "validate", "--source-path", source, "--map", filepath.Join(source, "missing.yaml"))
	if result.code != 3 || !strings.HasPrefix(result.stderr, "Error: ") || result.stdout != "" {
		t.Fatalf("unreadable map must exit 3 with Error: on stderr, got %d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

func TestCLIMapChanged(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	source := t.TempDir()
	gitIn(t, source, "init", "-q")
	writeMapSource(t, source, "placeholder")
	gitIn(t, source, "add", ".")
	gitIn(t, source, "commit", "-q", "-m", "base")
	base := gitIn(t, source, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(source, "routes", "otp.ts"), []byte("v2\n"), 0644); err != nil {
		t.Fatalf("edit: %v", err)
	}

	result := runCLISplit(t, "map", "changed", "--source-path", source, "--since", base)
	if result.code != 0 {
		t.Fatalf("map changed exit %d stderr=%s", result.code, result.stderr)
	}
	var out struct {
		Since           string   `json:"since"`
		Head            string   `json:"head"`
		ChangedFiles    []string `json:"changed_files"`
		ChangedSurfaces []struct {
			ID           string   `json:"id"`
			Sessions     []string `json:"sessions"`
			ChangedFiles []string `json:"changed_files"`
		} `json:"changed_surfaces"`
		UnmappedChangedFiles []string `json:"unmapped_changed_files"`
		MissingFiles         []any    `json:"missing_files"`
		SessionsAffected     []string `json:"sessions_affected"`
	}
	decodeJSON(t, result.stdout, &out)
	if out.Since != base || out.Head != base || !reflect.DeepEqual(out.ChangedFiles, []string{"routes/otp.ts"}) {
		t.Fatalf("unexpected change set: %+v", out)
	}
	if len(out.ChangedSurfaces) != 1 || out.ChangedSurfaces[0].ID != "SURF-001" || !reflect.DeepEqual(out.ChangedSurfaces[0].ChangedFiles, []string{"routes/otp.ts"}) {
		t.Fatalf("unexpected changed surfaces: %+v", out.ChangedSurfaces)
	}
	if !reflect.DeepEqual(out.SessionsAffected, []string{"03", "08.5"}) || out.UnmappedChangedFiles == nil || len(out.UnmappedChangedFiles) != 0 || out.MissingFiles == nil {
		t.Fatalf("unexpected sessions or empty lists: %+v", out)
	}

	result = runCLISplit(t, "map", "changed", "--source-path", source)
	if result.code != 3 || !strings.Contains(result.stderr, "placeholder") {
		t.Fatalf("a reconciled_at git cannot resolve must exit 3 with git's error, got %d stderr=%s", result.code, result.stderr)
	}
}
