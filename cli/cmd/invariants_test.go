package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const cmdHTTPInvariant = `id: %s
title: "Admin route answers 404"
origin: {kind: vulnerability, ref: VULN-001}
enforce: %t
kind: http
request: {path: %s}
expect: {status: 404}
`

func invariantSource(t *testing.T, files map[string]string) string {
	t.Helper()
	source := t.TempDir()
	dir := filepath.Join(source, ".ensphere", "invariants")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return source
}

func notFoundServer(t *testing.T) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(server.Close)
	return server
}

type invariantsValidateJSON struct {
	Dir        string           `json:"dir"`
	Invariants int              `json:"invariants"`
	Valid      bool             `json:"valid"`
	Issues     []map[string]any `json:"issues"`
}

func TestCLIInvariantsValidate(t *testing.T) {
	source := invariantSource(t, map[string]string{"admin.yaml": fmt.Sprintf(cmdHTTPInvariant, "INV-001", true, "/admin")})
	result := runCLIIn(t, source, "", "invariants", "validate")
	if result.code != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%s stdout=%s", result.code, result.stderr, result.stdout)
	}
	var out invariantsValidateJSON
	decodeJSON(t, result.stdout, &out)
	if !out.Valid || out.Invariants != 1 || out.Issues == nil || len(out.Issues) != 0 || out.Dir != filepath.Join(".", ".ensphere", "invariants") {
		t.Fatalf("unexpected validate output: %+v", out)
	}

	bad := invariantSource(t, map[string]string{
		"a.yaml": fmt.Sprintf(cmdHTTPInvariant, "INV-001", true, "/admin"),
		"b.yaml": fmt.Sprintf(cmdHTTPInvariant, "INV-001", false, "admin"),
	})
	result = runCLIIn(t, bad, "", "invariants", "validate")
	if result.code != 1 {
		t.Fatalf("expected exit 1, got %d stderr=%s stdout=%s", result.code, result.stderr, result.stdout)
	}
	decodeJSON(t, result.stdout, &out)
	if out.Valid || out.Invariants != 2 || len(out.Issues) != 2 || out.Issues[0]["code"] != "invariant_field_invalid" || out.Issues[1]["code"] != "invariant_id_duplicate" {
		t.Fatalf("unexpected invalid output: %+v", out)
	}

	result = runCLIIn(t, t.TempDir(), "", "invariants", "validate")
	if result.code != 3 {
		t.Fatalf("expected exit 3 for a missing directory, got %d stderr=%s", result.code, result.stderr)
	}
}

func TestCLIInvariantsValidateChecksSurfacesFromMap(t *testing.T) {
	inv := fmt.Sprintf(cmdHTTPInvariant, "INV-001", true, "/admin") + "surface: SURF-009\n"
	source := invariantSource(t, map[string]string{"admin.yaml": inv})
	mapPath := filepath.Join(source, ".ensphere", "surfaces.yaml")
	if err := os.WriteFile(mapPath, []byte("surfaces:\n  - id: SURF-001\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result := runCLIIn(t, source, "", "invariants", "validate")
	var out invariantsValidateJSON
	decodeJSON(t, result.stdout, &out)
	if result.code != 1 || len(out.Issues) != 1 || out.Issues[0]["code"] != "invariant_surface_unknown" {
		t.Fatalf("expected one surface issue and exit 1, got %d %+v", result.code, out)
	}
	other := filepath.Join(t.TempDir(), "map.yaml")
	if err := os.WriteFile(other, []byte("surfaces:\n  - id: SURF-009\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if result := runCLIIn(t, source, "", "invariants", "validate", "--map", other); result.code != 0 {
		t.Fatalf("--map naming the surface should pass, got %d stdout=%s", result.code, result.stdout)
	}
}

func TestCLIInvariantsRun(t *testing.T) {
	server := notFoundServer(t)
	source := invariantSource(t, map[string]string{
		"admin.yaml":  fmt.Sprintf(cmdHTTPInvariant, "INV-001", true, "/admin"),
		"public.yaml": fmt.Sprintf(cmdHTTPInvariant, "INV-002", false, "/public"),
	})
	outFile := filepath.Join(t.TempDir(), "report.json")
	result := runCLIIn(t, source, "", "invariants", "run", "--target", server.URL, "--in-scope", "127.0.0.1", "--throttle", "0", "--out", outFile)
	if result.code != 0 {
		t.Fatalf("an unenforced failure alone should exit 0, got %d stderr=%s stdout=%s", result.code, result.stderr, result.stdout)
	}
	var report struct {
		Target     string           `json:"target"`
		SourcePath string           `json:"source_path"`
		Invariants []map[string]any `json:"invariants"`
		Summary    map[string]int   `json:"summary"`
		Message    string           `json:"message"`
	}
	decodeJSON(t, result.stdout, &report)
	if report.Target != server.URL || len(report.Invariants) != 2 || report.Summary["pass"] != 1 || report.Summary["unenforced_fail"] != 1 || report.Message == "" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Invariants[0]["result"] != "pass" || report.Invariants[1]["result"] != "fail" {
		t.Fatalf("unexpected results: %+v", report.Invariants)
	}
	written, err := os.ReadFile(outFile)
	if err != nil || string(written) != result.stdout {
		t.Fatalf("--out should hold the printed report, err=%v", err)
	}

	enforced := invariantSource(t, map[string]string{"public.yaml": fmt.Sprintf(cmdHTTPInvariant, "INV-002", true, "/public")})
	result = runCLIIn(t, enforced, "", "invariants", "run", "--target", server.URL, "--in-scope", "127.0.0.1", "--throttle", "0")
	if result.code != 1 {
		t.Fatalf("an enforced failure should exit 1, got %d stderr=%s", result.code, result.stderr)
	}
	decodeJSON(t, result.stdout, &report)
	if report.Summary["enforced_fail"] != 1 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}

	result = runCLIIn(t, source, "", "invariants", "run", "--target", server.URL, "--in-scope", "127.0.0.1", "--throttle", "0", "--only", "INV-002")
	decodeJSON(t, result.stdout, &report)
	if result.code != 0 || len(report.Invariants) != 1 || report.Invariants[0]["id"] != "INV-002" {
		t.Fatalf("--only should run INV-002 alone, got %d %+v", result.code, report.Invariants)
	}
}

func TestCLIInvariantsRunUsageAndValidationExits(t *testing.T) {
	server := notFoundServer(t)
	source := invariantSource(t, map[string]string{"admin.yaml": fmt.Sprintf(cmdHTTPInvariant, "INV-001", true, "/admin")})

	if result := runCLIIn(t, source, "", "invariants", "run", "--target", server.URL); result.code != 2 {
		t.Fatalf("missing --in-scope should exit 2, got %d stderr=%s", result.code, result.stderr)
	}
	if result := runCLIIn(t, source, "", "invariants", "run", "--target", server.URL, "--in-scope", "127.0.0.1", "--only", "INV-404"); result.code != 2 {
		t.Fatalf("an unknown --only id should exit 2, got %d stderr=%s", result.code, result.stderr)
	}
	if result := runCLIIn(t, source, "", "invariants", "run", "--target", "not a url", "--in-scope", "127.0.0.1"); result.code != 2 {
		t.Fatalf("a malformed --target should exit 2, got %d stderr=%s", result.code, result.stderr)
	}

	invalid := invariantSource(t, map[string]string{"admin.yaml": fmt.Sprintf(cmdHTTPInvariant, "INV-1", true, "/admin")})
	result := runCLIIn(t, invalid, "", "invariants", "run", "--target", server.URL, "--in-scope", "127.0.0.1")
	if result.code != 1 {
		t.Fatalf("invalid invariants should exit 1 before running, got %d stderr=%s", result.code, result.stderr)
	}
	var out invariantsValidateJSON
	decodeJSON(t, result.stdout, &out)
	if out.Valid || len(out.Issues) != 1 || out.Issues[0]["code"] != "invariant_id_invalid" {
		t.Fatalf("expected the validate output, got %+v", out)
	}
}
