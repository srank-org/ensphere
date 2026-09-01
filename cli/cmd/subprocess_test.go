package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

var (
	cliRoot      string
	cliBinary    string
	cliBinaryDir string
)

type commandResult struct {
	stdout string
	stderr string
	code   int
}

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "get wd: %v\n", err)
		os.Exit(1)
	}
	cliRoot = filepath.Dir(wd)
	cliBinaryDir, err = os.MkdirTemp("", "ensphere-cli-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdir temp: %v\n", err)
		os.Exit(1)
	}
	cliBinary = filepath.Join(cliBinaryDir, "ensphere-test")
	build := exec.Command("go", "build", "-o", cliBinary, ".")
	build.Dir = cliRoot
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build cli: %v\n%s\n", err, out)
		os.RemoveAll(cliBinaryDir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(cliBinaryDir)
	os.Exit(code)
}

func runCLISplit(t *testing.T, args ...string) commandResult {
	t.Helper()
	cmd := exec.Command(cliBinary, args...)
	cmd.Dir = cliRoot
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		code = 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
	}
	return commandResult{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

func decodeJSON(t *testing.T, raw string, out any) {
	t.Helper()
	if err := json.Unmarshal([]byte(raw), out); err != nil {
		t.Fatalf("decode JSON failed: %v\n%s", err, raw)
	}
}

func TestCLIHelpIncludesRepresentativeCommands(t *testing.T) {
	result := runCLISplit(t, "--help")
	if result.code != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%s", result.code, result.stderr)
	}
	for _, want := range []string{"payloads", "verify", "scan", "evidence"} {
		if !strings.Contains(result.stdout, want) {
			t.Fatalf("help missing %q:\n%s", want, result.stdout)
		}
	}
}

func TestCLIRequiredFlagFailure(t *testing.T) {
	result := runCLISplit(t, "verify", "sqli",
		"--url", "http://127.0.0.1:1/search?id=1",
		"--param", "id",
	)
	if result.code == 0 {
		t.Fatalf("expected required flag failure, got exit 0 stdout=%s", result.stdout)
	}
	if combined := result.stdout + result.stderr; !strings.Contains(combined, "required flag") || !strings.Contains(combined, "in-scope") {
		t.Fatalf("expected required in-scope flag message, got stdout=%s stderr=%s", result.stdout, result.stderr)
	}
}

func TestCLIPayloadsJSONContract(t *testing.T) {
	result := runCLISplit(t, "payloads", "sqli", "--db", "postgres", "--technique", "blind_time", "--limit", "1")
	if result.code != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%s", result.code, result.stderr)
	}
	var out struct {
		Query   map[string]any   `json:"query"`
		Count   int              `json:"count"`
		Results []map[string]any `json:"results"`
	}
	decodeJSON(t, result.stdout, &out)
	if out.Count != 1 || len(out.Results) != 1 {
		t.Fatalf("expected one payload, got %+v", out)
	}
	if out.Results[0]["payload"] == "" || out.Results[0]["risk"] == nil {
		t.Fatalf("payload result missing core fields: %+v", out.Results[0])
	}
}

func TestCLICvssJSONContract(t *testing.T) {
	result := runCLISplit(t, "cvss", "--av", "N", "--ac", "L", "--at", "N", "--pr", "N", "--ui", "N", "--vc", "H", "--vi", "H", "--va", "H", "--sc", "H", "--si", "H", "--sa", "H")
	if result.code != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%s", result.code, result.stderr)
	}
	var out map[string]any
	decodeJSON(t, result.stdout, &out)
	if out["severity"] != "Critical" || out["base_score"].(float64) != 10.0 {
		t.Fatalf("unexpected cvss output: %+v", out)
	}
}

func TestCLIComplianceJSONContract(t *testing.T) {
	complianceResult := runCLISplit(t, "compliance", "--list")
	if complianceResult.code != 0 {
		t.Fatalf("compliance --list exit %d stderr=%s", complianceResult.code, complianceResult.stderr)
	}
	var compliance struct {
		VulnTypes []map[string]any `json:"vuln_types"`
	}
	decodeJSON(t, complianceResult.stdout, &compliance)
	if len(compliance.VulnTypes) == 0 || compliance.VulnTypes[0]["vuln_type"] == "" {
		t.Fatalf("unexpected compliance list: %+v", compliance)
	}
}

func TestCLIOpenAPIFileJSONContract(t *testing.T) {
	specPath := filepath.Join(t.TempDir(), "openapi.json")
	spec := `{"openapi":"3.0.0","info":{"title":"Test API","version":"1.0.0"},"paths":{"/items":{"get":{"operationId":"listItems","parameters":[{"name":"q","in":"query","schema":{"type":"string"}}]}}}}`
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatalf("write spec: %v", err)
	}

	result := runCLISplit(t, "openapi", "--file", specPath)
	if result.code != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%s", result.code, result.stderr)
	}
	var out struct {
		Title      string           `json:"title"`
		TotalOps   int              `json:"total_operations"`
		Endpoints  []map[string]any `json:"endpoints"`
		TotalPaths int              `json:"total_paths"`
	}
	decodeJSON(t, result.stdout, &out)
	if out.Title != "Test API" || out.TotalOps != 1 || out.TotalPaths != 1 || out.Endpoints[0]["method"] != "GET" {
		t.Fatalf("unexpected openapi output: %+v", out)
	}
}

func TestCLIEvidenceLogAndQueryJSONContracts(t *testing.T) {
	evidenceFile := filepath.Join(t.TempDir(), "evidence.jsonl")
	logResult := runCLISplit(t, "evidence", "log", "--file", evidenceFile, "--probe-type", "sqli", "--technique", "manual", "--url", "http://target.local/api", "--result", "manual_note")
	if logResult.code != 0 {
		t.Fatalf("evidence log exit %d stderr=%s", logResult.code, logResult.stderr)
	}
	var entry map[string]any
	decodeJSON(t, logResult.stdout, &entry)
	if entry["id"] != "EVID-001" || entry["hash"] == "" || entry["result"] != "manual_note" {
		t.Fatalf("unexpected evidence entry: %+v", entry)
	}

	queryResult := runCLISplit(t, "evidence", "query", "--file", evidenceFile, "--result", "manual_note")
	if queryResult.code != 0 {
		t.Fatalf("evidence query exit %d stderr=%s", queryResult.code, queryResult.stderr)
	}
	var entries []map[string]any
	decodeJSON(t, queryResult.stdout, &entries)
	if len(entries) != 1 || entries[0]["id"] != "EVID-001" {
		t.Fatalf("unexpected evidence query output: %+v", entries)
	}
}

func TestCLIVerifyOutputHasNoJudgmentFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	evidenceFile := filepath.Join(t.TempDir(), "evidence.jsonl")

	result := runCLISplit(t, "verify", "sqli",
		"--url", server.URL+"/search?id=1",
		"--param", "id",
		"--db", "sqlite",
		"--technique", "error_based",
		"--in-scope", "127.0.0.1",
		"--throttle", "0",
		"--evidence", evidenceFile,
	)
	if result.code != 0 {
		t.Fatalf("verify sqli exit %d stderr=%s stdout=%s", result.code, result.stderr, result.stdout)
	}
	var out map[string]any
	decodeJSON(t, result.stdout, &out)
	if out["vuln_type"] != "sqli" || out["technique"] != "error_based" {
		t.Fatalf("unexpected verify output: %+v", out)
	}
	assertNoForbiddenFields(t, out)
}

func TestCLIScopeFailureDoesNotExecuteRequest(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "unexpected")
	}))
	defer server.Close()

	result := runCLISplit(t, "verify", "xss",
		"--url", server.URL+"/search?q=x",
		"--param", "q",
		"--payload", "<script>alert(1)</script>",
		"--in-scope", "example.com",
		"--evidence", filepath.Join(t.TempDir(), "evidence.jsonl"),
	)
	if result.code != 2 {
		t.Fatalf("expected scope exit 2, got %d stderr=%s stdout=%s", result.code, result.stderr, result.stdout)
	}
	if hits.Load() != 0 {
		t.Fatalf("scope failure should not execute request, got %d hits", hits.Load())
	}
}

func TestCLIMalformedHeaderIsUsageExit(t *testing.T) {
	result := runCLISplit(t, "verify", "sqli",
		"--url", "http://127.0.0.1:1/search?id=1",
		"--param", "id",
		"--in-scope", "127.0.0.1",
		"--header", "bad-header",
		"--evidence", filepath.Join(t.TempDir(), "evidence.jsonl"),
	)
	if result.code != 2 {
		t.Fatalf("expected usage exit 2, got %d stderr=%s stdout=%s", result.code, result.stderr, result.stdout)
	}
	if !strings.Contains(result.stderr, "malformed --header") {
		t.Fatalf("expected malformed header message, got %s", result.stderr)
	}

	result = runCLISplit(t, "verify", "cors",
		"--url", "http://127.0.0.1:1/",
		"--in-scope", "127.0.0.1",
		"--header", "bad-header",
		"--evidence", filepath.Join(t.TempDir(), "evidence.jsonl"),
	)
	if result.code != 2 {
		t.Fatalf("expected usage exit 2 for cors, got %d stderr=%s stdout=%s", result.code, result.stderr, result.stdout)
	}
	if !strings.Contains(result.stderr, "malformed --header") {
		t.Fatalf("expected malformed header message for cors, got %s", result.stderr)
	}
}

func assertNoForbiddenFields(t *testing.T, value any) {
	t.Helper()
	forbidden := map[string]bool{
		"status":     true,
		"confidence": true,
		"confirmed":  true,
		"safe":       true,
		"potential":  true,
	}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for key, child := range x {
				if forbidden[key] {
					t.Fatalf("forbidden judgment field %q in verify output", key)
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(value)
}
