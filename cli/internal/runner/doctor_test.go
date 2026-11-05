package runner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/srank-org/ensphere/internal/evidence"
)

func doctorCheck(t *testing.T, out *DoctorOutput, name string) DoctorCheck {
	t.Helper()
	for _, check := range out.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("no %s check in %+v", name, out.Checks)
	return DoctorCheck{}
}

func TestRunDoctorWithoutWorkspace(t *testing.T) {
	root := t.TempDir()
	out := RunDoctor(DoctorConfig{Workspace: filepath.Join(root, "ensphere-pentest"), BinaryVersion: "0.2.0", PluginVersion: "0.2.0"})
	if out.Ready {
		t.Fatalf("no workspace must not be ready: %+v", out)
	}
	if c := doctorCheck(t, out, "workspace"); c.State != DoctorError || !strings.Contains(c.Detail, "run init") {
		t.Fatalf("workspace check %+v", c)
	}
	if c := doctorCheck(t, out, "binary"); c.State != DoctorOK {
		t.Fatalf("binary check %+v", c)
	}
	for _, name := range []string{"target", "sandbox", "providers", "ledgers"} {
		if c := doctorCheck(t, out, name); c.State != DoctorSkipped {
			t.Fatalf("%s must be skipped without a workspace, got %+v", name, c)
		}
	}
	if c := doctorCheck(t, out, "map"); c.State != DoctorSkipped {
		t.Fatalf("map check %+v", c)
	}
}

func TestRunDoctorSourceOnlyWorkspaceIsReadyWithWarnings(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, SourcePath: root}); err != nil {
		t.Fatalf("init: %v", err)
	}
	out := RunDoctor(DoctorConfig{Workspace: workspace, BinaryVersion: "v0.2.0", PluginVersion: "0.2.0"})
	if !out.Ready {
		t.Fatalf("a source-only workspace outside git must be ready with warnings: %+v", out)
	}
	if c := doctorCheck(t, out, "source"); c.State != DoctorWarning || !strings.Contains(c.Detail, "not in a git repository") {
		t.Fatalf("source check %+v", c)
	}
	if c := doctorCheck(t, out, "target"); c.State != DoctorSkipped {
		t.Fatalf("target check %+v", c)
	}
	if c := doctorCheck(t, out, "sandbox"); c.State != DoctorSkipped {
		t.Fatalf("sandbox check %+v", c)
	}
	if c := doctorCheck(t, out, "providers"); c.State != DoctorSkipped {
		t.Fatalf("providers check %+v", c)
	}
	if !strings.HasPrefix(out.Message, "Ready with") {
		t.Fatalf("message %q", out.Message)
	}

	out = RunDoctor(DoctorConfig{Workspace: workspace, BinaryVersion: "0.1.0", PluginVersion: "0.2.0"})
	if out.Ready || doctorCheck(t, out, "binary").State != DoctorError {
		t.Fatalf("a binary that does not match the plugin must block: %+v", out)
	}
	out = RunDoctor(DoctorConfig{Workspace: workspace, BinaryVersion: "v0.2.0-3-gabcdef"})
	if c := doctorCheck(t, out, "binary"); c.State != DoctorWarning {
		t.Fatalf("an untagged build with no plugin version is a warning, got %+v", c)
	}
}

func TestRunDoctorChecksTheTargetInsideTheApprovedScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	root := t.TempDir()
	workspace := filepath.Join(root, "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, SourcePath: root, TargetURL: server.URL, InScope: "127.0.0.1", SandboxStart: "make up"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	out := RunDoctor(DoctorConfig{Workspace: workspace, BinaryVersion: "0.2.0", PluginVersion: "0.2.0"})
	if c := doctorCheck(t, out, "target"); c.State != DoctorOK || !strings.Contains(c.Detail, "answered 204") {
		t.Fatalf("target check %+v", c)
	}
	if c := doctorCheck(t, out, "sandbox"); c.State != DoctorWarning || !strings.Contains(c.Detail, "Seed, Reset") {
		t.Fatalf("sandbox check %+v", c)
	}

	setConfigLine(t, workspace, "- In scope: 127.0.0.1", "- In scope: example.com")
	out = RunDoctor(DoctorConfig{Workspace: workspace, BinaryVersion: "0.2.0", PluginVersion: "0.2.0"})
	if c := doctorCheck(t, out, "target"); c.State != DoctorError || !strings.Contains(c.Detail, "outside the approved scope") {
		t.Fatalf("a target outside the approved scope must block, got %+v", c)
	}

	server.Close()
	setConfigLine(t, workspace, "- In scope: example.com", "- In scope: 127.0.0.1")
	out = RunDoctor(DoctorConfig{Workspace: workspace, BinaryVersion: "0.2.0", PluginVersion: "0.2.0", TimeoutSec: 2})
	if c := doctorCheck(t, out, "target"); c.State != DoctorError || !strings.Contains(c.Detail, "failed") {
		t.Fatalf("an unreachable target must block, got %+v", c)
	}
}

func TestRunDoctorChecksProviderCLIs(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, SourcePath: root, Cloud: "aws,cloudflare"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	out := RunDoctor(DoctorConfig{Workspace: workspace, BinaryVersion: "0.2.0", PluginVersion: "0.2.0"})
	if c := doctorCheck(t, out, "providers"); c.State != DoctorError || !strings.Contains(c.Detail, "aws (aws)") || !strings.Contains(c.Detail, "wrangler (cloudflare)") {
		t.Fatalf("missing provider CLIs must block, got %+v", c)
	}
	for _, name := range []string{"aws", "wrangler"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	out = RunDoctor(DoctorConfig{Workspace: workspace, BinaryVersion: "0.2.0", PluginVersion: "0.2.0"})
	if c := doctorCheck(t, out, "providers"); c.State != DoctorOK || !strings.Contains(c.Detail, "aws sts get-caller-identity") {
		t.Fatalf("installed CLIs must pass and name the login check, got %+v", c)
	}
}

func TestRunDoctorVerifiesLedgersAndTheMap(t *testing.T) {
	source, head := committedSource(t)
	workspace := filepath.Join(source, "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, SourcePath: source}); err != nil {
		t.Fatalf("init: %v", err)
	}
	writeSystemMap(t, source, head)
	writeInvariantFor(t, source, "INV-001", "VULN-001", false)
	ledger := filepath.Join(workspace, "02-injection", "evidence.jsonl")
	writer, err := evidence.NewWriter(ledger)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	for _, stage := range []string{"baseline", "probe"} {
		if _, err := writer.WriteEntry(evidence.NewEntry("sqli", "blind_boolean", "https://example.com/search", "q", 200, "12ms", stage, "fixture")); err != nil {
			t.Fatalf("write evidence: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	out := RunDoctor(DoctorConfig{Workspace: workspace, BinaryVersion: "0.2.0", PluginVersion: "0.2.0"})
	if !out.Ready {
		t.Fatalf("expected ready: %+v", out)
	}
	if c := doctorCheck(t, out, "source"); c.State != DoctorOK || !strings.Contains(c.Detail, "clean") {
		t.Fatalf("source check %+v", c)
	}
	if c := doctorCheck(t, out, "map"); c.State != DoctorOK || !strings.Contains(c.Detail, "2 surface(s)") {
		t.Fatalf("map check %+v", c)
	}
	if c := doctorCheck(t, out, "invariants"); c.State != DoctorOK || !strings.Contains(c.Detail, "1 invariant(s), 0 enforced") {
		t.Fatalf("invariants check %+v", c)
	}
	if c := doctorCheck(t, out, "ledgers"); c.State != DoctorOK || !strings.Contains(c.Detail, "2 entries") {
		t.Fatalf("ledgers check %+v", c)
	}

	raw, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledger, []byte(strings.Replace(string(raw), `"baseline"`, `"control"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	writeSourceFile(t, source, "routes/otp.ts", "v2\n")
	writeSourceFile(t, source, ".ensphere/invariants/INV-002.yaml", "id: INV-002\ntitle: bogus\norigin: {kind: tested_defense, ref: COV-02-001}\nkind: telepathy\nexpect: {}\n")
	out = RunDoctor(DoctorConfig{Workspace: workspace, BinaryVersion: "0.2.0", PluginVersion: "0.2.0"})
	if out.Ready {
		t.Fatalf("a broken ledger must block: %+v", out)
	}
	if c := doctorCheck(t, out, "ledgers"); c.State != DoctorError || !strings.Contains(c.Detail, "session 02") {
		t.Fatalf("ledgers check %+v", c)
	}
	if c := doctorCheck(t, out, "source"); c.State != DoctorWarning || !strings.Contains(c.Detail, "routes/otp.ts") {
		t.Fatalf("a modified tree warns before the run and names the file, got %+v", c)
	}
	if c := doctorCheck(t, out, "invariants"); c.State != DoctorError {
		t.Fatalf("invariants check %+v", c)
	}
}

func TestPluginVersionReadsTheManifest(t *testing.T) {
	root := t.TempDir()
	if PluginVersion("") != "" || PluginVersion(root) != "" {
		t.Fatal("no root or no manifest must yield an empty version")
	}
	writeSourceFile(t, root, ".claude-plugin/plugin.json", `{"name": "ensphere", "version": "0.2.0"}`)
	if got := PluginVersion(root); got != "0.2.0" {
		t.Fatalf("PluginVersion = %q", got)
	}
}
