package runner

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/srank-org/ensphere/internal/verify"
)

func TestParseScopeList(t *testing.T) {
	got, err := ParseScopeList(" Localhost, *.Staging.Example.com ,10.0.0.0/8,127.0.0.1,::1")
	if err != nil {
		t.Fatalf("parse valid list: %v", err)
	}
	want := []string{"localhost", "*.staging.example.com", "10.0.0.0/8", "127.0.0.1", "::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseScopeList = %q, want %q", got, want)
	}
	if got, err := ParseScopeList("  "); err != nil || len(got) != 0 {
		t.Fatalf("expected an empty list for an empty value, got %q err=%v", got, err)
	}
	for _, bad := range []string{"a b", "https://example.com", "example.com/api", "10.0.0.0/33", "a,,b", "All network-reachable endpoints"} {
		if _, err := ParseScopeList(bad); !errors.Is(err, ErrInvalidScope) {
			t.Fatalf("ParseScopeList(%q) err = %v, want ErrInvalidScope", bad, err)
		} else if !strings.Contains(err.Error(), "comma-separated list of hostnames, globs, IPs, or CIDRs") {
			t.Fatalf("error does not show the expected form: %v", err)
		}
	}
}

func readScopeLine(t *testing.T, workspace string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(workspace, "config.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "- In scope:") {
			return line
		}
	}
	t.Fatalf("config.md has no In scope line:\n%s", raw)
	return ""
}

func TestInitWorkspaceScope(t *testing.T) {
	dir := t.TempDir()

	listed := filepath.Join(dir, "listed")
	if _, err := InitWorkspace(InitConfig{Workspace: listed, TargetURL: "http://localhost:3000", InScope: "LOCALHOST, 127.0.0.1"}); err != nil {
		t.Fatalf("init with a scope list: %v", err)
	}
	if line := readScopeLine(t, listed); line != "- In scope: localhost, 127.0.0.1" {
		t.Fatalf("scope line = %q", line)
	}

	defaulted := filepath.Join(dir, "defaulted")
	if _, err := InitWorkspace(InitConfig{Workspace: defaulted, TargetURL: "https://Staging.Example.com:8443/app"}); err != nil {
		t.Fatalf("init with a target only: %v", err)
	}
	if line := readScopeLine(t, defaulted); line != "- In scope: staging.example.com" {
		t.Fatalf("scope line = %q, want the target host", line)
	}
	plan, err := RunPlan(defaulted, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !reflect.DeepEqual(plan.Plan.Target.Scope, []string{"staging.example.com"}) {
		t.Fatalf("plan scope = %q", plan.Plan.Target.Scope)
	}

	sourceOnly := filepath.Join(dir, "source-only")
	if _, err := InitWorkspace(InitConfig{Workspace: sourceOnly}); err != nil {
		t.Fatalf("init source-only: %v", err)
	}
	if line := strings.TrimSpace(readScopeLine(t, sourceOnly)); line != "- In scope:" {
		t.Fatalf("scope line = %q, want empty", line)
	}
	cfg, err := readConfig(sourceOnly)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InScope != "" {
		t.Fatalf("readConfig substituted a scope: %q", cfg.InScope)
	}

	rejected := filepath.Join(dir, "rejected")
	if _, err := InitWorkspace(InitConfig{Workspace: rejected, TargetURL: "http://localhost", InScope: "a b"}); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("expected ErrInvalidScope, got %v", err)
	}
	if _, err := os.Stat(rejected); !os.IsNotExist(err) {
		t.Fatalf("a rejected init wrote the workspace: %v", err)
	}
}

func TestCheckScopeApproved(t *testing.T) {
	dir := t.TempDir()
	workspace := filepath.Join(dir, "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "http://localhost:3000", InScope: "localhost, *.sandbox.test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := CheckScopeApproved(workspace, []string{"LOCALHOST", " *.sandbox.test "}); err != nil {
		t.Fatalf("approved patterns refused: %v", err)
	}

	err := CheckScopeApproved(workspace, []string{"localhost", "example.com"})
	var scopeErr *verify.ScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("expected a ScopeError, got %v", err)
	}
	want := "--in-scope example.com is not in the workspace scope approved in " + filepath.Join(workspace, "config.md") + " (localhost, *.sandbox.test); scope is operator-approved there, not on the command line"
	if err.Error() != want {
		t.Fatalf("message = %q\nwant      %q", err.Error(), want)
	}

	sourceOnly := filepath.Join(dir, "source-only")
	if _, err := InitWorkspace(InitConfig{Workspace: sourceOnly}); err != nil {
		t.Fatalf("init source-only: %v", err)
	}
	err = CheckScopeApproved(sourceOnly, []string{"localhost"})
	if !errors.As(err, &scopeErr) || err.Error() != "the workspace at "+sourceOnly+" has no live-target scope; a source-only assessment sends no requests" {
		t.Fatalf("unexpected empty-scope result: %v", err)
	}
}
