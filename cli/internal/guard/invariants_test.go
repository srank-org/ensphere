package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sourceWithWorkspace(t *testing.T, sandbox string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "ensphere-pentest")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.md"), []byte("# Config\n\n## Sandbox\n\n"+sandbox+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func noEnv(string) string { return "" }

func TestCommandGuardRefusesANetworkToolInAWorkspace(t *testing.T) {
	root := sourceWithWorkspace(t, "- Start: docker compose up -d")
	g := CommandGuard(root, noEnv)
	if g == nil {
		t.Fatal("a workspace under the source path must produce a guard")
	}
	if reason := g("curl http://x/"); !strings.Contains(reason, "Ensphere guard") {
		t.Fatalf("expected a refusal naming the guard, got %q", reason)
	}
	if reason := g("psql \"$DATABASE_URL\" -tAc 'select 1'"); reason != "" {
		t.Fatalf("a database client is not a network tool the guard refuses, got %q", reason)
	}
}

func TestCommandGuardLetsAnApprovedSandboxCommandThrough(t *testing.T) {
	root := sourceWithWorkspace(t, "- Seed: ./curl http://x/")
	g := CommandGuard(root, noEnv)
	if g == nil {
		t.Fatal("expected a guard")
	}
	if reason := g("./curl http://x/"); reason != "" {
		t.Fatalf("the approved sandbox command must run, got %q", reason)
	}
}

func TestCommandGuardIsAbsentWithoutAWorkspaceOrWhenOff(t *testing.T) {
	if g := CommandGuard(t.TempDir(), noEnv); g != nil {
		t.Fatal("no workspace means no guard")
	}
	root := sourceWithWorkspace(t, "- Start: docker compose up -d")
	off := func(k string) string {
		if k == "ENSPHERE_GUARD" {
			return "off"
		}
		return ""
	}
	if g := CommandGuard(root, off); g != nil {
		t.Fatal("ENSPHERE_GUARD=off means no guard")
	}
}
