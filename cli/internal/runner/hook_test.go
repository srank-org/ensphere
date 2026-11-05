package runner

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSandboxCommandsReadsOnlyTheSandboxSection(t *testing.T) {
	config := `# Assessment Configuration

## Target
- Start: not-a-sandbox-command

## Sandbox
- Start: docker compose -f compose.sandbox.yml up -d --wait
- Seed:   npm run seed  
- Reset: make reset
- Logs: docker compose logs api
- (Writing the commands here approves them.)
- Two words: ignored
- Stop:

## Scope
- Reset: also-not-a-sandbox-command
`
	got := SandboxCommands(config)
	want := []string{
		"docker compose -f compose.sandbox.yml up -d --wait",
		"npm run seed",
		"make reset",
		"docker compose logs api",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SandboxCommands = %q, want %q", got, want)
	}
	if got := SandboxCommands("## Scope\n- In scope: localhost\n"); len(got) != 0 {
		t.Fatalf("expected no commands without a Sandbox section, got %q", got)
	}
}

func makeWorkspace(t *testing.T, dir string) string {
	t.Helper()
	workspace := filepath.Join(dir, "ensphere-pentest")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "config.md"), []byte("# Assessment Configuration\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return workspace
}

func TestFindWorkspacePrecedence(t *testing.T) {
	envWorkspace := makeWorkspace(t, t.TempDir())
	cwd := t.TempDir()
	cwdWorkspace := makeWorkspace(t, cwd)
	project := t.TempDir()
	projectWorkspace := makeWorkspace(t, project)
	env := map[string]string{
		"ENSPHERE_WORKSPACE": envWorkspace,
		"CLAUDE_PROJECT_DIR": project,
	}
	getenv := func(key string) string { return env[key] }

	if got, ok := FindWorkspace(cwd, getenv); !ok || got != envWorkspace {
		t.Fatalf("expected ENSPHERE_WORKSPACE first, got %q ok=%v", got, ok)
	}
	delete(env, "ENSPHERE_WORKSPACE")
	if got, ok := FindWorkspace(cwd, getenv); !ok || got != cwdWorkspace {
		t.Fatalf("expected the cwd workspace before the project dir, got %q ok=%v", got, ok)
	}
	if got, ok := FindWorkspace(t.TempDir(), getenv); !ok || got != projectWorkspace {
		t.Fatalf("expected the project dir workspace, got %q ok=%v", got, ok)
	}
	env["ENSPHERE_WORKSPACE"] = t.TempDir()
	if got, ok := FindWorkspace(t.TempDir(), getenv); !ok || got != projectWorkspace {
		t.Fatalf("expected an ENSPHERE_WORKSPACE without config.md to be skipped, got %q ok=%v", got, ok)
	}
}

func TestFindWorkspaceNone(t *testing.T) {
	getenv := func(string) string { return "" }
	if got, ok := FindWorkspace(t.TempDir(), getenv); ok || got != "" {
		t.Fatalf("expected no workspace, got %q", got)
	}
	if got, ok := FindWorkspace("", getenv); ok || got != "" {
		t.Fatalf("expected no workspace without a cwd, got %q", got)
	}
}

func TestSessionStartContext(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	action, err := os.ReadFile(filepath.Join(workspace, "next-action.md"))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		binary, plugin, want string
	}{
		{"v0.2.0", "0.2.0", "ensphere v0.2.0 matches plugin v0.2.0."},
		{"0.2.0", "v0.3.1", "ensphere binary v0.2.0 does not match plugin v0.3.1. Run the ensphere-setup skill before continuing the assessment."},
		{"4b7c544-dirty", "0.2.0", "ensphere binary reports 4b7c544-dirty, which is not a release version; plugin is v0.2.0. Run the ensphere-setup skill to install the matching release."},
		{"dev", "0.2.0", "ensphere binary reports dev, which is not a release version"},
		{"", "0.2.0", `ensphere binary reports "", which is not a release version`},
	}
	for _, tc := range cases {
		text := SessionStartContext(workspace, tc.binary, tc.plugin)
		lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		if lines[0] != "Ensphere assessment workspace: "+workspace {
			t.Fatalf("first line = %q", lines[0])
		}
		if !strings.Contains(text, string(action)) {
			t.Fatalf("context does not carry next-action.md:\n%s", text)
		}
		if !strings.Contains(text, "\nProgress: 01 PENDING, 01.5 PENDING, 02 PENDING,") {
			t.Fatalf("context lacks the progress line:\n%s", text)
		}
		if last := lines[len(lines)-1]; !strings.HasPrefix(last, tc.want) {
			t.Fatalf("version line for %q/%q = %q, want prefix %q", tc.binary, tc.plugin, last, tc.want)
		}
	}

	if err := os.Remove(filepath.Join(workspace, "next-action.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(workspace, "progress.md")); err != nil {
		t.Fatal(err)
	}
	text := SessionStartContext(workspace, "0.2.0", "0.2.0")
	if !strings.Contains(text, "No next-action.md yet; run ensphere run status.\n") || strings.Contains(text, "Progress:") {
		t.Fatalf("expected the missing next-action note and no progress line:\n%s", text)
	}
}

func TestInitWorkspaceWritesSandboxCommands(t *testing.T) {
	dir := t.TempDir()
	workspace := filepath.Join(dir, "with-sandbox")
	if _, err := InitWorkspace(InitConfig{
		Workspace:    workspace,
		TargetURL:    "http://localhost:3000",
		SandboxStart: "docker compose -f compose.sandbox.yml up -d --wait",
		SandboxSeed:  "npm run seed -- --tenant a --tenant b",
		SandboxReset: `docker compose exec db psql -c "truncate orders"`,
	}); err != nil {
		t.Fatalf("init: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(workspace, "config.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"docker compose -f compose.sandbox.yml up -d --wait",
		"npm run seed -- --tenant a --tenant b",
		`docker compose exec db psql -c "truncate orders"`,
	}
	if got := SandboxCommands(string(raw)); !reflect.DeepEqual(got, want) {
		t.Fatalf("SandboxCommands = %q, want %q", got, want)
	}
	cfg, err := readConfig(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cloud != "none" || cfg.Username != "" || cfg.TargetURL != "http://localhost:3000" {
		t.Fatalf("the Sandbox section disturbed config parsing: %+v", cfg)
	}

	seedOnly := filepath.Join(dir, "seed-only")
	if _, err := InitWorkspace(InitConfig{Workspace: seedOnly, SandboxSeed: "make seed"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	raw, err = os.ReadFile(filepath.Join(seedOnly, "config.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "## Sandbox\n- Seed: make seed\n") || strings.Contains(string(raw), "- Start:") {
		t.Fatalf("expected only the Seed line:\n%s", raw)
	}

	without := filepath.Join(dir, "without")
	if _, err := InitWorkspace(InitConfig{Workspace: without}); err != nil {
		t.Fatalf("init: %v", err)
	}
	raw, err = os.ReadFile(filepath.Join(without, "config.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "## Sandbox") {
		t.Fatalf("init without sandbox flags wrote a Sandbox section:\n%s", raw)
	}
}
