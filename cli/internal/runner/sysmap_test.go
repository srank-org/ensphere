package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/srank-org/ensphere/internal/sysmap"
)

const testSystemMap = `version: 1
reconciled_at: "%s"
surfaces:
  - id: SURF-001
    kind: endpoint
    name: "POST /api/auth/otp"
    role: billed_operation
    identity: anonymous
    files: [routes/otp.ts]
    sessions: ["03", "08.5"]
    checks: [auth_control, rate_limit_burst]
  - id: SURF-002
    kind: table
    name: "items"
    role: data_store
    files: [db/schema.sql]
    sessions: ["02"]
    checks: [sql_predicate_control]
`

func writeSourceFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func writeSystemMap(t *testing.T, root, reconciledAt string) {
	t.Helper()
	writeSourceFile(t, root, sysmap.RelativePath, strings.Replace(testSystemMap, "%s", reconciledAt, 1))
}

func setConfigLine(t *testing.T, workspace, old, replacement string) {
	t.Helper()
	raw, err := os.ReadFile(configPath(workspace))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	edited := strings.Replace(string(raw), old, replacement, 1)
	if edited == string(raw) {
		t.Fatalf("config has no line %q:\n%s", old, raw)
	}
	if err := os.WriteFile(configPath(workspace), []byte(edited), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func runGitCommand(t *testing.T, dir string, args ...string) string {
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

// committedSource returns a git repository holding the files the test map
// claims, committed, and the commit hash.
func committedSource(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	runGitCommand(t, root, "init", "-q")
	writeSourceFile(t, root, "routes/otp.ts", "v1\n")
	writeSourceFile(t, root, "db/schema.sql", "v1\n")
	runGitCommand(t, root, "add", ".")
	runGitCommand(t, root, "commit", "-q", "-m", "base")
	return root, runGitCommand(t, root, "rev-parse", "HEAD")
}

func TestCheckSessionIDsAreTheCoverageSessions(t *testing.T) {
	want := []string{"02", "03", "04", "05", "06", "07", "08", "08.5", "08.7"}
	if got := CheckSessionIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("CheckSessionIDs() = %v, want %v", got, want)
	}
}

func TestRunReportChecksCoverageSurfaceIDsAgainstTheMap(t *testing.T) {
	workspace := writeStatementReadyWorkspace(t)
	writeCoverageFile(t, workspace, "08", `session: "08"
rows:
  - id: COV-08-001
    surface: "POST /api/auth/otp"
    surface_id: SURF-001
    check: "auth_control"
    state: not_tested
    reason: "fixture workspace"
  - id: COV-08-002
    surface: "GET /legacy"
    surface_id: SURF-009
    check: "auth_control"
    state: not_tested
    reason: "fixture workspace"
`)
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if hasIssue(gate.Issues, "coverage_surface_unknown") {
		t.Fatalf("without a system map surface_id must go unchecked, got %+v", gate.Issues)
	}

	source := t.TempDir()
	writeSourceFile(t, source, "routes/otp.ts", "v1\n")
	writeSourceFile(t, source, "db/schema.sql", "v1\n")
	writeSystemMap(t, source, "9f1c2d3e")
	setConfigLine(t, workspace, "- Source path: .", "- Source path: "+source)
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	var unknown []ReportGateIssue
	for _, issue := range gate.Issues {
		if issue.Code == "coverage_surface_unknown" {
			unknown = append(unknown, issue)
		}
	}
	if len(unknown) != 1 || !strings.HasSuffix(unknown[0].Path, "#rows[1]") || !strings.Contains(unknown[0].Message, "SURF-009") {
		t.Fatalf("expected only the SURF-009 row to be rejected, got %+v", unknown)
	}
}

func TestRunReportReportsSystemMapErrors(t *testing.T) {
	workspace := writeStatementReadyWorkspace(t)
	source := t.TempDir()
	writeSourceFile(t, source, "routes/otp.ts", "v1\n")
	writeSystemMap(t, source, "9f1c2d3e")
	setConfigLine(t, workspace, "- Source path: .", "- Source path: "+source)
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if gate.Ready {
		t.Fatal("a map naming a missing file must block the gate")
	}
	var found *ReportGateIssue
	for i, issue := range gate.Issues {
		if issue.Code == "surface_file_missing" {
			found = &gate.Issues[i]
		}
	}
	if found == nil || found.Severity != "error" || found.Path != sysmap.Path(source)+"#surfaces[1].files[0]" {
		t.Fatalf("expected surface_file_missing at the map path, got %+v", gate.Issues)
	}

	writeSourceFile(t, source, sysmap.RelativePath, "version: 1\nunknown: true\n")
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "map_parse_failed") {
		t.Fatalf("expected map_parse_failed, got ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
}

func TestInitWorkspaceRecordsDeltaSince(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, DeltaSince: "9f1c2d3e", SandboxStart: "make sandbox"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	raw, err := os.ReadFile(configPath(workspace))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(raw), "- Cloud: none\n- Delta since: 9f1c2d3e\n\n## Sandbox\n") {
		t.Fatalf("config must list Delta since in the Target section:\n%s", raw)
	}
	cfg, err := readConfig(workspace)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if cfg.DeltaSince != "9f1c2d3e" {
		t.Fatalf("DeltaSince = %q", cfg.DeltaSince)
	}

	plain := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: plain}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	raw, err = os.ReadFile(configPath(plain))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(raw), "Delta since") {
		t.Fatalf("config without a delta must not list one:\n%s", raw)
	}
}

func deltaWorkspace(t *testing.T, source, since string) (string, InitConfig) {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{
		Workspace:  workspace,
		TargetURL:  "https://example.com",
		TargetType: "api_backend",
		SourcePath: source,
		DeltaSince: since,
	}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	cfg, err := readConfig(workspace)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	return workspace, cfg
}

func fullDraft(cfg InitConfig) map[string]PlanSession {
	cfg.DeltaSince = ""
	return BuildAssessmentPlan(cfg, cfg.Workspace).Sessions
}

func TestRunPlanDraftsDeltaFromSystemMap(t *testing.T) {
	source, base := committedSource(t)
	writeSystemMap(t, source, base)
	writeSourceFile(t, source, "routes/otp.ts", "v2\n")
	workspace, cfg := deltaWorkspace(t, source, base)

	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !out.Valid {
		t.Fatalf("delta draft must validate: %v", out.Validation)
	}
	plan, err := ReadAssessmentPlan(assessmentPlanPath(workspace))
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	if plan.Delta == nil || plan.Delta.Since != base || plan.Delta.Head != base || plan.Delta.Reason != "" ||
		!reflect.DeepEqual(plan.Delta.ChangedSurfaces, []string{"SURF-001"}) ||
		!reflect.DeepEqual(plan.Delta.SessionsAffected, []string{"03", "08.5"}) ||
		len(plan.Delta.UnmappedChangedFiles) != 0 {
		t.Fatalf("unexpected delta: %+v", plan.Delta)
	}
	full := fullDraft(cfg)
	for _, key := range planSessionKeys {
		got := plan.Sessions[key]
		if key == "03-auth" || key == "08.5-abuse" {
			if !reflect.DeepEqual(got, full[key]) {
				t.Fatalf("affected session %s must keep its full draft: got %+v want %+v", key, got, full[key])
			}
			continue
		}
		if got.Decision != decisionSkip || got.Applicability != full[key].Applicability || !strings.Contains(got.Reason, "delta run since "+base) {
			t.Fatalf("unaffected session %s must draft skip with its applicability kept: got %+v full %+v", key, got, full[key])
		}
	}
}

func TestRunPlanKeepsFullDraftWhenChangedFilesAreUnmapped(t *testing.T) {
	source, base := committedSource(t)
	writeSystemMap(t, source, base)
	writeSourceFile(t, source, "routes/otp.ts", "v2\n")
	writeSourceFile(t, source, "routes/admin.ts", "new\n")
	_, cfg := deltaWorkspace(t, source, base)

	plan := BuildAssessmentPlan(cfg, cfg.Workspace)
	if plan.Delta == nil || !reflect.DeepEqual(plan.Delta.UnmappedChangedFiles, []string{"routes/admin.ts"}) {
		t.Fatalf("unexpected delta: %+v", plan.Delta)
	}
	if !reflect.DeepEqual(plan.Sessions, fullDraft(cfg)) {
		t.Fatalf("unmapped changes must keep every session's full draft: %+v", plan.Sessions)
	}
	if !strings.Contains(strings.Join(plan.Target.Rationale, "\n"), "belong to no surface") {
		t.Fatalf("rationale must name the unmapped files: %v", plan.Target.Rationale)
	}
	if problems := ValidateAssessmentPlan(plan); len(problems) != 0 {
		t.Fatalf("plan must validate: %v", problems)
	}
}

func TestRunPlanRecordsWhyNoDeltaWasComputed(t *testing.T) {
	source := t.TempDir()
	_, cfg := deltaWorkspace(t, source, "9f1c2d3e")
	plan := BuildAssessmentPlan(cfg, cfg.Workspace)
	if plan.Delta == nil || plan.Delta.Since != "9f1c2d3e" || !strings.Contains(plan.Delta.Reason, "no system map") ||
		plan.Delta.Head != "" || len(plan.Delta.SessionsAffected) != 0 {
		t.Fatalf("a missing map must leave only since and reason: %+v", plan.Delta)
	}
	if !reflect.DeepEqual(plan.Sessions, fullDraft(cfg)) {
		t.Fatalf("a missing map must keep the full draft: %+v", plan.Sessions)
	}

	writeSystemMap(t, source, "9f1c2d3e")
	plan = BuildAssessmentPlan(cfg, cfg.Workspace)
	if plan.Delta == nil || !strings.Contains(plan.Delta.Reason, "validation errors") {
		t.Fatalf("an invalid map must leave a reason: %+v", plan.Delta)
	}

	plan.Delta = &PlanDelta{}
	if problems := ValidateAssessmentPlan(plan); !reflect.DeepEqual(problems, []string{"delta.since is required when delta is present"}) {
		t.Fatalf("unexpected validation: %v", problems)
	}
}

func TestStatementShowsDeltaSince(t *testing.T) {
	workspace := writeStatementReadyWorkspace(t)
	before, err := BuildStatement(workspace, "test", nil)
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	if strings.Contains(renderStatementMarkdown(before), "Delta since") {
		t.Fatal("a full run must not print a delta line")
	}
	setConfigLine(t, workspace, "- Cloud: none\n", "- Cloud: none\n- Delta since: 9f1c2d3e\n")
	after, err := BuildStatement(workspace, "test", nil)
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	if after.System.DeltaSince != "9f1c2d3e" || after.InputsDigest == before.InputsDigest {
		t.Fatalf("delta must be recorded and change the digest: %+v", after.System)
	}
	if !strings.Contains(renderStatementMarkdown(after), "- **Environment tier**: sandbox\n- **Delta since**: 9f1c2d3e\n") {
		t.Fatalf("statement must print the delta after the environment:\n%s", renderStatementMarkdown(after))
	}
}
