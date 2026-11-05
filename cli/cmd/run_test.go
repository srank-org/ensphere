package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIRunInitStatusAndNext(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	initResult := runCLISplit(t, "run", "--workspace", workspace, "init",
		"--target", "https://staging.example.com",
		"--source-path", ".",
		"--target-type", "api_backend",
		"--in-scope", "staging.example.com",
	)
	if initResult.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", initResult.code, initResult.stderr)
	}
	var initOut struct {
		NextSession *struct {
			ID string `json:"id"`
		} `json:"next_session"`
	}
	decodeJSON(t, initResult.stdout, &initOut)
	if initOut.NextSession == nil || initOut.NextSession.ID != "01" {
		t.Fatalf("unexpected run init output: %+v", initOut)
	}
	for _, name := range []string{"config.md", "progress.md", "next-action.md", "agent-prompt.md"} {
		if _, err := os.Stat(filepath.Join(workspace, name)); err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
	}

	statusResult := runCLISplit(t, "run", "--workspace", workspace, "status")
	if statusResult.code != 0 {
		t.Fatalf("run status exit %d stderr=%s", statusResult.code, statusResult.stderr)
	}
	if !strings.Contains(statusResult.stdout, `"assessment_plan_exists": false`) {
		t.Fatalf("status missing assessment plan flag:\n%s", statusResult.stdout)
	}

	nextResult := runCLISplit(t, "run", "--workspace", workspace, "next")
	if nextResult.code != 0 {
		t.Fatalf("run next exit %d stderr=%s", nextResult.code, nextResult.stderr)
	}
	if !strings.Contains(nextResult.stdout, `"action_path"`) || !strings.Contains(nextResult.stdout, `"prompt_path"`) {
		t.Fatalf("next output missing handoff paths:\n%s", nextResult.stdout)
	}
}

func TestCLIRunPlanWritesAssessmentPlan(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	initResult := runCLISplit(t, "run", "--workspace", workspace, "init",
		"--target", "https://api.example.com",
		"--target-type", "api_backend",
		"--cloud", "aws",
		"--in-scope", "api.example.com, aws://123456789012",
	)
	if initResult.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", initResult.code, initResult.stderr)
	}
	planResult := runCLISplit(t, "run", "--workspace", workspace, "plan")
	if planResult.code != 0 {
		t.Fatalf("run plan exit %d stderr=%s", planResult.code, planResult.stderr)
	}
	if !strings.Contains(planResult.stdout, `"written": true`) ||
		!strings.Contains(planResult.stdout, `"target_type":`) && !strings.Contains(planResult.stdout, `"type": "api_backend"`) {
		t.Fatalf("run plan output missing generated plan:\n%s", planResult.stdout)
	}
	for _, path := range []string{
		filepath.Join(workspace, "assessment-plan.yaml"),
		filepath.Join(workspace, "01.5-session-plan", "assessment-plan.yaml"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected assessment plan artifact %s: %v", path, err)
		}
	}

	statusResult := runCLISplit(t, "run", "--workspace", workspace, "status")
	if statusResult.code != 0 {
		t.Fatalf("run status exit %d stderr=%s", statusResult.code, statusResult.stderr)
	}
	if !strings.Contains(statusResult.stdout, `"assessment_plan_exists": true`) ||
		!strings.Contains(statusResult.stdout, `"target_type": "api_backend"`) {
		t.Fatalf("status missing plan summary:\n%s", statusResult.stdout)
	}
}

func TestCLIRunReportWritesGate(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "https://example.com"); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	if result := runCLISplit(t, "run", "--workspace", workspace, "plan"); result.code != 0 {
		t.Fatalf("run plan exit %d stderr=%s", result.code, result.stderr)
	}
	result := runCLISplit(t, "run", "--workspace", workspace, "report")
	if result.code != 0 {
		t.Fatalf("run report exit %d stderr=%s", result.code, result.stderr)
	}
	if !strings.Contains(result.stdout, `"ready": false`) || !strings.Contains(result.stdout, `"session_not_terminal"`) {
		t.Fatalf("report gate output missing blocking issue:\n%s", result.stdout)
	}
	for _, path := range []string{
		filepath.Join(workspace, "09-report", "report-gate.yaml"),
		filepath.Join(workspace, "09-report", "report-gate.md"),
		filepath.Join(workspace, "next-action.md"),
		filepath.Join(workspace, "agent-prompt.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected report gate artifact %s: %v", path, err)
		}
	}
}

func TestCLIRunInitRejectsUnknownEnvironment(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	result := runCLISplit(t, "run", "--workspace", workspace, "init",
		"--target", "https://staging.example.com",
		"--environment", "production",
	)
	if result.code != 2 {
		t.Fatalf("expected usage exit 2, got %d stderr=%s", result.code, result.stderr)
	}
	if !strings.Contains(result.stderr, "usage error") {
		t.Fatalf("expected usage error on stderr, got %s", result.stderr)
	}
	if _, err := os.Stat(filepath.Join(workspace, "config.md")); err == nil {
		t.Fatal("expected no workspace to be created for a rejected environment")
	}
}

func TestCLIRunInitRecordsEnvironmentInConfig(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init",
		"--target", "https://staging.example.com",
		"--environment", "staging",
	); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	raw, err := os.ReadFile(filepath.Join(workspace, "config.md"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(raw), "- Environment: staging") {
		t.Fatalf("config missing environment:\n%s", raw)
	}
}

func TestCLIRunStatementRefusesUntilGateReady(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init",
		"--target", "https://example.com",
		"--assessed-by", "Claude Fable 5.1 via Claude Code",
		"--operator", "Test Operator",
	); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	config, err := os.ReadFile(filepath.Join(workspace, "config.md"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(config), "- Assessed by: Claude Fable 5.1 via Claude Code") ||
		!strings.Contains(string(config), "- Operator: Test Operator") {
		t.Fatalf("config missing assessment fields:\n%s", config)
	}
	result := runCLISplit(t, "run", "--workspace", workspace, "statement")
	if result.code != 2 {
		t.Fatalf("expected exit 2 while the gate is not ready, got %d stdout=%s stderr=%s", result.code, result.stdout, result.stderr)
	}
	if !strings.Contains(result.stderr, "report gate not ready") {
		t.Fatalf("expected gate refusal on stderr, got %s", result.stderr)
	}
	for _, name := range []string{"statement.yaml", "statement.md"} {
		if _, err := os.Stat(filepath.Join(workspace, "09-report", name)); err == nil {
			t.Fatalf("expected no %s while the gate is not ready", name)
		}
	}
}

const cliTestRegistry = `generated_from: Session 09
findings:
  - id: %s
    kind: missing_control
    title: No rate limit on OTP
    category: abuse_and_cost
    status: %s
    confidence: high
    evidence_strength: direct
    severity: medium
    priority: P2
    affected_assets: [app.example.invalid]
    affected_locations: ["app/api/otp.ts:%d", "POST /api/otp"]
    observed_facts: [Twenty requests in ten seconds all returned 200]
    root_cause: No limiter on the route
    security_impact: SMS cost abuse
    remediation: Add a per-number limiter
    validation_criteria: [The eleventh request in ten seconds is refused]
    evidence_ids: [EVID-001]
    evidence_categories: [ensphere_measurement, agent_judgment]
`

func initCLIWorkspaceWithRegistry(t *testing.T, workspace, id, status string, line int) {
	t.Helper()
	if result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "https://example.com"); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	dir := filepath.Join(workspace, "09-report")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir 09-report: %v", err)
	}
	registry := fmt.Sprintf(cliTestRegistry, id, status, line)
	if err := os.WriteFile(filepath.Join(dir, "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
}

func TestCLIRunDiffComparesWorkspaces(t *testing.T) {
	root := t.TempDir()
	previous := filepath.Join(root, "previous")
	current := filepath.Join(root, "current")
	initCLIWorkspaceWithRegistry(t, previous, "CTRL-001", "not_supported", 24)
	initCLIWorkspaceWithRegistry(t, current, "CTRL-002", "confirmed", 31)

	result := runCLISplit(t, "run", "--workspace", current, "diff", "--previous", previous)
	if result.code != 0 {
		t.Fatalf("run diff exit %d stderr=%s", result.code, result.stderr)
	}
	var out struct {
		DiffPath string `json:"diff_path"`
		Findings struct {
			Changed []struct {
				PreviousID string `json:"previous_id"`
				CurrentID  string `json:"current_id"`
			} `json:"changed"`
			Summary *struct {
				UnresolvedBefore int `json:"unresolved_before"`
				UnresolvedAfter  int `json:"unresolved_after"`
				Reopened         int `json:"reopened"`
			} `json:"summary"`
		} `json:"findings"`
	}
	decodeJSON(t, result.stdout, &out)
	if out.Findings.Summary == nil || out.Findings.Summary.Reopened != 1 || out.Findings.Summary.UnresolvedAfter <= out.Findings.Summary.UnresolvedBefore {
		t.Fatalf("unexpected diff summary:\n%s", result.stdout)
	}
	if len(out.Findings.Changed) != 1 || out.Findings.Changed[0].PreviousID != "CTRL-001" || out.Findings.Changed[0].CurrentID != "CTRL-002" {
		t.Fatalf("expected CTRL-001 -> CTRL-002:\n%s", result.stdout)
	}
	for _, path := range []string{out.DiffPath, filepath.Join(current, "09-report", "diff.md")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}
}

func TestCLIRunDiffUsageErrors(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current")
	initCLIWorkspaceWithRegistry(t, current, "CTRL-001", "confirmed", 24)
	for name, args := range map[string][]string{
		"missing --previous":         {"run", "--workspace", current, "diff"},
		"--previous not a directory": {"run", "--workspace", current, "diff", "--previous", filepath.Join(root, "nope")},
	} {
		result := runCLISplit(t, args...)
		if result.code != 2 || !strings.Contains(result.stderr, "usage error") {
			t.Fatalf("%s: expected usage exit 2, got %d stderr=%s", name, result.code, result.stderr)
		}
	}
}

func TestCLIRunSarifWritesFindings(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	initCLIWorkspaceWithRegistry(t, workspace, "CTRL-001", "confirmed", 24)
	result := runCLISplit(t, "run", "--workspace", workspace, "sarif")
	if result.code != 0 {
		t.Fatalf("run sarif exit %d stderr=%s", result.code, result.stderr)
	}
	var out struct {
		SARIFPath string `json:"sarif_path"`
		Results   int    `json:"results"`
		Rules     int    `json:"rules"`
	}
	decodeJSON(t, result.stdout, &out)
	if out.Results != 1 || out.Rules != 1 {
		t.Fatalf("expected one result and one rule:\n%s", result.stdout)
	}
	raw, err := os.ReadFile(out.SARIFPath)
	if err != nil {
		t.Fatalf("read findings.sarif: %v", err)
	}
	var log struct {
		Version string `json:"version"`
	}
	decodeJSON(t, string(raw), &log)
	if log.Version != "2.1.0" {
		t.Fatalf("unexpected SARIF version %q", log.Version)
	}
}
