package cmd

import (
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
