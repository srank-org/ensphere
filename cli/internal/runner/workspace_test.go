package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitWorkspaceWritesCoreArtifacts(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	status, err := InitWorkspace(InitConfig{
		Workspace:  workspace,
		TargetURL:  "https://staging.example.com",
		SourcePath: ".",
		TargetType: "api_backend",
		Cloud:      "none",
		InScope:    "staging.example.com",
	})
	if err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if status.NextSession == nil || status.NextSession.ID != "01" {
		t.Fatalf("expected next session 01, got %+v", status.NextSession)
	}
	for _, path := range []string{
		filepath.Join(workspace, "config.md"),
		filepath.Join(workspace, "progress.md"),
		filepath.Join(workspace, "next-action.md"),
		filepath.Join(workspace, "agent-prompt.md"),
		filepath.Join(workspace, "01.5-session-plan"),
		filepath.Join(workspace, "08.5-abuse"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
	config, err := os.ReadFile(filepath.Join(workspace, "config.md"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(config), "Target type: api_backend") {
		t.Fatalf("config missing target type:\n%s", config)
	}
	progress, err := os.ReadFile(filepath.Join(workspace, "progress.md"))
	if err != nil {
		t.Fatalf("read progress: %v", err)
	}
	if !strings.Contains(string(progress), filepath.Join(workspace, "assessment-plan.yaml")) {
		t.Fatalf("progress uses wrong assessment plan path:\n%s", progress)
	}
	prompt, err := os.ReadFile(filepath.Join(workspace, "agent-prompt.md"))
	if err != nil {
		t.Fatalf("read prompt: %v", err)
	}
	if !strings.Contains(string(prompt), filepath.Join(workspace, "config.md")) ||
		!strings.Contains(string(prompt), filepath.Join(workspace, "progress.md")) {
		t.Fatalf("prompt uses wrong workspace paths:\n%s", prompt)
	}
}

func TestInitWorkspaceRefusesExistingWorkspace(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	_, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"})
	if err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("expected existing workspace error, got %v", err)
	}
}

func TestRunPlanWritesDraftAndStatusSummary(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{
		Workspace:  workspace,
		TargetURL:  "https://api.example.com",
		TargetType: "api_backend",
		Cloud:      "aws",
		InScope:    "api.example.com, aws://123456789012",
	}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}

	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !out.Written || !out.Valid {
		t.Fatalf("expected written valid plan, got written=%v valid=%v validation=%v", out.Written, out.Valid, out.Validation)
	}
	if out.Plan.Target.Type != "api_backend" || out.Plan.Target.CoverageLabel != coverageFull {
		t.Fatalf("unexpected target summary: %+v", out.Plan.Target)
	}
	if out.Plan.Target.Environment != "sandbox" {
		t.Fatalf("expected sandbox environment for an init with a target, got %q", out.Plan.Target.Environment)
	}
	if out.Plan.Sessions["08.7-chains"].Decision != decisionBlocked {
		t.Fatalf("expected chains blocked without a recon profile, got %+v", out.Plan.Sessions["08.7-chains"])
	}
	if out.Plan.Sessions["05-xss"].Decision != decisionSkip {
		t.Fatalf("expected API backend XSS skip, got %+v", out.Plan.Sessions["05-xss"])
	}
	if out.Plan.Sessions["07-cloud"].Decision != decisionRun {
		t.Fatalf("expected cloud run, got %+v", out.Plan.Sessions["07-cloud"])
	}
	for _, path := range []string{
		filepath.Join(workspace, "assessment-plan.yaml"),
		filepath.Join(workspace, "01.5-session-plan", "assessment-plan.yaml"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected plan artifact %s: %v", path, err)
		}
	}

	status, err := WorkspaceStatus(workspace)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.AssessmentPlan == nil || !status.AssessmentPlan.Exists || !status.AssessmentPlan.Valid {
		t.Fatalf("expected valid plan summary, got %+v", status.AssessmentPlan)
	}
	if status.AssessmentPlan.SessionDecisions["07-cloud"] != decisionRun {
		t.Fatalf("status missing cloud decision: %+v", status.AssessmentPlan.SessionDecisions)
	}
}

func TestRunPlanValidatesExistingPlanWithoutOverwrite(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "assessment-plan.yaml"), []byte("draft: false\n"), 0644); err != nil {
		t.Fatalf("write invalid plan: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("validate existing plan: %v", err)
	}
	if out.Written || out.Valid {
		t.Fatalf("expected invalid existing plan without overwrite, got written=%v valid=%v", out.Written, out.Valid)
	}
	if len(out.Validation) == 0 {
		t.Fatal("expected validation errors")
	}

	out, err = RunPlan(workspace, true)
	if err != nil {
		t.Fatalf("force plan: %v", err)
	}
	if !out.Written || !out.Valid {
		t.Fatalf("expected force-generated valid plan, got written=%v valid=%v validation=%v", out.Written, out.Valid, out.Validation)
	}
}

func TestRunPlanMirrorsExistingPlanWithoutRewritingRoot(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, true); err != nil {
		t.Fatalf("seed plan: %v", err)
	}
	rootPath := filepath.Join(workspace, "assessment-plan.yaml")
	mirrorPath := filepath.Join(workspace, "01.5-session-plan", "assessment-plan.yaml")
	rootRaw, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatalf("read root plan: %v", err)
	}
	rootRaw = append([]byte("# analyst comment that should survive\n"), rootRaw...)
	if err := os.WriteFile(rootPath, rootRaw, 0644); err != nil {
		t.Fatalf("write commented root plan: %v", err)
	}
	if err := os.Remove(mirrorPath); err != nil {
		t.Fatalf("remove mirror: %v", err)
	}

	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("validate existing plan: %v", err)
	}
	if out.Written || !out.Valid {
		t.Fatalf("expected existing valid plan without rewrite, got written=%v valid=%v validation=%v", out.Written, out.Valid, out.Validation)
	}
	rootAfter, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatalf("read root after plan: %v", err)
	}
	mirrorRaw, err := os.ReadFile(mirrorPath)
	if err != nil {
		t.Fatalf("read mirror after plan: %v", err)
	}
	if string(rootAfter) != string(rootRaw) {
		t.Fatalf("root plan was rewritten:\n%s", rootAfter)
	}
	if string(mirrorRaw) != string(rootRaw) {
		t.Fatalf("mirror was not synced from root:\n%s", mirrorRaw)
	}
}

func TestRunPlanUsesReconTargetProfileForClientOnlyTarget(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", TargetType: "auto"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	profile := `target:
  type: mobile_client_offline
  environment: sandbox
  coverage_label: client_only
  classification_confidence: high
  rationale:
    - "Session 01 found only Android client code and no configured backend URL."
  evidence_refs:
    - "01-recon/report.md#target-classification"
signals:
  client_only: true
  api_surface: false
  server_side_surface: false
  authentication: false
  outbound_fetch_surface: false
client_exposure_review:
  - "Review hardcoded endpoints, embedded keys, local storage, and WebView bridges."
`
	if err := os.WriteFile(filepath.Join(workspace, "01-recon", "target-profile.yaml"), []byte(profile), 0644); err != nil {
		t.Fatalf("write target profile: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !out.Valid || out.Plan.Target.Type != "mobile_client_offline" || out.Plan.Target.ClassificationConfidence != "high" {
		t.Fatalf("expected recon-classified client-only target, valid=%v validation=%v target=%+v", out.Valid, out.Validation, out.Plan.Target)
	}
	if out.Plan.Target.ClassificationSource != "01-recon/target-profile.yaml" || len(out.Plan.Target.ClientExposureReview) == 0 {
		t.Fatalf("target profile metadata missing: %+v", out.Plan.Target)
	}
	if out.Plan.Sessions["02-injection"].Decision != decisionNotApplicable || out.Plan.Sessions["08-api"].Decision != decisionNotApplicable {
		t.Fatalf("client-only target should stop normal web/API workflow, sessions=%+v", out.Plan.Sessions)
	}
}

func TestRunPlanRecordsReconBackendInventory(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://mobile.example.com", TargetType: "auto", Username: "user"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	profile := `target:
  type: mobile_client_remote_backend
  environment: sandbox
  classification_confidence: high
  rationale:
    - "Session 01 extracted API base URLs from mobile source and traffic capture."
  evidence_refs:
    - "01-recon/report.md#backend-inventory"
backend_inventory:
  - name: primary-api
    base_url: https://api.example.com
    kind: rest
    source: mobile source constants
    evidence_refs:
      - "01-recon/report.md#backend-inventory"
signals:
  api_surface: true
  server_side_surface: true
  authentication: true
  authorization_boundaries: true
`
	if err := os.WriteFile(filepath.Join(workspace, "01-recon", "target-profile.yaml"), []byte(profile), 0644); err != nil {
		t.Fatalf("write target profile: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !out.Valid {
		t.Fatalf("expected valid plan, validation=%v", out.Validation)
	}
	if len(out.Plan.Target.BackendInventory) != 1 || out.Plan.Target.BackendInventory[0].BaseURL != "https://api.example.com" {
		t.Fatalf("backend inventory missing from plan: %+v", out.Plan.Target.BackendInventory)
	}
	if out.Plan.Sessions["08-api"].Decision != decisionLimited || out.Plan.Sessions["04-authz"].Decision != decisionLimited {
		t.Fatalf("unexpected mobile remote backend decisions: api=%+v authz=%+v", out.Plan.Sessions["08-api"], out.Plan.Sessions["04-authz"])
	}
}

func TestRunPlanDraftsChainsSessionFromSandboxEnvironment(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://sandbox.example.com", TargetType: "web_app"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	profile := `target:
  type: web_app
  environment: sandbox
  classification_confidence: high
  rationale:
    - "Session 01 confirmed a disposable sandbox copy of the application."
  evidence_refs:
    - "01-recon/report.md#environment"
`
	if err := os.WriteFile(filepath.Join(workspace, "01-recon", "target-profile.yaml"), []byte(profile), 0644); err != nil {
		t.Fatalf("write target profile: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !out.Valid {
		t.Fatalf("expected valid plan, validation=%v", out.Validation)
	}
	if out.Plan.Target.Environment != "sandbox" {
		t.Fatalf("expected sandbox environment from the recon profile, got %q", out.Plan.Target.Environment)
	}
	chains := out.Plan.Sessions["08.7-chains"]
	if chains.Decision != decisionRun || chains.Applicability != applicabilityApplicable {
		t.Fatalf("expected chains run for a sandbox environment, got %+v", chains)
	}
}

func TestRunPlanBlocksChainsForStagingEnvironment(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://staging.example.com", TargetType: "web_app", Environment: "staging"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	profile := `target:
  type: web_app
  environment: staging
  classification_confidence: high
  rationale:
    - "Session 01 confirmed a shared staging deployment, not a disposable copy."
  evidence_refs:
    - "01-recon/report.md#environment"
`
	if err := os.WriteFile(filepath.Join(workspace, "01-recon", "target-profile.yaml"), []byte(profile), 0644); err != nil {
		t.Fatalf("write target profile: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !out.Valid {
		t.Fatalf("expected valid plan, validation=%v", out.Validation)
	}
	chains := out.Plan.Sessions["08.7-chains"]
	if chains.Decision != decisionBlocked || chains.CoverageLabel != coverageBlocked {
		t.Fatalf("expected chains blocked outside a sandbox, got %+v", chains)
	}
	if len(chains.RequiredInput) != 1 || chains.RequiredInput[0] != "environment: sandbox in 01-recon/target-profile.yaml" {
		t.Fatalf("unexpected chains required input: %+v", chains.RequiredInput)
	}
}

func TestValidateAssessmentPlanChecksEnvironmentAgainstTargetURL(t *testing.T) {
	base := func() *AssessmentPlan {
		return &AssessmentPlan{
			Target: PlanTarget{
				Type:          "web_app",
				URL:           "https://sandbox.example.com",
				Environment:   "sandbox",
				CoverageLabel: coverageFull,
			},
		}
	}
	cases := []struct {
		name        string
		url         string
		environment string
		coverage    string
		want        string
	}{
		{name: "sandbox with url", url: "https://sandbox.example.com", environment: "sandbox", coverage: coverageFull},
		{name: "invalid value", url: "https://sandbox.example.com", environment: "production", coverage: coverageFull, want: `target.environment "production" is invalid`},
		{name: "missing with url", url: "https://sandbox.example.com", environment: "", coverage: coverageFull, want: "target.environment is required when target.url is set"},
		{name: "none with url", url: "https://sandbox.example.com", environment: "none", coverage: coverageFull, want: "target.environment none is only valid when target.url is empty"},
		{name: "staging without url", url: "", environment: "staging", coverage: coverageSourceOnly, want: "target.environment staging requires a non-empty target.url"},
		{name: "none without url", url: "", environment: "none", coverage: coverageSourceOnly},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := base()
			plan.Target.URL = tc.url
			plan.Target.Environment = tc.environment
			plan.Target.CoverageLabel = tc.coverage
			problems := strings.Join(ValidateAssessmentPlan(plan), "\n")
			if tc.want == "" {
				if strings.Contains(problems, "target.environment") {
					t.Fatalf("expected no environment problem, got:\n%s", problems)
				}
				return
			}
			if !strings.Contains(problems, tc.want) {
				t.Fatalf("expected %q, got:\n%s", tc.want, problems)
			}
		})
	}
}

func TestRunPlanSurfacesInvalidReconTargetProfile(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", TargetType: "auto"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	profile := `target:
  type: not_a_target
  classification_confidence: impossible
`
	if err := os.WriteFile(filepath.Join(workspace, "01-recon", "target-profile.yaml"), []byte(profile), 0644); err != nil {
		t.Fatalf("write target profile: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if out.Valid || len(out.Validation) == 0 {
		t.Fatalf("expected invalid target profile validation, got valid=%v validation=%v", out.Valid, out.Validation)
	}
}

func TestWriteNextActionIncludesPlanDecision(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://api.example.com", TargetType: "api_backend"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	progress := `# Assessment Progress

| Session | Category | Status | Findings |
|---------|----------|--------|----------|
| 01 | Recon | DONE | |
| 01.5 | Plan | DONE | |
| 02 | Injection | PENDING | |
| 03 | Authentication | PENDING | |
| 04 | Authorization | PENDING | |
| 05 | Cross-Site Scripting | PENDING | |
| 06 | Server-Side Request Forgery | PENDING | |
| 07 | Cloud and Platform | PENDING | |
| 08 | API Security | PENDING | |
| 08.5 | Abuse and Cost Controls | PENDING | |
| 08.7 | Chains and Workflows | PENDING | |
| 09 | Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
	action, err := WriteNextAction(workspace)
	if err != nil {
		t.Fatalf("write next action: %v", err)
	}
	if action.Session == nil || action.Session.ID != "02" {
		t.Fatalf("expected next session 02, got %+v", action.Session)
	}
	if action.PlanDecision == nil || action.PlanDecision.SessionKey != "02-injection" {
		t.Fatalf("expected plan decision for 02, got %+v", action.PlanDecision)
	}
	raw, err := os.ReadFile(filepath.Join(workspace, "next-action.md"))
	if err != nil {
		t.Fatalf("read next-action: %v", err)
	}
	if !strings.Contains(string(raw), "Assessment Plan Decision") {
		t.Fatalf("next-action missing plan block:\n%s", raw)
	}
}

func TestRunReportBlocksUntilSessionsAreReady(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if gate.Ready {
		t.Fatal("expected report gate to block on pending sessions")
	}
	if !hasIssue(gate.Issues, "session_not_terminal") {
		t.Fatalf("expected session_not_terminal issue, got %+v", gate.Issues)
	}
	for _, path := range []string{gate.GatePath, gate.GateMarkdownPath, gate.NextActionPath, gate.PromptPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected gate artifact %s: %v", path, err)
		}
	}
}

func TestRunReportPassesWhenSessionsHaveReports(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)

	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if !gate.Ready {
		t.Fatalf("expected report gate ready, got issues %+v", gate.Issues)
	}
	if gate.FindingRegistryState != "missing" {
		t.Fatalf("expected missing optional finding registry, got %s", gate.FindingRegistryState)
	}
	raw, err := os.ReadFile(filepath.Join(workspace, "next-action.md"))
	if err != nil {
		t.Fatalf("read next action: %v", err)
	}
	if !strings.Contains(string(raw), "Session") || !strings.Contains(string(raw), "09") {
		t.Fatalf("expected Session 09 handoff, got:\n%s", raw)
	}
}

func TestRunReportRejectsUncitedFindingRegistry(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	registry := `generated_from: Session 09
findings:
  - id: VULN-001
    kind: vulnerability
    title: Missing citation
    category: injection
    status: confirmed
    confidence: high
    evidence_strength: direct
    severity: high
    priority: P1
    cvss_v4: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
    affected_assets: [test.example.invalid]
    affected_locations: [GET /test]
    observed_facts: [Controlled observation]
    root_cause: Missing control
    security_impact: Controlled impact
    business_impact: Test business impact
    remediation: Add the control
    validation_criteria: [Unauthorized control is denied]
    evidence_categories:
      - ensphere_measurement
      - agent_judgment
    coverage_label: full
`
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if gate.Ready {
		t.Fatal("expected report gate to reject uncited finding")
	}
	if gate.FindingRegistryState != "invalid" || !hasIssue(gate.Issues, "finding_uncited") {
		t.Fatalf("expected finding_uncited issue, state=%s issues=%+v", gate.FindingRegistryState, gate.Issues)
	}

	registry = `generated_from: Session 09
findings:
  - id: VULN-001
    kind: vulnerability
    title: Cited finding
    category: injection
    status: confirmed
    confidence: high
    evidence_strength: direct
    severity: high
    priority: P1
    cvss_v4: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
    affected_assets: [test.example.invalid]
    affected_locations: [GET /test]
    observed_facts: [Controlled observation]
    root_cause: Missing control
    security_impact: Controlled impact
    business_impact: Test business impact
    remediation: Add the control
    validation_criteria: [Unauthorized control is denied]
    coverage_label: full
    evidence_categories:
      - ensphere_measurement
      - agent_judgment
    evidence_ids:
      - EVID-001
`
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write cited registry: %v", err)
	}
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate with cited registry: %v", err)
	}
	if !gate.Ready || gate.FindingRegistryState != "valid" {
		t.Fatalf("expected cited registry ready, state=%s issues=%+v", gate.FindingRegistryState, gate.Issues)
	}
}

func TestRunReportRejectsInvalidFindingRegistryEnums(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	registry := `generated_from: Session 09
findings:
  - id: VULN-001
    kind: vulnerability
    title: Bad enum values
    category: injection
    status: impossible
    confidence: certain
    evidence_strength: direct
    severity: severe
    priority: P1
    coverage_label: broad
    evidence_categories:
      - scanner_says_so
    evidence_ids:
      - EVID-001
`
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	for _, code := range []string{
		"finding_status_invalid",
		"finding_confidence_invalid",
		"finding_severity_invalid",
		"finding_evidence_category_invalid",
		"finding_coverage_invalid",
	} {
		if !hasIssue(gate.Issues, code) {
			t.Fatalf("expected %s in issues %+v", code, gate.Issues)
		}
	}
}

func TestRunReportRejectsConfirmedFindingWithIndicativeEvidence(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	path := findingRegistryPath(workspace)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	raw = []byte(strings.Replace(string(raw), "evidence_strength: direct", "evidence_strength: indicative", 1))
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "finding_confirmed_evidence_weak") {
		t.Fatalf("expected weak confirmed evidence rejection, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
}

func TestRunReportRequiresStructuredFinalArtifacts(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "report.md"), []byte("   \n"), 0644); err != nil {
		t.Fatalf("write empty report: %v", err)
	}
	if err := os.Remove(filepath.Join(workspace, "09-report", "evidence-appendix.md")); err != nil {
		t.Fatalf("remove appendix: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "final_report_missing") || !hasIssue(gate.Issues, "evidence_appendix_missing") {
		t.Fatalf("expected missing report artifacts rejection, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
}

func TestRunReportAcceptsMissingControlWithoutCVSS(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	registry := `generated_from: Sessions 01-08.5
findings:
  - id: CTRL-001
    kind: missing_control
    title: No rate limit on OTP send
    category: abuse_and_cost
    status: confirmed
    confidence: high
    evidence_strength: corroborated
    severity: medium
    priority: P1
    affected_assets: [test.example.invalid]
    affected_locations: [POST /api/auth/otp]
    observed_facts: [Handler has no limiter middleware, Approved burst returned 20x 200]
    root_cause: Edge function does no counting
    security_impact: Unbounded SMS sends at the owner's cost
    remediation: Add a shared-store limiter keyed on phone number and IP
    validation_criteria: [Sixth request in 60s returns 429]
    coverage_label: partial
    evidence_categories:
      - source_review
      - ensphere_measurement
      - agent_judgment
    evidence_ids:
      - EVID-088
`
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if !gate.Ready || gate.FindingRegistryState != "valid" {
		t.Fatalf("expected missing_control registry to pass without cvss, state=%s issues=%+v", gate.FindingRegistryState, gate.Issues)
	}

	registry = strings.Replace(registry, "kind: missing_control", "kind: exploit", 1)
	registry = strings.Replace(registry, "id: CTRL-001", "id: FINDING-1", 1)
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "finding_kind_invalid") || !hasIssue(gate.Issues, "finding_id_invalid") {
		t.Fatalf("expected kind and id rejection, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
}

func TestRunPlanRecordsStackAndPlansAbuseSession(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://app.example.com", TargetType: "web_app", Username: "user"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	profile := `target:
  type: web_app
  environment: sandbox
  classification_confidence: high
  rationale:
    - "Next.js app with a Supabase backend."
  evidence_refs:
    - "01-recon/report.md#deployable-components"
stack:
  languages: [typescript]
  frameworks: [nextjs]
  data_layers: [supabase_postgres, prisma]
  hosting: [vercel]
  storage: [cloudflare_r2]
  billing_exposed_services: [supabase_edge_functions, openai]
  evidence_refs:
    - "01-recon/report.md#stack"
signals:
  api_surface: true
  authentication: true
  billing_exposed_surface: true
  storage_surface: true
`
	if err := os.WriteFile(filepath.Join(workspace, "01-recon", "target-profile.yaml"), []byte(profile), 0644); err != nil {
		t.Fatalf("write target profile: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !out.Valid {
		t.Fatalf("expected valid plan, validation=%v", out.Validation)
	}
	if out.Plan.Target.Stack == nil || len(out.Plan.Target.Stack.BillingExposedServices) != 2 {
		t.Fatalf("stack not carried into plan: %+v", out.Plan.Target.Stack)
	}
	if out.Plan.Sessions["08.5-abuse"].Decision != decisionRun {
		t.Fatalf("expected abuse session run, got %+v", out.Plan.Sessions["08.5-abuse"])
	}
	if out.Plan.Checklists == nil || out.Plan.UncoveredStack == nil {
		t.Fatalf("draft must emit empty checklists and uncovered_stack lists: %+v", out.Plan)
	}

	// The analyst plan assigns checklists; the runner validates their names and surfaces them.
	raw, err := os.ReadFile(filepath.Join(workspace, "assessment-plan.yaml"))
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	edited := strings.Replace(string(raw), "checklists: []", "checklists: [abuse-and-cost, nextjs-app-router, supabase-rls]", 1)
	edited = strings.Replace(edited, "uncovered_stack: []", "uncovered_stack: [openai]", 1)
	if err := os.WriteFile(filepath.Join(workspace, "assessment-plan.yaml"), []byte(edited), 0644); err != nil {
		t.Fatalf("write edited plan: %v", err)
	}
	out, err = RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("validate edited plan: %v", err)
	}
	if !out.Valid || len(out.Plan.Checklists) != 3 {
		t.Fatalf("expected valid plan with three checklists, valid=%v validation=%v checklists=%v", out.Valid, out.Validation, out.Plan.Checklists)
	}
	status, err := WorkspaceStatus(workspace)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(status.AssessmentPlan.Checklists) != 3 {
		t.Fatalf("status missing checklists: %+v", status.AssessmentPlan)
	}

	edited = strings.Replace(edited, "checklists: [abuse-and-cost, nextjs-app-router, supabase-rls]", "checklists: [\"Next JS.md\"]", 1)
	if err := os.WriteFile(filepath.Join(workspace, "assessment-plan.yaml"), []byte(edited), 0644); err != nil {
		t.Fatalf("write invalid plan: %v", err)
	}
	out, err = RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("validate invalid plan: %v", err)
	}
	if out.Valid {
		t.Fatalf("expected invalid checklist name to fail validation: %+v", out.Plan.Checklists)
	}
}

func TestRunPlanRejectsStackWithoutEvidence(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://app.example.com", TargetType: "web_app"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	profile := `target:
  type: web_app
  environment: sandbox
  classification_confidence: high
  rationale: ["Observed"]
  evidence_refs: ["01-recon/report.md#target"]
stack:
  frameworks: [Next.js]
`
	if err := os.WriteFile(filepath.Join(workspace, "01-recon", "target-profile.yaml"), []byte(profile), 0644); err != nil {
		t.Fatalf("write target profile: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if out.Valid {
		t.Fatal("expected stack validation errors")
	}
	joined := strings.Join(out.Validation, "\n")
	if !strings.Contains(joined, "evidence_refs is required") || !strings.Contains(joined, "lowercase identifier") {
		t.Fatalf("unexpected validation output:\n%s", joined)
	}
}

func TestNextActionListsSessionChecklists(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://api.example.com", TargetType: "api_backend"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(workspace, "assessment-plan.yaml"))
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	edited := strings.Replace(string(raw), "    02-injection:\n", "    02-injection:\n        checklists: [prisma-drizzle]\n", 1)
	if edited == string(raw) {
		t.Fatalf("could not locate 02-injection block in plan:\n%s", raw)
	}
	if err := os.WriteFile(filepath.Join(workspace, "assessment-plan.yaml"), []byte(edited), 0644); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	progress := strings.Replace(renderProgress(workspace), "| 01 | Recon | PENDING | |", "| 01 | Recon | DONE | |", 1)
	progress = strings.Replace(progress, "| 01.5 | Plan | PENDING | |", "| 01.5 | Plan | DONE | |", 1)
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
	action, err := WriteNextAction(workspace)
	if err != nil {
		t.Fatalf("write next action: %v", err)
	}
	if action.Session == nil || action.Session.ID != "02" || action.PlanDecision == nil || len(action.PlanDecision.Checklists) != 1 {
		t.Fatalf("expected session 02 with one checklist, got session=%+v decision=%+v", action.Session, action.PlanDecision)
	}
	rendered, err := os.ReadFile(action.ActionPath)
	if err != nil {
		t.Fatalf("read next action: %v", err)
	}
	if !strings.Contains(string(rendered), "skills/checklists/prisma-drizzle.md") {
		t.Fatalf("next-action does not list the checklist:\n%s", rendered)
	}
}

func TestRunReportRejectsEmptyCitationPlaceholders(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	registry := `generated_from: Session 09
findings:
  - id: VULN-001
    kind: vulnerability
    title: Blank citation placeholder
    category: injection
    status: not_supported
    confidence: medium
    evidence_strength: direct
    severity: high
    priority: P3
    coverage_label: full
    evidence_categories:
      - ensphere_measurement
    evidence_ids:
      - " "
`
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "finding_uncited") {
		t.Fatalf("expected blank citation to be rejected, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
}

func TestRunReportRejectsUnsafeFindingRegistryPaths(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	registry := `generated_from: Session 09
findings:
  - id: VULN-001
    kind: vulnerability
    title: Unsafe citation paths
    category: injection
    status: not_supported
    confidence: medium
    evidence_strength: direct
    severity: high
    priority: P3
    coverage_label: full
    evidence_categories:
      - ensphere_measurement
    transcripts:
      - /tmp/outside.md
    artifact_paths:
      - ../outside.txt
    cleanup_evidence:
      - 08.5-abuse/cleanup.md#VULN-001
`
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "finding_path_unsafe") {
		t.Fatalf("expected unsafe path issue, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
}

func writeReportReadyWorkspace(t *testing.T, workspace string) {
	t.Helper()
	progress := `# Assessment Progress

| Session | Category | Status | Findings |
|---------|----------|--------|----------|
| 01 | Recon | DONE | |
| 01.5 | Plan | DONE | |
| 02 | Injection | DONE | |
| 03 | Authentication | SKIPPED | No authentication mechanism |
| 04 | Authorization | BLOCKED | Missing second account |
| 05 | Cross-Site Scripting | NOT_APPLICABLE | API only |
| 06 | Server-Side Request Forgery | DONE | |
| 07 | Cloud and Platform | SKIPPED | No cloud scope |
| 08 | API Security | DONE | |
| 08.5 | Abuse and Cost Controls | DONE | |
| 08.7 | Chains and Workflows | BLOCKED | No sandbox environment |
| 09 | Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
	for _, session := range reportRequiredSessions {
		path := filepath.Join(workspace, session.Directory, "report.md")
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir report dir: %v", err)
		}
		if err := os.WriteFile(path, []byte("# Session Report\n\nReason and evidence summary.\n"), 0644); err != nil {
			t.Fatalf("write report %s: %v", path, err)
		}
	}
	writeSession09Artifacts(t, workspace)
}

func writeValidFindingRegistry(t *testing.T, workspace string, ids ...string) {
	t.Helper()
	if len(ids) == 0 {
		ids = []string{"VULN-001"}
	}
	dir := filepath.Join(workspace, "09-report")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir finding registry dir: %v", err)
	}
	var b strings.Builder
	b.WriteString("generated_from: Session 09\n")
	b.WriteString("findings:\n")
	for _, id := range ids {
		b.WriteString("  - id: " + id + "\n")
		b.WriteString("    kind: vulnerability\n")
		b.WriteString("    title: Registry finding " + id + "\n")
		b.WriteString("    category: injection\n")
		b.WriteString("    status: confirmed\n")
		b.WriteString("    confidence: high\n")
		b.WriteString("    evidence_strength: direct\n")
		b.WriteString("    severity: high\n")
		b.WriteString("    priority: P1\n")
		b.WriteString("    cvss_v4: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N\n")
		b.WriteString("    affected_assets: [test.example.invalid]\n")
		b.WriteString("    affected_locations: [GET /test]\n")
		b.WriteString("    observed_facts: [Controlled observation]\n")
		b.WriteString("    root_cause: Missing control\n")
		b.WriteString("    security_impact: Controlled impact\n")
		b.WriteString("    business_impact: Test business impact\n")
		b.WriteString("    remediation: Add the control\n")
		b.WriteString("    validation_criteria: [Unauthorized control is denied]\n")
		b.WriteString("    coverage_label: full\n")
		b.WriteString("    evidence_categories:\n")
		b.WriteString("      - ensphere_measurement\n")
		b.WriteString("      - agent_judgment\n")
		b.WriteString("    evidence_ids:\n")
		b.WriteString("      - EVID-001\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "finding-registry.yaml"), []byte(b.String()), 0644); err != nil {
		t.Fatalf("write finding registry: %v", err)
	}
	writeSession09Artifacts(t, workspace)
}

func writeSession09Artifacts(t *testing.T, workspace string) {
	t.Helper()
	dir := filepath.Join(workspace, "09-report")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir Session 09 dir: %v", err)
	}
	report := "# Assessment Report\n\n## Summary\nWhat was assessed and what to fix first.\n\n## Checks executed\nSee coverage matrices.\n"
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(report), 0644); err != nil {
		t.Fatalf("write Session 09 report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-appendix.md"), []byte("# Evidence Appendix\n\nClaim-to-evidence provenance.\n"), 0644); err != nil {
		t.Fatalf("write Session 09 appendix: %v", err)
	}
}

func hasIssue(issues []ReportGateIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func TestRunPlanWithoutLiveTargetIsSourceOnly(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{
		Workspace:  workspace,
		SourcePath: ".",
		TargetType: "web_app",
		InScope:    "example.invalid",
	}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !out.Written || !out.Valid {
		t.Fatalf("expected written valid source-only plan, got written=%v valid=%v validation=%v", out.Written, out.Valid, out.Validation)
	}
	if out.Plan.Target.URL != "" || out.Plan.Target.CoverageLabel != coverageSourceOnly {
		t.Fatalf("expected empty url and source_only coverage, got %+v", out.Plan.Target)
	}
	if out.Plan.Target.Environment != "none" {
		t.Fatalf("expected none environment without a live target, got %q", out.Plan.Target.Environment)
	}
	plan := *out.Plan
	plan.Target.CoverageLabel = coverageFull
	problems := ValidateAssessmentPlan(&plan)
	found := false
	for _, problem := range problems {
		if strings.Contains(problem, "target.url is required") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected target.url validation error for full coverage without a URL, got %v", problems)
	}
}
