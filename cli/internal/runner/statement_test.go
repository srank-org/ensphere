package runner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/srank/ensphere/internal/evidence"
)

func writeStatementReadyWorkspace(t *testing.T) string {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{
		Workspace:  workspace,
		TargetURL:  "https://example.com",
		TargetType: "api_backend",
		InScope:    "example.com",
		AssessedBy: "Claude Fable 5.1 via Claude Code",
		Operator:   "Test Operator",
	}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)

	ledger := filepath.Join(workspace, "02-injection", "evidence.jsonl")
	writer, err := evidence.NewWriter(ledger)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	var ids []string
	for _, stage := range []string{"baseline", "probe", "control"} {
		entry, err := writer.WriteEntry(evidence.NewEntry("sqli", "blind_boolean", "https://example.com/search", "q", 200, "12ms", stage, "fixture "+stage))
		if err != nil {
			t.Fatalf("write evidence: %v", err)
		}
		ids = append(ids, entry.ID)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close ledger: %v", err)
	}
	writeCoverageFile(t, workspace, "02", `session: "02"
rows:
  - id: COV-02-001
    surface: "GET /search"
    check: "sql_predicate_control"
    identity: "[TENANT_A_USER]"
    state: tested
    evidence_ids: [`+strings.Join(ids, ", ")+`]
  - id: COV-02-002
    surface: "POST /import"
    check: "xml_entity_handling"
    identity: anonymous
    state: not_applicable
    reason: "no XML parser in the inventory"
`)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	return workspace
}

func TestRunStatementWritesFilesAndDetectsDrift(t *testing.T) {
	workspace := writeStatementReadyWorkspace(t)

	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if !gate.Ready {
		t.Fatalf("expected ready gate, got %+v", gate.Issues)
	}
	if gate.Coverage == nil || gate.Coverage.Totals.Tested != 1 || gate.Coverage.Totals.NotApplicable != 1 || gate.Coverage.Totals.NotTested != 5 || gate.Coverage.Totals.Blocked != 2 {
		t.Fatalf("unexpected coverage totals: %+v", gate.Coverage)
	}
	if gate.StatementState != "missing" {
		t.Fatalf("expected missing statement before generation, got %q", gate.StatementState)
	}

	out, err := RunStatement(workspace, "test-version")
	if err != nil {
		t.Fatalf("run statement: %v", err)
	}
	md, err := os.ReadFile(out.MarkdownPath)
	if err != nil {
		t.Fatalf("read statement.md: %v", err)
	}
	for _, want := range []string{
		"# Statement of Assessment",
		statementSentence,
		"Inputs digest: " + out.InputsDigest,
		"Test Operator",
		"Claude Fable 5.1 via Claude Code",
		"VULN-001",
		"test-version",
		"| 02 | 02-injection/evidence.jsonl | 3 | true |",
	} {
		if !strings.Contains(string(md), want) {
			t.Fatalf("statement.md missing %q:\n%s", want, md)
		}
	}

	again, err := RunStatement(workspace, "test-version")
	if err != nil {
		t.Fatalf("run statement again: %v", err)
	}
	if again.InputsDigest != out.InputsDigest {
		t.Fatalf("digest changed between identical runs: %s vs %s", out.InputsDigest, again.InputsDigest)
	}

	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report after statement: %v", err)
	}
	if !gate.Ready || gate.StatementState != "current" {
		t.Fatalf("expected current statement, got ready=%v state=%q issues=%+v", gate.Ready, gate.StatementState, gate.Issues)
	}

	writeCoverageFile(t, workspace, "06", `session: "06"
rows:
  - id: COV-06-001
    surface: "POST /webhook"
    check: "destination_policy"
    identity: anonymous
    state: blocked
    reason: "no callback service"
`)
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report after drift: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "statement_stale") || gate.StatementState != "stale" {
		t.Fatalf("expected statement_stale, got ready=%v state=%q issues=%+v", gate.Ready, gate.StatementState, gate.Issues)
	}

	if _, err := RunStatement(workspace, "test-version"); err != nil {
		t.Fatalf("regenerate statement: %v", err)
	}
	md, _ = os.ReadFile(statementMarkdownPath(workspace))
	edited := strings.Replace(string(md), "Inputs digest: ", "Inputs digest: 0000", 1)
	if err := os.WriteFile(statementMarkdownPath(workspace), []byte(edited), 0644); err != nil {
		t.Fatalf("edit statement.md: %v", err)
	}
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report after edit: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "statement_edited") || gate.StatementState != "edited" {
		t.Fatalf("expected statement_edited, got ready=%v state=%q issues=%+v", gate.Ready, gate.StatementState, gate.Issues)
	}
}

func TestRunStatementRefusesWhenGateNotReady(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	_, err := RunStatement(workspace, "test-version")
	if !errors.Is(err, ErrReportGateNotReady) {
		t.Fatalf("expected ErrReportGateNotReady, got %v", err)
	}
	if fileExists(statementPath(workspace)) {
		t.Fatal("statement must not be written when the gate is not ready")
	}
}

func TestRunReportAcceptsOptionalCoverageFields(t *testing.T) {
	workspace := writeStatementReadyWorkspace(t)
	writeCoverageFile(t, workspace, "08", `session: "08"
rows:
  - id: COV-08-001
    surface: "POST /api/checkout/coupon"
    check: "coupon_redemption_race"
    identity: "[TENANT_A_USER]"
    state: not_tested
    checklist: "abuse-and-cost"
    hypothesis: "HYP-001"
    reason: "no live target"
`)
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	for _, issue := range gate.Issues {
		if strings.HasPrefix(issue.Code, "coverage_") && strings.Contains(issue.Path, "08-api") {
			t.Fatalf("unexpected coverage issue for optional fields: %+v", issue)
		}
	}
}

func TestRunReportValidatesCoverageRows(t *testing.T) {
	workspace := writeStatementReadyWorkspace(t)
	writeCoverageFile(t, workspace, "08", `session: "07"
rows:
  - id: COV-08-001
    surface: "GET /items"
    check: "pagination_cap"
    state: planned
  - id: COV-08-001
    surface: "GET /items"
    check: "mass_assignment"
    state: tested
  - id: COV-08-003
    surface: "GET /items"
    check: "batching"
    state: tested
    evidence_ids: [EVID-999]
  - id: COV-08-004
    surface: ""
    check: "graphql_introspection"
    state: not_tested
  - id: BAD-ID
    surface: "GET /x"
    check: "y"
    state: maybe
`)
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if gate.Ready {
		t.Fatal("expected gate to block on coverage errors")
	}
	for _, code := range []string{
		"coverage_session_mismatch",
		"coverage_row_planned",
		"coverage_id_duplicate",
		"coverage_evidence_missing",
		"coverage_evidence_unknown",
		"coverage_field_missing",
		"coverage_reason_missing",
		"coverage_id_invalid",
		"coverage_state_invalid",
	} {
		if !hasIssue(gate.Issues, code) {
			t.Fatalf("expected issue %s, got %+v", code, gate.Issues)
		}
	}
	raw, err := os.ReadFile(reportGateMarkdownPath(workspace))
	if err != nil {
		t.Fatalf("read gate markdown: %v", err)
	}
	if !strings.Contains(string(raw), "## Coverage") {
		t.Fatalf("gate markdown missing coverage table:\n%s", raw)
	}
}

func TestRunReportRequiresBaselineAndControlForProbedRows(t *testing.T) {
	workspace := writeStatementReadyWorkspace(t)
	ledger := filepath.Join(workspace, "08-api", "evidence.jsonl")
	writer, err := evidence.NewWriter(ledger)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	probe, err := writer.WriteEntry(evidence.NewEntry("request", "scoped_request", "https://example.com/items", "", 200, "9ms", "probe", "canary property"))
	if err != nil {
		t.Fatalf("write probe: %v", err)
	}
	note, err := writer.WriteEntry(evidence.NewEntry("source_review", "manual", "https://example.com/items", "", 0, "", "manual_note", "handler at api/items.ts:40 spreads the body into the update"))
	if err != nil {
		t.Fatalf("write note: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close ledger: %v", err)
	}
	writeCoverageFile(t, workspace, "08", `session: "08"
rows:
  - id: COV-08-001
    surface: "PATCH /items/{id}"
    check: "mass_assignment"
    identity: "[TENANT_A_USER]"
    state: tested
    evidence_ids: [`+probe.ID+`]
  - id: COV-08-002
    surface: "PATCH /items/{id}"
    check: "body_spread_source_review"
    identity: "[TENANT_A_USER]"
    state: tested
    evidence_ids: [`+note.ID+`]
`)
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "coverage_baseline_missing") || !hasIssue(gate.Issues, "coverage_control_missing") {
		t.Fatalf("expected a probe-only row to need baseline and control, got ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
	for _, issue := range gate.Issues {
		if strings.HasSuffix(issue.Path, "#rows[1]") {
			t.Fatalf("a source-review row citing only a manual note must not need baseline or control: %+v", issue)
		}
	}
}
