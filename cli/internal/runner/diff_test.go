package runner

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func registryFinding(id, kind, category, title, status, severity, priority string, locations ...string) FindingSummary {
	return FindingSummary{
		ID:                 id,
		Kind:               kind,
		Title:              title,
		Category:           category,
		Status:             status,
		Confidence:         "high",
		EvidenceStrength:   "direct",
		Severity:           severity,
		Priority:           priority,
		AffectedAssets:     []string{"app.example.invalid"},
		AffectedLocations:  locations,
		ObservedFacts:      []string{"Controlled observation"},
		RootCause:          "Missing control",
		SecurityImpact:     "Controlled impact",
		Remediation:        "Add the control",
		ValidationCriteria: []string{"The control is enforced"},
		EvidenceIDs:        []string{"EVID-001"},
		EvidenceCategories: []string{"ensphere_measurement", "agent_judgment"},
	}
}

func writeRegistryFindings(t *testing.T, workspace string, findings ...FindingSummary) {
	t.Helper()
	raw, err := yaml.Marshal(FindingRegistry{GeneratedFrom: "Session 09", Findings: findings})
	if err != nil {
		t.Fatalf("encode registry: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "09-report"), 0755); err != nil {
		t.Fatalf("mkdir report dir: %v", err)
	}
	if err := os.WriteFile(findingRegistryPath(workspace), raw, 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
}

func writeDiffWorkspace(t *testing.T, root, name string) string {
	t.Helper()
	workspace := filepath.Join(root, name)
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", SourcePath: root}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	return workspace
}

func writeStatementFile(t *testing.T, workspace, version, assessedBy string, entries int) {
	t.Helper()
	raw, err := yaml.Marshal(Statement{
		EnsphereVersion: version,
		System:          StatementSystem{AssessedBy: assessedBy},
		Ledgers:         []StatementLedger{{Session: "02", Entries: entries}},
	})
	if err != nil {
		t.Fatalf("encode statement: %v", err)
	}
	if err := os.WriteFile(statementPath(workspace), raw, 0644); err != nil {
		t.Fatalf("write statement: %v", err)
	}
}

func TestRunDiffComparesFindingsCoverageAndStatement(t *testing.T) {
	root := t.TempDir()
	previous := writeDiffWorkspace(t, root, "previous")
	current := writeDiffWorkspace(t, root, "current")

	writeRegistryFindings(t, previous,
		registryFinding("VULN-001", "vulnerability", "injection", "SQL injection in search", "confirmed", "high", "P1", "GET /search"),
		registryFinding("VULN-002", "vulnerability", "authorization", "IDOR on invoices", "not_supported", "none", "NONE", "GET /invoices/{id}"),
		registryFinding("CTRL-001", "missing_control", "abuse_and_cost", "No rate limit on OTP", "confirmed", "medium", "P2", "app/api/x.ts:24"),
		registryFinding("VULN-003", "vulnerability", "xss", "Stored XSS in comments", "confirmed", "high", "P1", "POST /comments"),
		registryFinding("VULN-004", "vulnerability", "ssrf", "SSRF in webhook", "likely", "high", "P1", "POST /webhook"),
	)
	writeRegistryFindings(t, current,
		registryFinding("VULN-001", "vulnerability", "injection", "SQL  Injection in search ", "confirmed", "high", "P1", "GET /search"),
		registryFinding("VULN-005", "vulnerability", "authorization", "IDOR on invoices", "likely", "high", "P1", "GET /invoices/{id}"),
		registryFinding("CTRL-003", "missing_control", "abuse_and_cost", "OTP endpoint lacks a rate limit", "confirmed", "medium", "P2", "app/api/x.ts:31"),
		registryFinding("VULN-003", "vulnerability", "xss", "Stored XSS in comments", "not_supported", "none", "NONE", "POST /comments"),
		registryFinding("CTRL-004", "missing_control", "cloud", "Bucket allows public listing", "confirmed", "high", "P1", "r2://uploads"),
	)
	writeCoverageFile(t, previous, "02", `session: "02"
rows:
  - id: COV-02-001
    surface: "GET /fixture"
    check: "fixture_control"
    identity: anonymous
    state: not_tested
    reason: "fixture workspace"
  - id: COV-02-002
    surface: "POST /login"
    check: "credential_burst"
    identity: anonymous
    state: blocked
    reason: "no sandbox"
`)
	writeCoverageFile(t, current, "02", `session: "02"
rows:
  - id: COV-02-010
    surface: "get /Fixture "
    check: "fixture_control"
    identity: anonymous
    state: tested
    evidence_ids: [EVID-001]
  - id: COV-02-003
    surface: "GET /export"
    check: "csv_formula"
    identity: anonymous
    state: not_tested
    reason: "no export fixture"
`)

	out, err := RunDiff(current, previous)
	if err != nil {
		t.Fatalf("run diff: %v", err)
	}

	f := out.Findings
	if len(f.New) != 1 || f.New[0].ID != "CTRL-004" {
		t.Fatalf("expected CTRL-004 as the only new finding, got %+v", f.New)
	}
	if len(f.Gone) != 1 || f.Gone[0].ID != "VULN-004" {
		t.Fatalf("expected VULN-004 as the only gone finding, got %+v", f.Gone)
	}
	changed := map[string]FindingChange{}
	for _, change := range f.Changed {
		changed[change.PreviousID] = change
	}
	reopened, ok := changed["VULN-002"]
	if !ok || reopened.CurrentID != "VULN-005" || reopened.MatchedBy != matchedByTitle {
		t.Fatalf("expected VULN-002 -> VULN-005 matched by title, got %+v", f.Changed)
	}
	if !hasFieldChange(reopened.Changes, "status", "not_supported", "likely") {
		t.Fatalf("expected a status change on the reopened pair, got %+v", reopened.Changes)
	}
	resolved, ok := changed["VULN-003"]
	if !ok || !hasFieldChange(resolved.Changes, "status", "confirmed", "not_supported") {
		t.Fatalf("expected VULN-003 confirmed -> not_supported, got %+v", f.Changed)
	}
	unchanged := map[string]FindingPair{}
	for _, pair := range f.Unchanged {
		unchanged[pair.PreviousID] = pair
	}
	if pair := unchanged["CTRL-001"]; pair.CurrentID != "CTRL-003" || pair.MatchedBy != matchedByLocation {
		t.Fatalf("expected CTRL-001 -> CTRL-003 matched by location after a line drift, got %+v", f.Unchanged)
	}
	if pair := unchanged["VULN-001"]; pair.CurrentID != "VULN-001" || pair.MatchedBy != matchedByTitle {
		t.Fatalf("expected VULN-001 matched by normalized title, got %+v", f.Unchanged)
	}

	s := f.Summary
	if s.PreviousTotal != 5 || s.CurrentTotal != 5 {
		t.Fatalf("unexpected totals: %+v", s)
	}
	if s.Reopened != 1 || s.Resolved != 1 || s.NewUnresolved != 1 || s.GoneUnresolved != 1 {
		t.Fatalf("unexpected movement counts: %+v", s)
	}
	if s.UnresolvedBefore != s.ByKind["vulnerability"].UnresolvedBefore+s.ByKind["missing_control"].UnresolvedBefore ||
		s.UnresolvedAfter != s.ByKind["vulnerability"].UnresolvedAfter+s.ByKind["missing_control"].UnresolvedAfter {
		t.Fatalf("by_kind does not add up to the totals: %+v", s)
	}
	if s.ByKind["missing_control"].UnresolvedAfter <= s.ByKind["missing_control"].UnresolvedBefore ||
		s.ByKind["vulnerability"].UnresolvedAfter >= s.ByKind["vulnerability"].UnresolvedBefore {
		t.Fatalf("expected missing controls up and vulnerabilities down: %+v", s.ByKind)
	}

	c := out.Coverage
	if len(c.Changed) != 1 || c.Changed[0].PreviousID != "COV-02-001" || c.Changed[0].CurrentID != "COV-02-010" ||
		c.Changed[0].From != coverageStateNotTested || c.Changed[0].To != coverageStateTested {
		t.Fatalf("expected COV-02-001 -> COV-02-010 not_tested -> tested, got %+v", c.Changed)
	}
	if len(c.Added) != 1 || c.Added[0].ID != "COV-02-003" {
		t.Fatalf("expected COV-02-003 added, got %+v", c.Added)
	}
	if len(c.Removed) != 1 || c.Removed[0].ID != "COV-02-002" {
		t.Fatalf("expected COV-02-002 removed, got %+v", c.Removed)
	}
	if c.Unchanged == 0 || c.TotalsAfter.Tested != c.TotalsBefore.Tested+1 || c.TotalsAfter.Total != c.TotalsBefore.Total {
		t.Fatalf("unexpected coverage totals: unchanged=%d before=%+v after=%+v", c.Unchanged, c.TotalsBefore, c.TotalsAfter)
	}
	if len(c.Sessions) != len(coverageSessions()) {
		t.Fatalf("expected one coverage entry per session, got %d", len(c.Sessions))
	}
	if out.Statement.Compared {
		t.Fatalf("expected no statement comparison without statements, got %+v", out.Statement)
	}

	first, err := os.ReadFile(out.DiffPath)
	if err != nil {
		t.Fatalf("read diff.json: %v", err)
	}
	if _, err := RunDiff(current, previous); err != nil {
		t.Fatalf("run diff again: %v", err)
	}
	second, err := os.ReadFile(out.DiffPath)
	if err != nil {
		t.Fatalf("read diff.json again: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("diff.json differs between identical runs")
	}
	md, err := os.ReadFile(out.MarkdownPath)
	if err != nil {
		t.Fatalf("read diff.md: %v", err)
	}
	for _, id := range []string{"CTRL-004", "VULN-004", "VULN-002", "VULN-005", "COV-02-010"} {
		if !strings.Contains(string(md), id) {
			t.Fatalf("diff.md missing %s:\n%s", id, md)
		}
	}

	writeStatementFile(t, previous, "v1.0.0", "Model A", 3)
	writeStatementFile(t, current, "v1.1.0", "Model B", 7)
	out, err = RunDiff(current, previous)
	if err != nil {
		t.Fatalf("run diff with statements: %v", err)
	}
	st := out.Statement
	if !st.Compared || st.EnsphereVersionBefore != "v1.0.0" || st.EnsphereVersionAfter != "v1.1.0" ||
		st.AssessedByBefore != "Model A" || st.AssessedByAfter != "Model B" || st.LedgerEntriesAfter <= st.LedgerEntriesBefore {
		t.Fatalf("unexpected statement comparison: %+v", st)
	}
}

func TestRunDiffRejectsMissingPreviousAndRegistry(t *testing.T) {
	root := t.TempDir()
	current := writeDiffWorkspace(t, root, "current")
	writeRegistryFindings(t, current)

	_, err := RunDiff(current, filepath.Join(root, "does-not-exist"))
	if !errors.Is(err, ErrPreviousNotDirectory) {
		t.Fatalf("expected ErrPreviousNotDirectory, got %v", err)
	}
	if fileExists(diffPath(current)) {
		t.Fatal("diff.json must not be written when the previous workspace is missing")
	}

	previous := filepath.Join(root, "empty")
	if err := os.MkdirAll(previous, 0755); err != nil {
		t.Fatalf("mkdir previous: %v", err)
	}
	_, err = RunDiff(current, previous)
	if err == nil || errors.Is(err, ErrPreviousNotDirectory) {
		t.Fatalf("expected a runtime error for a previous workspace without a registry, got %v", err)
	}
}

func hasFieldChange(changes []FieldChange, field, from, to string) bool {
	for _, change := range changes {
		if change.Field == field && change.From == from && change.To == to {
			return true
		}
	}
	return false
}
