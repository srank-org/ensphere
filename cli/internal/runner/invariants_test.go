package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const promotedInvariant = `id: %s
title: "Promoted from %s"
origin: {kind: %s, ref: %s}
enforce: %t
kind: source
include: ["**/*.ts"]
pattern: 'eval\('
expect: {matches: 0}
`

// registryWorkspace is a report-ready workspace whose registry holds the
// given findings, every one confirmed, and whose source path is a fresh tree.
func registryWorkspace(t *testing.T, ids ...string) (string, string) {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	writeValidFindingRegistry(t, workspace, ids...)
	source := t.TempDir()
	setConfigLine(t, workspace, "- Source path: .", "- Source path: "+source)
	return workspace, source
}

func writeInvariantFor(t *testing.T, source, invID, findingID string, enforce bool) string {
	t.Helper()
	kind := "vulnerability"
	if strings.HasPrefix(findingID, "CTRL-") {
		kind = "missing_control"
	}
	rel := filepath.Join(".ensphere", "invariants", invID+".yaml")
	writeSourceFile(t, source, rel, fmt.Sprintf(promotedInvariant, invID, findingID, kind, findingID, enforce))
	return filepath.Join(source, rel)
}

// setSourcePath points the workspace at source, whatever path config.md
// names now.
func setSourcePath(t *testing.T, workspace, source string) {
	t.Helper()
	cfg, err := readConfig(workspace)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	setConfigLine(t, workspace, "- Source path: "+cfg.SourcePath, "- Source path: "+source)
}

// promoteRegistryFindings writes one unenforced invariant for every confirmed
// or likely finding in the registry into the configured source tree, moving
// a workspace whose source path is still "." onto a fresh temporary tree
// first, so a fixture that is otherwise report-ready satisfies the gate's
// promotion rule.
func promoteRegistryFindings(t *testing.T, workspace string) string {
	t.Helper()
	cfg, err := readConfig(workspace)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	source := cfg.SourcePath
	if source == "." {
		source = t.TempDir()
		setSourcePath(t, workspace, source)
	}
	registry, err := readFindingRegistry(findingRegistryPath(workspace))
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	n := 0
	for _, finding := range registry.Findings {
		if !vulnerabilityFindingStatus(finding.Status) {
			continue
		}
		n++
		writeInvariantFor(t, source, fmt.Sprintf("INV-%03d", n), strings.TrimSpace(finding.ID), false)
	}
	return source
}

func issuesWithCode(issues []ReportGateIssue, code string) []ReportGateIssue {
	var out []ReportGateIssue
	for _, issue := range issues {
		if issue.Code == code {
			out = append(out, issue)
		}
	}
	return out
}

func TestRunReportRequiresAnInvariantForEveryOpenFinding(t *testing.T) {
	workspace, source := registryWorkspace(t, "VULN-001", "VULN-002")

	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	missing := issuesWithCode(gate.Issues, "finding_invariant_missing")
	if gate.Ready || len(missing) != 2 {
		t.Fatalf("without an invariant directory every confirmed finding must block the gate, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
	if !strings.HasSuffix(missing[0].Path, filepath.Join(".ensphere", "invariants")) || !strings.Contains(missing[0].Message, "VULN-001") {
		t.Fatalf("the issue must name the directory and the finding, got %+v", missing[0])
	}

	writeInvariantFor(t, source, "INV-001", "VULN-001", false)
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	missing = issuesWithCode(gate.Issues, "finding_invariant_missing")
	if gate.Ready || len(missing) != 1 || !strings.Contains(missing[0].Message, "VULN-002") {
		t.Fatalf("expected only VULN-002 to lack an invariant, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}

	writeInvariantFor(t, source, "INV-002", "VULN-002", false)
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if !gate.Ready || hasIssue(gate.Issues, "finding_invariant_missing") {
		t.Fatalf("every finding promoted must pass the gate, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
}

func TestRunReportRejectsAnEnforcedInvariantFromAnOpenFinding(t *testing.T) {
	workspace, source := registryWorkspace(t, "VULN-001")
	path := writeInvariantFor(t, source, "INV-001", "VULN-001", true)

	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	enforced := issuesWithCode(gate.Issues, "invariant_enforced_before_fix")
	if gate.Ready || len(enforced) != 1 || enforced[0].Path != path || !strings.Contains(enforced[0].Message, "VULN-001") {
		t.Fatalf("an enforced invariant from an open finding must block the gate at its file, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
	if hasIssue(gate.Issues, "finding_invariant_missing") {
		t.Fatalf("the finding is promoted, only wrongly enforced: %+v", gate.Issues)
	}
}

func TestRunReportReportsInvariantFilesThatDoNotValidate(t *testing.T) {
	workspace, source := registryWorkspace(t, "VULN-001")
	writeInvariantFor(t, source, "INV-001", "VULN-001", false)
	writeSourceFile(t, source, filepath.Join(".ensphere", "invariants", "INV-002.yaml"), "id: INV-002\ntitle: bogus\norigin: {kind: tested_defense, ref: COV-02-001}\nkind: telepathy\nexpect: {}\n")

	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "invariant_kind_invalid") {
		t.Fatalf("an invariant file that does not validate must block the gate, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
	if hasIssue(gate.Issues, "finding_invariant_missing") {
		t.Fatalf("VULN-001 is promoted by INV-001: %+v", gate.Issues)
	}
}

func TestRunReportNeedsNoInvariantForAFindingThatIsNotOpen(t *testing.T) {
	workspace, _ := registryWorkspace(t, "VULN-001")
	raw, err := os.ReadFile(findingRegistryPath(workspace))
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	edited := strings.Replace(string(raw), "status: confirmed", "status: informational", 1)
	if err := os.WriteFile(findingRegistryPath(workspace), []byte(edited), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if hasIssue(gate.Issues, "finding_invariant_missing") {
		t.Fatalf("only confirmed and likely findings are promoted: %+v", gate.Issues)
	}
}
