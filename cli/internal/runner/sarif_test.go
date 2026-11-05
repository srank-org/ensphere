package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSARIFExportsReportableFindings(t *testing.T) {
	root := t.TempDir()
	workspace := writeDiffWorkspace(t, root, "ensphere-pentest")
	writeRegistryFindings(t, workspace,
		registryFinding("VULN-001", "vulnerability", "injection", "SQL injection in search", "confirmed", "critical", "P0", "app/api/search.ts:24:7", "GET /api/search"),
		registryFinding("VULN-002", "vulnerability", "injection", "SQL Injection in  search", "likely", "high", "P1", "src/db.go"),
		registryFinding("CTRL-001", "missing_control", "abuse_and_cost", "No rate limit on OTP", "confirmed", "medium", "P2", "POST /api/otp"),
		registryFinding("VULN-003", "vulnerability", "xss", "Reflected XSS in preview", "informational", "low", "P4", "https://example.com/preview"),
		registryFinding("VULN-004", "vulnerability", "ssrf", "SSRF in webhook", "not_supported", "none", "NONE", "app/webhook.ts:9"),
		registryFinding("VULN-005", "vulnerability", "api", "GraphQL batching", "not_tested", "none", "NONE", "POST /graphql"),
	)

	out, err := RunSARIF(workspace, "test-version")
	if err != nil {
		t.Fatalf("run sarif: %v", err)
	}
	raw, err := os.ReadFile(out.SARIFPath)
	if err != nil {
		t.Fatalf("read findings.sarif: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("decode findings.sarif: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("unexpected SARIF envelope: version=%q runs=%d", log.Version, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Version != "test-version" || run.Tool.Driver.Name != "ensphere" {
		t.Fatalf("unexpected driver: %+v", run.Tool.Driver)
	}

	wantRules := []string{"ensphere/missing_control/abuse_and_cost", "ensphere/vulnerability/injection", "ensphere/vulnerability/xss"}
	if len(run.Tool.Driver.Rules) != len(wantRules) || out.Rules != len(wantRules) {
		t.Fatalf("expected %d rules, got %+v", len(wantRules), run.Tool.Driver.Rules)
	}
	for i, rule := range run.Tool.Driver.Rules {
		if rule.ID != wantRules[i] {
			t.Fatalf("rule %d is %s, want %s", i, rule.ID, wantRules[i])
		}
	}
	if rule := run.Tool.Driver.Rules[0]; rule.Name != "MissingControlAbuseAndCost" || !strings.HasSuffix(rule.HelpURI, "skills/ensphere/methodology/08.5-abuse.md") {
		t.Fatalf("unexpected abuse rule: %+v", rule)
	}

	results := map[string]sarifResult{}
	for _, result := range run.Results {
		results[result.Properties.ID] = result
		if run.Tool.Driver.Rules[result.RuleIndex].ID != result.RuleID {
			t.Fatalf("ruleIndex of %s points at %s, want %s", result.Properties.ID, run.Tool.Driver.Rules[result.RuleIndex].ID, result.RuleID)
		}
	}
	if len(run.Results) != 4 || out.Results != len(run.Results) {
		t.Fatalf("expected the four reportable findings, got %d results (output says %d)", len(run.Results), out.Results)
	}
	for _, excluded := range []string{"VULN-004", "VULN-005"} {
		if _, ok := results[excluded]; ok {
			t.Fatalf("%s is not reportable and must not be a result", excluded)
		}
	}
	for id, level := range map[string]string{"VULN-001": "error", "VULN-002": "error", "CTRL-001": "warning", "VULN-003": "note"} {
		if results[id].Level != level {
			t.Fatalf("%s level %q, want %q", id, results[id].Level, level)
		}
	}

	first := results["VULN-001"].Locations
	if len(first) != 2 || first[0].PhysicalLocation == nil || first[1].LogicalLocations == nil {
		t.Fatalf("expected a physical then a logical location for VULN-001, got %+v", first)
	}
	if loc := first[0].PhysicalLocation; loc.ArtifactLocation.URI != "app/api/search.ts" || loc.ArtifactLocation.URIBaseID != "%SRCROOT%" ||
		loc.Region == nil || loc.Region.StartLine != 24 || loc.Region.StartColumn != 7 {
		t.Fatalf("unexpected physical location: %+v region=%+v", loc, loc.Region)
	}
	if first[1].LogicalLocations[0].FullyQualifiedName != "GET /api/search" {
		t.Fatalf("unexpected logical location: %+v", first[1].LogicalLocations)
	}
	if loc := results["VULN-002"].Locations[0].PhysicalLocation; loc == nil || loc.ArtifactLocation.URI != "src/db.go" || loc.Region != nil {
		t.Fatalf("expected a region-less physical location for src/db.go, got %+v", loc)
	}

	ctrl := results["CTRL-001"].Locations
	if len(ctrl) != 2 || ctrl[0].PhysicalLocation == nil || ctrl[1].LogicalLocations == nil {
		t.Fatalf("expected the registry fallback before the endpoint, got %+v", ctrl)
	}
	fallback := ctrl[0].PhysicalLocation
	if fallback.ArtifactLocation.URI != "ensphere-pentest/09-report/finding-registry.yaml" {
		t.Fatalf("unexpected fallback uri %q", fallback.ArtifactLocation.URI)
	}
	registryRaw, err := os.ReadFile(findingRegistryPath(workspace))
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	lines := strings.Split(string(registryRaw), "\n")
	if fallback.Region == nil || fallback.Region.StartLine < 1 || fallback.Region.StartLine > len(lines) ||
		strings.TrimSpace(lines[fallback.Region.StartLine-1]) != "- id: CTRL-001" {
		t.Fatalf("fallback startLine %+v does not point at the CTRL-001 entry", fallback.Region)
	}
	if loc := results["VULN-003"].Locations[0]; loc.PhysicalLocation == nil || !strings.HasSuffix(loc.PhysicalLocation.ArtifactLocation.URI, "finding-registry.yaml") {
		t.Fatalf("a URL location is not a source path; expected the registry fallback, got %+v", results["VULN-003"].Locations)
	}

	fingerprint := func(id string) string { return results[id].PartialFingerprints["ensphere/finding/v1"] }
	if fingerprint("VULN-001") == "" || fingerprint("VULN-001") != fingerprint("VULN-002") {
		t.Fatalf("same kind, category, and normalized title must share a fingerprint: %q vs %q", fingerprint("VULN-001"), fingerprint("VULN-002"))
	}
	if fingerprint("VULN-001") == fingerprint("CTRL-001") || fingerprint("VULN-001") == fingerprint("VULN-003") {
		t.Fatal("different findings must not share a fingerprint")
	}

	if _, err := RunSARIF(workspace, "test-version"); err != nil {
		t.Fatalf("run sarif again: %v", err)
	}
	again, err := os.ReadFile(out.SARIFPath)
	if err != nil {
		t.Fatalf("read findings.sarif again: %v", err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("findings.sarif differs between identical runs")
	}
}

func TestRunSARIFRequiresRegistry(t *testing.T) {
	workspace := writeDiffWorkspace(t, t.TempDir(), "ensphere-pentest")
	if _, err := RunSARIF(workspace, "test-version"); err == nil {
		t.Fatal("expected an error without a finding registry")
	}
	if fileExists(filepath.Join(workspace, "09-report", "findings.sarif")) {
		t.Fatal("findings.sarif must not be written without a registry")
	}
}
