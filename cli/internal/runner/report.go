package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
	"gopkg.in/yaml.v3"
)

var reportRequiredSessions = []Session{
	{ID: "01", Directory: "01-recon"},
	{ID: "01.5", Directory: "01.5-session-plan"},
	{ID: "02", Directory: "02-injection"},
	{ID: "03", Directory: "03-auth"},
	{ID: "04", Directory: "04-authz"},
	{ID: "05", Directory: "05-xss"},
	{ID: "06", Directory: "06-ssrf"},
	{ID: "07", Directory: "07-cloud"},
	{ID: "08", Directory: "08-api"},
	{ID: "08.5", Directory: "08.5-abuse"},
	{ID: "08.7", Directory: "08.7-chains"},
}

var findingIDPattern = regexp.MustCompile(`^(VULN|CTRL)-[0-9]{3,}$`)

func RunReport(workspace string) (*ReportGateOutput, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	if err := ensureWorkspaceInitialized(workspace); err != nil {
		return nil, err
	}

	gate := buildReportGate(workspace)
	if err := writeReportGate(workspace, gate); err != nil {
		return nil, err
	}
	if gate.Ready {
		action, err := WriteNextAction(workspace)
		if err != nil {
			return nil, err
		}
		gate.NextActionPath = action.ActionPath
		gate.PromptPath = action.PromptPath
	} else if err := writeBlockedReportAction(workspace, gate); err != nil {
		return nil, err
	}
	return gate, nil
}

func buildReportGate(workspace string) *ReportGateOutput {
	issues := make([]ReportGateIssue, 0)
	states, err := readProgress(workspace)
	if err != nil {
		issues = append(issues, gateIssue("error", "progress_read_failed", progressPath(workspace), err.Error()))
	}

	var plan *AssessmentPlan
	if !fileExists(assessmentPlanPath(workspace)) {
		issues = append(issues, gateIssue("error", "assessment_plan_missing", assessmentPlanPath(workspace), "assessment-plan.yaml is required before Session 09"))
	} else {
		parsed, err := ReadAssessmentPlan(assessmentPlanPath(workspace))
		if err != nil {
			issues = append(issues, gateIssue("error", "assessment_plan_parse_failed", assessmentPlanPath(workspace), err.Error()))
		} else {
			plan = parsed
			for _, problem := range ValidateAssessmentPlan(plan) {
				issues = append(issues, gateIssue("error", "assessment_plan_invalid", assessmentPlanPath(workspace), problem))
			}
		}
	}

	if states != nil {
		issues = append(issues, validateSessionReportReadiness(workspace, states)...)
	}
	issues = append(issues, validateEvidenceFiles(workspace)...)
	coverageIssues, coverage := validateCoverageFiles(workspace, states, planDecisions(plan))
	issues = append(issues, coverageIssues...)

	registryPath := findingRegistryPath(workspace)
	registryState := "missing"
	if fileExists(registryPath) {
		registryState = "valid"
		registryIssues := validateFindingRegistry(registryPath)
		if len(registryIssues) > 0 {
			registryState = "invalid"
			issues = append(issues, registryIssues...)
		}
		issues = append(issues, validateSession09Artifacts(workspace)...)
	}

	statementIssues, statementState := validateStatement(workspace, coverage)
	issues = append(issues, statementIssues...)

	ready := !hasErrorIssue(issues)
	message := "Report gate passed. Session 09 can generate or refresh the evidence-backed assessment report."
	if !ready {
		message = "Report gate blocked. Resolve error issues before treating Session 09 as ready."
	}

	return &ReportGateOutput{
		Workspace:            workspace,
		Ready:                ready,
		GatePath:             reportGatePath(workspace),
		GateMarkdownPath:     reportGateMarkdownPath(workspace),
		FindingRegistryPath:  registryPath,
		FindingRegistryState: registryState,
		Issues:               issues,
		Coverage:             coverage,
		StatementPath:        statementPath(workspace),
		StatementMarkdown:    statementMarkdownPath(workspace),
		StatementState:       statementState,
		NextActionPath:       filepath.Join(workspace, "next-action.md"),
		PromptPath:           filepath.Join(workspace, "agent-prompt.md"),
		Message:              message,
	}
}

// planDecisions maps each session id to its plan decision, or nil when there
// is no readable plan.
func planDecisions(plan *AssessmentPlan) map[string]string {
	if plan == nil {
		return nil
	}
	decisions := make(map[string]string, len(plan.Sessions))
	for _, session := range Sessions {
		if entry, ok := plan.Sessions[planKeyForSession(session)]; ok {
			decisions[session.ID] = strings.TrimSpace(entry.Decision)
		}
	}
	return decisions
}

func validateSessionReportReadiness(workspace string, states map[string]string) []ReportGateIssue {
	var issues []ReportGateIssue
	for _, session := range reportRequiredSessions {
		state := strings.ToUpper(strings.TrimSpace(states[session.ID]))
		if !validWorkflowState(state) {
			issues = append(issues, gateIssue("error", "session_state_invalid", progressPath(workspace), fmt.Sprintf("Session %s is %q; progress.md states are PENDING, IN_PROGRESS, and DONE", session.ID, state)))
			continue
		}
		if state != stateDone {
			issues = append(issues, gateIssue("error", "session_not_terminal", progressPath(workspace), fmt.Sprintf("Session %s is %s; Session 09 requires sessions 01, 01.5, and 02-08.7 to be DONE. A session the plan decided skip, not_applicable, or blocked is DONE once its short report.md names that decision", session.ID, state)))
			continue
		}
		reportPath := filepath.Join(workspace, session.Directory, "report.md")
		if !fileExists(reportPath) {
			issues = append(issues, gateIssue("error", "session_report_missing", reportPath, fmt.Sprintf("Session %s is %s but report.md is missing", session.ID, state)))
			continue
		}
		if isEmptyFile(reportPath) {
			issues = append(issues, gateIssue("error", "session_report_empty", reportPath, fmt.Sprintf("Session %s report.md is empty", session.ID)))
		}
	}
	return issues
}

func validateEvidenceFiles(workspace string) []ReportGateIssue {
	var issues []ReportGateIssue
	for _, session := range reportRequiredSessions {
		path := filepath.Join(workspace, session.Directory, "evidence.jsonl")
		if !fileExists(path) {
			continue
		}
		result, err := evidence.VerifyChain(path)
		if err != nil {
			issues = append(issues, gateIssue("error", "evidence_verify_failed", path, err.Error()))
			continue
		}
		if !result.Valid {
			issues = append(issues, gateIssue("error", "evidence_hash_chain_invalid", path, fmt.Sprintf("hash chain invalid at %s: %s", result.BrokenAt, result.Error)))
		}
		if result.SkippedLines > 0 {
			issues = append(issues, gateIssue("warning", "evidence_skipped_lines", path, fmt.Sprintf("%d malformed evidence line(s) were skipped", result.SkippedLines)))
		}
	}
	return issues
}

func validateFindingRegistry(path string) []ReportGateIssue {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []ReportGateIssue{gateIssue("error", "finding_registry_read_failed", path, err.Error())}
	}
	registry, err := parseFindingRegistry(raw)
	if err != nil {
		return []ReportGateIssue{gateIssue("error", "finding_registry_parse_failed", path, err.Error())}
	}
	var issues []ReportGateIssue
	seen := make(map[string]struct{}, len(registry.Findings))
	for i, finding := range registry.Findings {
		refPath := fmt.Sprintf("%s#findings[%d]", path, i)
		id := strings.TrimSpace(finding.ID)
		if id == "" {
			issues = append(issues, gateIssue("error", "finding_id_missing", refPath, "finding id is required"))
		} else if !findingIDPattern.MatchString(id) {
			issues = append(issues, gateIssue("error", "finding_id_invalid", refPath, fmt.Sprintf("finding id %q must look like VULN-001 or CTRL-001", id)))
		} else if _, ok := seen[id]; ok {
			issues = append(issues, gateIssue("error", "finding_id_duplicate", refPath, fmt.Sprintf("duplicate finding id %s", id)))
		} else {
			seen[id] = struct{}{}
		}
		if strings.TrimSpace(finding.Kind) == "" {
			issues = append(issues, gateIssue("error", "finding_kind_missing", refPath, "finding kind is required (vulnerability or missing_control)"))
		} else if !validFindingKind(finding.Kind) {
			issues = append(issues, gateIssue("error", "finding_kind_invalid", refPath, fmt.Sprintf("finding kind %q must be vulnerability or missing_control", finding.Kind)))
		}
		if strings.TrimSpace(finding.Title) == "" {
			issues = append(issues, gateIssue("error", "finding_title_missing", refPath, "finding title is required"))
		}
		if strings.TrimSpace(finding.Category) == "" {
			issues = append(issues, gateIssue("error", "finding_category_missing", refPath, "finding category is required"))
		} else if !validFindingCategory(finding.Category) {
			issues = append(issues, gateIssue("error", "finding_category_invalid", refPath, fmt.Sprintf("finding category %q is invalid", finding.Category)))
		}
		if strings.TrimSpace(finding.Status) == "" {
			issues = append(issues, gateIssue("error", "finding_status_missing", refPath, "finding status is required"))
		} else if !validFindingStatus(finding.Status) {
			issues = append(issues, gateIssue("error", "finding_status_invalid", refPath, fmt.Sprintf("finding status %q is invalid", finding.Status)))
		}
		if strings.TrimSpace(finding.Confidence) == "" {
			issues = append(issues, gateIssue("error", "finding_confidence_missing", refPath, "finding confidence is required"))
		} else if !validFindingConfidence(finding.Confidence) {
			issues = append(issues, gateIssue("error", "finding_confidence_invalid", refPath, fmt.Sprintf("finding confidence %q is invalid", finding.Confidence)))
		}
		if strings.TrimSpace(finding.EvidenceStrength) == "" {
			issues = append(issues, gateIssue("error", "finding_evidence_strength_missing", refPath, "evidence_strength is required"))
		} else if !validEvidenceStrength(finding.EvidenceStrength) {
			issues = append(issues, gateIssue("error", "finding_evidence_strength_invalid", refPath, fmt.Sprintf("evidence_strength %q is invalid", finding.EvidenceStrength)))
		}
		if strings.TrimSpace(finding.Status) == "confirmed" && !strongFindingEvidence(finding.EvidenceStrength) {
			issues = append(issues, gateIssue("error", "finding_confirmed_evidence_weak", refPath, "confirmed findings require direct or corroborated evidence_strength"))
		}
		if strings.TrimSpace(finding.Status) == "likely" && strings.TrimSpace(finding.EvidenceStrength) == "insufficient" {
			issues = append(issues, gateIssue("error", "finding_likely_evidence_insufficient", refPath, "likely findings cannot use insufficient evidence_strength"))
		}
		if strings.TrimSpace(finding.Severity) == "" {
			issues = append(issues, gateIssue("error", "finding_severity_missing", refPath, "finding severity is required"))
		} else if !validFindingSeverity(finding.Severity) {
			issues = append(issues, gateIssue("error", "finding_severity_invalid", refPath, fmt.Sprintf("finding severity %q is invalid", finding.Severity)))
		}
		if strings.TrimSpace(finding.Priority) == "" {
			issues = append(issues, gateIssue("error", "finding_priority_missing", refPath, "priority is required"))
		} else if !validFindingPriority(finding.Priority) {
			issues = append(issues, gateIssue("error", "finding_priority_invalid", refPath, fmt.Sprintf("priority %q is invalid", finding.Priority)))
		}
		if vulnerabilityFindingStatus(finding.Status) {
			severity := strings.TrimSpace(finding.Severity)
			if severity == "info" || severity == "informational" || severity == "none" || severity == "not_applicable" {
				issues = append(issues, gateIssue("error", "finding_vulnerability_severity_invalid", refPath, "confirmed and likely findings require critical, high, medium, or low severity"))
			}
		}
		if cvss := strings.TrimSpace(finding.CVSSV4); cvss != "" {
			if !strings.HasPrefix(cvss, "CVSS:4.0/") {
				issues = append(issues, gateIssue("error", "finding_cvss_v4_invalid", refPath, "cvss_v4 must be a CVSS:4.0/ vector when present"))
			}
			if strings.TrimSpace(finding.Kind) == "missing_control" {
				issues = append(issues, gateIssue("warning", "finding_cvss_on_missing_control", refPath, "cvss_v4 is only meaningful for kind: vulnerability"))
			}
		}
		if reportableFindingStatus(finding.Status) {
			issues = append(issues, validateReportableFindingFields(refPath, finding)...)
		}
		if !findingHasCitation(finding) {
			issues = append(issues, gateIssue("error", "finding_uncited", refPath, fmt.Sprintf("finding %s has no evidence_ids, transcripts, import_refs, or manual_notes", displayFindingID(id))))
		}
		issues = append(issues, validateCitationPaths(workspaceRootForArtifact(path), refPath, "transcripts", finding.Transcripts)...)
		issues = append(issues, validateCitationPaths(workspaceRootForArtifact(path), refPath, "artifact_paths", finding.ArtifactPaths)...)
		issues = append(issues, validateCitationPaths(workspaceRootForArtifact(path), refPath, "cleanup_evidence", finding.CleanupEvidence)...)
		if len(finding.EvidenceCategories) == 0 {
			issues = append(issues, gateIssue("error", "finding_evidence_category_missing", refPath, "at least one evidence category is required"))
		}
		for _, category := range finding.EvidenceCategories {
			if !validEvidenceCategory(category) {
				issues = append(issues, gateIssue("error", "finding_evidence_category_invalid", refPath, fmt.Sprintf("evidence category %q is invalid", category)))
			}
		}
		if !containsRegistryValue(finding.EvidenceCategories, "agent_judgment") {
			issues = append(issues, gateIssue("error", "finding_agent_judgment_missing", refPath, "finding registry entries require agent_judgment to identify report-layer conclusions"))
		}
	}
	return issues
}

func readFindingRegistry(path string) (*FindingRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read finding registry: %w", err)
	}
	return parseFindingRegistry(raw)
}

func parseFindingRegistry(raw []byte) (*FindingRegistry, error) {
	var registry FindingRegistry
	if err := decodeStrictYAML(raw, &registry); err != nil {
		return nil, fmt.Errorf("parse finding registry: %w", err)
	}
	return &registry, nil
}

func writeReportGate(workspace string, gate *ReportGateOutput) error {
	if err := os.MkdirAll(filepath.Join(workspace, "09-report"), 0755); err != nil {
		return fmt.Errorf("create report gate directory: %w", err)
	}
	raw, err := yaml.Marshal(gate)
	if err != nil {
		return fmt.Errorf("encode report gate: %w", err)
	}
	if err := os.WriteFile(reportGatePath(workspace), raw, 0644); err != nil {
		return fmt.Errorf("write report gate: %w", err)
	}
	if err := os.WriteFile(reportGateMarkdownPath(workspace), []byte(renderReportGateMarkdown(gate)), 0644); err != nil {
		return fmt.Errorf("write report gate markdown: %w", err)
	}
	return nil
}

func writeBlockedReportAction(workspace string, gate *ReportGateOutput) error {
	actionPath := filepath.Join(workspace, "next-action.md")
	promptPath := filepath.Join(workspace, "agent-prompt.md")
	if err := os.WriteFile(actionPath, []byte(renderBlockedReportAction(gate)), 0644); err != nil {
		return fmt.Errorf("write report gate action: %w", err)
	}
	if err := os.WriteFile(promptPath, []byte(fmt.Sprintf("ensphere status\n\nResolve report gate issues listed in %s before running Session 09.\n", gate.GateMarkdownPath)), 0644); err != nil {
		return fmt.Errorf("write report gate prompt: %w", err)
	}
	gate.NextActionPath = actionPath
	gate.PromptPath = promptPath
	return nil
}

func renderReportGateMarkdown(gate *ReportGateOutput) string {
	var b strings.Builder
	b.WriteString("# Session 09 Report Gate\n\n")
	b.WriteString(fmt.Sprintf("- **Ready**: %t\n", gate.Ready))
	b.WriteString(fmt.Sprintf("- **Finding Registry**: %s\n", gate.FindingRegistryState))
	b.WriteString(fmt.Sprintf("- **Finding Registry Path**: %s\n", gate.FindingRegistryPath))
	b.WriteString(fmt.Sprintf("- **Statement**: %s\n\n", orNone(gate.StatementState, "missing")))
	if len(gate.Issues) == 0 {
		b.WriteString("No blocking or warning issues detected.\n\n")
	} else {
		b.WriteString("| Severity | Code | Path | Message |\n")
		b.WriteString("|----------|------|------|---------|\n")
		for _, issue := range gate.Issues {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", escapeMarkdownCell(issue.Severity), escapeMarkdownCell(issue.Code), escapeMarkdownCell(issue.Path), escapeMarkdownCell(issue.Message)))
		}
		b.WriteString("\n")
	}
	b.WriteString(renderCoverageSummaryMarkdown(gate.Coverage))
	return b.String()
}

func renderBlockedReportAction(gate *ReportGateOutput) string {
	var b strings.Builder
	b.WriteString("# Next Action\n\n")
	b.WriteString("Session 09 is blocked by report gate errors.\n\n")
	b.WriteString(fmt.Sprintf("- **Gate Report**: %s\n", gate.GateMarkdownPath))
	b.WriteString(fmt.Sprintf("- **Machine Gate**: %s\n\n", gate.GatePath))
	for _, issue := range gate.Issues {
		if issue.Severity != "error" {
			continue
		}
		b.WriteString(fmt.Sprintf("- `%s`: %s", issue.Code, issue.Message))
		if issue.Path != "" {
			b.WriteString(fmt.Sprintf(" (`%s`)", issue.Path))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func gateIssue(severity, code, path, message string) ReportGateIssue {
	return ReportGateIssue{
		Severity: severity,
		Code:     code,
		Path:     path,
		Message:  message,
	}
}

func hasErrorIssue(issues []ReportGateIssue) bool {
	for _, issue := range issues {
		if issue.Severity == "error" {
			return true
		}
	}
	return false
}

func isEmptyFile(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(raw)) == ""
}

func findingHasCitation(finding FindingSummary) bool {
	return hasNonEmptyString(finding.EvidenceIDs) ||
		hasNonEmptyString(finding.Transcripts) ||
		hasNonEmptyString(finding.ArtifactPaths) ||
		hasNonEmptyString(finding.CleanupEvidence) ||
		hasNonEmptyString(finding.ImportRefs) ||
		hasNonEmptyString(finding.ManualNotes)
}

func hasNonEmptyString(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func validFindingStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case "confirmed", "likely", "informational", "not_supported", "not_tested":
		return true
	default:
		return false
	}
}

func validFindingConfidence(value string) bool {
	switch strings.TrimSpace(value) {
	case "high", "medium", "low", "not_applicable", "none":
		return true
	default:
		return false
	}
}

func validFindingSeverity(value string) bool {
	switch strings.TrimSpace(value) {
	case "critical", "high", "medium", "low", "info", "informational", "not_applicable", "none":
		return true
	default:
		return false
	}
}

func validEvidenceCategory(value string) bool {
	switch strings.TrimSpace(value) {
	case "imported_lead",
		"ensphere_measurement",
		"source_review",
		"manual_observation",
		"agent_judgment":
		return true
	default:
		return false
	}
}

func validFindingKind(value string) bool {
	switch strings.TrimSpace(value) {
	case "vulnerability", "missing_control":
		return true
	default:
		return false
	}
}

func validFindingCategory(value string) bool {
	switch strings.TrimSpace(value) {
	case "injection", "authentication", "authorization", "xss", "ssrf", "cloud", "api", "abuse_and_cost", "configuration", "secrets", "other":
		return true
	default:
		return false
	}
}

func containsRegistryValue(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func displayFindingID(id string) string {
	if id == "" {
		return "<missing-id>"
	}
	return id
}

func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

func validateCitationPaths(workspace, refPath, field string, values []string) []ReportGateIssue {
	var issues []ReportGateIssue
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !safeWorkspaceRelativePath(value) {
			issues = append(issues, gateIssue("error", "finding_path_unsafe", refPath, fmt.Sprintf("%s path %q must be workspace-relative and must not escape the workspace", field, value)))
			continue
		}
		if workspace != "" {
			clean := cleanCitationPath(value)
			joined := filepath.Join(workspace, filepath.FromSlash(clean))
			rel, err := filepath.Rel(workspace, joined)
			if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
				issues = append(issues, gateIssue("error", "finding_path_unsafe", refPath, fmt.Sprintf("%s path %q resolves outside workspace", field, value)))
				continue
			}
			if !fileExists(joined) {
				issues = append(issues, gateIssue("error", "finding_path_missing", refPath, fmt.Sprintf("%s path %q does not exist", field, value)))
			}
		}
	}
	return issues
}

func validEvidenceStrength(value string) bool {
	switch strings.TrimSpace(value) {
	case "direct", "corroborated", "indicative", "insufficient":
		return true
	default:
		return false
	}
}

func strongFindingEvidence(value string) bool {
	switch strings.TrimSpace(value) {
	case "direct", "corroborated":
		return true
	default:
		return false
	}
}

func validFindingPriority(value string) bool {
	switch strings.TrimSpace(value) {
	case "P0", "P1", "P2", "P3", "P4", "NONE", "NOT_APPLICABLE":
		return true
	default:
		return false
	}
}

func reportableFindingStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case "confirmed", "likely", "informational":
		return true
	default:
		return false
	}
}

func vulnerabilityFindingStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case "confirmed", "likely":
		return true
	default:
		return false
	}
}

func validateReportableFindingFields(refPath string, finding FindingSummary) []ReportGateIssue {
	var issues []ReportGateIssue
	requireList := func(code, field string, values []string) {
		if !hasNonEmptyString(values) {
			issues = append(issues, gateIssue("error", code, refPath, field+" is required for reportable findings"))
		}
	}
	requireText := func(code, field, value string) {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, gateIssue("error", code, refPath, field+" is required for reportable findings"))
		}
	}
	requireList("finding_affected_assets_missing", "affected_assets", finding.AffectedAssets)
	requireList("finding_affected_locations_missing", "affected_locations", finding.AffectedLocations)
	requireList("finding_observed_facts_missing", "observed_facts", finding.ObservedFacts)
	requireText("finding_root_cause_missing", "root_cause", finding.RootCause)
	requireText("finding_security_impact_missing", "security_impact", finding.SecurityImpact)
	requireText("finding_remediation_missing", "remediation", finding.Remediation)
	requireList("finding_validation_criteria_missing", "validation_criteria", finding.ValidationCriteria)
	return issues
}

func validateSession09Artifacts(workspace string) []ReportGateIssue {
	var issues []ReportGateIssue
	reportPath := filepath.Join(workspace, "09-report", "report.md")
	appendixPath := filepath.Join(workspace, "09-report", "evidence-appendix.md")
	if !fileExists(reportPath) || isEmptyFile(reportPath) {
		issues = append(issues, gateIssue("error", "final_report_missing", reportPath, "a non-empty Session 09 report.md is required when the finding registry exists"))
	}
	if !fileExists(appendixPath) || isEmptyFile(appendixPath) {
		issues = append(issues, gateIssue("error", "evidence_appendix_missing", appendixPath, "a non-empty Session 09 evidence-appendix.md is required when the finding registry exists"))
	}
	return issues
}

func safeWorkspaceRelativePath(value string) bool {
	path := cleanCitationPath(value)
	if path == "" || path == "." {
		return false
	}
	if strings.Contains(path, "\x00") || strings.Contains(path, "\\") || strings.Contains(path, "://") || strings.HasPrefix(path, "~") {
		return false
	}
	if len(path) >= 2 && path[1] == ':' {
		return false
	}
	if filepath.IsAbs(path) || strings.HasPrefix(path, "/") {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	return clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func cleanCitationPath(value string) string {
	value = strings.TrimSpace(value)
	if before, _, ok := strings.Cut(value, "#"); ok {
		value = before
	}
	return strings.TrimSpace(value)
}

// workspaceRootForArtifact returns the workspace directory for a registry
// stored at <workspace>/09-report/finding-registry.yaml.
func workspaceRootForArtifact(path string) string {
	return filepath.Dir(filepath.Dir(path))
}

func reportGatePath(workspace string) string {
	return filepath.Join(workspace, "09-report", "report-gate.yaml")
}

func reportGateMarkdownPath(workspace string) string {
	return filepath.Join(workspace, "09-report", "report-gate.md")
}

func findingRegistryPath(workspace string) string {
	return filepath.Join(workspace, "09-report", "finding-registry.yaml")
}
