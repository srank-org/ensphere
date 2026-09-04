package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/srank-org/ensphere/internal/evidence"
	"gopkg.in/yaml.v3"
)

// statementSentence is the fixed closing sentence of the Statement of
// Assessment. It is quoted verbatim in skills/methodology/09-report.md.
const statementSentence = "This is a self-assessment performed by the system owner with Ensphere. It is not an independent audit, attestation, or certification."

const statementDigestPrefix = "Inputs digest: "

// ErrReportGateNotReady is returned by RunStatement when the Session 09 gate
// still has error issues.
var ErrReportGateNotReady = errors.New("report gate not ready")

func statementPath(workspace string) string {
	return filepath.Join(workspace, "09-report", "statement.yaml")
}

func statementMarkdownPath(workspace string) string {
	return filepath.Join(workspace, "09-report", "statement.md")
}

// RunStatement writes 09-report/statement.yaml and statement.md from the
// workspace. It refuses to run while the report gate has error issues.
func RunStatement(workspace, version string) (*StatementOutput, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	if err := ensureWorkspaceInitialized(workspace); err != nil {
		return nil, err
	}
	gate := buildReportGate(workspace)
	if !gate.Ready {
		var codes []string
		for _, issue := range gate.Issues {
			if issue.Severity == "error" && issue.Code != "statement_stale" && issue.Code != "statement_edited" {
				codes = append(codes, issue.Code)
			}
		}
		if len(codes) > 0 {
			return nil, fmt.Errorf("%w: resolve %s first (see %s)", ErrReportGateNotReady, strings.Join(uniqueStrings(codes), ", "), gate.GateMarkdownPath)
		}
	}
	statement, err := BuildStatement(workspace, version, gate.Coverage)
	if err != nil {
		return nil, err
	}
	statement.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := yaml.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("encode statement: %w", err)
	}
	if err := os.WriteFile(statementPath(workspace), raw, 0644); err != nil {
		return nil, fmt.Errorf("write statement: %w", err)
	}
	if err := os.WriteFile(statementMarkdownPath(workspace), []byte(renderStatementMarkdown(statement)), 0644); err != nil {
		return nil, fmt.Errorf("write statement markdown: %w", err)
	}
	return &StatementOutput{
		Workspace:     workspace,
		StatementPath: statementPath(workspace),
		MarkdownPath:  statementMarkdownPath(workspace),
		InputsDigest:  statement.InputsDigest,
		Message:       "Statement of Assessment written from the workspace. The operator signs statement.md; do not edit it by hand.",
	}, nil
}

// BuildStatement derives every statement number from the workspace. The
// coverage summary is passed in so the gate and the statement count the same
// files the same way; pass nil to compute it here.
func BuildStatement(workspace, version string, coverage *CoverageSummary) (*Statement, error) {
	cfg, err := readConfig(workspace)
	if err != nil {
		return nil, err
	}
	states, err := readProgress(workspace)
	if err != nil {
		return nil, err
	}
	var plan *AssessmentPlan
	if fileExists(assessmentPlanPath(workspace)) {
		plan, _ = ReadAssessmentPlan(assessmentPlanPath(workspace))
	}
	if coverage == nil {
		_, coverage = validateCoverageFiles(workspace, states, planDecisions(plan))
	}
	statement := &Statement{
		EnsphereVersion: version,
		System: StatementSystem{
			TargetURL:   cfg.TargetURL,
			Environment: cfg.Environment,
			SourcePath:  cfg.SourcePath,
			TargetType:  cfg.TargetType,
			Cloud:       splitList(cfg.Cloud),
			InScope:     cfg.InScope,
			AssessedBy:  cfg.AssessedBy,
			Operator:    cfg.Operator,
		},
		Coverage: *coverage,
		Findings: StatementFindings{
			ByKind:     map[string]int{},
			ByStatus:   map[string]int{},
			BySeverity: map[string]int{},
			Unresolved: []UnresolvedFinding{},
		},
		Checklists: []string{},
		Ledgers:    []StatementLedger{},
	}

	if plan != nil {
		statement.Checklists = cleanStrings(plan.Checklists)
	}
	for _, session := range Sessions {
		entry := StatementSession{ID: session.ID, Name: session.Name, State: strings.ToUpper(strings.TrimSpace(states[session.ID]))}
		if plan != nil {
			if decision, ok := plan.Sessions[planKeyForSession(session)]; ok {
				entry.Decision = decision.Decision
			}
		}
		statement.Sessions = append(statement.Sessions, entry)
	}

	if fileExists(findingRegistryPath(workspace)) {
		registry, err := readFindingRegistry(findingRegistryPath(workspace))
		if err != nil {
			return nil, err
		}
		for _, finding := range registry.Findings {
			statement.Findings.ByKind[strings.TrimSpace(finding.Kind)]++
			statement.Findings.ByStatus[strings.TrimSpace(finding.Status)]++
			if vulnerabilityFindingStatus(finding.Status) {
				statement.Findings.BySeverity[strings.TrimSpace(finding.Severity)]++
				statement.Findings.Unresolved = append(statement.Findings.Unresolved, UnresolvedFinding{
					ID:       strings.TrimSpace(finding.ID),
					Kind:     strings.TrimSpace(finding.Kind),
					Status:   strings.TrimSpace(finding.Status),
					Severity: strings.TrimSpace(finding.Severity),
					Title:    strings.TrimSpace(finding.Title),
				})
			}
		}
		sort.SliceStable(statement.Findings.Unresolved, func(i, j int) bool {
			a, b := statement.Findings.Unresolved[i], statement.Findings.Unresolved[j]
			if severityRank(a.Severity) != severityRank(b.Severity) {
				return severityRank(a.Severity) < severityRank(b.Severity)
			}
			return a.ID < b.ID
		})
	}

	earliest, latest := "", ""
	for _, session := range reportRequiredSessions {
		path := filepath.Join(workspace, session.Directory, "evidence.jsonl")
		if !fileExists(path) {
			continue
		}
		entries, _, err := evidence.ReadAll(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		chain, err := evidence.VerifyChain(path)
		if err != nil {
			return nil, fmt.Errorf("verify %s: %w", path, err)
		}
		ledger := StatementLedger{
			Session: session.ID,
			Path:    filepath.ToSlash(filepath.Join(session.Directory, "evidence.jsonl")),
			Entries: len(entries),
			Valid:   chain.Valid,
		}
		if len(entries) > 0 {
			ledger.FinalHash = entries[len(entries)-1].Hash
		}
		statement.Ledgers = append(statement.Ledgers, ledger)
		for _, entry := range entries {
			ts := strings.TrimSpace(entry.Timestamp)
			if ts == "" {
				continue
			}
			if earliest == "" || ts < earliest {
				earliest = ts
			}
			if latest == "" || ts > latest {
				latest = ts
			}
		}
	}
	statement.Dates = StatementDates{EarliestEvidence: earliest, LatestEvidence: latest}

	digest, err := statementDigest(statement)
	if err != nil {
		return nil, err
	}
	statement.InputsDigest = digest
	return statement, nil
}

// statementDigest hashes a canonical JSON encoding of every statement input
// except the generation time and the digest itself.
func statementDigest(statement *Statement) (string, error) {
	copyStatement := *statement
	copyStatement.GeneratedAt = ""
	copyStatement.InputsDigest = ""
	raw, err := json.Marshal(copyStatement)
	if err != nil {
		return "", fmt.Errorf("encode statement for digest: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// validateStatement compares an existing statement against the workspace.
func validateStatement(workspace string, coverage *CoverageSummary) ([]ReportGateIssue, string) {
	yamlPath := statementPath(workspace)
	mdPath := statementMarkdownPath(workspace)
	if !fileExists(yamlPath) {
		return nil, "missing"
	}
	raw, err := os.ReadFile(yamlPath)
	if err != nil {
		return []ReportGateIssue{gateIssue("error", "statement_read_failed", yamlPath, err.Error())}, "invalid"
	}
	var stored Statement
	if err := decodeStrictYAML(raw, &stored); err != nil {
		return []ReportGateIssue{gateIssue("error", "statement_parse_failed", yamlPath, err.Error())}, "invalid"
	}
	var issues []ReportGateIssue
	state := "current"
	current, err := BuildStatement(workspace, stored.EnsphereVersion, coverage)
	if err != nil {
		return []ReportGateIssue{gateIssue("error", "statement_rebuild_failed", yamlPath, err.Error())}, "invalid"
	}
	if current.InputsDigest != stored.InputsDigest {
		state = "stale"
		issues = append(issues, gateIssue("error", "statement_stale", yamlPath, "the workspace changed after the statement was generated; run ensphere run statement again"))
	}
	if fileExists(mdPath) {
		md, err := os.ReadFile(mdPath)
		if err != nil {
			issues = append(issues, gateIssue("error", "statement_read_failed", mdPath, err.Error()))
		} else if digest := statementMarkdownDigest(string(md)); digest != stored.InputsDigest {
			state = "edited"
			issues = append(issues, gateIssue("error", "statement_edited", mdPath, "statement.md does not match statement.yaml; regenerate it instead of editing by hand"))
		}
	} else {
		issues = append(issues, gateIssue("error", "statement_markdown_missing", mdPath, "statement.yaml exists but statement.md is missing; run ensphere run statement again"))
	}
	return issues, state
}

func statementMarkdownDigest(markdown string) string {
	for _, line := range strings.Split(markdown, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, statementDigestPrefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, statementDigestPrefix))
		}
	}
	return ""
}

func renderStatementMarkdown(s *Statement) string {
	var b strings.Builder
	b.WriteString("# Statement of Assessment\n\n")
	b.WriteString(fmt.Sprintf("- **System**: %s\n", orNone(s.System.TargetURL, "source only, no live target")))
	b.WriteString(fmt.Sprintf("- **Source path**: %s\n", orNone(s.System.SourcePath, "none")))
	b.WriteString(fmt.Sprintf("- **Target type**: %s\n", orNone(s.System.TargetType, "auto")))
	b.WriteString(fmt.Sprintf("- **Environment tier**: %s\n", orNone(s.System.Environment, "none")))
	b.WriteString(fmt.Sprintf("- **Platforms**: %s\n", orNone(strings.Join(s.System.Cloud, ", "), "none")))
	b.WriteString(fmt.Sprintf("- **In scope**: %s\n", orNone(s.System.InScope, "not recorded")))
	b.WriteString(fmt.Sprintf("- **Assessed by**: %s\n", orNone(s.System.AssessedBy, "not recorded")))
	b.WriteString(fmt.Sprintf("- **Operator**: %s\n", orNone(s.System.Operator, "not recorded")))
	b.WriteString(fmt.Sprintf("- **Evidence dates**: %s to %s\n", orNone(s.Dates.EarliestEvidence, "no evidence"), orNone(s.Dates.LatestEvidence, "no evidence")))
	b.WriteString(fmt.Sprintf("- **Ensphere version**: %s\n", orNone(s.EnsphereVersion, "unknown")))
	b.WriteString(fmt.Sprintf("- **Checklists loaded**: %s\n", orNone(strings.Join(s.Checklists, ", "), "none")))
	b.WriteString(fmt.Sprintf("- **Generated**: %s\n\n", s.GeneratedAt))

	b.WriteString("## Sessions\n\n")
	b.WriteString("| Session | Name | Decision | State |\n")
	b.WriteString("|---------|------|----------|-------|\n")
	for _, session := range s.Sessions {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", session.ID, escapeMarkdownCell(session.Name), orNone(session.Decision, "-"), orNone(session.State, "-")))
	}
	b.WriteString("\n## Checks\n\n")
	t := s.Coverage.Totals
	b.WriteString(fmt.Sprintf("- **Executed**: %d\n", t.Tested))
	b.WriteString(fmt.Sprintf("- **Not checked**: %d (not tested %d, blocked %d, not applicable %d)\n\n", t.NotTested+t.Blocked+t.NotApplicable, t.NotTested, t.Blocked, t.NotApplicable))
	for _, session := range s.Coverage.Sessions {
		if !session.Present {
			b.WriteString(fmt.Sprintf("- Session %s: no coverage file\n", session.ID))
			continue
		}
		c := session.Counts
		b.WriteString(fmt.Sprintf("- Session %s: %d executed, %d not tested, %d blocked, %d not applicable\n", session.ID, c.Tested, c.NotTested, c.Blocked, c.NotApplicable))
	}

	b.WriteString("\n## Findings\n\n")
	b.WriteString(fmt.Sprintf("- **Vulnerabilities**: %d\n", s.Findings.ByKind["vulnerability"]))
	b.WriteString(fmt.Sprintf("- **Missing controls**: %d\n", s.Findings.ByKind["missing_control"]))
	b.WriteString(fmt.Sprintf("- **Confirmed**: %d, **likely**: %d, **informational**: %d, **not supported**: %d, **not tested**: %d\n\n",
		s.Findings.ByStatus["confirmed"], s.Findings.ByStatus["likely"], s.Findings.ByStatus["informational"], s.Findings.ByStatus["not_supported"], s.Findings.ByStatus["not_tested"]))
	if len(s.Findings.Unresolved) == 0 {
		b.WriteString("No confirmed or likely findings are recorded in the registry.\n")
	} else {
		b.WriteString("Unresolved findings by severity:\n\n")
		b.WriteString("| ID | Kind | Status | Severity | Title |\n")
		b.WriteString("|----|------|--------|----------|-------|\n")
		for _, finding := range s.Findings.Unresolved {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", finding.ID, finding.Kind, finding.Status, finding.Severity, escapeMarkdownCell(finding.Title)))
		}
	}

	b.WriteString("\n## Evidence ledgers\n\n")
	if len(s.Ledgers) == 0 {
		b.WriteString("No evidence ledgers were recorded.\n")
	} else {
		b.WriteString("| Session | Ledger | Entries | Chain valid | Final hash |\n")
		b.WriteString("|---------|--------|---------|-------------|------------|\n")
		for _, ledger := range s.Ledgers {
			b.WriteString(fmt.Sprintf("| %s | %s | %d | %t | %s |\n", ledger.Session, ledger.Path, ledger.Entries, ledger.Valid, orNone(ledger.FinalHash, "-")))
		}
	}

	b.WriteString("\n" + statementSentence + "\n\n")
	b.WriteString("Signed by the operator:\n\n")
	b.WriteString(fmt.Sprintf("Name: %s\n\n", orNone(s.System.Operator, "________________________")))
	b.WriteString("Signature: ________________________\n\n")
	b.WriteString("Date: ________________________\n\n")
	b.WriteString(statementDigestPrefix + s.InputsDigest + "\n")
	return b.String()
}

func orNone(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func splitList(value string) []string {
	out := []string{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" && part != "none" {
			out = append(out, part)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func severityRank(value string) int {
	switch strings.TrimSpace(value) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// planKeyForSession maps a runner session to its assessment-plan key.
func planKeyForSession(session Session) string {
	for _, key := range planSessionKeys {
		if strings.HasPrefix(key, session.ID+"-") {
			return key
		}
	}
	return ""
}
