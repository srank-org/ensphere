package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
)

const (
	coverageStatePlanned       = "planned"
	coverageStateTested        = "tested"
	coverageStateNotTested     = "not_tested"
	coverageStateBlocked       = "blocked"
	coverageStateNotApplicable = "not_applicable"
)

// coverageSessions are the sessions whose coverage.yaml the report gate
// reads. Recon (01) and the plan (01.5) inventory and decide; they do not
// run checks, so they carry no coverage file.
func coverageSessions() []Session {
	var out []Session
	for _, session := range reportRequiredSessions {
		if session.ID == "01" || session.ID == "01.5" {
			continue
		}
		out = append(out, session)
	}
	return out
}

func coverageFilePath(workspace string, session Session) string {
	return filepath.Join(workspace, session.Directory, "coverage.yaml")
}

func readCoverageFile(path string) (*CoverageFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read coverage file: %w", err)
	}
	var file CoverageFile
	if err := decodeStrictYAML(raw, &file); err != nil {
		return nil, fmt.Errorf("parse coverage file: %w", err)
	}
	return &file, nil
}

func validCoverageState(value string) bool {
	switch strings.TrimSpace(value) {
	case coverageStatePlanned, coverageStateTested, coverageStateNotTested, coverageStateBlocked, coverageStateNotApplicable:
		return true
	default:
		return false
	}
}

func (c *CoverageCounts) add(state string) {
	c.Total++
	switch strings.TrimSpace(state) {
	case coverageStatePlanned:
		c.Planned++
	case coverageStateTested:
		c.Tested++
	case coverageStateNotTested:
		c.NotTested++
	case coverageStateBlocked:
		c.Blocked++
	case coverageStateNotApplicable:
		c.NotApplicable++
	}
}

func (c *CoverageCounts) merge(other CoverageCounts) {
	c.Planned += other.Planned
	c.Tested += other.Tested
	c.NotTested += other.NotTested
	c.Blocked += other.Blocked
	c.NotApplicable += other.NotApplicable
	c.Total += other.Total
}

// evidenceIDSet returns the set of evidence IDs recorded in a session ledger.
// A missing ledger yields an empty set, not an error; the caller decides what
// that means for the rows that cite it.
func evidenceIDSet(path string) (map[string]struct{}, error) {
	ids := make(map[string]struct{})
	if !fileExists(path) {
		return ids, nil
	}
	entries, _, err := evidence.ReadAll(path)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		ids[strings.TrimSpace(entry.ID)] = struct{}{}
	}
	return ids, nil
}

// validateCoverageFiles checks every session's coverage.yaml against the
// contract and returns the gate issues plus the counts the statement uses.
func validateCoverageFiles(workspace string, states map[string]string) ([]ReportGateIssue, *CoverageSummary) {
	var issues []ReportGateIssue
	summary := &CoverageSummary{}
	for _, session := range coverageSessions() {
		path := coverageFilePath(workspace, session)
		entry := SessionCoverage{ID: session.ID, Directory: session.Directory}
		state := ""
		if states != nil {
			state = strings.ToUpper(strings.TrimSpace(states[session.ID]))
		}
		if !fileExists(path) {
			if state == stateDone {
				issues = append(issues, gateIssue("error", "coverage_missing", path, fmt.Sprintf("Session %s is DONE but coverage.yaml is missing; every check must be a coverage row", session.ID)))
			}
			summary.Sessions = append(summary.Sessions, entry)
			continue
		}
		entry.Present = true
		file, err := readCoverageFile(path)
		if err != nil {
			issues = append(issues, gateIssue("error", "coverage_parse_failed", path, err.Error()))
			summary.Sessions = append(summary.Sessions, entry)
			continue
		}
		rowIssues, counts := validateCoverageRows(workspace, session, path, file)
		issues = append(issues, rowIssues...)
		entry.Counts = counts
		summary.Totals.merge(counts)
		summary.Sessions = append(summary.Sessions, entry)
	}
	return issues, summary
}

func validateCoverageRows(workspace string, session Session, path string, file *CoverageFile) ([]ReportGateIssue, CoverageCounts) {
	var issues []ReportGateIssue
	var counts CoverageCounts
	if strings.TrimSpace(file.Session) != session.ID {
		issues = append(issues, gateIssue("error", "coverage_session_mismatch", path, fmt.Sprintf("coverage session %q must be %q", file.Session, session.ID)))
	}
	idPattern := regexp.MustCompile(`^COV-` + regexp.QuoteMeta(session.ID) + `-[0-9]{3,}$`)
	ledger := filepath.Join(workspace, session.Directory, "evidence.jsonl")
	knownIDs, ledgerErr := evidenceIDSet(ledger)
	if ledgerErr != nil {
		issues = append(issues, gateIssue("error", "coverage_evidence_read_failed", ledger, ledgerErr.Error()))
	}
	seen := make(map[string]struct{}, len(file.Rows))
	for i, row := range file.Rows {
		refPath := fmt.Sprintf("%s#rows[%d]", path, i)
		id := strings.TrimSpace(row.ID)
		if !idPattern.MatchString(id) {
			issues = append(issues, gateIssue("error", "coverage_id_invalid", refPath, fmt.Sprintf("coverage row id %q must look like COV-%s-001", id, session.ID)))
		} else if _, ok := seen[id]; ok {
			issues = append(issues, gateIssue("error", "coverage_id_duplicate", refPath, fmt.Sprintf("duplicate coverage row id %s", id)))
		} else {
			seen[id] = struct{}{}
		}
		if strings.TrimSpace(row.Surface) == "" || strings.TrimSpace(row.Check) == "" {
			issues = append(issues, gateIssue("error", "coverage_field_missing", refPath, "coverage rows require surface and check"))
		}
		state := strings.TrimSpace(row.State)
		if !validCoverageState(state) {
			issues = append(issues, gateIssue("error", "coverage_state_invalid", refPath, fmt.Sprintf("coverage state %q must be planned, tested, not_tested, blocked, or not_applicable", row.State)))
			counts.Total++
			continue
		}
		counts.add(state)
		switch state {
		case coverageStatePlanned:
			issues = append(issues, gateIssue("error", "coverage_row_planned", refPath, fmt.Sprintf("coverage row %s is still planned; resolve it to tested, not_tested, blocked, or not_applicable before Session 09", id)))
		case coverageStateTested:
			if !hasNonEmptyString(row.EvidenceIDs) {
				issues = append(issues, gateIssue("error", "coverage_evidence_missing", refPath, fmt.Sprintf("tested coverage row %s cites no evidence IDs; a check without evidence is not tested", id)))
			} else if ledgerErr == nil {
				for _, evidenceID := range row.EvidenceIDs {
					evidenceID = strings.TrimSpace(evidenceID)
					if evidenceID == "" {
						continue
					}
					if _, ok := knownIDs[evidenceID]; !ok {
						issues = append(issues, gateIssue("error", "coverage_evidence_unknown", refPath, fmt.Sprintf("coverage row %s cites %s, which is not in %s", id, evidenceID, ledger)))
					}
				}
			}
		default:
			if strings.TrimSpace(row.Reason) == "" {
				issues = append(issues, gateIssue("error", "coverage_reason_missing", refPath, fmt.Sprintf("coverage row %s is %s and needs a reason", id, state)))
			}
		}
		issues = append(issues, validateCitationPaths(workspace, refPath, "transcripts", row.Transcripts)...)
	}
	return issues, counts
}

func renderCoverageSummaryMarkdown(summary *CoverageSummary) string {
	if summary == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Coverage\n\n")
	b.WriteString("| Session | File | Tested | Not tested | Blocked | Not applicable | Planned | Total |\n")
	b.WriteString("|---------|------|--------|------------|---------|----------------|---------|-------|\n")
	for _, session := range summary.Sessions {
		present := "missing"
		if session.Present {
			present = "present"
		}
		c := session.Counts
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %d | %d | %d | %d |\n", session.ID, present, c.Tested, c.NotTested, c.Blocked, c.NotApplicable, c.Planned, c.Total))
	}
	t := summary.Totals
	b.WriteString(fmt.Sprintf("| **Total** | | %d | %d | %d | %d | %d | %d |\n", t.Tested, t.NotTested, t.Blocked, t.NotApplicable, t.Planned, t.Total))
	return b.String()
}
