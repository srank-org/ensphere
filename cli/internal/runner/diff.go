package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrPreviousNotDirectory is returned by RunDiff when --previous does not
// name a directory.
var ErrPreviousNotDirectory = errors.New("previous workspace is not a directory")

const (
	matchedByTitle    = "title"
	matchedByLocation = "location"
)

func diffPath(workspace string) string {
	return filepath.Join(workspace, "09-report", "diff.json")
}

func diffMarkdownPath(workspace string) string {
	return filepath.Join(workspace, "09-report", "diff.md")
}

// RunDiff compares this workspace's finding registry, coverage files, and
// statement with a previous assessment's workspace and writes
// 09-report/diff.json and diff.md. Identical inputs produce identical bytes.
func RunDiff(workspace, previous string) (*DiffOutput, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	if err := ensureWorkspaceInitialized(workspace); err != nil {
		return nil, err
	}
	if info, err := os.Stat(previous); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%w: %q", ErrPreviousNotDirectory, previous)
	}

	previousRegistry, err := readFindingRegistry(findingRegistryPath(previous))
	if err != nil {
		return nil, fmt.Errorf("previous workspace: %w", err)
	}
	currentRegistry, err := readFindingRegistry(findingRegistryPath(workspace))
	if err != nil {
		return nil, fmt.Errorf("current workspace: %w", err)
	}
	previousRows, err := readCoverageRows(previous)
	if err != nil {
		return nil, fmt.Errorf("previous workspace: %w", err)
	}
	currentRows, err := readCoverageRows(workspace)
	if err != nil {
		return nil, fmt.Errorf("current workspace: %w", err)
	}
	statement, err := diffStatements(previous, workspace)
	if err != nil {
		return nil, err
	}

	out := &DiffOutput{
		Workspace:    workspace,
		Previous:     previous,
		DiffPath:     diffPath(workspace),
		MarkdownPath: diffMarkdownPath(workspace),
		Findings:     diffFindings(previousRegistry.Findings, currentRegistry.Findings),
		Coverage:     diffCoverage(previousRows, currentRows),
		Statement:    statement,
		Message:      "Compared the finding registry and coverage files of the two workspaces. The diff records what changed and assigns nothing; the pipeline decides what fails.",
	}
	if err := os.MkdirAll(filepath.Join(workspace, "09-report"), 0755); err != nil {
		return nil, fmt.Errorf("create report directory: %w", err)
	}
	if err := writeIndentedJSON(out.DiffPath, out); err != nil {
		return nil, err
	}
	if err := os.WriteFile(out.MarkdownPath, []byte(renderDiffMarkdown(out)), 0644); err != nil {
		return nil, fmt.Errorf("write diff markdown: %w", err)
	}
	return out, nil
}

type findingMatch struct {
	previous  FindingSummary
	current   FindingSummary
	matchedBy string
}

func diffFindings(previousFindings, currentFindings []FindingSummary) FindingDiff {
	previous := sortedFindings(previousFindings)
	current := sortedFindings(currentFindings)
	previousMatched := make([]bool, len(previous))
	currentMatched := make([]bool, len(current))
	var matches []findingMatch

	currentByKey := make(map[string][]int)
	for j, finding := range current {
		key := findingKey(finding)
		currentByKey[key] = append(currentByKey[key], j)
	}
	for i, finding := range previous {
		key := findingKey(finding)
		candidates := currentByKey[key]
		if len(candidates) == 0 {
			continue
		}
		j := candidates[0]
		currentByKey[key] = candidates[1:]
		previousMatched[i], currentMatched[j] = true, true
		matches = append(matches, findingMatch{previous: finding, current: current[j], matchedBy: matchedByTitle})
	}
	for i, finding := range previous {
		if previousMatched[i] {
			continue
		}
		for j, candidate := range current {
			if currentMatched[j] || !sameKindAndCategory(finding, candidate) || !sharesLocation(finding, candidate) {
				continue
			}
			previousMatched[i], currentMatched[j] = true, true
			matches = append(matches, findingMatch{previous: finding, current: candidate, matchedBy: matchedByLocation})
			break
		}
	}
	sort.SliceStable(matches, func(a, b int) bool {
		ma, mb := matches[a], matches[b]
		if ida, idb := strings.TrimSpace(ma.current.ID), strings.TrimSpace(mb.current.ID); ida != idb {
			return ida < idb
		}
		return strings.TrimSpace(ma.previous.ID) < strings.TrimSpace(mb.previous.ID)
	})

	diff := FindingDiff{
		New:       []FindingRef{},
		Gone:      []FindingRef{},
		Changed:   []FindingChange{},
		Unchanged: []FindingPair{},
		Summary: FindingDiffSummary{
			PreviousTotal: len(previous),
			CurrentTotal:  len(current),
			ByKind: map[string]KindUnresolvedDiff{
				"vulnerability":   {},
				"missing_control": {},
			},
		},
	}
	summary := &diff.Summary
	for _, finding := range previous {
		if vulnerabilityFindingStatus(finding.Status) {
			summary.UnresolvedBefore++
			kind := normalizeText(finding.Kind)
			entry := summary.ByKind[kind]
			entry.UnresolvedBefore++
			summary.ByKind[kind] = entry
		}
	}
	for _, finding := range current {
		if vulnerabilityFindingStatus(finding.Status) {
			summary.UnresolvedAfter++
			kind := normalizeText(finding.Kind)
			entry := summary.ByKind[kind]
			entry.UnresolvedAfter++
			summary.ByKind[kind] = entry
		}
	}
	for j, finding := range current {
		if currentMatched[j] {
			continue
		}
		diff.New = append(diff.New, findingRef(finding))
		if vulnerabilityFindingStatus(finding.Status) {
			summary.NewUnresolved++
		}
	}
	for i, finding := range previous {
		if previousMatched[i] {
			continue
		}
		diff.Gone = append(diff.Gone, findingRef(finding))
		if vulnerabilityFindingStatus(finding.Status) {
			summary.GoneUnresolved++
		}
	}
	for _, match := range matches {
		before := vulnerabilityFindingStatus(match.previous.Status)
		after := vulnerabilityFindingStatus(match.current.Status)
		if !before && after {
			summary.Reopened++
		}
		if before && !after {
			summary.Resolved++
		}
		changes := findingFieldChanges(match.previous, match.current)
		if len(changes) == 0 {
			diff.Unchanged = append(diff.Unchanged, FindingPair{
				PreviousID: strings.TrimSpace(match.previous.ID),
				CurrentID:  strings.TrimSpace(match.current.ID),
				MatchedBy:  match.matchedBy,
			})
			continue
		}
		diff.Changed = append(diff.Changed, FindingChange{
			PreviousID: strings.TrimSpace(match.previous.ID),
			CurrentID:  strings.TrimSpace(match.current.ID),
			MatchedBy:  match.matchedBy,
			Title:      strings.TrimSpace(match.current.Title),
			Kind:       strings.TrimSpace(match.current.Kind),
			Category:   strings.TrimSpace(match.current.Category),
			Changes:    changes,
		})
	}
	return diff
}

func sortedFindings(findings []FindingSummary) []FindingSummary {
	out := append([]FindingSummary(nil), findings...)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.TrimSpace(out[i].ID) < strings.TrimSpace(out[j].ID)
	})
	return out
}

func sameKindAndCategory(a, b FindingSummary) bool {
	return normalizeText(a.Kind) == normalizeText(b.Kind) && normalizeText(a.Category) == normalizeText(b.Category)
}

func sharesLocation(a, b FindingSummary) bool {
	locations := make(map[string]struct{}, len(a.AffectedLocations))
	for _, location := range a.AffectedLocations {
		if normalized := normalizeLocation(location); normalized != "" {
			locations[normalized] = struct{}{}
		}
	}
	for _, location := range b.AffectedLocations {
		if _, ok := locations[normalizeLocation(location)]; ok {
			return true
		}
	}
	return false
}

func findingFieldChanges(previous, current FindingSummary) []FieldChange {
	var changes []FieldChange
	for _, field := range []struct{ name, from, to string }{
		{"status", previous.Status, current.Status},
		{"severity", previous.Severity, current.Severity},
		{"priority", previous.Priority, current.Priority},
	} {
		from, to := strings.TrimSpace(field.from), strings.TrimSpace(field.to)
		if from != to {
			changes = append(changes, FieldChange{Field: field.name, From: from, To: to})
		}
	}
	return changes
}

func findingRef(finding FindingSummary) FindingRef {
	return FindingRef{
		ID:       strings.TrimSpace(finding.ID),
		Kind:     strings.TrimSpace(finding.Kind),
		Category: strings.TrimSpace(finding.Category),
		Status:   strings.TrimSpace(finding.Status),
		Severity: strings.TrimSpace(finding.Severity),
		Priority: strings.TrimSpace(finding.Priority),
		Title:    strings.TrimSpace(finding.Title),
	}
}

// readCoverageRows returns each session's coverage rows. A session without
// coverage.yaml contributes no rows.
func readCoverageRows(workspace string) (map[string][]CoverageRow, error) {
	rows := make(map[string][]CoverageRow)
	for _, session := range coverageSessions() {
		path := coverageFilePath(workspace, session)
		if !fileExists(path) {
			continue
		}
		file, err := readCoverageFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		rows[session.ID] = file.Rows
	}
	return rows, nil
}

func diffCoverage(previousRows, currentRows map[string][]CoverageRow) CoverageDiff {
	diff := CoverageDiff{
		Added:    []CoverageRef{},
		Removed:  []CoverageRef{},
		Changed:  []CoverageChange{},
		Sessions: []SessionCoverageDiff{},
	}
	for _, session := range coverageSessions() {
		previous := sortedCoverageRows(previousRows[session.ID])
		current := sortedCoverageRows(currentRows[session.ID])
		entry := SessionCoverageDiff{ID: session.ID}
		for _, row := range previous {
			entry.Before.add(row.State)
		}
		for _, row := range current {
			entry.After.add(row.State)
		}
		diff.TotalsBefore.merge(entry.Before)
		diff.TotalsAfter.merge(entry.After)
		diff.Sessions = append(diff.Sessions, entry)

		currentByKey := make(map[string][]int)
		for j, row := range current {
			key := coverageRowKey(session.ID, row)
			currentByKey[key] = append(currentByKey[key], j)
		}
		currentMatched := make([]bool, len(current))
		for _, row := range previous {
			key := coverageRowKey(session.ID, row)
			candidates := currentByKey[key]
			if len(candidates) == 0 {
				diff.Removed = append(diff.Removed, coverageRef(session.ID, row))
				continue
			}
			j := candidates[0]
			currentByKey[key] = candidates[1:]
			currentMatched[j] = true
			match := current[j]
			from, to := strings.TrimSpace(row.State), strings.TrimSpace(match.State)
			if from == to {
				diff.Unchanged++
				continue
			}
			diff.Changed = append(diff.Changed, CoverageChange{
				Session:    session.ID,
				PreviousID: strings.TrimSpace(row.ID),
				CurrentID:  strings.TrimSpace(match.ID),
				Surface:    strings.TrimSpace(match.Surface),
				Check:      strings.TrimSpace(match.Check),
				Identity:   strings.TrimSpace(match.Identity),
				From:       from,
				To:         to,
			})
		}
		for j, row := range current {
			if !currentMatched[j] {
				diff.Added = append(diff.Added, coverageRef(session.ID, row))
			}
		}
	}
	return diff
}

func sortedCoverageRows(rows []CoverageRow) []CoverageRow {
	out := append([]CoverageRow(nil), rows...)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.TrimSpace(out[i].ID) < strings.TrimSpace(out[j].ID)
	})
	return out
}

func coverageRef(session string, row CoverageRow) CoverageRef {
	return CoverageRef{
		Session:  session,
		ID:       strings.TrimSpace(row.ID),
		Surface:  strings.TrimSpace(row.Surface),
		Check:    strings.TrimSpace(row.Check),
		Identity: strings.TrimSpace(row.Identity),
		State:    strings.TrimSpace(row.State),
	}
}

func diffStatements(previous, workspace string) (StatementDiff, error) {
	if !fileExists(statementPath(previous)) || !fileExists(statementPath(workspace)) {
		return StatementDiff{}, nil
	}
	before, err := readStatementFile(statementPath(previous))
	if err != nil {
		return StatementDiff{}, fmt.Errorf("previous workspace: %w", err)
	}
	after, err := readStatementFile(statementPath(workspace))
	if err != nil {
		return StatementDiff{}, fmt.Errorf("current workspace: %w", err)
	}
	return StatementDiff{
		Compared:              true,
		EnsphereVersionBefore: before.EnsphereVersion,
		EnsphereVersionAfter:  after.EnsphereVersion,
		AssessedByBefore:      before.System.AssessedBy,
		AssessedByAfter:       after.System.AssessedBy,
		LedgerEntriesBefore:   ledgerEntryTotal(before.Ledgers),
		LedgerEntriesAfter:    ledgerEntryTotal(after.Ledgers),
	}, nil
}

func readStatementFile(path string) (*Statement, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read statement: %w", err)
	}
	var statement Statement
	if err := decodeStrictYAML(raw, &statement); err != nil {
		return nil, fmt.Errorf("parse statement %s: %w", path, err)
	}
	return &statement, nil
}

func ledgerEntryTotal(ledgers []StatementLedger) int {
	total := 0
	for _, ledger := range ledgers {
		total += ledger.Entries
	}
	return total
}

func renderDiffMarkdown(d *DiffOutput) string {
	var b strings.Builder
	s := d.Findings.Summary
	b.WriteString("# Assessment Diff\n\n")
	b.WriteString(fmt.Sprintf("- **Current workspace**: %s\n", d.Workspace))
	b.WriteString(fmt.Sprintf("- **Previous workspace**: %s\n", d.Previous))
	b.WriteString(fmt.Sprintf("- **Findings**: %d before, %d after\n\n", s.PreviousTotal, s.CurrentTotal))

	b.WriteString("## Summary\n\n")
	b.WriteString("| Kind | Unresolved before | Unresolved after |\n")
	b.WriteString("|------|-------------------|------------------|\n")
	kinds := make([]string, 0, len(s.ByKind))
	for kind := range s.ByKind {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		entry := s.ByKind[kind]
		b.WriteString(fmt.Sprintf("| %s | %d | %d |\n", escapeMarkdownCell(kind), entry.UnresolvedBefore, entry.UnresolvedAfter))
	}
	b.WriteString(fmt.Sprintf("| **Total** | %d | %d |\n\n", s.UnresolvedBefore, s.UnresolvedAfter))
	b.WriteString("| New | Gone | New unresolved | Gone unresolved | Reopened | Resolved |\n")
	b.WriteString("|-----|------|----------------|-----------------|----------|----------|\n")
	b.WriteString(fmt.Sprintf("| %d | %d | %d | %d | %d | %d |\n\n", len(d.Findings.New), len(d.Findings.Gone), s.NewUnresolved, s.GoneUnresolved, s.Reopened, s.Resolved))

	writeFindingRefTable(&b, "New findings", d.Findings.New)
	writeFindingRefTable(&b, "Gone findings", d.Findings.Gone)

	b.WriteString("## Changed findings\n\n")
	if len(d.Findings.Changed) == 0 {
		b.WriteString("None.\n\n")
	} else {
		b.WriteString("| Previous | Current | Matched by | Changes | Title |\n")
		b.WriteString("|----------|---------|------------|---------|-------|\n")
		for _, change := range d.Findings.Changed {
			var parts []string
			for _, field := range change.Changes {
				parts = append(parts, fmt.Sprintf("%s: %s -> %s", field.Field, field.From, field.To))
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", change.PreviousID, change.CurrentID, change.MatchedBy, escapeMarkdownCell(strings.Join(parts, "; ")), escapeMarkdownCell(change.Title)))
		}
		b.WriteString("\n")
	}

	c := d.Coverage
	b.WriteString("## Coverage\n\n")
	b.WriteString(fmt.Sprintf("- **Rows added**: %d\n", len(c.Added)))
	b.WriteString(fmt.Sprintf("- **Rows removed**: %d\n", len(c.Removed)))
	b.WriteString(fmt.Sprintf("- **Rows changed**: %d\n", len(c.Changed)))
	b.WriteString(fmt.Sprintf("- **Rows unchanged**: %d\n\n", c.Unchanged))
	if len(c.Changed) > 0 {
		b.WriteString("| Session | Previous | Current | Surface | Check | Identity | From | To |\n")
		b.WriteString("|---------|----------|---------|---------|-------|----------|------|----|\n")
		for _, change := range c.Changed {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |\n", change.Session, change.PreviousID, change.CurrentID, escapeMarkdownCell(change.Surface), escapeMarkdownCell(change.Check), escapeMarkdownCell(change.Identity), change.From, change.To))
		}
		b.WriteString("\n")
	}
	b.WriteString("| Session | Tested | Not tested | Blocked | Not applicable | Planned | Total |\n")
	b.WriteString("|---------|--------|------------|---------|----------------|---------|-------|\n")
	for _, session := range c.Sessions {
		b.WriteString(fmt.Sprintf("| %s | %s |\n", session.ID, coverageCountCells(session.Before, session.After)))
	}
	b.WriteString(fmt.Sprintf("| **Total** | %s |\n", coverageCountCells(c.TotalsBefore, c.TotalsAfter)))

	if d.Statement.Compared {
		st := d.Statement
		b.WriteString("\n## Statement\n\n")
		b.WriteString(fmt.Sprintf("- **Ensphere version**: %s -> %s\n", orNone(st.EnsphereVersionBefore, "unknown"), orNone(st.EnsphereVersionAfter, "unknown")))
		b.WriteString(fmt.Sprintf("- **Assessed by**: %s -> %s\n", orNone(st.AssessedByBefore, "not recorded"), orNone(st.AssessedByAfter, "not recorded")))
		b.WriteString(fmt.Sprintf("- **Ledger entries**: %d -> %d\n", st.LedgerEntriesBefore, st.LedgerEntriesAfter))
	}
	return b.String()
}

func writeFindingRefTable(b *strings.Builder, heading string, refs []FindingRef) {
	b.WriteString("## " + heading + "\n\n")
	if len(refs) == 0 {
		b.WriteString("None.\n\n")
		return
	}
	b.WriteString("| ID | Kind | Category | Status | Severity | Priority | Title |\n")
	b.WriteString("|----|------|----------|--------|----------|----------|-------|\n")
	for _, ref := range refs {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n", ref.ID, ref.Kind, ref.Category, ref.Status, ref.Severity, ref.Priority, escapeMarkdownCell(ref.Title)))
	}
	b.WriteString("\n")
}

func coverageCountCells(before, after CoverageCounts) string {
	pairs := [][2]int{
		{before.Tested, after.Tested},
		{before.NotTested, after.NotTested},
		{before.Blocked, after.Blocked},
		{before.NotApplicable, after.NotApplicable},
		{before.Planned, after.Planned},
		{before.Total, after.Total},
	}
	cells := make([]string, len(pairs))
	for i, pair := range pairs {
		cells[i] = fmt.Sprintf("%d -> %d", pair[0], pair[1])
	}
	return strings.Join(cells, " | ")
}
