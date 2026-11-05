package runner

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/srank-org/ensphere/internal/sysmap"
)

// readSourceState asks git about the configured source tree, leaving out
// Ensphere's own files and the workspace when it sits inside the tree.
func readSourceState(workspace string, cfg InitConfig) (*sysmap.SourceState, error) {
	var exclude []string
	if rel, err := filepath.Rel(cfg.SourcePath, workspace); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		exclude = append(exclude, filepath.ToSlash(rel))
	}
	state, err := sysmap.ReadSourceState(cfg.SourcePath, exclude...)
	if err != nil {
		return nil, fmt.Errorf("read source state: %w", err)
	}
	return state, nil
}

// validateSourceTree enforces that an assessment describes one commit. A
// tracked file that differs from HEAD, outside .ensphere/ and the workspace,
// blocks the report: the agent does not change the system it is assessing.
// Untracked files and a source path outside git are warnings the report
// states as limitations.
func validateSourceTree(workspace string) []ReportGateIssue {
	cfg, err := readConfig(workspace)
	if err != nil {
		return nil // validateWorkspaceSystemMap reports the config failure
	}
	state, err := readSourceState(workspace, cfg)
	if err != nil {
		return []ReportGateIssue{gateIssue("error", "source_state_failed", cfg.SourcePath, err.Error())}
	}
	if !state.Git {
		return []ReportGateIssue{gateIssue("warning", "source_not_git", cfg.SourcePath, "the source path is not in a git repository, so the statement cannot name the commit it describes")}
	}
	var issues []ReportGateIssue
	if !state.Clean() {
		issues = append(issues, gateIssue("error", "source_tree_modified", cfg.SourcePath,
			fmt.Sprintf("tracked files differ from commit %s: %s. The assessment describes one commit; commit or revert the change, then run the gate again", shortCommit(state.Commit), listPaths(state.Modified))))
	}
	if len(state.Untracked) > 0 {
		issues = append(issues, gateIssue("warning", "source_tree_untracked", cfg.SourcePath,
			fmt.Sprintf("untracked files are not part of commit %s and the statement does not describe them: %s", shortCommit(state.Commit), listPaths(state.Untracked))))
	}
	return issues
}

func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

func listPaths(paths []string) string {
	const limit = 10
	if len(paths) <= limit {
		return strings.Join(paths, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(paths[:limit], ", "), len(paths)-limit)
}
