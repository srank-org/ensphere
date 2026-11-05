package runner

import (
	"testing"
)

func TestRunReportDescribesOneCommit(t *testing.T) {
	workspace := writeStatementReadyWorkspace(t)
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if !gate.Ready || !hasIssue(gate.Issues, "source_not_git") {
		t.Fatalf("a source path outside git is a warning, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}

	source, head := committedSource(t)
	setSourcePath(t, workspace, source)
	promoteRegistryFindings(t, workspace)
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if !gate.Ready || hasIssue(gate.Issues, "source_not_git") || hasIssue(gate.Issues, "source_tree_modified") {
		t.Fatalf("a clean checkout passes; Ensphere's own untracked files do not count, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
	statement, err := BuildStatement(workspace, "0.2.0", gate.Coverage)
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	if statement.System.SourceCommit != head {
		t.Fatalf("statement must name the source commit %s, got %q", head, statement.System.SourceCommit)
	}
	if md := renderStatementMarkdown(statement); !contains(md, "- **Source commit**: "+head) {
		t.Fatalf("statement.md must print the commit:\n%s", md)
	}

	writeSourceFile(t, source, "routes/new.ts", "untracked\n")
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if !gate.Ready || !hasIssue(gate.Issues, "source_tree_untracked") {
		t.Fatalf("an untracked file is a warning, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}

	writeSourceFile(t, source, "routes/otp.ts", "changed during the run\n")
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "source_tree_modified") {
		t.Fatalf("a tracked file changed since the commit must block the report, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
	for _, issue := range gate.Issues {
		if issue.Code == "source_tree_modified" && !contains(issue.Message, "routes/otp.ts") {
			t.Fatalf("the issue must name the file: %+v", issue)
		}
	}
	if _, err := RunStatement(workspace, "0.2.0"); err == nil {
		t.Fatal("run statement must refuse while the tree is modified")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
