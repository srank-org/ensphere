package guard

import (
	"os"

	"github.com/srank-org/ensphere/internal/runner"
)

// CommandGuard returns the classifier `invariants run` applies to a command
// invariant's substituted shell string while an assessment workspace exists
// under sourcePath: the reason to refuse it, or "" to let it run. It is nil
// when no workspace is found or ENSPHERE_GUARD is off, and then commands run
// as written, as they do in CI.
func CommandGuard(sourcePath string, getenv func(string) string) func(run string) string {
	if getenv("ENSPHERE_GUARD") == "off" {
		return nil
	}
	workspace, ok := runner.FindWorkspace(sourcePath, getenv)
	if !ok {
		return nil
	}
	var approved []string
	if raw, err := os.ReadFile(runner.ConfigPath(workspace)); err == nil {
		approved = runner.SandboxCommands(string(raw))
	}
	return func(run string) string {
		if decision := Decide(run, approved); decision.Verdict == VerdictDeny {
			return decision.Reason
		}
		return ""
	}
}
