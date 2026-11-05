package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/guard"
	"github.com/srank-org/ensphere/internal/runner"
)

var hookPluginVersion string

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Claude Code hook handlers for an assessment workspace",
	Long: `Handlers the Ensphere plugin's Claude Code hooks call. Each has no opinion
unless an assessment workspace exists: $ENSPHERE_WORKSPACE, ./ensphere-pentest,
or $CLAUDE_PROJECT_DIR/ensphere-pentest, whichever first holds a config.md.
Both always exit 0.`,
}

var hookPreToolUseCmd = &cobra.Command{
	Use:   "pre-tool-use",
	Short: "Allow, deny, or pass on a Bash command read from PreToolUse hook JSON",
	Long: `Read one Claude Code PreToolUse hook input on stdin. For a Bash command run
while an assessment workspace exists, print allow for an ensphere command or a
command listed under ## Sandbox in config.md, deny for a raw network tool, an
interpreter given inline code, or a construct the guard cannot follow, and
nothing otherwise. ENSPHERE_GUARD=off disables the guard.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, _ := os.Getwd()
		out, err := guard.PreToolUse(os.Stdin, cwd, os.Getenv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ensphere hook: %v\n", err)
			return nil
		}
		if out == nil {
			return nil
		}
		if err := encodeJSON(out); err != nil {
			fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		}
		return nil
	},
}

var hookSessionStartCmd = &cobra.Command{
	Use:   "session-start",
	Short: "Print the workspace's next action, progress, and version check",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, _ = io.Copy(io.Discard, os.Stdin)
		cwd, _ := os.Getwd()
		workspace, ok := runner.FindWorkspace(cwd, os.Getenv)
		if !ok {
			return nil
		}
		fmt.Print(runner.SessionStartContext(workspace, version, hookPluginVersion))
		return nil
	},
}

func init() {
	hookSessionStartCmd.Flags().StringVar(&hookPluginVersion, "plugin-version", "", "Version of the Ensphere plugin that runs the hook")
	hookCmd.AddCommand(hookPreToolUseCmd, hookSessionStartCmd)
	rootCmd.AddCommand(hookCmd)
}
