package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/runner"
)

var (
	runWorkspace           string
	runTarget              string
	runSourcePath          string
	runTargetType          string
	runEnvironment         string
	runCloud               string
	runInScope             string
	runOutOfScope          string
	runLoginURL            string
	runUsername            string
	runPassword            string
	runApprovedBursts      string
	runApprovedUploadSizes string
	runAssessedBy          string
	runOperator            string
	runPlanForce           bool
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Orchestrate the Ensphere assessment workspace",
	Long: `Create and inspect the ensphere-pentest workspace used by AI agents.

The runner writes deterministic workspace files, next-action.md, and
agent-prompt.md for Claude Code, Codex, or another agent. It validates the
assessment plan and the Session 09 report gate. It does not execute AI
reasoning and has no exploitation command.

Source code is always in scope; a live target (a sandbox or staging) is
optional. Without --target the draft plan records environment none and limits
measurement sessions to source review.`,
}

var runInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create the ensphere-pentest workspace",
	RunE: func(cmd *cobra.Command, args []string) error {
		environment, err := parseRunEnvironment(runEnvironment)
		if err != nil {
			writeVerifyError(err)
			osExit(exitForVerifyError(err))
			return nil
		}
		out, err := runner.InitWorkspace(runner.InitConfig{
			Workspace:           runWorkspace,
			TargetURL:           runTarget,
			SourcePath:          runSourcePath,
			TargetType:          runTargetType,
			Environment:         environment,
			Cloud:               runCloud,
			InScope:             runInScope,
			OutOfScope:          runOutOfScope,
			LoginURL:            runLoginURL,
			Username:            runUsername,
			Password:            runPassword,
			ApprovedBursts:      runApprovedBursts,
			ApprovedUploadSizes: runApprovedUploadSizes,
			AssessedBy:          runAssessedBy,
			Operator:            runOperator,
		})
		if err != nil {
			return err
		}
		return encodeRunJSON(out)
	},
}

var runStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show workspace progress and the next session",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.WorkspaceStatus(runWorkspace)
		if err != nil {
			return err
		}
		return encodeRunJSON(out)
	},
}

var runNextCmd = &cobra.Command{
	Use:   "next",
	Short: "Write next-action.md and agent-prompt.md",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.WriteNextAction(runWorkspace)
		if err != nil {
			return err
		}
		return encodeRunJSON(out)
	},
}

var runPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Draft, mirror, or validate assessment-plan.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.RunPlan(runWorkspace, runPlanForce)
		if err != nil {
			return err
		}
		return encodeRunJSON(out)
	},
}

var runReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Validate Session 09 report readiness",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.RunReport(runWorkspace)
		if err != nil {
			return err
		}
		return encodeRunJSON(out)
	},
}

var runStatementCmd = &cobra.Command{
	Use:   "statement",
	Short: "Write the Statement of Assessment from the workspace",
	Long: `Derive 09-report/statement.yaml and statement.md from the workspace: config,
progress, plan decisions, coverage counts, finding counts, and evidence ledger
hashes. Nothing is typed by the caller. The command refuses to run until
ensphere run report is ready, and the report gate fails with statement_stale
or statement_edited if the workspace or the markdown changes afterwards.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.RunStatement(runWorkspace, version)
		if err != nil {
			if errors.Is(err, runner.ErrReportGateNotReady) {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				osExit(2)
				return nil
			}
			return err
		}
		return encodeRunJSON(out)
	},
}

func init() {
	runCmd.PersistentFlags().StringVar(&runWorkspace, "workspace", runner.DefaultWorkspace(), "Ensphere workspace directory")

	runInitCmd.Flags().StringVar(&runTarget, "target", "", "Base URL of the live target (a sandbox or staging). Omit for a source-only assessment")
	runInitCmd.Flags().StringVar(&runSourcePath, "source-path", ".", "Path to the source tree under assessment")
	runInitCmd.Flags().StringVar(&runTargetType, "target-type", "auto", "Target type: auto, web_app, api_backend, static_site, mobile_client_remote_backend, mobile_client_offline, desktop_or_extension_client, cloud_only, or library_or_cli")
	runInitCmd.Flags().StringVar(&runEnvironment, "environment", "", "Environment tier of the live target: sandbox, staging, or none (default: sandbox when --target is set, none otherwise)")
	runInitCmd.Flags().StringVar(&runCloud, "cloud", "none", "Platform scope: none, aws, gcp, azure, kubernetes, cloudflare, supabase, or comma-separated")
	runInitCmd.Flags().StringVar(&runInScope, "in-scope", "", "In-scope boundary summary")
	runInitCmd.Flags().StringVar(&runOutOfScope, "out-of-scope", "", "Out-of-scope boundary summary")
	runInitCmd.Flags().StringVar(&runLoginURL, "login-url", "", "Login URL")
	runInitCmd.Flags().StringVar(&runUsername, "username", "", "Test username")
	runInitCmd.Flags().StringVar(&runPassword, "password", "", "Test password")
	runInitCmd.Flags().StringVar(&runApprovedBursts, "approved-bursts", "", "Operator-approved rate-limit bursts, e.g. \"POST /api/otp: 10/10s\"")
	runInitCmd.Flags().StringVar(&runApprovedUploadSizes, "approved-upload-sizes", "", "Operator-approved upload sizes in bytes for Session 08.5")
	runInitCmd.Flags().StringVar(&runAssessedBy, "assessed-by", "", "Model or person performing the assessment, e.g. \"Claude Fable 5.1 via Claude Code\"")
	runInitCmd.Flags().StringVar(&runOperator, "operator", "", "Person who authorizes the assessment and signs the statement")

	runPlanCmd.Flags().BoolVar(&runPlanForce, "force", false, "Overwrite an existing assessment-plan.yaml from config")

	runCmd.AddCommand(runInitCmd, runStatusCmd, runNextCmd, runPlanCmd, runReportCmd, runStatementCmd)
	rootCmd.AddCommand(runCmd)
}

// parseRunEnvironment accepts an explicit --environment value. An empty value
// is left for the runner to default from whether a live target was supplied.
func parseRunEnvironment(value string) (string, error) {
	value = strings.TrimSpace(value)
	switch value {
	case "", "sandbox", "staging", "none":
		return value, nil
	default:
		return "", fmt.Errorf("%w: --environment %q must be sandbox, staging, or none", errUsage, value)
	}
}

func encodeRunJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		os.Exit(3)
	}
	return nil
}
