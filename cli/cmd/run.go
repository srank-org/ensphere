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
	runSandboxStart        string
	runSandboxSeed         string
	runSandboxReset        string
	runDeltaSince          string
	runPlanForce           bool
	runDiffPrevious        string
	runDoctorPluginVersion string
	runDoctorTimeout       int
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
			SandboxStart:        runSandboxStart,
			SandboxSeed:         runSandboxSeed,
			SandboxReset:        runSandboxReset,
			DeltaSince:          runDeltaSince,
		})
		if errors.Is(err, runner.ErrInvalidScope) {
			return exitRunError(fmt.Errorf("%w: %v", errUsage, err))
		}
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
	Long: `Derive 09-report/statement.yaml, statement.md, and statement.json from the
workspace: config, progress, plan decisions, coverage counts, finding counts,
and evidence ledger hashes. Nothing is typed by the caller. statement.json is
the predicate a CI provenance attestation signs. The command refuses to run
until ensphere run report is ready, and the report gate fails with
statement_stale, statement_edited, or statement_json_missing if the workspace,
the markdown, or the JSON changes afterwards.`,
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

var runDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare this workspace with a previous assessment",
	Long: `Compare this workspace's finding registry, coverage files, and statement with
a previous assessment's workspace and write 09-report/diff.json and diff.md.

Findings match by kind, category, and normalized title, then by kind,
category, and a shared affected location with line numbers ignored. The diff
reports what changed between the two registries and coverage sets and assigns
nothing: it exits 0 whenever both inputs parse, and the release pipeline
decides which changes fail the build.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(runDiffPrevious) == "" {
			return exitRunError(fmt.Errorf("%w: --previous is required", errUsage))
		}
		out, err := runner.RunDiff(runWorkspace, runDiffPrevious)
		if errors.Is(err, runner.ErrPreviousNotDirectory) {
			return exitRunError(fmt.Errorf("%w: --previous: %v", errUsage, err))
		}
		if err != nil {
			return exitRunError(err)
		}
		return encodeRunJSON(out)
	},
}

var runSarifCmd = &cobra.Command{
	Use:   "sarif",
	Short: "Export the finding registry as SARIF 2.1.0",
	Long: `Write 09-report/findings.sarif from the finding registry for upload to code
scanning. Only confirmed, likely, and informational findings become results.
The SARIF level translates the analyst's severity (critical and high to error,
medium to warning, anything else to note); nothing is assigned.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.RunSARIF(runWorkspace, version)
		if err != nil {
			return exitRunError(err)
		}
		return encodeRunJSON(out)
	},
}

var runDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check that an assessment can run here, read-only",
	Long: `Run every readiness check once and report each one: the binary against the
plugin version, the workspace, the source tree's git state, the system map and
invariants when present, one GET to the configured target inside the approved
scope, the sandbox commands, the provider CLIs the cloud scope needs, and the
evidence chain of every ledger. Nothing is written. Each check is ok, warning,
error, or skipped; the output describes the tooling, never the system.

Without a workspace the binary, source, map, and invariants are still checked
from the current directory. --plugin-version defaults to the version in
$CLAUDE_PLUGIN_ROOT/.claude-plugin/plugin.json when the plugin runs the command.

Exit 0 when no check is an error, 1 otherwise.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		pluginVersion := runDoctorPluginVersion
		if pluginVersion == "" {
			pluginVersion = runner.PluginVersion(os.Getenv("CLAUDE_PLUGIN_ROOT"))
		}
		out := runner.RunDoctor(runner.DoctorConfig{
			Workspace:     runWorkspace,
			BinaryVersion: version,
			PluginVersion: pluginVersion,
			TimeoutSec:    runDoctorTimeout,
		})
		if err := encodeRunJSON(out); err != nil {
			return err
		}
		if !out.Ready {
			osExit(1)
		}
		return nil
	},
}

// exitRunError exits 2 for a usage error and 3 for a runtime failure, so a
// release pipeline can tell a bad invocation from an unreadable workspace.
func exitRunError(err error) error {
	if errors.Is(err, errUsage) {
		writeVerifyError(err)
	} else {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	osExit(exitForVerifyError(err))
	return nil
}

func init() {
	runCmd.PersistentFlags().StringVar(&runWorkspace, "workspace", runner.DefaultWorkspace(), "Ensphere workspace directory")

	runInitCmd.Flags().StringVar(&runTarget, "target", "", "Base URL of the live target (a sandbox or staging). Omit for a source-only assessment")
	runInitCmd.Flags().StringVar(&runSourcePath, "source-path", ".", "Path to the source tree under assessment")
	runInitCmd.Flags().StringVar(&runTargetType, "target-type", "auto", "Target type: auto, web_app, api_backend, static_site, mobile_client_remote_backend, mobile_client_offline, desktop_or_extension_client, cloud_only, or library_or_cli")
	runInitCmd.Flags().StringVar(&runEnvironment, "environment", "", "Environment tier of the live target: sandbox, staging, or none (default: sandbox when --target is set, none otherwise)")
	runInitCmd.Flags().StringVar(&runCloud, "cloud", "none", "Platform scope: none, aws, gcp, azure, kubernetes, cloudflare, supabase, or comma-separated")
	runInitCmd.Flags().StringVar(&runInScope, "in-scope", "", "Comma-separated host patterns every verify command must stay within: hostnames, globs (*.example.com), IPs, or CIDRs (default: the --target host; empty for a source-only assessment)")
	runInitCmd.Flags().StringVar(&runOutOfScope, "out-of-scope", "", "Out-of-scope boundary summary")
	runInitCmd.Flags().StringVar(&runLoginURL, "login-url", "", "Login URL")
	runInitCmd.Flags().StringVar(&runUsername, "username", "", "Test username")
	runInitCmd.Flags().StringVar(&runPassword, "password", "", "Test password")
	runInitCmd.Flags().StringVar(&runApprovedBursts, "approved-bursts", "", "Operator-approved rate-limit bursts, e.g. \"POST /api/otp: 10/10s\"")
	runInitCmd.Flags().StringVar(&runApprovedUploadSizes, "approved-upload-sizes", "", "Operator-approved upload sizes in bytes for Session 08.5")
	runInitCmd.Flags().StringVar(&runAssessedBy, "assessed-by", "", "Model or person performing the assessment, e.g. \"Claude Fable 5.1 via Claude Code\"")
	runInitCmd.Flags().StringVar(&runOperator, "operator", "", "Person who authorizes the assessment and signs the statement")
	runInitCmd.Flags().StringVar(&runSandboxStart, "sandbox-start", "", "Exact command that starts the disposable sandbox; writing it under ## Sandbox in config.md is the operator's approval to run it")
	runInitCmd.Flags().StringVar(&runSandboxSeed, "sandbox-seed", "", "Exact command that loads the sandbox's synthetic fixtures; writing it under ## Sandbox in config.md is the operator's approval to run it")
	runInitCmd.Flags().StringVar(&runSandboxReset, "sandbox-reset", "", "Exact command that returns the sandbox to its seeded state; writing it under ## Sandbox in config.md is the operator's approval to run it")

	runInitCmd.Flags().StringVar(&runDeltaSince, "delta-since", "", "Git commit of the previous assessment; run plan drafts sessions no changed surface in <source-path>/.ensphere/surfaces.yaml owns as skip")

	runPlanCmd.Flags().BoolVar(&runPlanForce, "force", false, "Overwrite an existing assessment-plan.yaml from config")
	runDiffCmd.Flags().StringVar(&runDiffPrevious, "previous", "", "Workspace directory of the previous assessment (required)")
	runDoctorCmd.Flags().StringVar(&runDoctorPluginVersion, "plugin-version", "", "Version of the installed Ensphere plugin to compare the binary with (default: read from $CLAUDE_PLUGIN_ROOT)")
	runDoctorCmd.Flags().IntVar(&runDoctorTimeout, "timeout", 10, "Seconds to wait for the target to answer")

	runCmd.AddCommand(runInitCmd, runStatusCmd, runNextCmd, runPlanCmd, runReportCmd, runStatementCmd, runDiffCmd, runSarifCmd, runDoctorCmd)
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
