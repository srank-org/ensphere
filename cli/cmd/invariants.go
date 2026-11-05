package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/guard"
	"github.com/srank-org/ensphere/internal/invariants"
	"github.com/srank-org/ensphere/internal/runner"
	"github.com/srank-org/ensphere/internal/sysmap"
)

var (
	invDir        string
	invSourcePath string
	invMap        string
	invTarget     string
	invInScope    []string
	invOnly       []string
	invMaxRisk    int
	invThrottle   int
	invTimeout    int
	invHeaders    []string
	invOut        string
	invSince      string
)

var invariantsCmd = &cobra.Command{
	Use:   "invariants",
	Short: "Validate and run the invariants an assessment left in the repository",
	Long: `Invariants are deterministic expectations written down after an assessment:
the validation criteria of a finding, or a tested defense that held. They live
one per file in <source-path>/.ensphere/invariants/*.yaml and run in the
target's own CI with no agent.

A pass records that the declared expectation held on that run and nothing
more. CI fails only on an enforced invariant that did not hold, or on an
invariant that could not be run.`,
}

var invariantsValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Check invariant files against the schema",
	Long: `Load every *.yaml and *.yml file in the invariant directory and check it
against the schema. When --map is given, or <source-path>/.ensphere/surfaces.yaml
exists, each surface an invariant names must be in that map.

Exit codes: 0 valid, 1 error issues, 3 the directory cannot be read.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := invariantDir()
		invs, issues, err := loadAndValidateInvariants(dir)
		if err != nil {
			return exitRunError(err)
		}
		if err := encodeJSON(validateOutput(dir, invs, issues)); err != nil {
			return exitRunError(fmt.Errorf("encode output: %w", err))
		}
		if invariants.HasErrors(issues) {
			osExit(1)
		}
		return nil
	},
}

var invariantsRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the invariants against a target and the source tree",
	Long: `Validate the invariants, then run them in file order: http, rate_limit, and
size_limit kinds against --target (joined to request.path), source kinds over
--source-path, command kinds with sh -c in --source-path. ${VAR} references in
request fields, run, and expect strings come from the environment; an unset
variable makes that invariant's result error. No evidence ledger is written.

Exit codes: 0 when no enforced invariant failed and none errored, 1 otherwise
or when validation fails, 2 usage or scope errors, 3 runtime failures.

Example:
  ensphere invariants run --target http://localhost:3000 --in-scope localhost --out invariants-report.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(invInScope) == 0 {
			return exitRunError(fmt.Errorf("%w: --in-scope is required", errUsage))
		}
		headers := mustParseHeaders(invHeaders)
		mustBeWorkspaceScope(invInScope)
		if invTarget != "" {
			if parsed, err := url.Parse(invTarget); err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
				return exitRunError(fmt.Errorf("%w: --target %q must be an http or https base URL", errUsage, invTarget))
			}
		}

		dir := invariantDir()
		invs, issues, err := loadAndValidateInvariants(dir)
		if err != nil {
			return exitRunError(err)
		}
		if invariants.HasErrors(issues) {
			if err := encodeJSON(validateOutput(dir, invs, issues)); err != nil {
				return exitRunError(fmt.Errorf("encode output: %w", err))
			}
			osExit(1)
			return nil
		}
		if unknown := invariants.UnknownIDs(invs, invOnly); len(unknown) > 0 {
			return exitRunError(fmt.Errorf("%w: --only names unknown invariants: %s", errUsage, strings.Join(unknown, ", ")))
		}
		var changedSurfaces []string
		if invSince != "" {
			ids, err := changedSurfaceIDs(invSourcePath, invMap, invSince)
			if err != nil {
				return exitRunError(err)
			}
			changedSurfaces = ids
		}

		report := invariants.Run(invs, invariants.RunConfig{
			Target:          invTarget,
			SourcePath:      invSourcePath,
			Scope:           invInScope,
			MaxRisk:         invMaxRisk,
			ThrottleMs:      invThrottle,
			TimeoutSec:      invTimeout,
			Headers:         headers,
			Only:            invOnly,
			Getenv:          os.Getenv,
			Since:           invSince,
			ChangedSurfaces: changedSurfaces,
			Guard:           guard.CommandGuard(invSourcePath, os.Getenv),
		})
		if invOut != "" {
			raw, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return exitRunError(fmt.Errorf("encode report: %w", err))
			}
			if err := os.WriteFile(invOut, append(raw, '\n'), 0o644); err != nil {
				return exitRunError(fmt.Errorf("write report: %w", err))
			}
		}
		if err := encodeJSON(report); err != nil {
			return exitRunError(fmt.Errorf("encode output: %w", err))
		}
		if !report.Passed() {
			osExit(1)
		}
		return nil
	},
}

type invariantsValidateOutput struct {
	Dir        string             `json:"dir"`
	Invariants int                `json:"invariants"`
	Valid      bool               `json:"valid"`
	Issues     []invariants.Issue `json:"issues"`
}

func validateOutput(dir string, invs []invariants.Invariant, issues []invariants.Issue) invariantsValidateOutput {
	if issues == nil {
		issues = []invariants.Issue{}
	}
	return invariantsValidateOutput{Dir: dir, Invariants: len(invs), Valid: !invariants.HasErrors(issues), Issues: issues}
}

func invariantDir() string {
	if invDir != "" {
		return invDir
	}
	return filepath.Join(invSourcePath, invariants.DefaultDir)
}

func loadAndValidateInvariants(dir string) ([]invariants.Invariant, []invariants.Issue, error) {
	invs, loadIssues, err := invariants.Load(dir)
	if err != nil {
		return nil, nil, err
	}
	surfaces, err := invariants.ResolveSurfaces(invSourcePath, invMap)
	if err != nil {
		return nil, nil, err
	}
	issues := append(loadIssues, invariants.Validate(invs, invSourcePath, surfaces)...)
	return invs, issues, nil
}

func init() {
	for _, c := range []*cobra.Command{invariantsValidateCmd, invariantsRunCmd} {
		c.Flags().StringVar(&invDir, "dir", "", "Invariant directory (default <source-path>/.ensphere/invariants)")
		c.Flags().StringVar(&invSourcePath, "source-path", ".", "Path to the source tree the invariants belong to")
		c.Flags().StringVar(&invMap, "map", "", "System map whose surface ids invariants may name (default <source-path>/.ensphere/surfaces.yaml when it exists)")
	}

	invariantsRunCmd.Flags().StringVar(&invTarget, "target", "", "Base URL of the live target (a sandbox or staging) for http, rate_limit, and size_limit invariants")
	invariantsRunCmd.Flags().StringSliceVar(&invInScope, "in-scope", nil, "In-scope patterns: globs (*.example.com) or CIDR (10.0.0.0/8) (required)")
	invariantsRunCmd.Flags().StringSliceVar(&invOnly, "only", nil, "Run only these invariant ids (comma-separated)")
	invariantsRunCmd.Flags().IntVar(&invMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	invariantsRunCmd.Flags().IntVar(&invThrottle, "throttle", 500, "Milliseconds between network invariants")
	invariantsRunCmd.Flags().IntVar(&invTimeout, "timeout", 10, "HTTP request timeout in seconds")
	invariantsRunCmd.Flags().StringSliceVar(&invHeaders, "header", nil, "Header added to every request (key:value, repeatable)")
	invariantsRunCmd.Flags().StringVar(&invOut, "out", "", "Also write the report JSON to this file")
	invariantsRunCmd.Flags().StringVar(&invSince, "since", "", "Git commit or ref to compare the working tree with, as ensphere map changed does; each result then says whether its surface changed (needs the system map)")

	invariantsCmd.AddCommand(invariantsValidateCmd, invariantsRunCmd)
	rootCmd.AddCommand(invariantsCmd)
}

// changedSurfaceIDs joins the working tree's changes since a ref to the
// system map, as ensphere map changed does, and returns the changed surface
// ids. Without a valid map the ref cannot be interpreted, which is a usage
// error.
func changedSurfaceIDs(sourcePath, mapPath, since string) ([]string, error) {
	if mapPath == "" {
		mapPath = sysmap.Path(sourcePath)
	}
	if _, err := os.Stat(mapPath); err != nil {
		return nil, fmt.Errorf("%w: --since needs the system map at %s", errUsage, mapPath)
	}
	validation, m, err := sysmap.ValidateFile(mapPath, sourcePath, runner.CheckSessionIDs())
	if err != nil {
		return nil, err
	}
	if !validation.Valid {
		return nil, fmt.Errorf("%w: the system map at %s has errors; run ensphere map validate", errUsage, mapPath)
	}
	changes, err := sysmap.Changed(m, sourcePath, since)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(changes.ChangedSurfaces))
	for _, surface := range changes.ChangedSurfaces {
		ids = append(ids, surface.ID)
	}
	return ids, nil
}
