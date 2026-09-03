package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/scan"
	"github.com/srank/ensphere/internal/sinks"
)

var (
	scanCategories   []string
	scanExtensions   []string
	scanExcludes     []string
	scanExitZero     bool
	scanAbsenceCheck bool
	scanContextLines int
)

var scanCmd = &cobra.Command{
	Use:   "scan [directory]",
	Short: "Scan source code for review-candidate pattern matches",
	Long: `Scan a directory for deterministic source pattern matches that require analyst review.

Uses the built-in pattern database to locate function calls, SQL construction,
command execution, and other review candidates. Matches are not findings.

Examples:
  ensphere scan ./src                          # scan all categories
  ensphere scan ./src --category sqli,xss      # filter by category
  ensphere scan ./src --exclude "test/**"      # exclude patterns
  ensphere scan ./src --context-lines 0        # omit surrounding context`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringSliceVar(&scanCategories, "category", nil, "Filter by sink category (repeatable)")
	scanCmd.Flags().StringSliceVar(&scanExtensions, "extensions", nil, "Override file extensions to scan (repeatable)")
	scanCmd.Flags().StringSliceVar(&scanExcludes, "exclude", nil, "Additional glob patterns to exclude (repeatable)")
	scanCmd.Flags().BoolVar(&scanExitZero, "exit-zero", false, "Always exit 0, even when matches are found")
	scanCmd.Flags().BoolVar(&scanAbsenceCheck, "absence-check", false, "Enable IaC absence detection (missing security config)")
	scanCmd.Flags().IntVar(&scanContextLines, "context-lines", 2, "Context lines before/after each match (0-5)")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	dir := args[0]

	if len(scanCategories) > 0 {
		validNames := sinks.CategoryNames()
		validSet := make(map[string]bool)
		for _, n := range validNames {
			validSet[n] = true
		}
		for _, c := range scanCategories {
			if !validSet[c] {
				return fmt.Errorf("invalid category %q — valid: %s", c, fmt.Sprintf("%v", validNames))
			}
		}
	}

	cfg := scan.ScanConfig{
		Directory:    dir,
		Categories:   scanCategories,
		Extensions:   scanExtensions,
		Excludes:     scanExcludes,
		AbsenceCheck: scanAbsenceCheck,
		ContextLines: scanContextLines,
	}

	result, err := scan.RunScan(cfg)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}

	if !scanExitZero && result.TotalMatches > 0 {
		os.Exit(1)
	}
	return nil
}
