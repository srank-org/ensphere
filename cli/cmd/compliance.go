package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/srank-org/ensphere/internal/compliance"
)

var complianceList bool

var complianceCmd = &cobra.Command{
	Use:   "compliance [vuln_type]",
	Short: "Compliance framework mappings for vulnerability types",
	Long: `Map vulnerability types to compliance framework controls.

Frameworks: OWASP Top 10 2025, OWASP API Security Top 10 2023, PCI-DSS v4.0.1, SOC 2, ISO 27001

Examples:
  ensphere compliance sqli       # compliance mappings for SQL injection
  ensphere compliance xss        # compliance mappings for XSS
  ensphere compliance --list     # list all vuln_types with framework counts`,
	Args: cobra.MaximumNArgs(1),
	RunE: runCompliance,
}

func init() {
	complianceCmd.Flags().BoolVar(&complianceList, "list", false, "List all vuln_types with framework counts")
	rootCmd.AddCommand(complianceCmd)
}

func runCompliance(cmd *cobra.Command, args []string) error {
	if complianceList {
		output, err := compliance.ListMappings()
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(output)
	}

	if len(args) == 0 {
		names := compliance.ValidVulnTypes()
		fmt.Fprintf(os.Stderr, "Available vuln_types:\n")
		for _, name := range names {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
		fmt.Fprintf(os.Stderr, "\nUse 'ensphere compliance <vuln_type>' or '--list' for JSON.\n")
		return nil
	}

	vulnType := args[0]
	mapping, err := compliance.GetMapping(vulnType)
	if err != nil {
		names := compliance.ValidVulnTypes()
		return fmt.Errorf("no mappings for %q — available: %s", vulnType, strings.Join(names, ", "))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(mapping)
}
