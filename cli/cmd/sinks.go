package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/srank-org/ensphere/internal/sinks"
)

var sinksCmd = &cobra.Command{
	Use:   "sinks [category]",
	Short: "Code sink patterns for vulnerability scanning",
	Long: `List dangerous code patterns (sinks) by vulnerability category.

Categories: cmdi, cors, csrf, deserialization, file_upload, header_injection, idor, jwt, ldap, lfi, nosql, redirect, sqli, ssrf, ssti, xpath, xss, xxe

Examples:
  ensphere sinks              # list all categories with pattern counts
  ensphere sinks sqli         # sink patterns for SQL injection
  ensphere sinks xss          # sink patterns for XSS`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSinks,
}

func init() {
	rootCmd.AddCommand(sinksCmd)
}

func runSinks(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		output, err := sinks.ListCategories()
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(output)
	}

	name := args[0]
	cat, err := sinks.GetCategory(name)
	if err != nil {
		names := sinks.CategoryNames()
		return fmt.Errorf("unknown category %q — valid: %s", name, strings.Join(names, ", "))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(cat)
}
