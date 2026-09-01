package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

var rootCmd = &cobra.Command{
	Use:     "ensphere",
	Short:   "Deterministic measurement CLI for Ensphere security assessments",
	Long:    "Ensphere produces verifiable facts about a system you own: scoped probes, source sink scans, provider configuration reads, and a hash-chained evidence ledger. It never assigns a verdict; the analyst does.",
	Version: version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
