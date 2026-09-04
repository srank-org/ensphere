package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/evidence"
)

var evidVerifyFile string

var evidenceVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify evidence chain integrity",
	Long: `Verify the hash chain integrity of an evidence JSONL file.

Each entry's hash is recomputed and checked against the stored hash.
The chain link (prev_hash -> previous entry's hash) is also validated.

Exit codes:
  0  Chain is valid
  1  Chain is broken (tampered or corrupted)

Examples:
  ensphere evidence verify --file ./evidence.jsonl
  ensphere evidence verify --file ./ensphere-pentest/02-injection/evidence.jsonl`,
	RunE: runEvidenceVerify,
}

func init() {
	evidenceVerifyCmd.Flags().StringVar(&evidVerifyFile, "file", "./evidence.jsonl", "Evidence file path")
	evidenceCmd.AddCommand(evidenceVerifyCmd)
}

func runEvidenceVerify(cmd *cobra.Command, args []string) error {
	result, err := evidence.VerifyChain(evidVerifyFile)
	if err != nil {
		return fmt.Errorf("verify chain: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}

	if !result.Valid {
		os.Exit(1)
	}
	return nil
}
