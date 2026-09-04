package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/cloud"
	"github.com/srank-org/ensphere/internal/verify"
)

var (
	clProvider string
	clInScope  []string
	clMaxRisk  int
	clTimeout  int
	clEvidence string
)

var cloudLoggingCmd = &cobra.Command{
	Use:   "logging",
	Short: "Verify cloud logging configuration",
	Long: `Verify cloud audit logging and trail configuration.

Checks CloudTrail/GCP logging sinks/Azure diagnostic settings for
active trails, multi-region coverage, and log file validation.

Examples:
  ensphere cloud logging --provider aws --in-scope "aws://123456789012"
  ensphere cloud logging --provider gcp --in-scope "gcp://my-project"
  ensphere cloud logging --provider azure --in-scope "azure://sub-id"`,
	RunE: runCloudLogging,
}

func init() {
	cloudLoggingCmd.Flags().StringVar(&clProvider, "provider", "", "Cloud provider: aws, gcp, azure (required)")
	cloudLoggingCmd.Flags().StringSliceVar(&clInScope, "in-scope", nil, "In-scope patterns (required)")
	cloudLoggingCmd.Flags().IntVar(&clMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	cloudLoggingCmd.Flags().IntVar(&clTimeout, "timeout", 30, "CLI command timeout in seconds")
	cloudLoggingCmd.Flags().StringVar(&clEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = cloudLoggingCmd.MarkFlagRequired("provider")
	_ = cloudLoggingCmd.MarkFlagRequired("in-scope")

	cloudCmd.AddCommand(cloudLoggingCmd)
}

func runCloudLogging(cmd *cobra.Command, args []string) error {
	accountID := extractAccountID(clInScope, clProvider)

	cfg := cloud.LoggingConfig{
		Provider:  clProvider,
		AccountID: accountID,
		ProbeConfig: verify.ProbeConfig{
			InScope:    clInScope,
			MaxRisk:    clMaxRisk,
			TimeoutSec: clTimeout,
			Evidence:   clEvidence,
		},
	}

	result, err := cloud.VerifyCloudLogging(cfg)
	if err != nil {
		var scopeErr *verify.ScopeError
		if errors.As(err, &scopeErr) {
			fmt.Fprintf(os.Stderr, "scope error: %s\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "probe error: %s\n", err)
		os.Exit(3)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		os.Exit(3)
	}
	return nil
}
