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
	ccProvider string
	ccRegion   string
	ccInScope  []string
	ccMaxRisk  int
	ccTimeout  int
	ccEvidence string
)

var cloudComputeCmd = &cobra.Command{
	Use:   "compute",
	Short: "Verify cloud compute security",
	Long: `Verify cloud serverless and compute resource security configuration.

Checks Lambda/Cloud Functions/Azure Functions for public exposure,
VPC attachment, and environment variable secret patterns.

Examples:
  ensphere cloud compute --provider aws --in-scope "aws://123456789012"
  ensphere cloud compute --provider gcp --in-scope "gcp://my-project"
  ensphere cloud compute --provider azure --in-scope "azure://sub-id"`,
	RunE: runCloudCompute,
}

func init() {
	cloudComputeCmd.Flags().StringVar(&ccProvider, "provider", "", "Cloud provider: aws, gcp, azure (required)")
	cloudComputeCmd.Flags().StringVar(&ccRegion, "region", "", "Cloud region (optional)")
	cloudComputeCmd.Flags().StringSliceVar(&ccInScope, "in-scope", nil, "In-scope patterns (required)")
	cloudComputeCmd.Flags().IntVar(&ccMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	cloudComputeCmd.Flags().IntVar(&ccTimeout, "timeout", 30, "CLI command timeout in seconds")
	cloudComputeCmd.Flags().StringVar(&ccEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = cloudComputeCmd.MarkFlagRequired("provider")
	_ = cloudComputeCmd.MarkFlagRequired("in-scope")

	cloudCmd.AddCommand(cloudComputeCmd)
}

func runCloudCompute(cmd *cobra.Command, args []string) error {
	accountID := extractAccountID(ccInScope, ccProvider)

	cfg := cloud.ComputeConfig{
		Provider:  ccProvider,
		AccountID: accountID,
		Region:    ccRegion,
		ProbeConfig: verify.ProbeConfig{
			InScope:    ccInScope,
			MaxRisk:    ccMaxRisk,
			TimeoutSec: ccTimeout,
			Evidence:   ccEvidence,
		},
	}

	result, err := cloud.VerifyCloudCompute(cfg)
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
