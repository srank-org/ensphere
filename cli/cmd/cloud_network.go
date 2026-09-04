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
	cnProvider string
	cnVPCID    string
	cnInScope  []string
	cnMaxRisk  int
	cnTimeout  int
	cnEvidence string
)

var cloudNetworkCmd = &cobra.Command{
	Use:   "network",
	Short: "Verify cloud network security",
	Long: `Verify cloud network security configuration.

Checks security groups for open ingress, flow logs, and public IP allocations.

Examples:
  ensphere cloud network --provider aws --in-scope "aws://123456789012"
  ensphere cloud network --provider aws --vpc-id vpc-abc123 --in-scope "aws://123456789012"`,
	RunE: runCloudNetwork,
}

func init() {
	cloudNetworkCmd.Flags().StringVar(&cnProvider, "provider", "", "Cloud provider: aws, gcp, azure (required)")
	cloudNetworkCmd.Flags().StringVar(&cnVPCID, "vpc-id", "", "VPC ID (optional, scan all if empty)")
	cloudNetworkCmd.Flags().StringSliceVar(&cnInScope, "in-scope", nil, "In-scope patterns (required)")
	cloudNetworkCmd.Flags().IntVar(&cnMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	cloudNetworkCmd.Flags().IntVar(&cnTimeout, "timeout", 30, "CLI command timeout in seconds")
	cloudNetworkCmd.Flags().StringVar(&cnEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = cloudNetworkCmd.MarkFlagRequired("provider")
	_ = cloudNetworkCmd.MarkFlagRequired("in-scope")

	cloudCmd.AddCommand(cloudNetworkCmd)
}

func runCloudNetwork(cmd *cobra.Command, args []string) error {
	accountID := extractAccountID(cnInScope, cnProvider)

	cfg := cloud.NetworkConfig{
		Provider:  cnProvider,
		VPCID:     cnVPCID,
		AccountID: accountID,
		ProbeConfig: verify.ProbeConfig{
			InScope:    cnInScope,
			MaxRisk:    cnMaxRisk,
			TimeoutSec: cnTimeout,
			Evidence:   cnEvidence,
		},
	}

	result, err := cloud.VerifyCloudNetwork(cfg)
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
