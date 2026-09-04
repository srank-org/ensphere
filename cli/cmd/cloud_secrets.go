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
	cseProvider string
	cseInScope  []string
	cseMaxRisk  int
	cseTimeout  int
	cseEvidence string
)

var cloudSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Verify cloud secrets management",
	Long: `Verify cloud secrets management configuration.

Checks AWS Secrets Manager/GCP Secret Manager/Azure Key Vault for
rotation settings, KMS usage, and secret inventory.

Examples:
  ensphere cloud secrets --provider aws --in-scope "aws://123456789012"
  ensphere cloud secrets --provider gcp --in-scope "gcp://my-project"
  ensphere cloud secrets --provider azure --in-scope "azure://sub-id"`,
	RunE: runCloudSecrets,
}

func init() {
	cloudSecretsCmd.Flags().StringVar(&cseProvider, "provider", "", "Cloud provider: aws, gcp, azure (required)")
	cloudSecretsCmd.Flags().StringSliceVar(&cseInScope, "in-scope", nil, "In-scope patterns (required)")
	cloudSecretsCmd.Flags().IntVar(&cseMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	cloudSecretsCmd.Flags().IntVar(&cseTimeout, "timeout", 30, "CLI command timeout in seconds")
	cloudSecretsCmd.Flags().StringVar(&cseEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = cloudSecretsCmd.MarkFlagRequired("provider")
	_ = cloudSecretsCmd.MarkFlagRequired("in-scope")

	cloudCmd.AddCommand(cloudSecretsCmd)
}

func runCloudSecrets(cmd *cobra.Command, args []string) error {
	accountID := extractAccountID(cseInScope, cseProvider)

	cfg := cloud.SecretsConfig{
		Provider:  cseProvider,
		AccountID: accountID,
		ProbeConfig: verify.ProbeConfig{
			InScope:    cseInScope,
			MaxRisk:    cseMaxRisk,
			TimeoutSec: cseTimeout,
			Evidence:   cseEvidence,
		},
	}

	result, err := cloud.VerifyCloudSecrets(cfg)
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
