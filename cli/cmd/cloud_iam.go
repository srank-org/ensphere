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
	ciProvider  string
	ciPrincipal string
	ciInScope   []string
	ciMaxRisk   int
	ciTimeout   int
	ciEvidence  string
)

var cloudIAMCmd = &cobra.Command{
	Use:   "iam",
	Short: "Verify cloud IAM configuration",
	Long: `Verify cloud IAM user/role configuration for privilege escalation risks.

Checks attached policies, inline policies, MFA status, and dangerous permission combinations.

Examples:
  ensphere cloud iam --provider aws --principal arn:aws:iam::123:user/alice --in-scope "aws://123456789012"
  ensphere cloud iam --provider gcp --principal user@project.iam.gserviceaccount.com --in-scope "gcp://my-project"`,
	RunE: runCloudIAM,
}

func init() {
	cloudIAMCmd.Flags().StringVar(&ciProvider, "provider", "", "Cloud provider: aws, gcp, azure (required)")
	cloudIAMCmd.Flags().StringVar(&ciPrincipal, "principal", "", "IAM principal (ARN, email, or service account) (required)")
	cloudIAMCmd.Flags().StringSliceVar(&ciInScope, "in-scope", nil, "In-scope patterns (required)")
	cloudIAMCmd.Flags().IntVar(&ciMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	cloudIAMCmd.Flags().IntVar(&ciTimeout, "timeout", 30, "CLI command timeout in seconds")
	cloudIAMCmd.Flags().StringVar(&ciEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = cloudIAMCmd.MarkFlagRequired("provider")
	_ = cloudIAMCmd.MarkFlagRequired("principal")
	_ = cloudIAMCmd.MarkFlagRequired("in-scope")

	cloudCmd.AddCommand(cloudIAMCmd)
}

func runCloudIAM(cmd *cobra.Command, args []string) error {
	accountID := extractAccountID(ciInScope, ciProvider)

	cfg := cloud.IAMConfig{
		Provider:  ciProvider,
		Principal: ciPrincipal,
		AccountID: accountID,
		ProbeConfig: verify.ProbeConfig{
			InScope:    ciInScope,
			MaxRisk:    ciMaxRisk,
			TimeoutSec: ciTimeout,
			Evidence:   ciEvidence,
		},
	}

	result, err := cloud.VerifyCloudIAM(cfg)
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
