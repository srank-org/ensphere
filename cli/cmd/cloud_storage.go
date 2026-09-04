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
	csProvider    string
	csBucket      string
	csRegion      string
	csAccountName string
	csInScope     []string
	csMaxRisk     int
	csTimeout     int
	csEvidence    string
)

var cloudStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Verify cloud storage security",
	Long: `Verify cloud storage bucket security configuration.

Checks ACLs, encryption, versioning, logging, and public access settings.

Examples:
  ensphere cloud storage --provider aws --bucket my-bucket --in-scope "aws://123456789012"
  ensphere cloud storage --provider gcp --bucket my-bucket --in-scope "gcp://my-project"`,
	RunE: runCloudStorage,
}

func init() {
	cloudStorageCmd.Flags().StringVar(&csProvider, "provider", "", "Cloud provider: aws, gcp, azure (required)")
	cloudStorageCmd.Flags().StringVar(&csBucket, "bucket", "", "Bucket/container name (required)")
	cloudStorageCmd.Flags().StringVar(&csRegion, "region", "", "Cloud region (optional)")
	cloudStorageCmd.Flags().StringVar(&csAccountName, "account-name", "", "Azure storage account name (required for --provider azure)")
	cloudStorageCmd.Flags().StringSliceVar(&csInScope, "in-scope", nil, "In-scope patterns (required, e.g., aws://ACCOUNT_ID)")
	cloudStorageCmd.Flags().IntVar(&csMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	cloudStorageCmd.Flags().IntVar(&csTimeout, "timeout", 30, "CLI command timeout in seconds")
	cloudStorageCmd.Flags().StringVar(&csEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = cloudStorageCmd.MarkFlagRequired("provider")
	_ = cloudStorageCmd.MarkFlagRequired("bucket")
	_ = cloudStorageCmd.MarkFlagRequired("in-scope")

	cloudCmd.AddCommand(cloudStorageCmd)
}

func runCloudStorage(cmd *cobra.Command, args []string) error {
	if csProvider == "azure" && csAccountName == "" {
		fmt.Fprintln(os.Stderr, "--account-name is required when --provider is azure")
		os.Exit(2)
	}

	accountID := extractAccountID(csInScope, csProvider)

	cfg := cloud.StorageConfig{
		Provider:    csProvider,
		Bucket:      csBucket,
		Region:      csRegion,
		AccountID:   accountID,
		AccountName: csAccountName,
		ProbeConfig: verify.ProbeConfig{
			InScope:    csInScope,
			MaxRisk:    csMaxRisk,
			TimeoutSec: csTimeout,
			Evidence:   csEvidence,
		},
	}

	result, err := cloud.VerifyCloudStorage(cfg)
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

// extractAccountID extracts the account/project ID from the first matching in-scope pattern.
func extractAccountID(patterns []string, provider string) string {
	prefix := provider + "://"
	for _, p := range patterns {
		if len(p) > len(prefix) && p[:len(prefix)] == prefix {
			return p[len(prefix):]
		}
	}
	return ""
}
