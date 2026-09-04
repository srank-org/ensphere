package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	authzURL       string
	authzMethod    string
	authzLowToken  string
	authzHighToken string
	authzProbe     probeFlags
)

var verifyAuthZCmd = &cobra.Command{
	Use:   "authz",
	Short: "Verify authorization bypass vulnerability",
	Long: `Verify authorization bypass by comparing responses for different privilege levels.

Sends the same request with a high-privilege and low-privilege token and compares results.

Examples:
  ensphere verify authz --url "http://target/api/admin" --low-token "user-jwt" --high-token "admin-jwt" --in-scope "*.target.com"`,
	RunE: runVerifyAuthZ,
}

func init() {
	verifyAuthZCmd.Flags().StringVar(&authzURL, "url", "", "Target URL (required)")
	verifyAuthZCmd.Flags().StringVar(&authzMethod, "method", "GET", "HTTP method")
	verifyAuthZCmd.Flags().StringVar(&authzLowToken, "low-token", "", "Low-privilege auth token (required)")
	verifyAuthZCmd.Flags().StringVar(&authzHighToken, "high-token", "", "High-privilege auth token (required)")

	_ = verifyAuthZCmd.MarkFlagRequired("url")
	_ = verifyAuthZCmd.MarkFlagRequired("low-token")
	_ = verifyAuthZCmd.MarkFlagRequired("high-token")

	addProbeFlags(verifyAuthZCmd, &authzProbe)

	verifyCmd.AddCommand(verifyAuthZCmd)
}

func runVerifyAuthZ(cmd *cobra.Command, args []string) error {

	cfg := verify.AuthZConfig{
		URL:           authzURL,
		Method:        authzMethod,
		LowPrivToken:  authzLowToken,
		HighPrivToken: authzHighToken,
		ProbeConfig:   buildProbeConfig(&authzProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyAuthZ(cfg)
	})
}
