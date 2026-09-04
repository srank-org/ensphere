package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	csrfURL    string
	csrfMethod string
	csrfToken  string
	csrfProbe  probeFlags
)

var verifyCSRFCmd = &cobra.Command{
	Use:   "csrf",
	Short: "Verify cross-site request forgery",
	Long: `Verify CSRF by testing Origin header validation and SameSite cookie attributes.

Examples:
  ensphere verify csrf --url "http://target/api/action" --method POST --in-scope "*.target.com"
  ensphere verify csrf --url "http://target/transfer" --token "auth-jwt" --in-scope "*.target.com"`,
	RunE: runVerifyCSRF,
}

func init() {
	verifyCSRFCmd.Flags().StringVar(&csrfURL, "url", "", "Target URL (required)")
	verifyCSRFCmd.Flags().StringVar(&csrfMethod, "method", "POST", "HTTP method")
	verifyCSRFCmd.Flags().StringVar(&csrfToken, "token", "", "Valid auth token")

	_ = verifyCSRFCmd.MarkFlagRequired("url")

	addProbeFlags(verifyCSRFCmd, &csrfProbe)

	verifyCmd.AddCommand(verifyCSRFCmd)
}

func runVerifyCSRF(cmd *cobra.Command, args []string) error {

	cfg := verify.CSRFConfig{
		URL:         csrfURL,
		Method:      csrfMethod,
		Token:       csrfToken,
		ProbeConfig: buildProbeConfig(&csrfProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyCSRF(cfg)
	})
}
