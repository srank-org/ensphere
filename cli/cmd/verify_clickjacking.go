package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	clickjackURL    string
	clickjackMethod string
	clickjackProbe  probeFlags
)

var verifyClickjackingCmd = &cobra.Command{
	Use:   "clickjacking",
	Short: "Verify clickjacking protection",
	Long: `Verify clickjacking protection by inspecting X-Frame-Options and CSP frame-ancestors headers.

Examples:
  ensphere verify clickjacking --url "http://target/app" --in-scope "*.target.com"
  ensphere verify clickjacking --url "http://target/login" --method GET --in-scope "*.target.com"`,
	RunE: runVerifyClickjacking,
}

func init() {
	verifyClickjackingCmd.Flags().StringVar(&clickjackURL, "url", "", "Target URL (required)")
	verifyClickjackingCmd.Flags().StringVar(&clickjackMethod, "method", "GET", "HTTP method")

	_ = verifyClickjackingCmd.MarkFlagRequired("url")

	addProbeFlags(verifyClickjackingCmd, &clickjackProbe)

	verifyCmd.AddCommand(verifyClickjackingCmd)
}

func runVerifyClickjacking(cmd *cobra.Command, args []string) error {

	cfg := verify.ClickjackingConfig{
		URL:         clickjackURL,
		Method:      clickjackMethod,
		ProbeConfig: buildProbeConfig(&clickjackProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyClickjacking(cfg)
	})
}
