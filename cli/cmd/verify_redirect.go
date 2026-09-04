package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	redirectURL    string
	redirectParam  string
	redirectMethod string
	redirectProbe  probeFlags
)

var verifyRedirectCmd = &cobra.Command{
	Use:   "redirect",
	Short: "Verify open redirect vulnerability",
	Long: `Verify open redirect by injecting an external URL and checking the Location header.

Examples:
  ensphere verify redirect --url "http://target/login?next=/dashboard" --param next --in-scope "*.target.com"
  ensphere verify redirect --url "http://target/goto?url=/" --param url --in-scope "*.target.com"`,
	RunE: runVerifyRedirect,
}

func init() {
	verifyRedirectCmd.Flags().StringVar(&redirectURL, "url", "", "Target URL (required)")
	verifyRedirectCmd.Flags().StringVar(&redirectParam, "param", "", "Redirect parameter name (required)")
	verifyRedirectCmd.Flags().StringVar(&redirectMethod, "method", "GET", "HTTP method")

	_ = verifyRedirectCmd.MarkFlagRequired("url")
	_ = verifyRedirectCmd.MarkFlagRequired("param")

	addProbeFlags(verifyRedirectCmd, &redirectProbe)

	verifyCmd.AddCommand(verifyRedirectCmd)
}

func runVerifyRedirect(cmd *cobra.Command, args []string) error {

	cfg := verify.RedirectConfig{
		URL:         redirectURL,
		Param:       redirectParam,
		Method:      redirectMethod,
		ProbeConfig: buildProbeConfig(&redirectProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyRedirect(cfg)
	})
}
