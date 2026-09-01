package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	ssrfURL         string
	ssrfParam       string
	ssrfCallbackURL string
	ssrfMethod      string
	ssrfProbe       probeFlags
)

var verifySSRFCmd = &cobra.Command{
	Use:   "ssrf",
	Short: "Verify server-side request forgery",
	Long: `Verify SSRF by injecting internal URLs and checking for metadata signatures or response differences.

Examples:
  ensphere verify ssrf --url "http://target/fetch" --param url --in-scope "*.target.com"
  ensphere verify ssrf --url "http://target/proxy" --param url --callback-url "https://attacker.com/cb" --in-scope "*.target.com"`,
	RunE: runVerifySSRF,
}

func init() {
	verifySSRFCmd.Flags().StringVar(&ssrfURL, "url", "", "Target URL (required)")
	verifySSRFCmd.Flags().StringVar(&ssrfParam, "param", "", "Parameter name to inject (required)")
	verifySSRFCmd.Flags().StringVar(&ssrfCallbackURL, "callback-url", "", "External callback URL for blind SSRF")
	verifySSRFCmd.Flags().StringVar(&ssrfMethod, "method", "GET", "HTTP method")

	_ = verifySSRFCmd.MarkFlagRequired("url")
	_ = verifySSRFCmd.MarkFlagRequired("param")

	addProbeFlags(verifySSRFCmd, &ssrfProbe)

	verifyCmd.AddCommand(verifySSRFCmd)
}

func runVerifySSRF(cmd *cobra.Command, args []string) error {

	cfg := verify.SSRFConfig{
		URL:         ssrfURL,
		Param:       ssrfParam,
		CallbackURL: ssrfCallbackURL,
		Method:      ssrfMethod,
		ProbeConfig: buildProbeConfig(&ssrfProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifySSRF(cfg)
	})
}
