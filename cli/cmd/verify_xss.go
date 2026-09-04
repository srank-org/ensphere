package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	xssURL     string
	xssParam   string
	xssPayload string
	xssMethod  string
	xssProbe   probeFlags
)

var verifyXSSCmd = &cobra.Command{
	Use:   "xss",
	Short: "Verify reflected cross-site scripting",
	Long: `Verify reflected XSS by injecting a payload and checking if it appears unencoded in the response.

Examples:
  ensphere verify xss --url "http://target/search" --param q --payload "<script>alert(1)</script>" --in-scope "*.target.com"
  ensphere verify xss --url "http://target/api" --param name --payload "<img src=x onerror=alert(1)>" --method POST --in-scope "*.target.com"`,
	RunE: runVerifyXSS,
}

func init() {
	verifyXSSCmd.Flags().StringVar(&xssURL, "url", "", "Target URL (required)")
	verifyXSSCmd.Flags().StringVar(&xssParam, "param", "", "Parameter name to inject (required)")
	verifyXSSCmd.Flags().StringVar(&xssPayload, "payload", "", "XSS payload string (required)")
	verifyXSSCmd.Flags().StringVar(&xssMethod, "method", "GET", "HTTP method: GET or POST")

	_ = verifyXSSCmd.MarkFlagRequired("url")
	_ = verifyXSSCmd.MarkFlagRequired("param")
	_ = verifyXSSCmd.MarkFlagRequired("payload")

	addProbeFlags(verifyXSSCmd, &xssProbe)

	verifyCmd.AddCommand(verifyXSSCmd)
}

func runVerifyXSS(cmd *cobra.Command, args []string) error {

	cfg := verify.XSSConfig{
		URL:         xssURL,
		Param:       xssParam,
		Payload:     xssPayload,
		Method:      xssMethod,
		ProbeConfig: buildProbeConfig(&xssProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyXSS(cfg)
	})
}
