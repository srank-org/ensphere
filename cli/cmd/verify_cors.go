package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	corsURL    string
	corsMethod string
	corsProbe  probeFlags
)

var verifyCORSCmd = &cobra.Command{
	Use:   "cors",
	Short: "Verify CORS misconfiguration",
	Long: `Verify CORS misconfiguration by testing Origin header reflection.

Sends requests with evil, null, and subdomain Origin headers and inspects ACAO response.

Examples:
  ensphere verify cors --url "http://target/api/data" --in-scope "*.target.com"
  ensphere verify cors --url "http://target/api/user" --method OPTIONS --in-scope "*.target.com"`,
	RunE: runVerifyCORS,
}

func init() {
	verifyCORSCmd.Flags().StringVar(&corsURL, "url", "", "Target URL (required)")
	verifyCORSCmd.Flags().StringVar(&corsMethod, "method", "GET", "HTTP method")

	_ = verifyCORSCmd.MarkFlagRequired("url")

	addProbeFlags(verifyCORSCmd, &corsProbe)

	verifyCmd.AddCommand(verifyCORSCmd)
}

func runVerifyCORS(cmd *cobra.Command, args []string) error {

	cfg := verify.CORSConfig{
		URL:         corsURL,
		Method:      corsMethod,
		ProbeConfig: buildProbeConfig(&corsProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyCORS(cfg)
	})
}
