package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	headerinjURL    string
	headerinjParam  string
	headerinjMethod string
	headerinjProbe  probeFlags
)

var verifyHeaderInjectionCmd = &cobra.Command{
	Use:   "headerinjection",
	Short: "Verify CRLF header injection",
	Long: `Verify CRLF header injection by injecting CR+LF into a parameter and checking if an injected header appears in the response.

Examples:
  ensphere verify headerinjection --url "http://target/api" --param q --in-scope "*.target.com"
  ensphere verify headerinjection --url "http://target/redirect" --param next --method GET --in-scope "*.target.com"`,
	RunE: runVerifyHeaderInjection,
}

func init() {
	verifyHeaderInjectionCmd.Flags().StringVar(&headerinjURL, "url", "", "Target URL (required)")
	verifyHeaderInjectionCmd.Flags().StringVar(&headerinjParam, "param", "", "Parameter name to inject (required)")
	verifyHeaderInjectionCmd.Flags().StringVar(&headerinjMethod, "method", "GET", "HTTP method: GET or POST")

	_ = verifyHeaderInjectionCmd.MarkFlagRequired("url")
	_ = verifyHeaderInjectionCmd.MarkFlagRequired("param")

	addProbeFlags(verifyHeaderInjectionCmd, &headerinjProbe)

	verifyCmd.AddCommand(verifyHeaderInjectionCmd)
}

func runVerifyHeaderInjection(cmd *cobra.Command, args []string) error {

	cfg := verify.HeaderInjectionConfig{
		URL:         headerinjURL,
		Param:       headerinjParam,
		Method:      headerinjMethod,
		ProbeConfig: buildProbeConfig(&headerinjProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyHeaderInjection(cfg)
	})
}
