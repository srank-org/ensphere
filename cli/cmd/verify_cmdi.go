package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	cmdiURL    string
	cmdiParam  string
	cmdiOS     string
	cmdiMethod string
	cmdiProbe  probeFlags
)

var verifyCMDiCmd = &cobra.Command{
	Use:   "cmdi",
	Short: "Verify command injection vulnerability",
	Long: `Verify command injection with time-based blind probes.

Injects OS-specific sleep commands and measures response delay.

Examples:
  ensphere verify cmdi --url "http://target/api?cmd=test" --param cmd --in-scope "*.target.com"
  ensphere verify cmdi --url "http://target/api?input=1" --param input --os windows --in-scope "*.target.com"`,
	RunE: runVerifyCMDi,
}

func init() {
	verifyCMDiCmd.Flags().StringVar(&cmdiURL, "url", "", "Target URL (required)")
	verifyCMDiCmd.Flags().StringVar(&cmdiParam, "param", "", "Parameter name to inject (required)")
	verifyCMDiCmd.Flags().StringVar(&cmdiOS, "os", "linux", "Target OS: linux, windows")
	verifyCMDiCmd.Flags().StringVar(&cmdiMethod, "method", "GET", "HTTP method")

	_ = verifyCMDiCmd.MarkFlagRequired("url")
	_ = verifyCMDiCmd.MarkFlagRequired("param")

	addProbeFlags(verifyCMDiCmd, &cmdiProbe)

	verifyCmd.AddCommand(verifyCMDiCmd)
}

func runVerifyCMDi(cmd *cobra.Command, args []string) error {

	cfg := verify.CMDiConfig{
		URL:         cmdiURL,
		Param:       cmdiParam,
		OS:          cmdiOS,
		Method:      cmdiMethod,
		ProbeConfig: buildProbeConfig(&cmdiProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyCMDi(cfg)
	})
}
