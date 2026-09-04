package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	lfiURL    string
	lfiParam  string
	lfiOS     string
	lfiMethod string
	lfiProbe  probeFlags
)

var verifyLFICmd = &cobra.Command{
	Use:   "lfi",
	Short: "Verify local file inclusion vulnerability",
	Long: `Verify LFI by injecting path traversal payloads and checking for file content signatures.

Examples:
  ensphere verify lfi --url "http://target/api?file=test" --param file --in-scope "*.target.com"
  ensphere verify lfi --url "http://target/load?path=x" --param path --os windows --in-scope "*.target.com"`,
	RunE: runVerifyLFI,
}

func init() {
	verifyLFICmd.Flags().StringVar(&lfiURL, "url", "", "Target URL (required)")
	verifyLFICmd.Flags().StringVar(&lfiParam, "param", "", "Parameter name to inject (required)")
	verifyLFICmd.Flags().StringVar(&lfiOS, "os", "linux", "Target OS: linux, windows")
	verifyLFICmd.Flags().StringVar(&lfiMethod, "method", "GET", "HTTP method")

	_ = verifyLFICmd.MarkFlagRequired("url")
	_ = verifyLFICmd.MarkFlagRequired("param")

	addProbeFlags(verifyLFICmd, &lfiProbe)

	verifyCmd.AddCommand(verifyLFICmd)
}

func runVerifyLFI(cmd *cobra.Command, args []string) error {

	cfg := verify.LFIConfig{
		URL:         lfiURL,
		Param:       lfiParam,
		OS:          lfiOS,
		Method:      lfiMethod,
		ProbeConfig: buildProbeConfig(&lfiProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyLFI(cfg)
	})
}
