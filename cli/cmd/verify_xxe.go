package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	xxeURL       string
	xxeTechnique string
	xxeMethod    string
	xxeProbe     probeFlags
)

var verifyXXECmd = &cobra.Command{
	Use:   "xxe",
	Short: "Verify XML external entity injection",
	Long: `Verify XXE by sending crafted XML with external entity references.

Techniques: file_read, ssrf

Out-of-band (OOB) XXE cannot be observed in the in-band response, so this probe
does not attempt it. Detect OOB effects manually: start a listener with
'ensphere callback', send a parameter-entity payload that references it, and
watch for the hit.

Examples:
  ensphere verify xxe --url "http://target/api/xml" --technique file_read --in-scope "*.target.com"
  ensphere verify xxe --url "http://target/upload" --technique ssrf --in-scope "*.target.com"`,
	RunE: runVerifyXXE,
}

func init() {
	verifyXXECmd.Flags().StringVar(&xxeURL, "url", "", "Target URL (required)")
	verifyXXECmd.Flags().StringVar(&xxeTechnique, "technique", "file_read", "Technique: file_read, ssrf")
	verifyXXECmd.Flags().StringVar(&xxeMethod, "method", "POST", "HTTP method")

	_ = verifyXXECmd.MarkFlagRequired("url")

	addProbeFlags(verifyXXECmd, &xxeProbe)

	verifyCmd.AddCommand(verifyXXECmd)
}

func runVerifyXXE(cmd *cobra.Command, args []string) error {

	cfg := verify.XXEConfig{
		URL:         xxeURL,
		Method:      xxeMethod,
		Technique:   xxeTechnique,
		ProbeConfig: buildProbeConfig(&xxeProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyXXE(cfg)
	})
}
