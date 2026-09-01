package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	csviSubmitURL string
	csviExportURL string
	csviParam     string
	csviMethod    string
	csviProbe     probeFlags
)

var verifyCSVInjectionCmd = &cobra.Command{
	Use:   "csvinjection",
	Short: "Verify CSV injection vulnerability",
	Long: `Verify CSV injection by submitting formula payloads and checking if they survive in exports.

Examples:
  ensphere verify csvinjection --submit-url "http://target/api/items" --export-url "http://target/api/export.csv" --param name --in-scope "*.target.com"`,
	RunE: runVerifyCSVInjection,
}

func init() {
	verifyCSVInjectionCmd.Flags().StringVar(&csviSubmitURL, "submit-url", "", "URL to submit data (required)")
	verifyCSVInjectionCmd.Flags().StringVar(&csviExportURL, "export-url", "", "URL to download CSV export (required)")
	verifyCSVInjectionCmd.Flags().StringVar(&csviParam, "param", "", "Field to inject into (required)")
	verifyCSVInjectionCmd.Flags().StringVar(&csviMethod, "method", "POST", "HTTP method for submit")

	_ = verifyCSVInjectionCmd.MarkFlagRequired("submit-url")
	_ = verifyCSVInjectionCmd.MarkFlagRequired("export-url")
	_ = verifyCSVInjectionCmd.MarkFlagRequired("param")

	addProbeFlags(verifyCSVInjectionCmd, &csviProbe)

	verifyCmd.AddCommand(verifyCSVInjectionCmd)
}

func runVerifyCSVInjection(cmd *cobra.Command, args []string) error {

	cfg := verify.CSVInjectionConfig{
		SubmitURL:   csviSubmitURL,
		ExportURL:   csviExportURL,
		Param:       csviParam,
		Method:      csviMethod,
		ProbeConfig: buildProbeConfig(&csviProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyCSVInjection(cfg)
	})
}
