package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	ppURL       string
	ppMethod    string
	ppTechnique string
	ppProbe     probeFlags
)

var verifyProtoPollutionCmd = &cobra.Command{
	Use:   "protopollution",
	Short: "Verify prototype pollution vulnerability",
	Long: `Verify prototype pollution by injecting __proto__ or constructor.prototype payloads.

Techniques: proto_assignment, constructor_pollution, json_merge

Examples:
  ensphere verify protopollution --url "http://target/api/config" --in-scope "*.target.com"
  ensphere verify protopollution --url "http://target/api/merge" --technique json_merge --in-scope "*.target.com"`,
	RunE: runVerifyProtoPollution,
}

func init() {
	verifyProtoPollutionCmd.Flags().StringVar(&ppURL, "url", "", "Target URL (required)")
	verifyProtoPollutionCmd.Flags().StringVar(&ppMethod, "method", "POST", "HTTP method")
	verifyProtoPollutionCmd.Flags().StringVar(&ppTechnique, "technique", "proto_assignment", "Technique: proto_assignment, constructor_pollution, json_merge")

	_ = verifyProtoPollutionCmd.MarkFlagRequired("url")

	addProbeFlags(verifyProtoPollutionCmd, &ppProbe)

	verifyCmd.AddCommand(verifyProtoPollutionCmd)
}

func runVerifyProtoPollution(cmd *cobra.Command, args []string) error {

	cfg := verify.ProtoPollutionConfig{
		URL:         ppURL,
		Method:      ppMethod,
		Technique:   ppTechnique,
		ProbeConfig: buildProbeConfig(&ppProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyProtoPollution(cfg)
	})
}
