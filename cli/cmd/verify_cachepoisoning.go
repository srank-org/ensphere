package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	cpURL       string
	cpTechnique string
	cpProbe     probeFlags
)

var verifyCachePoisoningCmd = &cobra.Command{
	Use:   "cachepoisoning",
	Short: "Verify cache poisoning vulnerability",
	Long: `Verify web cache poisoning by injecting unkeyed headers and checking for cache contamination.

Techniques:
  unkeyed_header  Inject X-Forwarded-Host header (default)
  unkeyed_cookie  Inject unexpected cookie value
  fat_get         Inject X-Original-URL header

Examples:
  ensphere verify cachepoisoning --url "http://target/page" --in-scope "*.target.com"
  ensphere verify cachepoisoning --url "http://target/page" --technique fat_get --in-scope "*.target.com"`,
	RunE: runVerifyCachePoisoning,
}

func init() {
	verifyCachePoisoningCmd.Flags().StringVar(&cpURL, "url", "", "Target URL (required)")
	verifyCachePoisoningCmd.Flags().StringVar(&cpTechnique, "technique", "unkeyed_header", "Technique: unkeyed_header, unkeyed_cookie, fat_get")

	_ = verifyCachePoisoningCmd.MarkFlagRequired("url")

	addProbeFlags(verifyCachePoisoningCmd, &cpProbe)

	verifyCmd.AddCommand(verifyCachePoisoningCmd)
}

func runVerifyCachePoisoning(cmd *cobra.Command, args []string) error {

	cfg := verify.CachePoisoningConfig{
		URL:         cpURL,
		Technique:   cpTechnique,
		ProbeConfig: buildProbeConfig(&cpProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyCachePoisoning(cfg)
	})
}
