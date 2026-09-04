package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	sstiURL    string
	sstiParam  string
	sstiEngine string
	sstiMethod string
	sstiProbe  probeFlags
)

var verifySSTICmd = &cobra.Command{
	Use:   "ssti",
	Short: "Verify server-side template injection",
	Long: `Verify SSTI by injecting template expressions and checking for evaluated output.

Engines: auto (try all), jinja2, twig, freemarker, erb

Examples:
  ensphere verify ssti --url "http://target/search?q=test" --param q --in-scope "*.target.com"
  ensphere verify ssti --url "http://target/render?tpl=x" --param tpl --engine jinja2 --in-scope "*.target.com"`,
	RunE: runVerifySSTI,
}

func init() {
	verifySSTICmd.Flags().StringVar(&sstiURL, "url", "", "Target URL (required)")
	verifySSTICmd.Flags().StringVar(&sstiParam, "param", "", "Parameter name to inject (required)")
	verifySSTICmd.Flags().StringVar(&sstiEngine, "engine", "auto", "Template engine: auto, jinja2, twig, freemarker, erb")
	verifySSTICmd.Flags().StringVar(&sstiMethod, "method", "GET", "HTTP method")

	_ = verifySSTICmd.MarkFlagRequired("url")
	_ = verifySSTICmd.MarkFlagRequired("param")

	addProbeFlags(verifySSTICmd, &sstiProbe)

	verifyCmd.AddCommand(verifySSTICmd)
}

func runVerifySSTI(cmd *cobra.Command, args []string) error {

	cfg := verify.SSTIConfig{
		URL:         sstiURL,
		Param:       sstiParam,
		Engine:      sstiEngine,
		Method:      sstiMethod,
		ProbeConfig: buildProbeConfig(&sstiProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifySSTI(cfg)
	})
}
