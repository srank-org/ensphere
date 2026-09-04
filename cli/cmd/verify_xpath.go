package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	xpathURL       string
	xpathParam     string
	xpathTechnique string
	xpathMethod    string
	xpathProbe     probeFlags
)

var verifyXPathCmd = &cobra.Command{
	Use:   "xpath",
	Short: "Verify XPath injection vulnerability",
	Long: `Verify XPath injection with classic injection, blind boolean, or blind error probes.

Techniques:
  xpath_injection      Inject XPath tautology and compare response hash/error patterns (default)
  xpath_blind_boolean  Inject true/false XPath conditions and compare response hashes
  xpath_blind_error    Inject XPath syntax error and compare status/hash/error patterns

Examples:
  ensphere verify xpath --url "http://target/search" --param query --in-scope "*.target.com"
  ensphere verify xpath --url "http://target/login" --param user --technique xpath_blind_boolean --in-scope "*.target.com"
  ensphere verify xpath --url "http://target/api/lookup" --param name --technique xpath_blind_error --method POST --in-scope "*.target.com"`,
	RunE: runVerifyXPath,
}

func init() {
	verifyXPathCmd.Flags().StringVar(&xpathURL, "url", "", "Target URL (required)")
	verifyXPathCmd.Flags().StringVar(&xpathParam, "param", "", "Parameter/field name (required)")
	verifyXPathCmd.Flags().StringVar(&xpathTechnique, "technique", "xpath_injection", "Technique: xpath_injection, xpath_blind_boolean, xpath_blind_error")
	verifyXPathCmd.Flags().StringVar(&xpathMethod, "method", "GET", "HTTP method")

	_ = verifyXPathCmd.MarkFlagRequired("url")
	_ = verifyXPathCmd.MarkFlagRequired("param")

	addProbeFlags(verifyXPathCmd, &xpathProbe)

	verifyCmd.AddCommand(verifyXPathCmd)
}

func runVerifyXPath(cmd *cobra.Command, args []string) error {

	cfg := verify.XPathConfig{
		URL:         xpathURL,
		Param:       xpathParam,
		Technique:   xpathTechnique,
		Method:      xpathMethod,
		ProbeConfig: buildProbeConfig(&xpathProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyXPath(cfg)
	})
}
