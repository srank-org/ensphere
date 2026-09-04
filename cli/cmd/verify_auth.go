package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	authURL       string
	authMethod    string
	authToken     string
	authTechnique string
	authProbe     probeFlags
)

var verifyAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Verify authentication bypass",
	Long: `Verify authentication bypass using various techniques.

Techniques:
  no_token        Send request without Authorization header
  expired_token   Send request with an invalid/expired token
  alg_none        Modify JWT to use alg:none with empty signature
  method_override Use X-HTTP-Method-Override to bypass method-based auth

Examples:
  ensphere verify auth --url "http://target/api/admin" --token "valid-jwt" --technique no_token --in-scope "*.target.com"
  ensphere verify auth --url "http://target/api/admin" --token "valid-jwt" --technique alg_none --in-scope "*.target.com"`,
	RunE: runVerifyAuth,
}

func init() {
	verifyAuthCmd.Flags().StringVar(&authURL, "url", "", "Target URL (required)")
	verifyAuthCmd.Flags().StringVar(&authMethod, "method", "GET", "HTTP method")
	verifyAuthCmd.Flags().StringVar(&authToken, "token", "", "Valid auth token for baseline (required)")
	verifyAuthCmd.Flags().StringVar(&authTechnique, "technique", "", "Technique: no_token, expired_token, alg_none, method_override (required)")

	_ = verifyAuthCmd.MarkFlagRequired("url")
	_ = verifyAuthCmd.MarkFlagRequired("token")
	_ = verifyAuthCmd.MarkFlagRequired("technique")

	addProbeFlags(verifyAuthCmd, &authProbe)

	verifyCmd.AddCommand(verifyAuthCmd)
}

func runVerifyAuth(cmd *cobra.Command, args []string) error {

	cfg := verify.AuthConfig{
		URL:         authURL,
		Method:      authMethod,
		Token:       authToken,
		Technique:   authTechnique,
		ProbeConfig: buildProbeConfig(&authProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyAuth(cfg)
	})
}
