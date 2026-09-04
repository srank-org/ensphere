package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	jwtURL       string
	jwtToken     string
	jwtTechnique string
	jwtMethod    string
	jwtProbe     probeFlags
)

var verifyJWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Verify JWT manipulation vulnerability",
	Long: `Verify JWT manipulation by modifying token algorithm or claims.

Techniques:
  alg_none       Change algorithm to "none" and strip signature
  kid_injection  Inject path traversal in kid header claim

Examples:
  ensphere verify jwt --url "http://target/api/me" --token "eyJ..." --technique alg_none --in-scope "*.target.com"
  ensphere verify jwt --url "http://target/api/me" --token "eyJ..." --technique kid_injection --in-scope "*.target.com"`,
	RunE: runVerifyJWT,
}

func init() {
	verifyJWTCmd.Flags().StringVar(&jwtURL, "url", "", "Target URL (required)")
	verifyJWTCmd.Flags().StringVar(&jwtToken, "token", "", "Valid JWT token (required)")
	verifyJWTCmd.Flags().StringVar(&jwtTechnique, "technique", "", "Technique: alg_none, kid_injection (required)")
	verifyJWTCmd.Flags().StringVar(&jwtMethod, "method", "GET", "HTTP method")

	_ = verifyJWTCmd.MarkFlagRequired("url")
	_ = verifyJWTCmd.MarkFlagRequired("token")
	_ = verifyJWTCmd.MarkFlagRequired("technique")

	addProbeFlags(verifyJWTCmd, &jwtProbe)

	verifyCmd.AddCommand(verifyJWTCmd)
}

func runVerifyJWT(cmd *cobra.Command, args []string) error {

	cfg := verify.JWTConfig{
		URL:         jwtURL,
		Token:       jwtToken,
		Technique:   jwtTechnique,
		Method:      jwtMethod,
		ProbeConfig: buildProbeConfig(&jwtProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyJWT(cfg)
	})
}
