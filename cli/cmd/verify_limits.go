package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	limitsURL       string
	limitsTechnique string
	limitsMethod    string
	limitsBody      string
	limitsParam     string
	limitsValues    []int
	limitsSizes     []int
	limitsField     string
	limitsToken     string
	limitsProbe     probeFlags
)

var verifyLimitsCmd = &cobra.Command{
	Use:   "limits",
	Short: "Measure size and volume limits",
	Long: `Measure whether an endpoint enforces size and volume limits. Raw measurement
only: this records item counts, byte sizes, and acceptance per requested value
or size. It never decides whether a limit is missing.

Techniques:
  pagination     Send one request per --values entry and record item counts and body bytes
  upload_size    Multipart POST a file of random bytes per --sizes entry and record acceptance
  response_size  One request; record body bytes, content-length, and content-encoding

Examples:
  ensphere verify limits --technique pagination --url "http://target/api/items?page_size=10" --param page_size --values 1,100,10000 --in-scope "*.target.com"
  ensphere verify limits --technique upload_size --url "http://target/api/upload" --sizes 1048576,10485760 --field file --in-scope "*.target.com"
  ensphere verify limits --technique response_size --url "http://target/api/export" --in-scope "*.target.com"`,
	RunE: runVerifyLimits,
}

func init() {
	verifyLimitsCmd.Flags().StringVar(&limitsURL, "url", "", "Target URL (required)")
	verifyLimitsCmd.Flags().StringVar(&limitsTechnique, "technique", "", "Technique: pagination, upload_size, response_size (required)")
	verifyLimitsCmd.Flags().StringVar(&limitsMethod, "method", "GET", "HTTP method")
	verifyLimitsCmd.Flags().StringVar(&limitsBody, "body", "", "Request body (JSON body field is set for pagination POST)")
	verifyLimitsCmd.Flags().StringVar(&limitsParam, "param", "", "Pagination parameter name")
	verifyLimitsCmd.Flags().IntSliceVar(&limitsValues, "values", nil, "Pagination values (comma-separated, max 10, non-negative)")
	verifyLimitsCmd.Flags().IntSliceVar(&limitsSizes, "sizes", nil, "Upload sizes in bytes (comma-separated, max 5, each <= 104857600)")
	verifyLimitsCmd.Flags().StringVar(&limitsField, "field", "file", "Upload multipart field name")
	verifyLimitsCmd.Flags().StringVar(&limitsToken, "token", "", "Auth token")

	_ = verifyLimitsCmd.MarkFlagRequired("url")
	_ = verifyLimitsCmd.MarkFlagRequired("technique")

	addProbeFlags(verifyLimitsCmd, &limitsProbe)

	verifyCmd.AddCommand(verifyLimitsCmd)
}

func runVerifyLimits(cmd *cobra.Command, args []string) error {
	cfg := verify.LimitsConfig{
		URL:         limitsURL,
		Technique:   limitsTechnique,
		Method:      limitsMethod,
		Body:        limitsBody,
		Param:       limitsParam,
		Values:      limitsValues,
		Sizes:       limitsSizes,
		Field:       limitsField,
		Token:       limitsToken,
		ProbeConfig: buildProbeConfig(&limitsProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyLimits(cfg)
	})
}
