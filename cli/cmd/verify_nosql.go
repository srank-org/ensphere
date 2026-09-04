package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	nosqlURL       string
	nosqlParam     string
	nosqlTechnique string
	nosqlMethod    string
	nosqlProbe     probeFlags
)

var verifyNoSQLCmd = &cobra.Command{
	Use:   "nosql",
	Short: "Verify NoSQL injection vulnerability",
	Long: `Verify NoSQL injection with operator injection or time-based probes.

Techniques:
  operator_injection  Inject MongoDB operators ($gt, $ne) and compare responses (default)
  where_time          Inject $where with sleep and measure delay

Examples:
  ensphere verify nosql --url "http://target/api/login" --param username --in-scope "*.target.com"
  ensphere verify nosql --url "http://target/api/search" --param q --technique where_time --in-scope "*.target.com"`,
	RunE: runVerifyNoSQL,
}

func init() {
	verifyNoSQLCmd.Flags().StringVar(&nosqlURL, "url", "", "Target URL (required)")
	verifyNoSQLCmd.Flags().StringVar(&nosqlParam, "param", "", "Parameter/field name (required)")
	verifyNoSQLCmd.Flags().StringVar(&nosqlTechnique, "technique", "operator_injection", "Technique: operator_injection, where_time")
	verifyNoSQLCmd.Flags().StringVar(&nosqlMethod, "method", "POST", "HTTP method")

	_ = verifyNoSQLCmd.MarkFlagRequired("url")
	_ = verifyNoSQLCmd.MarkFlagRequired("param")

	addProbeFlags(verifyNoSQLCmd, &nosqlProbe)

	verifyCmd.AddCommand(verifyNoSQLCmd)
}

func runVerifyNoSQL(cmd *cobra.Command, args []string) error {

	cfg := verify.NoSQLConfig{
		URL:         nosqlURL,
		Param:       nosqlParam,
		Technique:   nosqlTechnique,
		Method:      nosqlMethod,
		ProbeConfig: buildProbeConfig(&nosqlProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyNoSQL(cfg)
	})
}
