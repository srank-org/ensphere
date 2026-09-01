package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	sqliURL       string
	sqliParam     string
	sqliDB        string
	sqliTechnique string
	sqliMethod    string
	sqliBoundary  string
	sqliProbe     probeFlags
)

var verifySQLiCmd = &cobra.Command{
	Use:   "sqli",
	Short: "Verify SQL injection vulnerability",
	Long: `Verify SQL injection with targeted probes.

Techniques:
  blind_time     Inject a DB-specific delay payload and measure response delay (default)
  blind_boolean  Compare responses for true/false conditions
  error_based    Check for DB-specific error signatures in response

Examples:
  ensphere verify sqli --url http://localhost:3000/api?id=1 --param id --in-scope *.localhost
  ensphere verify sqli --url http://localhost:3000/rest/products/search?q=test --param q --db sqlite --technique blind_boolean --in-scope localhost
  ensphere verify sqli --url http://app.test/items?id=1 --param id --db mysql --technique error_based --in-scope *.test`,
	RunE: runVerifySQLi,
}

func init() {
	verifySQLiCmd.Flags().StringVar(&sqliURL, "url", "", "Target URL with injectable parameter (required)")
	verifySQLiCmd.Flags().StringVar(&sqliParam, "param", "", "Query parameter name to inject (required)")
	verifySQLiCmd.Flags().StringVar(&sqliDB, "db", "postgres", "Database engine: postgres, mysql, mssql, sqlite")
	verifySQLiCmd.Flags().StringVar(&sqliTechnique, "technique", "blind_time", "Technique: blind_time, blind_boolean, error_based")
	verifySQLiCmd.Flags().StringVar(&sqliMethod, "method", "GET", "HTTP method: GET or POST")
	verifySQLiCmd.Flags().StringVar(&sqliBoundary, "string-boundary", "single_quote", "String boundary: single_quote, double_quote, numeric")
	addProbeFlags(verifySQLiCmd, &sqliProbe)

	_ = verifySQLiCmd.MarkFlagRequired("url")
	_ = verifySQLiCmd.MarkFlagRequired("param")

	verifyCmd.AddCommand(verifySQLiCmd)
}

func runVerifySQLi(cmd *cobra.Command, args []string) error {
	cfg := verify.SQLiConfig{
		URL:         sqliURL,
		Param:       sqliParam,
		DBEngine:    sqliDB,
		Technique:   sqliTechnique,
		Method:      sqliMethod,
		Boundary:    sqliBoundary,
		ProbeConfig: buildProbeConfig(&sqliProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifySQLi(cfg)
	})
}
