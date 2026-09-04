package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	raceURL         string
	raceMethod      string
	raceBody        string
	raceToken       string
	raceConcurrency int
	raceProbe       probeFlags
)

var verifyRaceCmd = &cobra.Command{
	Use:   "race",
	Short: "Verify race condition vulnerability",
	Long: `Verify race conditions by sending concurrent request bursts.

Sends N identical requests in parallel and measures response distribution.

Examples:
  ensphere verify race --url "http://target/api/redeem" --method POST --body '{"code":"PROMO"}' --in-scope "*.target.com"
  ensphere verify race --url "http://target/api/transfer" --concurrency 20 --token "jwt" --in-scope "*.target.com"`,
	RunE: runVerifyRace,
}

func init() {
	verifyRaceCmd.Flags().StringVar(&raceURL, "url", "", "Target URL (required)")
	verifyRaceCmd.Flags().StringVar(&raceMethod, "method", "POST", "HTTP method")
	verifyRaceCmd.Flags().StringVar(&raceBody, "body", "", "Request body")
	verifyRaceCmd.Flags().StringVar(&raceToken, "token", "", "Auth token")
	verifyRaceCmd.Flags().IntVar(&raceConcurrency, "concurrency", 10, "Number of concurrent requests")

	_ = verifyRaceCmd.MarkFlagRequired("url")

	addProbeFlags(verifyRaceCmd, &raceProbe)

	verifyCmd.AddCommand(verifyRaceCmd)
}

func runVerifyRace(cmd *cobra.Command, args []string) error {

	cfg := verify.RaceConfig{
		URL:         raceURL,
		Method:      raceMethod,
		Body:        raceBody,
		Token:       raceToken,
		Concurrency: raceConcurrency,
		ProbeConfig: buildProbeConfig(&raceProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyRace(cfg)
	})
}
