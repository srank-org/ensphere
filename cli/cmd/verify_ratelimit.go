package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	ratelimitURL         string
	ratelimitMethod      string
	ratelimitBody        string
	ratelimitToken       string
	ratelimitSecondToken string
	ratelimitBurstCount  int
	ratelimitWindowSec   int
	ratelimitProbe       probeFlags
)

var verifyRateLimitCmd = &cobra.Command{
	Use:   "ratelimit",
	Short: "Verify rate limiting behavior",
	Long: `Measure rate limiting with an explicitly approved sequential request burst.

The caller must choose --burst-count for the specific endpoint and environment.
This is bounded behavior measurement, not load testing. Stop on instability.

Examples:
  ensphere verify ratelimit --url "http://target/api/login" --method POST --burst-count 10 --window-sec 10 --in-scope "*.target.com"
  ensphere verify ratelimit --url "http://target/api/data" --method GET --burst-count 5 --token "jwt" --in-scope "*.target.com"`,
	RunE: runVerifyRateLimit,
}

func init() {
	verifyRateLimitCmd.Flags().StringVar(&ratelimitURL, "url", "", "Target URL (required)")
	verifyRateLimitCmd.Flags().StringVar(&ratelimitMethod, "method", "POST", "HTTP method")
	verifyRateLimitCmd.Flags().StringVar(&ratelimitBody, "body", "", "Request body")
	verifyRateLimitCmd.Flags().StringVar(&ratelimitToken, "token", "", "Auth token")
	verifyRateLimitCmd.Flags().StringVar(&ratelimitSecondToken, "second-token", "", "Optional second identity token: after the first burst and one window, repeat the burst with this token")
	verifyRateLimitCmd.Flags().IntVar(&ratelimitBurstCount, "burst-count", 0, "Explicitly approved number of sequential requests (required)")
	verifyRateLimitCmd.Flags().IntVar(&ratelimitWindowSec, "window-sec", 10, "Time window in seconds")

	_ = verifyRateLimitCmd.MarkFlagRequired("url")
	_ = verifyRateLimitCmd.MarkFlagRequired("burst-count")

	addProbeFlags(verifyRateLimitCmd, &ratelimitProbe)

	verifyCmd.AddCommand(verifyRateLimitCmd)
}

func runVerifyRateLimit(cmd *cobra.Command, args []string) error {

	cfg := verify.RateLimitConfig{
		URL:         ratelimitURL,
		Method:      ratelimitMethod,
		Body:        ratelimitBody,
		Token:       ratelimitToken,
		SecondToken: ratelimitSecondToken,
		BurstCount:  ratelimitBurstCount,
		WindowSec:   ratelimitWindowSec,
		ProbeConfig: buildProbeConfig(&ratelimitProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyRateLimit(cfg)
	})
}
