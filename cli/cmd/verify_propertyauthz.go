package cmd

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	pauthzURL       string
	pauthzMethod    string
	pauthzHighToken string
	pauthzLowToken  string
	pauthzWatch     string
	pauthzProbe     probeFlags
)

var verifyPropertyAuthZCmd = &cobra.Command{
	Use:   "propertyauthz",
	Short: "Verify property-level authorization",
	Long: `Verify property-level authorization by comparing JSON response fields for different privilege levels.

Sends the same request with a high-privilege and low-privilege token and compares top-level JSON keys.

Examples:
  ensphere verify propertyauthz --url "http://target/api/user/profile" --high-token "admin-jwt" --low-token "user-jwt" --in-scope "*.target.com"
  ensphere verify propertyauthz --url "http://target/api/user/1" --high-token "admin" --low-token "user" --watch-fields "ssn,salary,role" --in-scope "*.target.com"`,
	RunE: runVerifyPropertyAuthZ,
}

func init() {
	verifyPropertyAuthZCmd.Flags().StringVar(&pauthzURL, "url", "", "Target URL (required)")
	verifyPropertyAuthZCmd.Flags().StringVar(&pauthzMethod, "method", "GET", "HTTP method")
	verifyPropertyAuthZCmd.Flags().StringVar(&pauthzHighToken, "high-token", "", "High-privilege auth token (required)")
	verifyPropertyAuthZCmd.Flags().StringVar(&pauthzLowToken, "low-token", "", "Low-privilege auth token (required)")
	verifyPropertyAuthZCmd.Flags().StringVar(&pauthzWatch, "watch-fields", "", "Comma-separated fields to watch (optional)")

	_ = verifyPropertyAuthZCmd.MarkFlagRequired("url")
	_ = verifyPropertyAuthZCmd.MarkFlagRequired("high-token")
	_ = verifyPropertyAuthZCmd.MarkFlagRequired("low-token")

	addProbeFlags(verifyPropertyAuthZCmd, &pauthzProbe)

	verifyCmd.AddCommand(verifyPropertyAuthZCmd)
}

func runVerifyPropertyAuthZ(cmd *cobra.Command, args []string) error {

	var watchFields []string
	if pauthzWatch != "" {
		for _, f := range strings.Split(pauthzWatch, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				watchFields = append(watchFields, f)
			}
		}
	}

	cfg := verify.PropertyAuthZConfig{
		URL:           pauthzURL,
		Method:        pauthzMethod,
		HighPrivToken: pauthzHighToken,
		LowPrivToken:  pauthzLowToken,
		WatchFields:   watchFields,
		ProbeConfig:   buildProbeConfig(&pauthzProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyPropertyAuthZ(cfg)
	})
}
