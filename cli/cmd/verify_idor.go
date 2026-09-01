package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	idorURL        string
	idorID         string
	idorToken      string
	idorOwnerToken string
	idorMethod     string
	idorProbe      probeFlags
)

var verifyIDORCmd = &cobra.Command{
	Use:   "idor",
	Short: "Verify insecure direct object reference",
	Long: `Verify IDOR by accessing a resource with an attacker's token.

The URL should contain {id} as a placeholder for the resource ID.

Examples:
  ensphere verify idor --url "http://target/api/items/{id}" --id "victim-uuid" --token "attacker-jwt" --in-scope "*.target.com"
  ensphere verify idor --url "http://target/api/users/{id}/profile" --id "123" --token "low-priv-token" --in-scope "*.target.com"`,
	RunE: runVerifyIDOR,
}

func init() {
	verifyIDORCmd.Flags().StringVar(&idorURL, "url", "", "Target URL with {id} placeholder (required)")
	verifyIDORCmd.Flags().StringVar(&idorID, "id", "", "Resource ID to access (required)")
	verifyIDORCmd.Flags().StringVar(&idorToken, "token", "", "Attacker's auth token (required)")
	verifyIDORCmd.Flags().StringVar(&idorOwnerToken, "owner-token", "", "Owner's auth token for the baseline round (optional)")
	verifyIDORCmd.Flags().StringVar(&idorMethod, "method", "GET", "HTTP method")

	_ = verifyIDORCmd.MarkFlagRequired("url")
	_ = verifyIDORCmd.MarkFlagRequired("id")
	_ = verifyIDORCmd.MarkFlagRequired("token")

	addProbeFlags(verifyIDORCmd, &idorProbe)

	verifyCmd.AddCommand(verifyIDORCmd)
}

func runVerifyIDOR(cmd *cobra.Command, args []string) error {

	cfg := verify.IDORConfig{
		URL:         idorURL,
		ID:          idorID,
		Token:       idorToken,
		OwnerToken:  idorOwnerToken,
		Method:      idorMethod,
		ProbeConfig: buildProbeConfig(&idorProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyIDOR(cfg)
	})
}
