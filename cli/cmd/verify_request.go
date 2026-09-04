package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	requestURL             string
	requestMethod          string
	requestBody            string
	requestResult          string
	requestNote            string
	requestRisk            int
	requestFollowRedirects bool
	requestProbe           probeFlags
)

var verifyRequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Send one analyst-constructed request through scope and the ledger",
	Long: `Send one request you construct yourself and record it in the evidence ledger
with the role it plays in the baseline, probe, control cycle.

Use it for any request shape no verify family anticipates: a workflow
transition, a multi-request sequence, a GraphQL mutation with variables, a
control for a family probe. The CLI contributes scope enforcement, the risk
ceiling, timing, hashes, header capture, and the ledger entry. It does not
interpret the response.

--result is required and names the request's role: baseline, probe, or
control. --risk is your declared payload risk (1 to 5, default 3) and is
checked against --max-risk. Redirects are not followed unless
--follow-redirects is set; every hop is scope-checked.

Examples:
  ensphere verify request --url "http://localhost:3000/api/orders/42/refund" --method POST \
    --header "Authorization: Bearer [TENANT_A_USER]" --result baseline --note "legitimate refund" --in-scope localhost
  ensphere verify request --url "http://localhost:3000/api/orders/42/refund" --method POST \
    --header "Authorization: Bearer [TENANT_A_USER]" --result probe --note "second refund of the same order" --in-scope localhost
  ensphere verify request --url "http://localhost:3000/api/orders/99999/refund" --method POST \
    --header "Authorization: Bearer [TENANT_A_USER]" --result control --note "nonexistent order" --in-scope localhost`,
	RunE: runVerifyRequest,
}

func init() {
	verifyRequestCmd.Flags().StringVar(&requestURL, "url", "", "Target URL (required)")
	verifyRequestCmd.Flags().StringVar(&requestMethod, "method", "GET", "HTTP method: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
	verifyRequestCmd.Flags().StringVar(&requestBody, "body", "", "Request body (at most 256 KiB)")
	verifyRequestCmd.Flags().StringVar(&requestResult, "result", "", "Role of this request: baseline, probe, or control (required)")
	verifyRequestCmd.Flags().StringVar(&requestNote, "note", "", "What this request is for, recorded in the ledger entry")
	verifyRequestCmd.Flags().IntVar(&requestRisk, "risk", 3, "Your declared payload risk, 1-5; checked against --max-risk")
	verifyRequestCmd.Flags().BoolVar(&requestFollowRedirects, "follow-redirects", false, "Follow redirects (each hop is scope-checked)")

	_ = verifyRequestCmd.MarkFlagRequired("url")
	_ = verifyRequestCmd.MarkFlagRequired("result")

	addProbeFlags(verifyRequestCmd, &requestProbe)

	verifyCmd.AddCommand(verifyRequestCmd)
}

func runVerifyRequest(cmd *cobra.Command, args []string) error {
	cfg := verify.RequestConfig{
		URL:             requestURL,
		Method:          requestMethod,
		Body:            requestBody,
		Result:          requestResult,
		Note:            requestNote,
		Risk:            requestRisk,
		FollowRedirects: requestFollowRedirects,
		ProbeConfig:     buildProbeConfig(&requestProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyRequest(cfg)
	})
}
