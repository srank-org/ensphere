package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	gqlURL       string
	gqlTechnique string
	gqlToken     string
	gqlMethod    string
	gqlProbe     probeFlags
)

var verifyGraphQLCmd = &cobra.Command{
	Use:   "graphql",
	Short: "Verify GraphQL abuse vulnerability",
	Long: `Verify GraphQL abuse via introspection, batch queries, or nested query DoS.

Techniques:
  introspection  Check if introspection is enabled
  batch_query    Check if batch queries are accepted
  nested_query_dos     Measure timing of deeply nested queries

Examples:
  ensphere verify graphql --url "http://target/graphql" --technique introspection --in-scope "*.target.com"
  ensphere verify graphql --url "http://target/graphql" --technique batch_query --token "jwt" --in-scope "*.target.com"`,
	RunE: runVerifyGraphQL,
}

func init() {
	verifyGraphQLCmd.Flags().StringVar(&gqlURL, "url", "", "Target GraphQL URL (required)")
	verifyGraphQLCmd.Flags().StringVar(&gqlTechnique, "technique", "", "Technique: introspection, batch_query, nested_query_dos (required)")
	verifyGraphQLCmd.Flags().StringVar(&gqlToken, "token", "", "Auth token (optional)")
	verifyGraphQLCmd.Flags().StringVar(&gqlMethod, "method", "POST", "HTTP method")

	_ = verifyGraphQLCmd.MarkFlagRequired("url")
	_ = verifyGraphQLCmd.MarkFlagRequired("technique")

	addProbeFlags(verifyGraphQLCmd, &gqlProbe)

	verifyCmd.AddCommand(verifyGraphQLCmd)
}

func runVerifyGraphQL(cmd *cobra.Command, args []string) error {

	cfg := verify.GraphQLConfig{
		URL:         gqlURL,
		Technique:   gqlTechnique,
		Token:       gqlToken,
		Method:      gqlMethod,
		ProbeConfig: buildProbeConfig(&gqlProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyGraphQL(cfg)
	})
}
