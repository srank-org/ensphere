package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	rlsProjectURL string
	rlsAnonKey    string
	rlsJWTSecret  string
	rlsTable      string
	rlsTenantA    string
	rlsTenantB    string
	rlsSelect     string
	rlsProbe      probeFlags
)

var verifyRLSCmd = &cobra.Command{
	Use:   "rls",
	Short: "Verify Supabase RLS tenant isolation",
	Long: `Verify Supabase Row Level Security by testing cross-tenant data access.

Constructs JWTs with different company_id claims and queries the PostgREST API
to check if tenant A can read tenant B's data.

Example:
  ensphere verify rls \
    --project-url http://127.0.0.1:54321 \
    --anon-key eyJ... \
    --jwt-secret super-secret-jwt-token-with-at-least-32-characters \
    --table invoices \
    --tenant-a uuid-company-a \
    --tenant-b uuid-company-b \
    --in-scope 127.0.0.1`,
	RunE: runVerifyRLS,
}

func init() {
	verifyRLSCmd.Flags().StringVar(&rlsProjectURL, "project-url", "", "Supabase project URL (required)")
	verifyRLSCmd.Flags().StringVar(&rlsAnonKey, "anon-key", "", "Supabase anon key (required)")
	verifyRLSCmd.Flags().StringVar(&rlsJWTSecret, "jwt-secret", "", "JWT signing secret (required)")
	verifyRLSCmd.Flags().StringVar(&rlsTable, "table", "", "Table to test (required)")
	verifyRLSCmd.Flags().StringVar(&rlsTenantA, "tenant-a", "", "Tenant A company ID (required)")
	verifyRLSCmd.Flags().StringVar(&rlsTenantB, "tenant-b", "", "Tenant B company ID (required)")
	verifyRLSCmd.Flags().StringVar(&rlsSelect, "select", "*", "Columns to select")
	addProbeFlags(verifyRLSCmd, &rlsProbe)

	_ = verifyRLSCmd.MarkFlagRequired("project-url")
	_ = verifyRLSCmd.MarkFlagRequired("anon-key")
	_ = verifyRLSCmd.MarkFlagRequired("jwt-secret")
	_ = verifyRLSCmd.MarkFlagRequired("table")
	_ = verifyRLSCmd.MarkFlagRequired("tenant-a")
	_ = verifyRLSCmd.MarkFlagRequired("tenant-b")

	verifyCmd.AddCommand(verifyRLSCmd)
}

func runVerifyRLS(cmd *cobra.Command, args []string) error {
	cfg := verify.RLSConfig{
		ProjectURL:  rlsProjectURL,
		AnonKey:     rlsAnonKey,
		JWTSecret:   rlsJWTSecret,
		Table:       rlsTable,
		TenantA:     rlsTenantA,
		TenantB:     rlsTenantB,
		Select:      rlsSelect,
		ProbeConfig: buildProbeConfig(&rlsProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyRLS(cfg)
	})
}
