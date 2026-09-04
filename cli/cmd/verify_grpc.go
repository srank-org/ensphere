package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	grpcURL       string
	grpcTechnique string
	grpcTLSVerify bool
	grpcProbe     probeFlags
)

var verifyGRPCCmd = &cobra.Command{
	Use:   "grpc",
	Short: "Verify gRPC security",
	Long: `Verify gRPC security via reflection probing and plaintext transport detection.

Techniques:
  grpc_reflection  Check if gRPC server reflection is enabled (exposes service inventory)
  grpc_plaintext   Check if server accepts plaintext (h2c) vs requiring TLS

Examples:
  ensphere verify grpc --url "https://target:50051" --technique grpc_reflection --in-scope "*.target.com"
  ensphere verify grpc --url "http://target:50051" --technique grpc_plaintext --in-scope "*.target.com"`,
	RunE: runVerifyGRPC,
}

func init() {
	verifyGRPCCmd.Flags().StringVar(&grpcURL, "url", "", "Target gRPC URL (required)")
	verifyGRPCCmd.Flags().StringVar(&grpcTechnique, "technique", "", "Technique: grpc_reflection, grpc_plaintext (required)")
	verifyGRPCCmd.Flags().BoolVar(&grpcTLSVerify, "tls-verify", true, "Verify the server TLS certificate")

	_ = verifyGRPCCmd.MarkFlagRequired("url")
	_ = verifyGRPCCmd.MarkFlagRequired("technique")

	addProbeFlags(verifyGRPCCmd, &grpcProbe)

	verifyCmd.AddCommand(verifyGRPCCmd)
}

func runVerifyGRPC(cmd *cobra.Command, args []string) error {

	cfg := verify.GRPCConfig{
		URL:         grpcURL,
		Technique:   grpcTechnique,
		TLSVerify:   grpcTLSVerify,
		ProbeConfig: buildProbeConfig(&grpcProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyGRPC(cfg)
	})
}
