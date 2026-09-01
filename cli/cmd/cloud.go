package cmd

import "github.com/spf13/cobra"

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Cloud security verification",
	Long: `Run cloud security verification probes against cloud provider resources.

Available subcommands:
  storage         Verify cloud storage security (S3, GCS, Azure Blob)
  iam             Verify cloud IAM configuration
  network         Verify cloud network security (security groups, firewalls)
  compute         Verify cloud compute security (Lambda, Cloud Functions, Azure Functions)
  logging         Verify cloud logging configuration (CloudTrail, GCP sinks, Azure diagnostics)
  secrets         Verify cloud secrets management (Secrets Manager, Secret Manager, Key Vault)`,
}

func init() {
	rootCmd.AddCommand(cloudCmd)
}
