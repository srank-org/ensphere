package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/openapi"
)

var (
	oaFile    string
	oaURL     string
	oaTimeout int
)

var openapiCmd = &cobra.Command{
	Use:   "openapi",
	Short: "Parse OpenAPI/Swagger specification",
	Long: `Parse an OpenAPI/Swagger specification and output structured endpoint inventory.

Reads a local file or fetches a remote URL, then extracts all endpoints,
parameters, request bodies, authentication requirements, and metadata.

Examples:
  ensphere openapi --file openapi.yaml
  ensphere openapi --url https://api.example.com/openapi.json
  ensphere openapi --url https://api.example.com/openapi.json --timeout 60`,
	RunE: runOpenAPI,
}

func init() {
	openapiCmd.Flags().StringVar(&oaFile, "file", "", "Local file path to OpenAPI spec (YAML or JSON)")
	openapiCmd.Flags().StringVar(&oaURL, "url", "", "Remote URL to fetch OpenAPI spec from")
	openapiCmd.Flags().IntVar(&oaTimeout, "timeout", 30, "HTTP timeout in seconds (for --url)")

	rootCmd.AddCommand(openapiCmd)
}

func runOpenAPI(cmd *cobra.Command, args []string) error {
	hasFile := oaFile != ""
	hasURL := oaURL != ""

	if hasFile == hasURL {
		fmt.Fprintln(os.Stderr, "exactly one of --file or --url must be provided")
		os.Exit(2)
	}

	var spec *openapi.Spec
	var err error

	if hasFile {
		spec, err = openapi.Parse(oaFile)
	} else {
		spec, err = openapi.ParseURL(oaURL, oaTimeout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %s\n", err)
		os.Exit(3)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(spec); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		os.Exit(3)
	}
	return nil
}
