package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/enums"
	"github.com/srank/ensphere/internal/payloads"
)

var (
	payloadDB          string
	payloadRuntime     string
	payloadTechnique   string
	payloadSurface     string
	payloadContentType string
	payloadEncoding    string
	payloadBoundary    string
	payloadTag         string
	payloadMaxRisk     int
	payloadLimit       int
)

var payloadsCmd = &cobra.Command{
	Use:   "payloads <vuln_type>",
	Short: "Query the curated payload database",
	Long: `Query curated security testing payloads by vulnerability type and context filters.

Supported vuln_types: auth_bypass, cache_poisoning, cmdi, cors, csrf, csv_injection, file_upload, graphql, header_injection, idor, jwt, ldap, lfi, nosql, prototype_pollution, race_condition, redirect, sqli, ssrf, ssti, xpath, xss, xxe

Note: clickjacking is a verify-only type with no payloads (detection is header-based).

Examples:
  ensphere payloads sqli --db postgres --technique blind_time
  ensphere payloads ssrf --max-risk 2
  ensphere payloads csv_injection
  ensphere payloads sqli --tag pg_sleep --limit 5`,
	Args: cobra.ExactArgs(1),
	RunE: runPayloads,
}

func init() {
	payloadsCmd.Flags().StringVar(&payloadDB, "db", "", "Database engine (postgres, mysql, mssql, sqlite, oracle)")
	payloadsCmd.Flags().StringVar(&payloadRuntime, "runtime", "", "Runtime (node, jvm, python, php, dotnet, ruby, go)")
	payloadsCmd.Flags().StringVar(&payloadTechnique, "technique", "", "Technique (e.g. blind_time, error_based, union, metadata_access)")
	payloadsCmd.Flags().StringVar(&payloadSurface, "surface", "", "Injection surface (query, path, header, cookie, json_body, form_body)")
	payloadsCmd.Flags().StringVar(&payloadContentType, "content-type", "", "Content type (application/json, etc.)")
	payloadsCmd.Flags().StringVar(&payloadEncoding, "encoding", "", "Encoding (raw, url, double_url, unicode, hex, base64)")
	payloadsCmd.Flags().StringVar(&payloadBoundary, "boundary", "", "String boundary (single_quote, double_quote, numeric, unquoted)")
	payloadsCmd.Flags().StringVar(&payloadTag, "tag", "", "Filter by tag")
	payloadsCmd.Flags().IntVar(&payloadMaxRisk, "max-risk", 3, "Maximum risk level (1-5, 0=no limit)")
	payloadsCmd.Flags().IntVar(&payloadLimit, "limit", 20, "Maximum results to return")

	rootCmd.AddCommand(payloadsCmd)
}

func runPayloads(cmd *cobra.Command, args []string) error {
	if err := enums.ValidateFilter(args[0], payloadDB, payloadRuntime, payloadTechnique, payloadSurface, payloadEncoding, payloadBoundary); err != nil {
		return err
	}

	store, err := payloads.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return err
	}

	filter := payloads.PayloadFilter{
		VulnType:    args[0],
		DBEngine:    payloadDB,
		Runtime:     payloadRuntime,
		Technique:   payloadTechnique,
		Surface:     payloadSurface,
		ContentType: payloadContentType,
		Encoding:    payloadEncoding,
		Boundary:    payloadBoundary,
		Tag:         payloadTag,
		MaxRisk:     payloadMaxRisk,
		Limit:       payloadLimit,
	}

	output := store.Query(filter)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}
