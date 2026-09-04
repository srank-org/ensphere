package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/evidence"
)

var (
	evidQueryFile       string
	evidQueryID         string
	evidQueryResult     string
	evidQueryProbeType  string
	evidQueryFindingRef string
	evidQueryAfter      string
	evidQueryBefore     string
	evidQueryLimit      int
	evidQuerySummary    bool
)

var evidenceQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Read and filter evidence entries",
	Long: `Query evidence entries from a JSONL file with optional filters.

Examples:
  ensphere evidence query --file ./evidence.jsonl --result probe
  ensphere evidence query --file ./evidence.jsonl --probe-type sqli --limit 10
  ensphere evidence query --file ./evidence.jsonl --summary`,
	RunE: runEvidenceQuery,
}

func init() {
	evidenceQueryCmd.Flags().StringVar(&evidQueryFile, "file", "./evidence.jsonl", "Evidence file path")
	evidenceQueryCmd.Flags().StringVar(&evidQueryID, "id", "", "Filter by evidence ID")
	evidenceQueryCmd.Flags().StringVar(&evidQueryResult, "result", "", "Filter by result type")
	evidenceQueryCmd.Flags().StringVar(&evidQueryProbeType, "probe-type", "", "Filter by probe type")
	evidenceQueryCmd.Flags().StringVar(&evidQueryFindingRef, "finding-ref", "", "Filter by finding reference")
	evidenceQueryCmd.Flags().StringVar(&evidQueryAfter, "after", "", "Filter entries after this timestamp (RFC3339)")
	evidenceQueryCmd.Flags().StringVar(&evidQueryBefore, "before", "", "Filter entries before this timestamp (RFC3339)")
	evidenceQueryCmd.Flags().IntVar(&evidQueryLimit, "limit", 0, "Maximum entries to return")
	evidenceQueryCmd.Flags().BoolVar(&evidQuerySummary, "summary", false, "Show summary counts instead of entries")

	evidenceCmd.AddCommand(evidenceQueryCmd)
}

func runEvidenceQuery(cmd *cobra.Command, args []string) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if evidQuerySummary {
		entries, _, err := evidence.ReadAll(evidQueryFile)
		if err != nil {
			return err
		}

		byResult := make(map[string]int)
		byProbeType := make(map[string]int)
		for _, e := range entries {
			byResult[e.Result]++
			byProbeType[e.ProbeType]++
		}

		summary := struct {
			Total       int            `json:"total"`
			ByResult    map[string]int `json:"by_result"`
			ByProbeType map[string]int `json:"by_probe_type"`
		}{
			Total:       len(entries),
			ByResult:    byResult,
			ByProbeType: byProbeType,
		}

		return enc.Encode(summary)
	}

	filter := evidence.EntryFilter{
		ID:         evidQueryID,
		Result:     evidQueryResult,
		ProbeType:  evidQueryProbeType,
		FindingRef: evidQueryFindingRef,
		After:      evidQueryAfter,
		Before:     evidQueryBefore,
		Limit:      evidQueryLimit,
	}

	entries, err := evidence.ReadFiltered(evidQueryFile, filter)
	if err != nil {
		return fmt.Errorf("query evidence: %w", err)
	}

	if entries == nil {
		entries = []evidence.Entry{}
	}

	return enc.Encode(entries)
}
