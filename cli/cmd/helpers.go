package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/srank/ensphere/internal/verify"
)

var errUsage = errors.New("usage error")
var osExit = os.Exit

// probeFlags holds the flags every verify probe shares. Register them with
// addProbeFlags and turn them into a verify.ProbeConfig with buildProbeConfig.
type probeFlags struct {
	inScope  []string
	maxRisk  int
	throttle int
	timeout  int
	headers  []string
	evidence string
}

// addProbeFlags registers the shared verify flags on cmd and marks --in-scope
// required. Every verify_*.go command uses this; probes with extra required
// flags mark those separately.
func addProbeFlags(cmd *cobra.Command, f *probeFlags) {
	cmd.Flags().StringSliceVar(&f.inScope, "in-scope", nil, "In-scope patterns: globs (*.example.com) or CIDR (10.0.0.0/8) (required)")
	cmd.Flags().IntVar(&f.maxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	cmd.Flags().IntVar(&f.throttle, "throttle", 500, "Milliseconds between probes")
	cmd.Flags().IntVar(&f.timeout, "timeout", 10, "HTTP request timeout in seconds")
	cmd.Flags().StringSliceVar(&f.headers, "header", nil, "Custom headers (key:value, repeatable)")
	cmd.Flags().StringVar(&f.evidence, "evidence", "./evidence.jsonl", "Evidence file path")
	_ = cmd.MarkFlagRequired("in-scope")
}

// buildProbeConfig turns shared flag values into a ProbeConfig. It exits the
// process on a malformed --header, matching the other verify error paths.
func buildProbeConfig(f *probeFlags) verify.ProbeConfig {
	return verify.ProbeConfig{
		InScope:    f.inScope,
		MaxRisk:    f.maxRisk,
		ThrottleMs: f.throttle,
		TimeoutSec: f.timeout,
		Headers:    mustParseHeaders(f.headers),
		Evidence:   f.evidence,
	}
}

func parseHeaders(raw []string) (map[string]string, error) {
	headers := make(map[string]string)
	for _, h := range raw {
		key, value, ok := strings.Cut(h, ":")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" {
			return nil, fmt.Errorf("%w: malformed --header %q (expected key:value)", errUsage, h)
		}
		headers[key] = value
	}
	return headers, nil
}

func mustParseHeaders(raw []string) map[string]string {
	headers, err := parseHeaders(raw)
	if err != nil {
		writeVerifyError(err)
		osExit(exitForVerifyError(err))
		return nil
	}
	return headers
}

func encodeJSON(out interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func exitForVerifyError(err error) int {
	var scopeErr *verify.ScopeError
	if errors.As(err, &scopeErr) || errors.Is(err, errUsage) {
		return 2
	}
	return 3
}

func runVerify(fn func() (*verify.ProbeResult, error)) error {
	result, err := fn()
	if err != nil {
		writeVerifyError(err)
		osExit(exitForVerifyError(err))
	}
	if err := encodeJSON(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		osExit(3)
	}
	return nil
}

func writeVerifyError(err error) {
	var scopeErr *verify.ScopeError
	switch {
	case errors.As(err, &scopeErr):
		fmt.Fprintf(os.Stderr, "scope error: %s\n", err)
	case errors.Is(err, errUsage):
		fmt.Fprintf(os.Stderr, "usage error: %s\n", err)
	default:
		fmt.Fprintf(os.Stderr, "probe error: %s\n", err)
	}
}
