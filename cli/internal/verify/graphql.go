package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// GraphQLConfig holds configuration for GraphQL abuse verification.
type GraphQLConfig struct {
	URL       string
	Technique string // introspection | batch_query | nested_query_dos
	Token     string // optional auth token
	Method    string // HTTP method (default POST)
	ProbeConfig
}

var validGraphQLTechniques = map[string]bool{
	"introspection": true, "batch_query": true, "nested_query_dos": true,
}

// VerifyGraphQL runs the GraphQL abuse verification probe.
func VerifyGraphQL(cfg GraphQLConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validGraphQLTechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: introspection, batch_query, nested_query_dos", cfg.Technique)}
	}

	timer := NewTimer()
	throttle := NewThrottle(cfg.ThrottleMs)

	var ew *evidence.Writer
	if cfg.Evidence != "" {
		var err error
		ew, err = evidence.NewWriter(cfg.Evidence)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not open evidence file: %v\n", err)
		} else {
			defer ew.Close()
		}
	}

	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	headers["Content-Type"] = "application/json"
	if cfg.Token != "" {
		headers["Authorization"] = "Bearer " + cfg.Token
	}

	switch cfg.Technique {
	case "introspection":
		return verifyGraphQLIntrospection(cfg, headers, throttle, timer, ew)
	case "batch_query":
		return verifyGraphQLBatch(cfg, headers, throttle, timer, ew)
	case "nested_query_dos":
		return verifyGraphQLNestedDOS(cfg, headers, throttle, timer, ew)
	default:
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q", cfg.Technique)}
	}
}

func verifyGraphQLIntrospection(cfg GraphQLConfig, headers map[string]string, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	query := `{"query":"{ __schema { types { name } } }"}`

	throttle.Wait()
	probeCount++
	resp := HTTPProbe(cfg.Method, cfg.URL, query, headers, cfg.TimeoutSec, cfg.InScope)
	if resp.Error != nil {
		return nil, fmt.Errorf("introspection probe: %w", resp.Error)
	}

	introspectionEnabled := false
	typeCount := 0
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &result); err == nil {
		if data, ok := result["data"].(map[string]interface{}); ok {
			if schema, ok := data["__schema"].(map[string]interface{}); ok {
				if types, ok := schema["types"].([]interface{}); ok {
					introspectionEnabled = true
					typeCount = len(types)
				}
			}
		}
	}

	snippet := resp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	fmt.Fprintf(os.Stderr, "[INTROSPECTION] status=%d enabled=%v types=%d\n", resp.StatusCode, introspectionEnabled, typeCount)
	writeEvidence(ew, "graphql", "introspection", cfg.URL, "", resp.StatusCode,
		fmt.Sprintf("%dms", resp.ElapsedMs), "probe",
		fmt.Sprintf("enabled=%v types=%d", introspectionEnabled, typeCount))

	probe := RoundResult{
		StatusCode: resp.StatusCode,
		ElapsedMs:  resp.ElapsedMs,
		BodyHash:   resp.BodyHash,
		BodyLength: len(resp.Body),
	}

	return &ProbeResult{
		VulnType:   "graphql",
		Technique:  "introspection",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: GraphQLMeasurements{
			Technique:            "introspection",
			Probe:                probe,
			IntrospectionEnabled: &introspectionEnabled,
			TypeCount:            &typeCount,
			PayloadUsed:          query,
			ResponseSnippet:      snippet,
		},
	}, nil
}

func verifyGraphQLBatch(cfg GraphQLConfig, headers map[string]string, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	query := `[{"query":"{ __typename }"},{"query":"{ __typename }"}]`

	throttle.Wait()
	probeCount++
	resp := HTTPProbe(cfg.Method, cfg.URL, query, headers, cfg.TimeoutSec, cfg.InScope)
	if resp.Error != nil {
		return nil, fmt.Errorf("batch query probe: %w", resp.Error)
	}

	// Check if response is a JSON array (batch accepted)
	batchAccepted := false
	trimmed := strings.TrimSpace(resp.Body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []interface{}
		if err := json.Unmarshal([]byte(trimmed), &arr); err == nil && len(arr) > 1 {
			batchAccepted = true
		}
	}

	snippet := resp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	fmt.Fprintf(os.Stderr, "[BATCH] status=%d accepted=%v\n", resp.StatusCode, batchAccepted)
	writeEvidence(ew, "graphql", "batch_query", cfg.URL, "", resp.StatusCode,
		fmt.Sprintf("%dms", resp.ElapsedMs), "probe",
		fmt.Sprintf("batch_accepted=%v", batchAccepted))

	probe := RoundResult{
		StatusCode: resp.StatusCode,
		ElapsedMs:  resp.ElapsedMs,
		BodyHash:   resp.BodyHash,
		BodyLength: len(resp.Body),
	}

	return &ProbeResult{
		VulnType:   "graphql",
		Technique:  "batch_query",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: GraphQLMeasurements{
			Technique:       "batch_query",
			Probe:           probe,
			BatchAccepted:   &batchAccepted,
			PayloadUsed:     query,
			ResponseSnippet: snippet,
		},
	}, nil
}

func verifyGraphQLNestedDOS(cfg GraphQLConfig, headers map[string]string, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	// Baseline: simple query
	baselineQuery := `{"query":"{ __typename }"}`
	throttle.Wait()
	probeCount++
	baselineResp := HTTPProbe(cfg.Method, cfg.URL, baselineQuery, headers, cfg.TimeoutSec, cfg.InScope)
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] %dms\n", baselineResp.ElapsedMs)

	// Deeply nested query
	nestedQuery := `{"query":"{ __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }"}`
	throttle.Wait()
	probeCount++
	probeResp := HTTPProbe(cfg.Method, cfg.URL, nestedQuery, headers, cfg.TimeoutSec, cfg.InScope)
	if probeResp.Error != nil {
		return nil, fmt.Errorf("nested DOS probe: %w", probeResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[NESTED] %dms\n", probeResp.ElapsedMs)

	writeEvidence(ew, "graphql", "nested_query_dos", cfg.URL, "", probeResp.StatusCode,
		fmt.Sprintf("%dms", probeResp.ElapsedMs), "probe",
		fmt.Sprintf("baseline=%dms nested=%dms", baselineResp.ElapsedMs, probeResp.ElapsedMs))

	snippet := probeResp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	probe := RoundResult{
		StatusCode: probeResp.StatusCode,
		ElapsedMs:  probeResp.ElapsedMs,
		BodyHash:   probeResp.BodyHash,
		BodyLength: len(probeResp.Body),
	}
	baseline := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	delta := probeResp.ElapsedMs - baselineResp.ElapsedMs

	return &ProbeResult{
		VulnType:   "graphql",
		Technique:  "nested_query_dos",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: GraphQLMeasurements{
			Technique:       "nested_query_dos",
			Probe:           probe,
			Baseline:        &baseline,
			DeltaMs:         &delta,
			PayloadUsed:     nestedQuery,
			ResponseSnippet: snippet,
		},
	}, nil
}
