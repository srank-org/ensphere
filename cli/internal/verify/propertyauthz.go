package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/srank/ensphere/internal/evidence"
)

// PropertyAuthZConfig holds configuration for property-level authorization verification.
type PropertyAuthZConfig struct {
	URL           string
	Method        string
	HighPrivToken string
	LowPrivToken  string
	WatchFields   []string // optional specific fields to check
	ProbeConfig
}

// VerifyPropertyAuthZ runs the property-level authorization verification probe.
func VerifyPropertyAuthZ(cfg PropertyAuthZConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
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

	probeCount := 0

	// High-privilege request
	highHeaders := make(map[string]string)
	for k, v := range cfg.Headers {
		highHeaders[k] = v
	}
	highHeaders["Authorization"] = "Bearer " + cfg.HighPrivToken

	throttle.Wait()
	probeCount++
	highResp := HTTPProbeNoRedirect(cfg.Method, cfg.URL, "", highHeaders, cfg.TimeoutSec, cfg.InScope)
	if highResp.Error != nil {
		return nil, fmt.Errorf("high-priv probe: %w", highResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[HIGH PRIV] status=%d len=%d\n", highResp.StatusCode, len(highResp.Body))
	writeEvidence(ew, "property_authz", "role_differential", cfg.URL, "", highResp.StatusCode,
		fmt.Sprintf("%dms", highResp.ElapsedMs), "baseline", "high-privilege token")

	// Low-privilege request
	lowHeaders := make(map[string]string)
	for k, v := range cfg.Headers {
		lowHeaders[k] = v
	}
	lowHeaders["Authorization"] = "Bearer " + cfg.LowPrivToken

	throttle.Wait()
	probeCount++
	lowResp := HTTPProbeNoRedirect(cfg.Method, cfg.URL, "", lowHeaders, cfg.TimeoutSec, cfg.InScope)
	if lowResp.Error != nil {
		return nil, fmt.Errorf("low-priv probe: %w", lowResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[LOW PRIV] status=%d len=%d\n", lowResp.StatusCode, len(lowResp.Body))
	writeEvidence(ew, "property_authz", "role_differential", cfg.URL, "", lowResp.StatusCode,
		fmt.Sprintf("%dms", lowResp.ElapsedMs), "probe", "low-privilege token")

	highRound := RoundResult{
		StatusCode: highResp.StatusCode,
		ElapsedMs:  highResp.ElapsedMs,
		BodyHash:   highResp.BodyHash,
		BodyLength: len(highResp.Body),
	}
	lowRound := RoundResult{
		StatusCode: lowResp.StatusCode,
		ElapsedMs:  lowResp.ElapsedMs,
		BodyHash:   lowResp.BodyHash,
		BodyLength: len(lowResp.Body),
	}

	// Extract top-level JSON keys from both responses
	highFields := extractTopLevelKeys(highResp.Body)
	lowFields := extractTopLevelKeys(lowResp.Body)

	shared, highOnly, lowOnly := fieldSets(highFields, lowFields)

	// Check watch fields
	var watchResults []WatchFieldResult
	if len(cfg.WatchFields) > 0 {
		highSet := toSet(highFields)
		lowSet := toSet(lowFields)
		for _, f := range cfg.WatchFields {
			watchResults = append(watchResults, WatchFieldResult{
				Name:       f,
				InHighPriv: highSet[f],
				InLowPriv:  lowSet[f],
			})
		}
	}

	return &ProbeResult{
		VulnType:   "property_authz",
		Technique:  "role_differential",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: PropertyAuthZMeasurements{
			HighPriv:           highRound,
			LowPriv:            lowRound,
			HighPrivFields:     highFields,
			LowPrivFields:      lowFields,
			SharedFields:       shared,
			HighPrivOnlyFields: highOnly,
			LowPrivOnlyFields:  lowOnly,
			WatchFieldResults:  watchResults,
			BodyLengthDelta:    len(lowResp.Body) - len(highResp.Body),
			HashesMatch:        highResp.BodyHash == lowResp.BodyHash,
		},
	}, nil
}

// extractTopLevelKeys parses a JSON object and returns sorted top-level keys.
// Returns nil for non-JSON responses.
func extractTopLevelKeys(body string) []string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return nil
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// fieldSets returns shared, aOnly, bOnly field lists.
func fieldSets(a, b []string) (shared, aOnly, bOnly []string) {
	aSet := toSet(a)
	bSet := toSet(b)

	for _, k := range a {
		if bSet[k] {
			shared = append(shared, k)
		} else {
			aOnly = append(aOnly, k)
		}
	}
	for _, k := range b {
		if !aSet[k] {
			bOnly = append(bOnly, k)
		}
	}
	return
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	return m
}
