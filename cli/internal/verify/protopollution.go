package verify

import (
	"fmt"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// ProtoPollutionConfig holds configuration for prototype pollution verification.
type ProtoPollutionConfig struct {
	URL       string
	Method    string
	Technique string // proto_assignment | constructor_pollution | json_merge
	ProbeConfig
}

var protoPollutionPayloads = map[string]string{
	"proto_assignment":      `{"__proto__":{"polluted":"ensphere_pp_test"}}`,
	"constructor_pollution": `{"constructor":{"prototype":{"polluted":"ensphere_pp_test"}}}`,
	"json_merge":            `{"__proto__":{"polluted":"ensphere_pp_test"},"constructor":{"prototype":{"polluted":"ensphere_pp_test"}}}`,
}

var validProtoPollutionTechniques = map[string]bool{
	"proto_assignment": true, "constructor_pollution": true, "json_merge": true,
}

// VerifyProtoPollution runs the prototype pollution verification probe.
func VerifyProtoPollution(cfg ProtoPollutionConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validProtoPollutionTechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: proto_assignment, constructor_pollution, json_merge", cfg.Technique)}
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

	probeCount := 0

	// Baseline: clean GET request
	throttle.Wait()
	probeCount++
	baselineResp := HTTPProbe("GET", cfg.URL, "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d hash=%s\n", baselineResp.StatusCode, baselineResp.BodyHash[:16])
	writeEvidence(ew, "prototype_pollution", cfg.Technique, cfg.URL, "", baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "")

	// Injection probe
	payload := protoPollutionPayloads[cfg.Technique]
	throttle.Wait()
	probeCount++
	injectionResp := HTTPProbe(cfg.Method, cfg.URL, payload, headers, cfg.TimeoutSec, cfg.InScope)
	if injectionResp.Error != nil {
		return nil, fmt.Errorf("injection probe: %w", injectionResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[INJECTION] status=%d\n", injectionResp.StatusCode)
	writeEvidence(ew, "prototype_pollution", cfg.Technique, cfg.URL, "", injectionResp.StatusCode,
		fmt.Sprintf("%dms", injectionResp.ElapsedMs), "probe", fmt.Sprintf("payload=%s", payload))

	// Verify: clean GET again to check if pollution persisted
	throttle.Wait()
	probeCount++
	verifyResp := HTTPProbe("GET", cfg.URL, "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
	if verifyResp.Error != nil {
		return nil, fmt.Errorf("verify probe: %w", verifyResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[VERIFY] status=%d hash=%s\n", verifyResp.StatusCode, verifyResp.BodyHash[:16])
	writeEvidence(ew, "prototype_pollution", cfg.Technique, cfg.URL, "", verifyResp.StatusCode,
		fmt.Sprintf("%dms", verifyResp.ElapsedMs), "probe", "verify after injection")

	// Did the injected marker key and value appear in the post-injection
	// response body? This is a raw reflection measurement, not a verdict.
	const markerKey = "polluted"
	const markerValue = "ensphere_pp_test"
	markerReflected := strings.Contains(verifyResp.Body, markerKey) && strings.Contains(verifyResp.Body, markerValue)

	snippet := verifyResp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	baseline := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	injection := RoundResult{
		StatusCode: injectionResp.StatusCode,
		ElapsedMs:  injectionResp.ElapsedMs,
		BodyHash:   injectionResp.BodyHash,
		BodyLength: len(injectionResp.Body),
	}
	verify := RoundResult{
		StatusCode: verifyResp.StatusCode,
		ElapsedMs:  verifyResp.ElapsedMs,
		BodyHash:   verifyResp.BodyHash,
		BodyLength: len(verifyResp.Body),
	}

	return &ProbeResult{
		VulnType:   "prototype_pollution",
		Technique:  cfg.Technique,
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: ProtoPollutionMeasurements{
			Technique:       cfg.Technique,
			Baseline:        baseline,
			InjectionProbe:  injection,
			VerifyProbe:     verify,
			HashesMatch:     baselineResp.BodyHash == verifyResp.BodyHash,
			MarkerReflected: markerReflected,
			PayloadUsed:     payload,
			ResponseSnippet: snippet,
		},
	}, nil
}
