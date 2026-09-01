package verify

import (
	"fmt"
	"os"

	"github.com/srank/ensphere/internal/evidence"
)

// AuthZConfig holds configuration for authorization bypass verification.
type AuthZConfig struct {
	URL           string
	Method        string
	LowPrivToken  string
	HighPrivToken string
	ProbeConfig
}

// VerifyAuthZ runs the authorization bypass verification probe.
func VerifyAuthZ(cfg AuthZConfig) (*ProbeResult, error) {
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
	writeEvidence(ew, "authz", "role_differential", cfg.URL, "", highResp.StatusCode,
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
	writeEvidence(ew, "authz", "role_differential", cfg.URL, "", lowResp.StatusCode,
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

	return &ProbeResult{
		VulnType:   "authz",
		Technique:  "role_differential",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: AuthZMeasurements{
			HighPriv:        highRound,
			LowPriv:         lowRound,
			StatusMatch:     highResp.StatusCode == lowResp.StatusCode,
			BodyLengthDelta: len(lowResp.Body) - len(highResp.Body),
			HashesMatch:     highResp.BodyHash == lowResp.BodyHash,
		},
	}, nil
}
