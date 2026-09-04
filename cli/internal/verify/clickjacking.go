package verify

import (
	"fmt"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// ClickjackingConfig holds configuration for clickjacking verification.
type ClickjackingConfig struct {
	URL    string
	Method string
	ProbeConfig
}

// VerifyClickjacking runs the clickjacking header inspection probe.
func VerifyClickjacking(cfg ClickjackingConfig) (*ProbeResult, error) {
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

	throttle.Wait()
	probeCount++

	resp := HTTPProbe(cfg.Method, cfg.URL, "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
	if resp.Error != nil {
		return nil, fmt.Errorf("clickjacking probe: %w", resp.Error)
	}

	xfo := resp.Headers.Get("X-Frame-Options")
	csp := resp.Headers.Get("Content-Security-Policy")

	cspFrameAncestors := ""
	for _, directive := range strings.Split(csp, ";") {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(strings.ToLower(directive), "frame-ancestors") {
			cspFrameAncestors = directive
			break
		}
	}

	xfoPresent := xfo != ""
	cspFAPresent := cspFrameAncestors != ""

	fmt.Fprintf(os.Stderr, "[PROBE] status=%d xfo=%q csp_fa=%q\n", resp.StatusCode, xfo, cspFrameAncestors)
	writeEvidence(ew, "clickjacking", "frame_header_check", cfg.URL, "", resp.StatusCode,
		fmt.Sprintf("%dms", resp.ElapsedMs), "probe",
		fmt.Sprintf("xfo=%q csp_frame_ancestors=%q", xfo, cspFrameAncestors))

	return &ProbeResult{
		VulnType:   "clickjacking",
		Technique:  "frame_header_check",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: ClickjackingMeasurements{
			Probe: RoundResult{
				StatusCode: resp.StatusCode,
				ElapsedMs:  resp.ElapsedMs,
				BodyHash:   resp.BodyHash,
				BodyLength: len(resp.Body),
			},
			XFrameOptions:     xfo,
			CSPFrameAncestors: cspFrameAncestors,
			XFOPresent:        xfoPresent,
			CSPFAPresent:      cspFAPresent,
		},
	}, nil
}
