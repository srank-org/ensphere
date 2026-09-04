package verify

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// CSRFConfig holds configuration for CSRF verification.
type CSRFConfig struct {
	URL    string
	Method string
	Token  string // valid auth token
	ProbeConfig
}

var csrfTokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)csrf[_-]?token`),
	regexp.MustCompile(`(?i)_token`),
	regexp.MustCompile(`(?i)authenticity_token`),
	regexp.MustCompile(`(?i)__RequestVerificationToken`),
}

// VerifyCSRF runs the CSRF verification probe.
func VerifyCSRF(cfg CSRFConfig) (*ProbeResult, error) {
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

	baseHeaders := make(map[string]string)
	for k, v := range cfg.Headers {
		baseHeaders[k] = v
	}
	if cfg.Token != "" {
		baseHeaders["Authorization"] = "Bearer " + cfg.Token
	}

	// Baseline: normal request with Origin
	throttle.Wait()
	probeCount++
	baselineHeaders := make(map[string]string)
	for k, v := range baseHeaders {
		baselineHeaders[k] = v
	}
	baselineHeaders["Origin"] = "https://legitimate-origin.com"
	baselineResp := HTTPProbe(cfg.Method, cfg.URL, "", baselineHeaders, cfg.TimeoutSec, cfg.InScope)
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d\n", baselineResp.StatusCode)
	writeEvidence(ew, "csrf", "origin_validation", cfg.URL, "", baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "with Origin header")

	// Probe 1: No Origin/Referer
	throttle.Wait()
	probeCount++
	noOriginHeaders := make(map[string]string)
	for k, v := range baseHeaders {
		noOriginHeaders[k] = v
	}
	noOriginResp := HTTPProbe(cfg.Method, cfg.URL, "", noOriginHeaders, cfg.TimeoutSec, cfg.InScope)
	if noOriginResp.Error != nil {
		return nil, fmt.Errorf("no-origin probe: %w", noOriginResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[NO ORIGIN] status=%d\n", noOriginResp.StatusCode)
	writeEvidence(ew, "csrf", "origin_validation", cfg.URL, "", noOriginResp.StatusCode,
		fmt.Sprintf("%dms", noOriginResp.ElapsedMs), "probe", "without Origin header")

	// Probe 2: Mismatched Origin
	throttle.Wait()
	probeCount++
	mismatchHeaders := make(map[string]string)
	for k, v := range baseHeaders {
		mismatchHeaders[k] = v
	}
	mismatchHeaders["Origin"] = "https://evil.com"
	mismatchResp := HTTPProbe(cfg.Method, cfg.URL, "", mismatchHeaders, cfg.TimeoutSec, cfg.InScope)
	if mismatchResp.Error != nil {
		return nil, fmt.Errorf("mismatch-origin probe: %w", mismatchResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[MISMATCH ORIGIN] status=%d\n", mismatchResp.StatusCode)
	writeEvidence(ew, "csrf", "origin_validation", cfg.URL, "", mismatchResp.StatusCode,
		fmt.Sprintf("%dms", mismatchResp.ElapsedMs), "probe", "Origin: https://evil.com")

	sameSiteFound := false
	sameSiteValue := ""
	for _, cookie := range baselineResp.Headers.Values("Set-Cookie") {
		lower := strings.ToLower(cookie)
		if strings.Contains(lower, "samesite") {
			sameSiteFound = true
			if strings.Contains(lower, "samesite=strict") {
				sameSiteValue = "Strict"
			} else if strings.Contains(lower, "samesite=lax") {
				sameSiteValue = "Lax"
			} else if strings.Contains(lower, "samesite=none") {
				sameSiteValue = "None"
			}
			break
		}
	}

	csrfTokenInBody := false
	for _, re := range csrfTokenPatterns {
		if re.MatchString(baselineResp.Body) {
			csrfTokenInBody = true
			break
		}
	}

	baseline := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	noOrigin := RoundResult{
		StatusCode: noOriginResp.StatusCode,
		ElapsedMs:  noOriginResp.ElapsedMs,
		BodyHash:   noOriginResp.BodyHash,
		BodyLength: len(noOriginResp.Body),
	}
	mismatchOrigin := RoundResult{
		StatusCode: mismatchResp.StatusCode,
		ElapsedMs:  mismatchResp.ElapsedMs,
		BodyHash:   mismatchResp.BodyHash,
		BodyLength: len(mismatchResp.Body),
	}

	return &ProbeResult{
		VulnType:   "csrf",
		Technique:  "origin_validation",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: CSRFMeasurements{
			NoOrigin:        noOrigin,
			MismatchOrigin:  mismatchOrigin,
			Baseline:        baseline,
			SameSiteFound:   sameSiteFound,
			SameSiteValue:   sameSiteValue,
			CSRFTokenInBody: csrfTokenInBody,
		},
	}, nil
}
