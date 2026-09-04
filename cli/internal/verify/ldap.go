package verify

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// LDAPConfig holds configuration for LDAP injection verification.
type LDAPConfig struct {
	URL       string
	Param     string
	Technique string // ldap_filter_injection | ldap_blind_boolean | ldap_blind_error
	Method    string
	ProbeConfig
}

var validLDAPTechniques = map[string]bool{
	"ldap_filter_injection": true, "ldap_blind_boolean": true, "ldap_blind_error": true,
}

var ldapErrorPatterns = []string{
	"LDAP", "ldap_search", "javax.naming", "NamingException",
	"Invalid filter", "Bad search filter", "LDAP_FILTER_ERROR",
}

// VerifyLDAP runs the LDAP injection verification probe.
func VerifyLDAP(cfg LDAPConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validLDAPTechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: ldap_filter_injection, ldap_blind_boolean, ldap_blind_error", cfg.Technique)}
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

	switch cfg.Technique {
	case "ldap_filter_injection":
		return verifyLDAPFilterInjection(cfg, throttle, timer, ew)
	case "ldap_blind_boolean":
		return verifyLDAPBlindBoolean(cfg, throttle, timer, ew)
	case "ldap_blind_error":
		return verifyLDAPBlindError(cfg, throttle, timer, ew)
	default:
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q", cfg.Technique)}
	}
}

func verifyLDAPFilterInjection(cfg LDAPConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	// Baseline probe
	throttle.Wait()
	probeCount++
	baselineResp := probeWithLDAPParam(cfg, "test")
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d hash=%s\n", baselineResp.StatusCode, baselineResp.BodyHash[:16])
	writeEvidence(ew, "ldap", "ldap_filter_injection", cfg.URL, cfg.Param, baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "benign value: test")

	// Injection probe
	payload := "*)(uid=*))(|(uid=*"
	throttle.Wait()
	probeCount++
	probeResp := probeWithLDAPParam(cfg, payload)
	if probeResp.Error != nil {
		return nil, fmt.Errorf("injection probe: %w", probeResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[PROBE] status=%d hash=%s\n", probeResp.StatusCode, probeResp.BodyHash[:16])
	writeEvidence(ew, "ldap", "ldap_filter_injection", cfg.URL, cfg.Param, probeResp.StatusCode,
		fmt.Sprintf("%dms", probeResp.ElapsedMs), "probe", fmt.Sprintf("payload: %s", payload))

	baselineRound := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	probeRound := RoundResult{
		StatusCode: probeResp.StatusCode,
		ElapsedMs:  probeResp.ElapsedMs,
		BodyHash:   probeResp.BodyHash,
		BodyLength: len(probeResp.Body),
	}
	hashesMatch := baselineResp.BodyHash == probeResp.BodyHash

	var matchedPatterns []string
	for _, pattern := range ldapErrorPatterns {
		if strings.Contains(probeResp.Body, pattern) {
			matchedPatterns = append(matchedPatterns, pattern)
		}
	}

	snippet := probeResp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	return &ProbeResult{
		VulnType:   "ldap",
		Technique:  "ldap_filter_injection",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: LDAPMeasurements{
			Technique:       "ldap_filter_injection",
			Baseline:        &baselineRound,
			Probe:           &probeRound,
			HashesMatch:     &hashesMatch,
			MatchedPatterns: matchedPatterns,
			PayloadUsed:     payload,
			ResponseSnippet: snippet,
		},
	}, nil
}

func verifyLDAPBlindBoolean(cfg LDAPConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	truePayload := "admin)(|(cn=a*))"
	falsePayload := "admin)(|(cn=ZZZZZZZZZ*))"

	// True probe
	throttle.Wait()
	probeCount++
	trueResp := probeWithLDAPParam(cfg, truePayload)
	if trueResp.Error != nil {
		return nil, fmt.Errorf("true probe: %w", trueResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[TRUE] status=%d hash=%s\n", trueResp.StatusCode, trueResp.BodyHash[:16])
	writeEvidence(ew, "ldap", "ldap_blind_boolean", cfg.URL, cfg.Param, trueResp.StatusCode,
		fmt.Sprintf("%dms", trueResp.ElapsedMs), "probe", fmt.Sprintf("true condition: %s", truePayload))

	// False probe
	throttle.Wait()
	probeCount++
	falseResp := probeWithLDAPParam(cfg, falsePayload)
	if falseResp.Error != nil {
		return nil, fmt.Errorf("false probe: %w", falseResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[FALSE] status=%d hash=%s\n", falseResp.StatusCode, falseResp.BodyHash[:16])
	writeEvidence(ew, "ldap", "ldap_blind_boolean", cfg.URL, cfg.Param, falseResp.StatusCode,
		fmt.Sprintf("%dms", falseResp.ElapsedMs), "probe", fmt.Sprintf("false condition: %s", falsePayload))

	trueRound := RoundResult{
		StatusCode: trueResp.StatusCode,
		ElapsedMs:  trueResp.ElapsedMs,
		BodyHash:   trueResp.BodyHash,
		BodyLength: len(trueResp.Body),
	}
	falseRound := RoundResult{
		StatusCode: falseResp.StatusCode,
		ElapsedMs:  falseResp.ElapsedMs,
		BodyHash:   falseResp.BodyHash,
		BodyLength: len(falseResp.Body),
	}
	hashesMatch := trueResp.BodyHash == falseResp.BodyHash

	return &ProbeResult{
		VulnType:   "ldap",
		Technique:  "ldap_blind_boolean",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: LDAPMeasurements{
			Technique:    "ldap_blind_boolean",
			TrueProbe:    &trueRound,
			FalseProbe:   &falseRound,
			HashesMatch:  &hashesMatch,
			TruePayload:  truePayload,
			FalsePayload: falsePayload,
			PayloadUsed:  truePayload,
		},
	}, nil
}

func verifyLDAPBlindError(cfg LDAPConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	// Baseline probe
	throttle.Wait()
	probeCount++
	baselineResp := probeWithLDAPParam(cfg, "test")
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d hash=%s\n", baselineResp.StatusCode, baselineResp.BodyHash[:16])
	writeEvidence(ew, "ldap", "ldap_blind_error", cfg.URL, cfg.Param, baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "benign value: test")

	// Error probe with unbalanced parens
	payload := "admin)((("
	throttle.Wait()
	probeCount++
	probeResp := probeWithLDAPParam(cfg, payload)
	if probeResp.Error != nil {
		return nil, fmt.Errorf("error probe: %w", probeResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[PROBE] status=%d hash=%s\n", probeResp.StatusCode, probeResp.BodyHash[:16])
	writeEvidence(ew, "ldap", "ldap_blind_error", cfg.URL, cfg.Param, probeResp.StatusCode,
		fmt.Sprintf("%dms", probeResp.ElapsedMs), "probe", fmt.Sprintf("payload: %s", payload))

	baselineRound := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	probeRound := RoundResult{
		StatusCode: probeResp.StatusCode,
		ElapsedMs:  probeResp.ElapsedMs,
		BodyHash:   probeResp.BodyHash,
		BodyLength: len(probeResp.Body),
	}
	hashesMatch := baselineResp.BodyHash == probeResp.BodyHash

	var matchedPatterns []string
	for _, pattern := range ldapErrorPatterns {
		if strings.Contains(probeResp.Body, pattern) {
			matchedPatterns = append(matchedPatterns, pattern)
		}
	}

	snippet := probeResp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	return &ProbeResult{
		VulnType:   "ldap",
		Technique:  "ldap_blind_error",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: LDAPMeasurements{
			Technique:       "ldap_blind_error",
			Baseline:        &baselineRound,
			Probe:           &probeRound,
			HashesMatch:     &hashesMatch,
			MatchedPatterns: matchedPatterns,
			PayloadUsed:     payload,
			ResponseSnippet: snippet,
		},
	}, nil
}

func probeWithLDAPParam(cfg LDAPConfig, value string) ProbeResponse {
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return ProbeResponse{Error: fmt.Errorf("parse URL: %w", err)}
	}
	if strings.EqualFold(cfg.Method, "GET") {
		params := parsed.Query()
		params.Set(cfg.Param, value)
		parsed.RawQuery = params.Encode()
		return HTTPProbe(cfg.Method, parsed.String(), "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
	}
	// POST: URL-encode body
	body := url.Values{}
	body.Set(cfg.Param, value)
	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	return HTTPProbe(cfg.Method, cfg.URL, body.Encode(), headers, cfg.TimeoutSec, cfg.InScope)
}
