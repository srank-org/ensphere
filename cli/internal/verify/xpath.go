package verify

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
)

// XPathConfig holds configuration for XPath injection verification.
type XPathConfig struct {
	URL       string
	Param     string
	Technique string // xpath_injection | xpath_blind_boolean | xpath_blind_error
	Method    string
	ProbeConfig
}

var validXPathTechniques = map[string]bool{
	"xpath_injection":     true,
	"xpath_blind_boolean": true,
	"xpath_blind_error":   true,
}

// XPath error patterns that indicate XPath processing errors in the response.
var xpathErrorPatterns = []string{
	"XPath",
	"XPathException",
	"DOMXPath",
	"SimpleXMLElement",
	"xmlXPathEval",
	"lxml.etree",
	"XPathEvalError",
	"Invalid expression",
}

// VerifyXPath runs the XPath injection verification probe.
func VerifyXPath(cfg XPathConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validXPathTechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: xpath_injection, xpath_blind_boolean, xpath_blind_error", cfg.Technique)}
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
	case "xpath_injection":
		return verifyXPathInjection(cfg, throttle, timer, ew)
	case "xpath_blind_boolean":
		return verifyXPathBlindBoolean(cfg, throttle, timer, ew)
	case "xpath_blind_error":
		return verifyXPathBlindError(cfg, throttle, timer, ew)
	default:
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q", cfg.Technique)}
	}
}

func verifyXPathInjection(cfg XPathConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	// Baseline probe with benign value
	throttle.Wait()
	probeCount++
	baselineResp := probeWithXPathParam(cfg, "test")
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d hash=%s\n", baselineResp.StatusCode, baselineResp.BodyHash[:16])
	writeEvidence(ew, "xpath", "xpath_injection", cfg.URL, cfg.Param, baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "benign value: test")

	// Injection probe
	payload := "' or '1'='1"
	throttle.Wait()
	probeCount++
	probeResp := probeWithXPathParam(cfg, payload)
	if probeResp.Error != nil {
		return nil, fmt.Errorf("injection probe: %w", probeResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[PROBE] status=%d hash=%s\n", probeResp.StatusCode, probeResp.BodyHash[:16])
	writeEvidence(ew, "xpath", "xpath_injection", cfg.URL, cfg.Param, probeResp.StatusCode,
		fmt.Sprintf("%dms", probeResp.ElapsedMs), "probe", fmt.Sprintf("payload: %s", payload))

	hashesMatch := baselineResp.BodyHash == probeResp.BodyHash

	var matchedPatterns []string
	for _, pattern := range xpathErrorPatterns {
		if strings.Contains(probeResp.Body, pattern) {
			matchedPatterns = append(matchedPatterns, pattern)
		}
	}

	snippet := probeResp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

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

	return &ProbeResult{
		VulnType:   "xpath",
		Technique:  "xpath_injection",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: XPathMeasurements{
			Technique:       "xpath_injection",
			Baseline:        &baselineRound,
			Probe:           &probeRound,
			HashesMatch:     &hashesMatch,
			MatchedPatterns: matchedPatterns,
			PayloadUsed:     payload,
			ResponseSnippet: snippet,
		},
	}, nil
}

func verifyXPathBlindBoolean(cfg XPathConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	// True probe — condition that should always be true
	truePayload := "' or string-length(name(/*[1]))>1 or '1'='1"
	throttle.Wait()
	probeCount++
	trueResp := probeWithXPathParam(cfg, truePayload)
	if trueResp.Error != nil {
		return nil, fmt.Errorf("true probe: %w", trueResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[TRUE] status=%d hash=%s\n", trueResp.StatusCode, trueResp.BodyHash[:16])
	writeEvidence(ew, "xpath", "xpath_blind_boolean", cfg.URL, cfg.Param, trueResp.StatusCode,
		fmt.Sprintf("%dms", trueResp.ElapsedMs), "probe", fmt.Sprintf("true condition: %s", truePayload))

	// False probe — condition that should always be false
	falsePayload := "' or string-length(name(/*[1]))>9999 or '1'='1"
	throttle.Wait()
	probeCount++
	falseResp := probeWithXPathParam(cfg, falsePayload)
	if falseResp.Error != nil {
		return nil, fmt.Errorf("false probe: %w", falseResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[FALSE] status=%d hash=%s\n", falseResp.StatusCode, falseResp.BodyHash[:16])
	writeEvidence(ew, "xpath", "xpath_blind_boolean", cfg.URL, cfg.Param, falseResp.StatusCode,
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
		VulnType:   "xpath",
		Technique:  "xpath_blind_boolean",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: XPathMeasurements{
			Technique:    "xpath_blind_boolean",
			TrueProbe:    &trueRound,
			FalseProbe:   &falseRound,
			HashesMatch:  &hashesMatch,
			TruePayload:  truePayload,
			FalsePayload: falsePayload,
			PayloadUsed:  truePayload,
		},
	}, nil
}

func verifyXPathBlindError(cfg XPathConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	// Baseline probe with benign value
	throttle.Wait()
	probeCount++
	baselineResp := probeWithXPathParam(cfg, "test")
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d hash=%s\n", baselineResp.StatusCode, baselineResp.BodyHash[:16])
	writeEvidence(ew, "xpath", "xpath_blind_error", cfg.URL, cfg.Param, baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "benign value: test")

	// Syntax error probe
	payload := "'][1"
	throttle.Wait()
	probeCount++
	probeResp := probeWithXPathParam(cfg, payload)
	if probeResp.Error != nil {
		return nil, fmt.Errorf("error probe: %w", probeResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[PROBE] status=%d hash=%s\n", probeResp.StatusCode, probeResp.BodyHash[:16])
	writeEvidence(ew, "xpath", "xpath_blind_error", cfg.URL, cfg.Param, probeResp.StatusCode,
		fmt.Sprintf("%dms", probeResp.ElapsedMs), "probe", fmt.Sprintf("syntax error payload: %s", payload))

	hashesMatch := baselineResp.BodyHash == probeResp.BodyHash

	var matchedPatterns []string
	for _, pattern := range xpathErrorPatterns {
		if strings.Contains(probeResp.Body, pattern) {
			matchedPatterns = append(matchedPatterns, pattern)
		}
	}

	snippet := probeResp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

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

	return &ProbeResult{
		VulnType:   "xpath",
		Technique:  "xpath_blind_error",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: XPathMeasurements{
			Technique:       "xpath_blind_error",
			Baseline:        &baselineRound,
			Probe:           &probeRound,
			HashesMatch:     &hashesMatch,
			MatchedPatterns: matchedPatterns,
			PayloadUsed:     payload,
			ResponseSnippet: snippet,
		},
	}, nil
}

// probeWithXPathParam injects a value into the target parameter and sends the request.
// GET: sets URL query parameter. POST: sends form-encoded body.
func probeWithXPathParam(cfg XPathConfig, value string) ProbeResponse {
	if strings.ToUpper(cfg.Method) == "POST" {
		body := url.Values{cfg.Param: {value}}.Encode()
		headers := make(map[string]string)
		for k, v := range cfg.Headers {
			headers[k] = v
		}
		headers["Content-Type"] = "application/x-www-form-urlencoded"
		return HTTPProbe("POST", cfg.URL, body, headers, cfg.TimeoutSec, cfg.InScope)
	}

	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return ProbeResponse{Error: fmt.Errorf("parse URL: %w", err)}
	}
	params := parsed.Query()
	params.Set(cfg.Param, value)
	parsed.RawQuery = params.Encode()
	return HTTPProbe(cfg.Method, parsed.String(), "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
}
