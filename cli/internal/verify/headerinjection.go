package verify

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// HeaderInjectionConfig holds configuration for CRLF/header injection verification.
type HeaderInjectionConfig struct {
	URL    string
	Param  string
	Method string
	ProbeConfig
}

// VerifyHeaderInjection runs the CRLF header injection probe.
func VerifyHeaderInjection(cfg HeaderInjectionConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
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

	// Baseline: send same param shape with clean value (no CRLF).
	throttle.Wait()
	probeCount++

	baselineResp := headerInjProbeWithParam(cfg, "test-baseline")
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d\n", baselineResp.StatusCode)
	writeEvidence(ew, "header_injection", "crlf_injection", cfg.URL, cfg.Param, baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "clean param value")

	// Probe: inject CRLF + custom header into parameter
	throttle.Wait()
	probeCount++

	injectedHeader := "X-Ensphere-Injected"
	injectedValue := "crlf-marker"
	// Use %0d%0a in a manually-constructed RawQuery to preserve
	// literal CRLF bytes. url.Values.Encode() would double-encode % to %25.
	crlfPayload := "test%0d%0a" + injectedHeader + ":%20" + injectedValue

	probeResp := headerInjProbeWithRawParam(cfg, crlfPayload)

	if probeResp.Error != nil {
		return nil, fmt.Errorf("header injection probe: %w", probeResp.Error)
	}

	headerFound := probeResp.Headers.Get(injectedHeader) == injectedValue

	fmt.Fprintf(os.Stderr, "[PROBE] status=%d header_found=%v\n", probeResp.StatusCode, headerFound)
	writeEvidence(ew, "header_injection", "crlf_injection", cfg.URL, cfg.Param, probeResp.StatusCode,
		fmt.Sprintf("%dms", probeResp.ElapsedMs), "probe",
		fmt.Sprintf("injected=%s:%s found=%v", injectedHeader, injectedValue, headerFound))

	snippet := ""
	if headerFound {
		snippet = fmt.Sprintf("Response header: %s: %s", injectedHeader, probeResp.Headers.Get(injectedHeader))
	}

	return &ProbeResult{
		VulnType:   "header_injection",
		Technique:  "crlf_injection",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: HeaderInjectionMeasurements{
			Baseline: RoundResult{
				StatusCode: baselineResp.StatusCode,
				ElapsedMs:  baselineResp.ElapsedMs,
				BodyHash:   baselineResp.BodyHash,
				BodyLength: len(baselineResp.Body),
			},
			Probe: RoundResult{
				StatusCode: probeResp.StatusCode,
				ElapsedMs:  probeResp.ElapsedMs,
				BodyHash:   probeResp.BodyHash,
				BodyLength: len(probeResp.Body),
			},
			InjectedHeader:  injectedHeader,
			InjectedValue:   injectedValue,
			HeaderFound:     headerFound,
			PayloadUsed:     crlfPayload,
			ResponseSnippet: snippet,
		},
	}, nil
}

// headerInjProbeWithParam sends a request with cfg.Param set to value via url.Values
// (safe encoding for baseline).
func headerInjProbeWithParam(cfg HeaderInjectionConfig, value string) ProbeResponse {
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
	return HTTPProbe("GET", parsed.String(), "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
}

// headerInjProbeWithRawParam sends a request with cfg.Param set to rawValue
// using RawQuery to avoid double-encoding of %0d%0a CRLF sequences.
func headerInjProbeWithRawParam(cfg HeaderInjectionConfig, rawValue string) ProbeResponse {
	if strings.ToUpper(cfg.Method) == "POST" {
		body := cfg.Param + "=" + rawValue
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
	injParam := cfg.Param + "=" + rawValue
	if parsed.RawQuery != "" {
		parsed.RawQuery = parsed.RawQuery + "&" + injParam
	} else {
		parsed.RawQuery = injParam
	}
	return HTTPProbe("GET", parsed.String(), "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
}
