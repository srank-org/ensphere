package verify

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// CORSConfig holds configuration for CORS misconfiguration verification.
type CORSConfig struct {
	URL    string
	Method string
	ProbeConfig
}

// VerifyCORS runs the CORS misconfiguration verification probe.
func VerifyCORS(cfg CORSConfig) (*ProbeResult, error) {
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

	// Extract target domain for subdomain test
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	subdomainOrigin := fmt.Sprintf("https://evil.%s", parsed.Hostname())

	type corsTest struct {
		label  string
		origin string
	}

	tests := []corsTest{
		{"baseline", ""},
		{"evil_origin", "https://evil.com"},
		{"null_origin", "null"},
		{"subdomain_origin", subdomainOrigin},
	}

	results := make([]CORSProbeResult, len(tests))

	for i, test := range tests {
		throttle.Wait()
		probeCount++

		headers := make(map[string]string)
		for k, v := range cfg.Headers {
			headers[k] = v
		}
		if test.origin != "" {
			headers["Origin"] = test.origin
		}

		resp := HTTPProbe(cfg.Method, cfg.URL, "", headers, cfg.TimeoutSec, cfg.InScope)
		if resp.Error != nil {
			return nil, fmt.Errorf("%s probe: %w", test.label, resp.Error)
		}

		acaoHeader := resp.Headers.Get("Access-Control-Allow-Origin")
		acacHeader := resp.Headers.Get("Access-Control-Allow-Credentials")

		originReflected := test.origin != "" && acaoHeader == test.origin
		credentialsAllowed := strings.EqualFold(acacHeader, "true")

		fmt.Fprintf(os.Stderr, "[%s] status=%d acao=%s acac=%s\n",
			strings.ToUpper(test.label), resp.StatusCode, acaoHeader, acacHeader)
		writeEvidence(ew, "cors", "origin_reflection", cfg.URL, "", resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "probe",
			fmt.Sprintf("origin=%s acao=%s reflected=%v", test.origin, acaoHeader, originReflected))

		results[i] = CORSProbeResult{
			RoundResult: RoundResult{
				StatusCode: resp.StatusCode,
				ElapsedMs:  resp.ElapsedMs,
				BodyHash:   resp.BodyHash,
				BodyLength: len(resp.Body),
			},
			OriginSent:         test.origin,
			ACAOHeader:         acaoHeader,
			ACACHeader:         acacHeader,
			OriginReflected:    originReflected,
			CredentialsAllowed: credentialsAllowed,
		}
	}

	return &ProbeResult{
		VulnType:   "cors",
		Technique:  "origin_reflection",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: CORSMeasurements{
			Baseline:        results[0],
			EvilOrigin:      results[1],
			NullOrigin:      results[2],
			SubdomainOrigin: results[3],
		},
	}, nil
}
