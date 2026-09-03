package verify

import (
	"fmt"
	"html"
	"net/url"
	"os"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
)

// XSSConfig holds configuration for XSS verification.
type XSSConfig struct {
	URL     string
	Param   string
	Payload string // The XSS payload string
	Method  string // GET or POST
	ProbeConfig
}

// VerifyXSS runs the XSS verification probe.
func VerifyXSS(cfg XSSConfig) (*ProbeResult, error) {
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

	var resp ProbeResponse
	if strings.ToUpper(cfg.Method) == "POST" {
		body := url.Values{cfg.Param: {cfg.Payload}}.Encode()
		headers := make(map[string]string)
		for k, v := range cfg.Headers {
			headers[k] = v
		}
		headers["Content-Type"] = "application/x-www-form-urlencoded"
		resp = HTTPProbe("POST", cfg.URL, body, headers, cfg.TimeoutSec, cfg.InScope)
	} else {
		parsed, err := url.Parse(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("parse URL: %w", err)
		}
		params := parsed.Query()
		params.Set(cfg.Param, cfg.Payload)
		parsed.RawQuery = params.Encode()
		resp = HTTPProbe("GET", parsed.String(), "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("xss probe: %w", resp.Error)
	}

	fmt.Fprintf(os.Stderr, "[PROBE] status=%d len=%d\n", resp.StatusCode, len(resp.Body))

	reflected := strings.Contains(resp.Body, cfg.Payload)
	encoded := strings.Contains(resp.Body, html.EscapeString(cfg.Payload))

	var context string
	if reflected {
		idx := strings.Index(resp.Body, cfg.Payload)
		if idx >= 0 {
			start := idx - 50
			if start < 0 {
				start = 0
			}
			end := idx + len(cfg.Payload) + 50
			if end > len(resp.Body) {
				end = len(resp.Body)
			}
			context = resp.Body[start:end]
		}
	}

	probeRound := RoundResult{
		StatusCode: resp.StatusCode,
		ElapsedMs:  resp.ElapsedMs,
		BodyHash:   resp.BodyHash,
		BodyLength: len(resp.Body),
	}

	writeEvidence(ew, "xss", "reflected", cfg.URL, cfg.Param, resp.StatusCode,
		fmt.Sprintf("%dms", resp.ElapsedMs), "probe",
		fmt.Sprintf("payload=%s reflected=%v encoded=%v", cfg.Payload, reflected, encoded))

	return &ProbeResult{
		VulnType:   "xss",
		Technique:  "reflected",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: XSSMeasurements{
			ProbeRound:  probeRound,
			Reflected:   reflected,
			Encoded:     encoded,
			Context:     context,
			PayloadUsed: cfg.Payload,
		},
	}, nil
}
