package verify

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// SSTIConfig holds configuration for SSTI verification.
type SSTIConfig struct {
	URL    string
	Param  string
	Engine string // auto | jinja2 | twig | freemarker | erb
	Method string
	ProbeConfig
}

type sstiPayloadEntry struct {
	payload  string
	expected string
	engines  []string
}

var sstiPayloadMatrix = []sstiPayloadEntry{
	{"{{7*7}}", "49", []string{"auto", "jinja2", "twig"}},
	{"${7*7}", "49", []string{"auto", "freemarker"}},
	{"<%= 7*7 %>", "49", []string{"auto", "erb"}},
	{"{{7*'7'}}", "7777777", []string{"auto", "jinja2"}},
	{"#{7*7}", "49", []string{"auto", "erb"}},
}

// VerifySSTI runs the SSTI verification probe.
func VerifySSTI(cfg SSTIConfig) (*ProbeResult, error) {
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
	var probes []SSTIProbeResult

	for _, entry := range sstiPayloadMatrix {
		if cfg.Engine != "auto" && !containsEngine(entry.engines, cfg.Engine) {
			continue
		}

		throttle.Wait()
		probeCount++
		resp := sstiProbeWithParam(cfg, entry.payload)
		if resp.Error != nil {
			fmt.Fprintf(os.Stderr, "[PROBE] error: %v payload=%s\n", resp.Error, entry.payload)
			continue
		}

		found := strings.Contains(resp.Body, entry.expected)
		var context string
		if found {
			idx := strings.Index(resp.Body, entry.expected)
			if idx >= 0 {
				start := idx - 50
				if start < 0 {
					start = 0
				}
				end := idx + len(entry.expected) + 50
				if end > len(resp.Body) {
					end = len(resp.Body)
				}
				context = resp.Body[start:end]
			}
		}

		fmt.Fprintf(os.Stderr, "[PROBE] status=%d found=%v payload=%s\n", resp.StatusCode, found, entry.payload)
		writeEvidence(ew, "ssti", "expression_eval", cfg.URL, cfg.Param, resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "probe",
			fmt.Sprintf("payload=%s expected=%s found=%v", entry.payload, entry.expected, found))

		probes = append(probes, SSTIProbeResult{
			RoundResult: RoundResult{
				StatusCode: resp.StatusCode,
				ElapsedMs:  resp.ElapsedMs,
				BodyHash:   resp.BodyHash,
				BodyLength: len(resp.Body),
			},
			PayloadUsed: entry.payload,
			Expected:    entry.expected,
			Found:       found,
			Context:     context,
		})
	}

	if len(probes) == 0 {
		return nil, fmt.Errorf("all SSTI probes failed")
	}

	return &ProbeResult{
		VulnType:     "ssti",
		Technique:    "expression_eval",
		StartedAt:    timer.StartedAt(),
		ProbeCount:   probeCount,
		Duration:     timer.Elapsed(),
		Measurements: SSTIMeasurements{Probes: probes},
	}, nil
}

func containsEngine(engines []string, engine string) bool {
	for _, e := range engines {
		if e == engine {
			return true
		}
	}
	return false
}

func sstiProbeWithParam(cfg SSTIConfig, value string) ProbeResponse {
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
