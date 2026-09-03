package verify

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
)

// CMDiConfig holds configuration for command injection verification.
type CMDiConfig struct {
	URL    string
	Param  string
	OS     string // linux | windows
	Method string
	ProbeConfig
}

var cmdiPayloads = map[string][]string{
	"linux":   {"; sleep %d", "| sleep %d", "`sleep %d`"},
	"windows": {"& ping -n %d 127.0.0.1", "| ping -n %d 127.0.0.1"},
}

// VerifyCMDi runs the command injection verification probe.
func VerifyCMDi(cfg CMDiConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
		return nil, err
	}

	payloads, ok := cmdiPayloads[cfg.OS]
	if !ok {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported OS %q — use: linux, windows", cfg.OS)}
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

	if cfg.TimeoutSec < 5 {
		return nil, fmt.Errorf("timeout must be >= 5 for time-based probes, got %d", cfg.TimeoutSec)
	}
	sleepSec := cfg.TimeoutSec / 2
	if sleepSec < 3 {
		sleepSec = 3
	}
	if sleepSec > cfg.TimeoutSec-2 {
		sleepSec = cfg.TimeoutSec - 2
	}

	probeCount := 0

	// Baseline probes
	var baselineRounds []RoundResult
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		resp := cmdiProbeWithParam(cfg, "1")
		if resp.Error != nil {
			return nil, fmt.Errorf("baseline probe %d: %w", i+1, resp.Error)
		}
		baselineRounds = append(baselineRounds, RoundResult{
			StatusCode: resp.StatusCode,
			ElapsedMs:  resp.ElapsedMs,
			BodyHash:   resp.BodyHash,
			BodyLength: len(resp.Body),
		})
		fmt.Fprintf(os.Stderr, "[BASELINE %d] %dms\n", i+1, resp.ElapsedMs)
		writeEvidence(ew, "cmdi", "command_injection", cfg.URL, cfg.Param, resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "baseline", fmt.Sprintf("round %d", i+1))
	}

	for _, tmpl := range payloads {
		payload := fmt.Sprintf(tmpl, sleepSec)
		var payloadRounds []RoundResult
		for i := 0; i < defaultRounds; i++ {
			throttle.Wait()
			probeCount++
			resp := cmdiProbeWithParam(cfg, payload)
			if resp.Error != nil {
				fmt.Fprintf(os.Stderr, "[PAYLOAD %d] error: %v\n", i+1, resp.Error)
				continue
			}
			payloadRounds = append(payloadRounds, RoundResult{
				StatusCode: resp.StatusCode,
				ElapsedMs:  resp.ElapsedMs,
				BodyHash:   resp.BodyHash,
				BodyLength: len(resp.Body),
			})
			fmt.Fprintf(os.Stderr, "[PAYLOAD %d] %dms payload=%s\n", i+1, resp.ElapsedMs, payload)
			writeEvidence(ew, "cmdi", "command_injection", cfg.URL, cfg.Param, resp.StatusCode,
				fmt.Sprintf("%dms", resp.ElapsedMs), "payload", fmt.Sprintf("round %d, payload: %s", i+1, payload))
		}

		if len(payloadRounds) == 0 {
			continue
		}

		baselineAvg := avgFromRounds(baselineRounds)
		payloadAvg := avgFromRounds(payloadRounds)

		return &ProbeResult{
			VulnType:   "cmdi",
			Technique:  "command_injection",
			StartedAt:  timer.StartedAt(),
			ProbeCount: probeCount,
			Duration:   timer.Elapsed(),
			Measurements: CMDiTimeMeasurements{
				SleepSeconds:   sleepSec,
				TargetOS:       cfg.OS,
				BaselineRounds: baselineRounds,
				PayloadRounds:  payloadRounds,
				BaselineAvgMs:  baselineAvg,
				PayloadAvgMs:   payloadAvg,
				DeltaMs:        payloadAvg - baselineAvg,
				PayloadUsed:    payload,
			},
		}, nil
	}

	return nil, fmt.Errorf("all payload probes failed")
}

func cmdiProbeWithParam(cfg CMDiConfig, value string) ProbeResponse {
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
