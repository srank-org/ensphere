package verify

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/srank-org/ensphere/internal/evidence"
)

// NoSQLConfig holds configuration for NoSQL injection verification.
type NoSQLConfig struct {
	URL       string
	Param     string
	Technique string // operator_injection | where_time
	Method    string
	ProbeConfig
}

var validNoSQLTechniques = map[string]bool{
	"operator_injection": true, "where_time": true,
}

// VerifyNoSQL runs the NoSQL injection verification probe.
func VerifyNoSQL(cfg NoSQLConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validNoSQLTechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: operator_injection, where_time", cfg.Technique)}
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
	case "operator_injection":
		return verifyNoSQLOperator(cfg, throttle, timer, ew)
	case "where_time":
		return verifyNoSQLWhereTime(cfg, throttle, timer, ew)
	default:
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q", cfg.Technique)}
	}
}

func verifyNoSQLOperator(cfg NoSQLConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	truePayload := map[string]interface{}{cfg.Param: map[string]interface{}{"$gt": ""}}
	falsePayload := map[string]interface{}{cfg.Param: map[string]interface{}{"$gt": "zzzzzzzzzzzzzzzzzzzzz"}}

	trueBody, _ := json.Marshal(truePayload)
	falseBody, _ := json.Marshal(falsePayload)

	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	headers["Content-Type"] = "application/json"

	// True probe
	throttle.Wait()
	probeCount++
	trueResp := HTTPProbe(cfg.Method, cfg.URL, string(trueBody), headers, cfg.TimeoutSec, cfg.InScope)
	if trueResp.Error != nil {
		return nil, fmt.Errorf("true probe: %w", trueResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[TRUE] status=%d hash=%s\n", trueResp.StatusCode, trueResp.BodyHash[:16])
	writeEvidence(ew, "nosql", "operator_injection", cfg.URL, cfg.Param, trueResp.StatusCode,
		fmt.Sprintf("%dms", trueResp.ElapsedMs), "probe", "true condition ($gt: '')")

	// False probe
	throttle.Wait()
	probeCount++
	falseResp := HTTPProbe(cfg.Method, cfg.URL, string(falseBody), headers, cfg.TimeoutSec, cfg.InScope)
	if falseResp.Error != nil {
		return nil, fmt.Errorf("false probe: %w", falseResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[FALSE] status=%d hash=%s\n", falseResp.StatusCode, falseResp.BodyHash[:16])
	writeEvidence(ew, "nosql", "operator_injection", cfg.URL, cfg.Param, falseResp.StatusCode,
		fmt.Sprintf("%dms", falseResp.ElapsedMs), "probe", "false condition ($gt: 'zzz...')")

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
		VulnType:   "nosql",
		Technique:  "operator_injection",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: NoSQLMeasurements{
			Technique:    "operator_injection",
			TrueProbe:    &trueRound,
			FalseProbe:   &falseRound,
			HashesMatch:  &hashesMatch,
			TruePayload:  string(trueBody),
			FalsePayload: string(falseBody),
			PayloadUsed:  string(trueBody),
		},
	}, nil
}

func verifyNoSQLWhereTime(cfg NoSQLConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
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

	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	headers["Content-Type"] = "application/json"

	probeCount := 0

	// Baseline probes
	baselineBody := map[string]interface{}{cfg.Param: "test"}
	baselineJSON, _ := json.Marshal(baselineBody)

	var baselineRounds []RoundResult
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		resp := HTTPProbe(cfg.Method, cfg.URL, string(baselineJSON), headers, cfg.TimeoutSec, cfg.InScope)
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
		writeEvidence(ew, "nosql", "where_time", cfg.URL, cfg.Param, resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "baseline", fmt.Sprintf("round %d", i+1))
	}

	// Payload probes with $where sleep
	payload := map[string]interface{}{"$where": fmt.Sprintf("sleep(%d000) || true", sleepSec)}
	payloadJSON, _ := json.Marshal(payload)

	var payloadRounds []RoundResult
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		resp := HTTPProbe(cfg.Method, cfg.URL, string(payloadJSON), headers, cfg.TimeoutSec, cfg.InScope)
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
		fmt.Fprintf(os.Stderr, "[PAYLOAD %d] %dms\n", i+1, resp.ElapsedMs)
		writeEvidence(ew, "nosql", "where_time", cfg.URL, cfg.Param, resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "payload", fmt.Sprintf("round %d", i+1))
	}

	if len(payloadRounds) == 0 {
		return nil, fmt.Errorf("all payload probes failed")
	}

	baselineAvg := avgFromRounds(baselineRounds)
	payloadAvg := avgFromRounds(payloadRounds)
	delta := payloadAvg - baselineAvg

	return &ProbeResult{
		VulnType:   "nosql",
		Technique:  "where_time",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: NoSQLMeasurements{
			Technique:      "where_time",
			SleepSeconds:   &sleepSec,
			BaselineRounds: baselineRounds,
			PayloadRounds:  payloadRounds,
			BaselineAvgMs:  &baselineAvg,
			PayloadAvgMs:   &payloadAvg,
			DeltaMs:        &delta,
			PayloadUsed:    string(payloadJSON),
		},
	}, nil
}
