package verify

import (
	"fmt"
	"os"
	"sync"

	"github.com/srank-org/ensphere/internal/evidence"
)

// RaceConfig holds configuration for race condition verification.
type RaceConfig struct {
	URL         string
	Method      string
	Body        string // request body to repeat
	Token       string
	Concurrency int // number of parallel requests (default 10)
	ProbeConfig
}

// VerifyRace runs the race condition verification probe.
func VerifyRace(cfg RaceConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(4, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if cfg.Concurrency < 2 {
		cfg.Concurrency = 10
	}

	timer := NewTimer()

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

	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	if cfg.Token != "" {
		headers["Authorization"] = "Bearer " + cfg.Token
	}

	fmt.Fprintf(os.Stderr, "[RACE] concurrency=%d\n", cfg.Concurrency)

	// Send all requests concurrently with a start barrier for true simultaneity.
	// No throttle: race probes intentionally fire in parallel.
	results := make([]ProbeResponse, cfg.Concurrency)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // wait for all goroutines to be ready
			results[idx] = HTTPProbe(cfg.Method, cfg.URL, cfg.Body, headers, cfg.TimeoutSec, cfg.InScope)
		}(i)
	}
	close(start) // release all goroutines at once
	wg.Wait()

	var rounds []RoundResult
	successCount := 0
	hashSet := make(map[string]bool)
	var minMs, maxMs, totalMs int64
	first := true

	for i, resp := range results {
		if resp.Error != nil {
			fmt.Fprintf(os.Stderr, "[RACE %d] error: %v\n", i+1, resp.Error)
			continue
		}

		round := RoundResult{
			StatusCode: resp.StatusCode,
			ElapsedMs:  resp.ElapsedMs,
			BodyHash:   resp.BodyHash,
			BodyLength: len(resp.Body),
		}
		rounds = append(rounds, round)

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		}
		hashSet[resp.BodyHash] = true
		totalMs += resp.ElapsedMs

		if first || resp.ElapsedMs < minMs {
			minMs = resp.ElapsedMs
		}
		if first || resp.ElapsedMs > maxMs {
			maxMs = resp.ElapsedMs
		}
		first = false

		fmt.Fprintf(os.Stderr, "[RACE %d] status=%d %dms\n", i+1, resp.StatusCode, resp.ElapsedMs)
		writeEvidence(ew, "race_condition", "parallel_request", cfg.URL, "", resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "probe", fmt.Sprintf("request %d/%d", i+1, cfg.Concurrency))
	}

	if len(rounds) == 0 {
		return nil, fmt.Errorf("all race probes failed")
	}

	avgMs := totalMs / int64(len(rounds))

	return &ProbeResult{
		VulnType:   "race_condition",
		Technique:  "parallel_request",
		StartedAt:  timer.StartedAt(),
		ProbeCount: cfg.Concurrency,
		Duration:   timer.Elapsed(),
		Measurements: RaceMeasurements{
			Concurrency:  cfg.Concurrency,
			Rounds:       rounds,
			SuccessCount: successCount,
			UniqueHashes: len(hashSet),
			MinMs:        minMs,
			MaxMs:        maxMs,
			AvgMs:        avgMs,
			PayloadUsed:  cfg.Body,
		},
	}, nil
}
