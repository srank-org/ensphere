package verify

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/srank-org/ensphere/internal/evidence"
)

// RateLimitConfig holds configuration for rate limit measurement.
type RateLimitConfig struct {
	URL         string
	Method      string
	Body        string
	Token       string
	SecondToken string // optional: repeat the burst with this token after the window
	BurstCount  int    // explicitly approved number of sequential requests
	WindowSec   int    // time window in seconds (default 10)
	ProbeConfig
}

// rateLimitHeaderAllowlist is the exact set of response headers captured per
// round. Keys are matched case-insensitively and stored lowercase.
var rateLimitHeaderAllowlist = map[string]bool{
	"retry-after":     true,
	"cf-ray":          true,
	"cf-cache-status": true,
	"server":          true,
	"x-vercel-id":     true,
	"x-served-by":     true,
	"via":             true,
}

// filterRateLimitHeaders returns the allowlisted response headers with
// lowercase keys. It also keeps any header starting with ratelimit- or
// x-ratelimit-.
func filterRateLimitHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string)
	for key, values := range h {
		lk := strings.ToLower(key)
		if rateLimitHeaderAllowlist[lk] || strings.HasPrefix(lk, "ratelimit-") || strings.HasPrefix(lk, "x-ratelimit-") {
			if len(values) > 0 {
				out[lk] = values[0]
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// VerifyRateLimit runs the rate limit measurement probe.
func VerifyRateLimit(cfg RateLimitConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if cfg.BurstCount < 1 {
		return nil, fmt.Errorf("burst count must be explicitly set to a positive approved value")
	}
	if cfg.WindowSec < 1 {
		cfg.WindowSec = 10
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

	fmt.Fprintf(os.Stderr, "[RATELIMIT] burst=%d window=%ds\n", cfg.BurstCount, cfg.WindowSec)

	identityA := cfg.runRateLimitBurst(ew, cfg.Token, "identity_a")
	if len(identityA.Rounds) == 0 {
		return nil, fmt.Errorf("all rate limit probes failed")
	}
	total := len(identityA.Rounds)

	set := RateLimitMeasurementSet{IdentityA: identityA}

	if cfg.SecondToken != "" {
		fmt.Fprintf(os.Stderr, "[RATELIMIT] waiting %ds before second-token burst\n", cfg.WindowSec)
		time.Sleep(time.Duration(cfg.WindowSec) * time.Second)
		identityB := cfg.runRateLimitBurst(ew, cfg.SecondToken, "identity_b")
		total += len(identityB.Rounds)
		set.IdentityB = &identityB
	}

	return &ProbeResult{
		VulnType:     "rate_limit",
		Technique:    "rate_limit_burst",
		StartedAt:    timer.StartedAt(),
		ProbeCount:   total,
		Duration:     timer.Elapsed(),
		Measurements: set,
	}, nil
}

// runRateLimitBurst runs a single approved burst with the given token and
// returns the raw per-round measurements. A window deadline bounds the burst.
func (cfg RateLimitConfig) runRateLimitBurst(ew *evidence.Writer, token, label string) RateLimitMeasurements {
	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}

	deadline := time.Now().Add(time.Duration(cfg.WindowSec) * time.Second)

	var rounds []RoundResult
	statusCodes := make(map[int]int)
	successCount := 0
	throttledCount := 0
	firstThrottleAt := 0
	var minMs, maxMs, totalMs int64
	first := true

	for i := 0; i < cfg.BurstCount; i++ {
		if time.Now().After(deadline) {
			break
		}

		resp := HTTPProbe(cfg.Method, cfg.URL, cfg.Body, headers, cfg.TimeoutSec, cfg.InScope)
		if resp.Error != nil {
			fmt.Fprintf(os.Stderr, "[RATELIMIT %s %d/%d] error: %v\n", label, i+1, cfg.BurstCount, resp.Error)
			continue
		}

		round := RoundResult{
			StatusCode: resp.StatusCode,
			ElapsedMs:  resp.ElapsedMs,
			BodyHash:   resp.BodyHash,
			BodyLength: len(resp.Body),
			Headers:    filterRateLimitHeaders(resp.Headers),
		}
		rounds = append(rounds, round)

		statusCodes[resp.StatusCode]++

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		}

		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			throttledCount++
			if firstThrottleAt == 0 {
				firstThrottleAt = i + 1
			}
		}

		totalMs += resp.ElapsedMs
		if first || resp.ElapsedMs < minMs {
			minMs = resp.ElapsedMs
		}
		if first || resp.ElapsedMs > maxMs {
			maxMs = resp.ElapsedMs
		}
		first = false

		fmt.Fprintf(os.Stderr, "[RATELIMIT %s %d/%d] status=%d %dms\n", label, i+1, cfg.BurstCount, resp.StatusCode, resp.ElapsedMs)
		writeEvidence(ew, "rate_limit", "rate_limit_burst", cfg.URL, "", resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "probe", fmt.Sprintf("%s request %d/%d", label, i+1, cfg.BurstCount))
	}

	avgMs := int64(0)
	if len(rounds) > 0 {
		avgMs = totalMs / int64(len(rounds))
	}

	return RateLimitMeasurements{
		BurstCount:      cfg.BurstCount,
		WindowSec:       cfg.WindowSec,
		SuccessCount:    successCount,
		ThrottledCount:  throttledCount,
		FirstThrottleAt: firstThrottleAt,
		StatusCodes:     statusCodes,
		Rounds:          rounds,
		MinMs:           minMs,
		MaxMs:           maxMs,
		AvgMs:           avgMs,
	}
}
