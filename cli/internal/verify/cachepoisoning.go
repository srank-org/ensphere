package verify

import (
	crypto_rand "crypto/rand"
	"fmt"
	"os"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
)

// CachePoisoningConfig holds configuration for cache poisoning verification.
type CachePoisoningConfig struct {
	URL       string
	Technique string // unkeyed_header | unkeyed_cookie | fat_get
	ProbeConfig
}

var cachePoisoningHeaders = map[string]struct {
	header string
	value  string
}{
	"unkeyed_header": {"X-Forwarded-Host", "evil.com"},
	"unkeyed_cookie": {"Cookie", "lang=ensphere_test_value"},
	"fat_get":        {"X-Original-URL", "/ensphere-cache-test"},
}

var validCacheTechniques = map[string]bool{
	"unkeyed_header": true, "unkeyed_cookie": true, "fat_get": true,
}

// VerifyCachePoisoning runs the cache poisoning verification probe.
func VerifyCachePoisoning(cfg CachePoisoningConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validCacheTechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: unkeyed_header, unkeyed_cookie, fat_get", cfg.Technique)}
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

	var buf [8]byte
	_, _ = crypto_rand.Read(buf[:])
	cacheBuster := fmt.Sprintf("ensphere_cb=%x", buf[:])
	testURL := cfg.URL
	if strings.Contains(testURL, "?") {
		testURL += "&" + cacheBuster
	} else {
		testURL += "?" + cacheBuster
	}

	// Baseline: clean request
	throttle.Wait()
	probeCount++
	baselineResp := HTTPProbe("GET", testURL, "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d hash=%s\n", baselineResp.StatusCode, baselineResp.BodyHash[:16])
	writeEvidence(ew, "cache_poisoning", cfg.Technique, cfg.URL, "", baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "clean request")

	// Injection: add unkeyed header
	headerCfg := cachePoisoningHeaders[cfg.Technique]
	injectionHeaders := make(map[string]string)
	for k, v := range cfg.Headers {
		injectionHeaders[k] = v
	}
	injectionHeaders[headerCfg.header] = headerCfg.value

	throttle.Wait()
	probeCount++
	injectionResp := HTTPProbe("GET", testURL, "", injectionHeaders, cfg.TimeoutSec, cfg.InScope)
	if injectionResp.Error != nil {
		return nil, fmt.Errorf("injection probe: %w", injectionResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[INJECTION] status=%d hash=%s\n", injectionResp.StatusCode, injectionResp.BodyHash[:16])
	writeEvidence(ew, "cache_poisoning", cfg.Technique, cfg.URL, "", injectionResp.StatusCode,
		fmt.Sprintf("%dms", injectionResp.ElapsedMs), "probe",
		fmt.Sprintf("header=%s: %s", headerCfg.header, headerCfg.value))

	// Verify: clean request again to check cache
	throttle.Wait()
	probeCount++
	verifyResp := HTTPProbe("GET", testURL, "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
	if verifyResp.Error != nil {
		return nil, fmt.Errorf("verify probe: %w", verifyResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[VERIFY] status=%d hash=%s\n", verifyResp.StatusCode, verifyResp.BodyHash[:16])
	writeEvidence(ew, "cache_poisoning", cfg.Technique, cfg.URL, "", verifyResp.StatusCode,
		fmt.Sprintf("%dms", verifyResp.ElapsedMs), "probe", "verify after injection")

	// Report factual hash comparisons; the AI decides whether the cache was poisoned.
	verifyMatchesInjection := verifyResp.BodyHash == injectionResp.BodyHash
	verifyMatchesBaseline := verifyResp.BodyHash == baselineResp.BodyHash

	snippet := verifyResp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	baseline := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	injection := RoundResult{
		StatusCode: injectionResp.StatusCode,
		ElapsedMs:  injectionResp.ElapsedMs,
		BodyHash:   injectionResp.BodyHash,
		BodyLength: len(injectionResp.Body),
	}
	verify := RoundResult{
		StatusCode: verifyResp.StatusCode,
		ElapsedMs:  verifyResp.ElapsedMs,
		BodyHash:   verifyResp.BodyHash,
		BodyLength: len(verifyResp.Body),
	}

	return &ProbeResult{
		VulnType:   "cache_poisoning",
		Technique:  cfg.Technique,
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: CachePoisoningMeasurements{
			Technique:              cfg.Technique,
			Baseline:               baseline,
			Injection:              injection,
			Verify:                 verify,
			BaselineHash:           baselineResp.BodyHash,
			VerifyHash:             verifyResp.BodyHash,
			VerifyMatchesInjection: verifyMatchesInjection,
			VerifyMatchesBaseline:  verifyMatchesBaseline,
			HeaderUsed:             fmt.Sprintf("%s: %s", headerCfg.header, headerCfg.value),
			PayloadUsed:            headerCfg.value,
			ResponseSnippet:        snippet,
		},
	}, nil
}
