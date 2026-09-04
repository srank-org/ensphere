package verify

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/srank-org/ensphere/internal/evidence"
)

// RedirectConfig holds configuration for open redirect verification.
type RedirectConfig struct {
	URL    string
	Param  string
	Method string
	ProbeConfig
}

// VerifyRedirect runs the open redirect verification probe.
func VerifyRedirect(cfg RedirectConfig) (*ProbeResult, error) {
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

	evilURL := "https://evil.com/ensphere-redirect-test"
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	params := parsed.Query()
	params.Set(cfg.Param, evilURL)
	parsed.RawQuery = params.Encode()

	// Shared no-redirect scoped client: it stops at the first response so the
	// Location header is recorded raw without following the redirect.
	redirectChain := []string{}
	client := scopedHTTPClient(cfg.TimeoutSec, cfg.InScope, len(cfg.InScope) > 0, false)

	throttle.Wait()
	probeCount++

	start := time.Now()
	var bodyReader *strings.Reader
	if cfg.Method == "POST" {
		bodyReader = strings.NewReader(url.Values{cfg.Param: {evilURL}}.Encode())
	}

	var req *http.Request
	if bodyReader != nil {
		req, err = http.NewRequest(cfg.Method, parsed.String(), bodyReader)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest(cfg.Method, parsed.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil && resp == nil {
		return nil, fmt.Errorf("redirect probe: %w", err)
	}

	var bodyHash string
	var bodyLength int
	if resp != nil {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyLength = len(bodyBytes)
		bodyHash = fmt.Sprintf("%x", sha256.Sum256(bodyBytes))
	}

	locationHeader := ""
	if resp != nil {
		locationHeader = resp.Header.Get("Location")
	}

	externalRedirect := strings.Contains(locationHeader, "evil.com")

	statusCode := 0
	if resp != nil {
		statusCode = resp.StatusCode
	}

	fmt.Fprintf(os.Stderr, "[PROBE] status=%d location=%s external=%v\n", statusCode, locationHeader, externalRedirect)
	writeEvidence(ew, "redirect", "open_redirect", cfg.URL, cfg.Param, statusCode,
		fmt.Sprintf("%dms", elapsed), "probe",
		fmt.Sprintf("location=%s external=%v", locationHeader, externalRedirect))

	probe := RoundResult{
		StatusCode: statusCode,
		ElapsedMs:  elapsed,
		BodyHash:   bodyHash,
		BodyLength: bodyLength,
	}

	return &ProbeResult{
		VulnType:   "redirect",
		Technique:  "open_redirect",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: RedirectMeasurements{
			Probe:            probe,
			LocationHeader:   locationHeader,
			RedirectChain:    redirectChain,
			PayloadUsed:      evilURL,
			ExternalRedirect: externalRedirect,
		},
	}, nil
}
