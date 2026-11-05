package invariants

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
	"github.com/srank-org/ensphere/internal/verify"
)

func requestURL(target, path string) string {
	return strings.TrimRight(target, "/") + path
}

func requestHeaders(base map[string]string, req *Request) map[string]string {
	headers := make(map[string]string, len(base)+len(req.Headers))
	for k, v := range base {
		headers[k] = v
	}
	for k, v := range req.Headers {
		headers[k] = v
	}
	return headers
}

func requestMethod(req *Request) string {
	if req.Method == "" {
		return http.MethodGet
	}
	return strings.ToUpper(req.Method)
}

func runHTTP(inv Invariant, cfg RunConfig) outcome {
	url := requestURL(cfg.Target, inv.Request.Path)
	if err := verify.CheckScope(url, cfg.Scope); err != nil {
		return errorOutcome("scope: %v", err)
	}
	timeout := cfg.TimeoutSec
	if inv.TimeoutSec != nil {
		timeout = *inv.TimeoutSec
	}
	if timeout < 1 {
		timeout = defaultTimeoutSec
	}
	resp := verify.HTTPProbeNoRedirect(requestMethod(inv.Request), url, inv.Request.Body,
		requestHeaders(cfg.Headers, inv.Request), timeout, cfg.Scope)
	if resp.Error != nil {
		return errorOutcome("request %s: %v", url, resp.Error)
	}

	e := inv.Expect
	measured := HTTPMeasured{URL: url, StatusCode: resp.StatusCode, BodyLength: len(resp.Body)}
	var checks []Check
	if e.Status != nil {
		checks = append(checks, Check{Check: fmt.Sprintf("status %d (got %d)", *e.Status, resp.StatusCode), Held: resp.StatusCode == *e.Status})
	}
	if len(e.StatusIn) > 0 {
		checks = append(checks, Check{Check: fmt.Sprintf("status_in %v (got %d)", e.StatusIn, resp.StatusCode), Held: containsInt(e.StatusIn, resp.StatusCode)})
	}
	seen := map[string]bool{}
	record := func(name string) []string {
		values := resp.Headers.Values(name)
		lower := strings.ToLower(name)
		if len(values) > 0 && !seen[lower] {
			seen[lower] = true
			if measured.Headers == nil {
				measured.Headers = map[string]string{}
			}
			measured.Headers[lower] = evidence.RedactSecrets(strings.Join(values, ", "))
		}
		return values
	}
	for _, name := range e.HeaderPresent {
		checks = append(checks, Check{Check: "header_present " + strings.ToLower(name), Held: len(record(name)) > 0})
	}
	for _, name := range e.HeaderAbsent {
		checks = append(checks, Check{Check: "header_absent " + strings.ToLower(name), Held: len(record(name)) == 0})
	}
	for _, name := range sortedKeys(e.HeaderMatches) {
		re, err := regexp.Compile(e.HeaderMatches[name])
		if err != nil {
			return errorOutcome("expect.header_matches.%s does not compile after substitution: %v", name, err)
		}
		held := false
		for _, v := range record(name) {
			if re.MatchString(v) {
				held = true
				break
			}
		}
		checks = append(checks, Check{Check: "header_matches " + strings.ToLower(name), Held: held})
	}
	if e.BodyContains != "" {
		checks = append(checks, Check{Check: "body_contains", Held: strings.Contains(resp.Body, e.BodyContains)})
	}
	if e.BodyNotContains != "" {
		checks = append(checks, Check{Check: "body_not_contains", Held: !strings.Contains(resp.Body, e.BodyNotContains)})
	}
	measured.Checks = checks
	return fromChecks(checks, measured)
}

func runRateLimit(inv Invariant, cfg RunConfig) outcome {
	url := requestURL(cfg.Target, inv.Request.Path)
	window := 10
	if inv.WindowSec != nil {
		window = *inv.WindowSec
	}
	result, err := verify.VerifyRateLimit(verify.RateLimitConfig{
		URL:        url,
		Method:     requestMethod(inv.Request),
		Body:       inv.Request.Body,
		BurstCount: *inv.Burst,
		WindowSec:  window,
		ProbeConfig: verify.ProbeConfig{
			InScope:    cfg.Scope,
			MaxRisk:    cfg.MaxRisk,
			TimeoutSec: positiveOr(cfg.TimeoutSec, defaultTimeoutSec),
			Headers:    requestHeaders(cfg.Headers, inv.Request),
		},
	})
	if err != nil {
		return errorOutcome("rate limit burst %s: %v", url, err)
	}
	set, ok := result.Measurements.(verify.RateLimitMeasurementSet)
	if !ok {
		return errorOutcome("rate limit burst returned unexpected measurements %T", result.Measurements)
	}
	m := set.IdentityA
	measured := RateLimitMeasured{
		URL:             url,
		Burst:           m.BurstCount,
		RequestsSent:    len(m.Rounds),
		FirstThrottleAt: m.FirstThrottleAt,
		ThrottledCount:  m.ThrottledCount,
		StatusCodes:     m.StatusCodes,
	}
	hasRetryAfter := false
	for _, round := range m.Rounds {
		if round.StatusCode == http.StatusTooManyRequests || round.StatusCode == http.StatusServiceUnavailable {
			measured.RetryAfter, hasRetryAfter = round.Headers["retry-after"]
			break
		}
	}

	within := *inv.Expect.ThrottledWithin
	checks := []Check{{
		Check: fmt.Sprintf("throttled_within %d (first throttle at %d)", within, m.FirstThrottleAt),
		Held:  m.FirstThrottleAt >= 1 && m.FirstThrottleAt <= within,
	}}
	if inv.Expect.RetryAfterHeader {
		checks = append(checks, Check{Check: "retry_after_header on the first throttled response", Held: hasRetryAfter})
	}
	measured.Checks = checks
	return fromChecks(checks, measured)
}

func runSizeLimit(inv Invariant, cfg RunConfig) outcome {
	url := requestURL(cfg.Target, inv.Request.Path)
	result, err := verify.VerifyLimits(verify.LimitsConfig{
		URL:       url,
		Technique: "upload_size",
		Method:    strings.ToUpper(inv.Request.Method),
		Sizes:     []int{*inv.SizeBytes},
		Field:     inv.Field,
		ProbeConfig: verify.ProbeConfig{
			InScope:    cfg.Scope,
			MaxRisk:    cfg.MaxRisk,
			TimeoutSec: positiveOr(cfg.TimeoutSec, defaultTimeoutSec),
			Headers:    requestHeaders(cfg.Headers, inv.Request),
		},
	})
	if err != nil {
		return errorOutcome("upload %d bytes to %s: %v", *inv.SizeBytes, url, err)
	}
	m, ok := result.Measurements.(verify.LimitsMeasurements)
	if !ok || len(m.Upload) != 1 {
		return errorOutcome("upload probe returned unexpected measurements %T", result.Measurements)
	}
	round := m.Upload[0]
	measured := SizeLimitMeasured{URL: url, SizeBytes: round.SizeBytes, StatusCode: round.StatusCode, ResponseBytes: round.ResponseBytes}

	wantRejected := inv.Expect.Rejected == nil || *inv.Expect.Rejected
	rejected := round.StatusCode < 200 || round.StatusCode > 299
	checks := []Check{{Check: fmt.Sprintf("rejected %t (got %d)", wantRejected, round.StatusCode), Held: rejected == wantRejected}}
	if len(inv.Expect.StatusIn) > 0 {
		checks = append(checks, Check{Check: fmt.Sprintf("status_in %v (got %d)", inv.Expect.StatusIn, round.StatusCode), Held: containsInt(inv.Expect.StatusIn, round.StatusCode)})
	}
	measured.Checks = checks
	return fromChecks(checks, measured)
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func positiveOr(v, fallback int) int {
	if v < 1 {
		return fallback
	}
	return v
}
