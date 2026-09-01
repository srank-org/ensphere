package verify

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyRateLimitRequiresExplicitBurstCount(t *testing.T) {
	cfg := RateLimitConfig{
		URL:         "http://localhost/api",
		Method:      "GET",
		BurstCount:  0,
		ProbeConfig: baseProbeConfig(),
	}
	_, err := VerifyRateLimit(cfg)
	if err == nil || !strings.Contains(err.Error(), "burst count must be explicitly set") {
		t.Fatalf("expected explicit burst-count error, got %v", err)
	}
}

func TestVerifyRateLimit_SequentialBurst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	var count atomic.Int32
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		if n > 5 {
			w.WriteHeader(429)
			fmt.Fprint(w, "rate limited")
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))

	cfg := RateLimitConfig{
		URL:         srv.URL + "/api",
		Method:      "GET",
		BurstCount:  10,
		WindowSec:   10,
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyRateLimit(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	set, ok := result.Measurements.(RateLimitMeasurementSet)
	if !ok {
		t.Fatal("unexpected measurements type")
	}
	m := set.IdentityA
	if m.SuccessCount != 5 {
		t.Errorf("expected 5 successes, got %d", m.SuccessCount)
	}
	if m.ThrottledCount != 5 {
		t.Errorf("expected 5 throttled, got %d", m.ThrottledCount)
	}
	if m.FirstThrottleAt != 6 {
		t.Errorf("expected first throttle at 6, got %d", m.FirstThrottleAt)
	}
}

func TestVerifyRateLimit_NoThrottling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))

	cfg := RateLimitConfig{
		URL:         srv.URL + "/api",
		Method:      "GET",
		BurstCount:  10,
		WindowSec:   10,
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyRateLimit(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	set, ok := result.Measurements.(RateLimitMeasurementSet)
	if !ok {
		t.Fatal("unexpected measurements type")
	}
	m := set.IdentityA
	if m.SuccessCount != 10 {
		t.Errorf("expected 10 successes, got %d", m.SuccessCount)
	}
	if m.ThrottledCount != 0 {
		t.Errorf("expected 0 throttled, got %d", m.ThrottledCount)
	}
	if m.FirstThrottleAt != 0 {
		t.Errorf("expected first throttle at 0, got %d", m.FirstThrottleAt)
	}
}

func TestVerifyRateLimit_WindowExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))

	cfg := RateLimitConfig{
		URL:         srv.URL + "/api",
		Method:      "GET",
		BurstCount:  100,
		WindowSec:   1,
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyRateLimit(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	set, ok := result.Measurements.(RateLimitMeasurementSet)
	if !ok {
		t.Fatal("unexpected measurements type")
	}
	m := set.IdentityA
	if len(m.Rounds) >= 100 {
		t.Errorf("expected fewer than 100 rounds due to window expiry, got %d", len(m.Rounds))
	}
}
