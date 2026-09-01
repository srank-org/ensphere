package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestVerifyLimits_Pagination(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if n > 1000 {
			n = 1000 // server-side cap
		}
		items := make([]int, n)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	}))
	t.Cleanup(ts.Close)

	cfg := LimitsConfig{
		URL:         ts.URL + "/api/items",
		Technique:   "pagination",
		Method:      "GET",
		Param:       "limit",
		Values:      []int{1, 100, 10000},
		ProbeConfig: baseProbeConfig(),
	}
	result, err := VerifyLimits(cfg)
	if err != nil {
		t.Fatalf("VerifyLimits: %v", err)
	}
	m, ok := result.Measurements.(LimitsMeasurements)
	if !ok {
		t.Fatalf("unexpected measurements type %T", result.Measurements)
	}
	if len(m.Pagination) != 3 {
		t.Fatalf("expected 3 rounds, got %d", len(m.Pagination))
	}
	if m.Pagination[0].ItemCount == nil || *m.Pagination[0].ItemCount != 1 {
		t.Fatalf("value=1 expected item_count 1, got %v", m.Pagination[0].ItemCount)
	}
	if m.Pagination[2].ItemCount == nil || *m.Pagination[2].ItemCount != 1000 {
		t.Fatalf("value=10000 expected capped item_count 1000, got %v", m.Pagination[2].ItemCount)
	}
	if result.ProbeCount != 3 {
		t.Fatalf("expected probe_count 3, got %d", result.ProbeCount)
	}
}

func TestVerifyLimits_PaginationRefusesWithoutValues(t *testing.T) {
	cfg := LimitsConfig{
		URL:         "http://localhost/api/items",
		Technique:   "pagination",
		Param:       "limit",
		ProbeConfig: baseProbeConfig(),
	}
	if _, err := VerifyLimits(cfg); err == nil {
		t.Fatal("expected error when values are missing")
	}
}

func TestVerifyLimits_UploadSize(t *testing.T) {
	var received []int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received = append(received, int(n))
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(ts.Close)

	cfg := LimitsConfig{
		URL:         ts.URL + "/upload",
		Technique:   "upload_size",
		Sizes:       []int{1024, 4096},
		Field:       "file",
		ProbeConfig: baseProbeConfig(),
	}
	result, err := VerifyLimits(cfg)
	if err != nil {
		t.Fatalf("VerifyLimits: %v", err)
	}
	m := result.Measurements.(LimitsMeasurements)
	if len(m.Upload) != 2 {
		t.Fatalf("expected 2 upload rounds, got %d", len(m.Upload))
	}
	for i, round := range m.Upload {
		if round.StatusCode != http.StatusCreated {
			t.Fatalf("round %d unexpected status %d", i, round.StatusCode)
		}
		if round.ResponseBytes != 2 {
			t.Fatalf("round %d expected response_bytes 2, got %d", i, round.ResponseBytes)
		}
	}
	// The multipart body must carry at least the requested bytes.
	if len(received) != 2 || received[0] < 1024 || received[1] < 4096 {
		t.Fatalf("server received unexpected sizes: %v", received)
	}
}

func TestVerifyLimits_UploadSizeCapRejected(t *testing.T) {
	cfg := LimitsConfig{
		URL:         "http://localhost/upload",
		Technique:   "upload_size",
		Sizes:       []int{maxUploadSizeBytes + 1},
		ProbeConfig: baseProbeConfig(),
	}
	if _, err := VerifyLimits(cfg); err == nil {
		t.Fatal("expected error for oversize upload request")
	}
}

func TestVerifyLimits_ResponseSize(t *testing.T) {
	body := strings.Repeat("A", 5000)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		fmt.Fprint(w, body)
	}))
	t.Cleanup(ts.Close)

	cfg := LimitsConfig{
		URL:         ts.URL + "/export",
		Technique:   "response_size",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}
	result, err := VerifyLimits(cfg)
	if err != nil {
		t.Fatalf("VerifyLimits: %v", err)
	}
	m := result.Measurements.(LimitsMeasurements)
	if m.Response == nil {
		t.Fatal("expected response measurement")
	}
	if m.Response.BodyBytes != 5000 {
		t.Fatalf("expected body_bytes 5000, got %d", m.Response.BodyBytes)
	}
	if m.Response.ContentLengthHeader != "5000" {
		t.Fatalf("expected content_length_header 5000, got %q", m.Response.ContentLengthHeader)
	}
}

func TestVerifyLimits_ScopeAndTechnique(t *testing.T) {
	// Out of scope
	if _, err := VerifyLimits(LimitsConfig{URL: "http://evil.example.com/x", Technique: "pagination", Param: "p", Values: []int{1}, ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}}}); err == nil {
		t.Fatal("expected scope error")
	}
	// Bad technique
	if _, err := VerifyLimits(LimitsConfig{URL: "http://localhost/x", Technique: "INVALID", ProbeConfig: baseProbeConfig()}); err == nil {
		t.Fatal("expected technique error")
	}
}
