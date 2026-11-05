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

func TestVerifyLimits_UploadSizeServerClosesBeforeReadingTheBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 9\r\nConnection: close\r\n\r\ntoo large")
		_ = conn.Close()
	}))
	t.Cleanup(ts.Close)

	cfg := LimitsConfig{
		URL:         ts.URL + "/upload",
		Technique:   "upload_size",
		Sizes:       []int{8 << 20},
		ProbeConfig: baseProbeConfig(),
	}
	result, err := VerifyLimits(cfg)
	if err != nil {
		t.Fatalf("a server that answers and closes before consuming the body is a measurement, not an error: %v", err)
	}
	round := result.Measurements.(LimitsMeasurements).Upload[0]
	// Expect: 100-continue lets the server answer before any body is sent, so
	// the 413 is read cleanly instead of being lost to a reset mid-upload.
	if round.SizeBytes != 8<<20 || round.StatusCode != http.StatusRequestEntityTooLarge || round.ResponseBytes != 9 {
		t.Fatalf("expected the 413 and its body, got %+v", round)
	}
}

func TestVerifyLimits_UploadSizeDeclaresLengthAndExpectContinue(t *testing.T) {
	var contentLength int64
	var expect string
	var received int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentLength, expect = r.ContentLength, r.Header.Get("Expect")
		received, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(ts.Close)

	result, err := VerifyLimits(LimitsConfig{URL: ts.URL + "/upload", Technique: "upload_size", Sizes: []int{2048}, ProbeConfig: baseProbeConfig()})
	if err != nil {
		t.Fatalf("VerifyLimits: %v", err)
	}
	round := result.Measurements.(LimitsMeasurements).Upload[0]
	if round.StatusCode != http.StatusCreated || round.ConnectionClosed {
		t.Fatalf("unexpected round %+v", round)
	}
	if contentLength <= 2048 || contentLength != received {
		t.Fatalf("the request must declare the multipart body's exact length: Content-Length %d, received %d", contentLength, received)
	}
	// Go's server consumes Expect itself and sends 100 Continue before the
	// first body read; the handler sees the body arrive in full.
	if expect != "" && expect != "100-continue" {
		t.Fatalf("unexpected Expect header %q", expect)
	}
}
