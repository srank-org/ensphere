package verify

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/srank-org/ensphere/internal/evidence"
)

func TestVerifyRequestRecordsStageAndHashes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=supersecret; HttpOnly")
		w.Header().Set("X-Request-Id", "abc123")
		if r.Method == http.MethodPost {
			w.WriteHeader(201)
		}
		w.Write([]byte("ok " + r.Method))
	}))
	ledger := filepath.Join(t.TempDir(), "evidence.jsonl")
	cfg := baseProbeConfig()
	cfg.Evidence = ledger

	result, err := VerifyRequest(RequestConfig{
		URL:         ts.URL + "/api/orders/1/refund",
		Method:      "post",
		Body:        `{"reason":"test"}`,
		Result:      "control",
		Note:        "nonexistent order",
		ProbeConfig: cfg,
	})
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	if result.VulnType != "request" || result.Technique != "scoped_request" || result.ProbeCount != 1 {
		t.Fatalf("unexpected result envelope: %+v", result)
	}
	m, ok := result.Measurements.(RequestMeasurements)
	if !ok {
		t.Fatalf("unexpected measurements type %T", result.Measurements)
	}
	if m.Method != "POST" || m.Result != "control" || m.DeclaredRisk != 3 || m.Round.StatusCode != 201 {
		t.Fatalf("unexpected measurements: %+v", m)
	}
	if m.Round.Headers["set-cookie"] != "[REDACTED]" || m.Round.Headers["x-request-id"] != "abc123" {
		t.Fatalf("headers not recorded as expected: %+v", m.Round.Headers)
	}
	if !strings.HasPrefix(m.EvidenceID, "EVID-") {
		t.Fatalf("expected an evidence id, got %q", m.EvidenceID)
	}

	entries, _, err := evidence.ReadAll(ledger)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one ledger entry, got %d", len(entries))
	}
	entry := entries[0]
	if entry.ID != m.EvidenceID || entry.Result != "control" || entry.ProbeType != "request" || entry.Notes != "nonexistent order" {
		t.Fatalf("unexpected ledger entry: %+v", entry)
	}
	if entry.RequestHash != m.RequestHash || entry.ResponseHash != m.Round.BodyHash || entry.StatusCode != 201 {
		t.Fatalf("ledger entry hashes do not match the measurement: %+v vs %+v", entry, m)
	}
}

func TestVerifyRequestDoesNotFollowRedirectsByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/landed", http.StatusFound)
			return
		}
		w.Write([]byte("landed"))
	}))
	cfg := baseProbeConfig()
	first, err := VerifyRequest(RequestConfig{URL: ts.URL + "/start", Result: "baseline", ProbeConfig: cfg})
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	if first.Measurements.(RequestMeasurements).Round.StatusCode != 302 {
		t.Fatalf("expected the first hop to be recorded, got %+v", first.Measurements)
	}
	followed, err := VerifyRequest(RequestConfig{URL: ts.URL + "/start", Result: "baseline", FollowRedirects: true, ProbeConfig: cfg})
	if err != nil {
		t.Fatalf("verify request with redirects: %v", err)
	}
	if followed.Measurements.(RequestMeasurements).Round.StatusCode != 200 {
		t.Fatalf("expected the redirect to be followed, got %+v", followed.Measurements)
	}
}

func TestVerifyRequestRejectsUndeclaredRoleMethodAndOversizedBody(t *testing.T) {
	cfg := baseProbeConfig()
	base := RequestConfig{URL: "http://localhost/api", Result: "probe", ProbeConfig: cfg}

	bad := base
	bad.Result = "finding"
	if _, err := VerifyRequest(bad); err == nil || !strings.Contains(err.Error(), "baseline, probe, or control") {
		t.Fatalf("expected role validation error, got %v", err)
	}
	bad = base
	bad.Method = "TRACE"
	if _, err := VerifyRequest(bad); err == nil || !strings.Contains(err.Error(), "unsupported method") {
		t.Fatalf("expected method validation error, got %v", err)
	}
	bad = base
	bad.Body = strings.Repeat("a", maxRequestBodyBytes+1)
	if _, err := VerifyRequest(bad); err == nil || !strings.Contains(err.Error(), "verify limits") {
		t.Fatalf("expected body size error, got %v", err)
	}
	bad = base
	bad.Risk = 6
	if _, err := VerifyRequest(bad); err == nil || !strings.Contains(err.Error(), "between 1 and 5") {
		t.Fatalf("expected risk range error, got %v", err)
	}
	bad = base
	bad.Risk = 4
	bad.MaxRisk = 3
	result, err := VerifyRequest(bad)
	assertScopeErr(t, result, err)
}
