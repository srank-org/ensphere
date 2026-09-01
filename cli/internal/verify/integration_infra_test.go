package verify

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestIntegration_SSRF(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, signatureHandler("latest/meta-data ami-id"))

	cfg := SSRFConfig{
		URL:         ts.URL + "/api",
		Param:       "url",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifySSRF(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(SSRFMeasurements)
	if !ok {
		t.Fatalf("expected SSRFMeasurements, got %T", result.Measurements)
	}
	if len(m.MatchedSignatures) == 0 {
		t.Fatal("expected non-empty MatchedSignatures")
	}
}

func TestIntegration_Redirect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextParam := r.URL.Query().Get("next")
		if nextParam != "" {
			w.Header().Set("Location", nextParam)
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "home")
	}))

	cfg := RedirectConfig{
		URL:         ts.URL + "/redirect",
		Param:       "next",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyRedirect(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(RedirectMeasurements)
	if !ok {
		t.Fatalf("expected RedirectMeasurements, got %T", result.Measurements)
	}
	if m.LocationHeader == "" {
		t.Fatal("expected non-empty LocationHeader")
	}
	if !m.ExternalRedirect {
		t.Fatal("expected ExternalRedirect == true")
	}
}

func TestIntegration_ProtoPollution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, echoHandler())

	cfg := ProtoPollutionConfig{
		URL:         ts.URL + "/api",
		Method:      "POST",
		Technique:   "proto_assignment",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyProtoPollution(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(ProtoPollutionMeasurements)
	if !ok {
		t.Fatalf("expected ProtoPollutionMeasurements, got %T", result.Measurements)
	}
	if m.Baseline.StatusCode == 0 {
		t.Fatal("expected Baseline.StatusCode > 0")
	}
	if m.InjectionProbe.StatusCode == 0 {
		t.Fatal("expected InjectionProbe.StatusCode > 0")
	}
	if m.VerifyProbe.StatusCode == 0 {
		t.Fatal("expected VerifyProbe.StatusCode > 0")
	}
}

func TestIntegration_GraphQL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"data":{"__schema":{"types":[{"name":"Query"},{"name":"Mutation"}]}}}`)
	}))

	cfg := GraphQLConfig{
		URL:         ts.URL + "/graphql",
		Technique:   "introspection",
		Method:      "POST",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyGraphQL(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(GraphQLMeasurements)
	if !ok {
		t.Fatalf("expected GraphQLMeasurements, got %T", result.Measurements)
	}
	if m.IntrospectionEnabled == nil {
		t.Fatal("expected IntrospectionEnabled to be non-nil")
	}
	if !*m.IntrospectionEnabled {
		t.Fatal("expected IntrospectionEnabled == true")
	}
}

func TestIntegration_Clickjacking(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))

	cfg := ClickjackingConfig{
		URL:         ts.URL + "/page",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyClickjacking(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(ClickjackingMeasurements)
	if !ok {
		t.Fatalf("expected ClickjackingMeasurements, got %T", result.Measurements)
	}
	if !m.XFOPresent {
		t.Fatal("expected XFOPresent == true")
	}
	if !m.CSPFAPresent {
		t.Fatal("expected CSPFAPresent == true")
	}
}

func TestIntegration_HeaderInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("q")
		if val != "" {
			w.Header().Set("X-Reflected", val)
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))

	cfg := HeaderInjectionConfig{
		URL:         ts.URL + "/api",
		Param:       "q",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyHeaderInjection(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(HeaderInjectionMeasurements)
	if !ok {
		t.Fatalf("expected HeaderInjectionMeasurements, got %T", result.Measurements)
	}
	if m.Baseline.StatusCode != 200 {
		t.Fatalf("expected baseline status 200, got %d", m.Baseline.StatusCode)
	}
	if m.Probe.StatusCode == 0 {
		t.Fatal("expected Probe.StatusCode > 0")
	}
	if m.InjectedHeader != "X-Ensphere-Injected" {
		t.Fatalf("expected InjectedHeader = X-Ensphere-Injected, got %q", m.InjectedHeader)
	}
	if m.PayloadUsed == "" {
		t.Fatal("expected PayloadUsed to be non-empty")
	}
	// Go's net/http sanitizes CRLF in header values, so HeaderFound must be
	// false against the test server. This validates the measurement is populated
	// correctly; the AI interprets whether a real target is vulnerable.
	if m.HeaderFound {
		t.Fatal("expected HeaderFound == false (Go net/http sanitizes CRLF)")
	}
}

func TestIntegration_CachePoisoning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, echoHandler())

	cfg := CachePoisoningConfig{
		URL:         ts.URL + "/page",
		Technique:   "unkeyed_header",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyCachePoisoning(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(CachePoisoningMeasurements)
	if !ok {
		t.Fatalf("expected CachePoisoningMeasurements, got %T", result.Measurements)
	}
	if m.Baseline.StatusCode == 0 {
		t.Fatal("expected Baseline.StatusCode > 0")
	}
	if m.Injection.StatusCode == 0 {
		t.Fatal("expected Injection.StatusCode > 0")
	}
	if m.Verify.StatusCode == 0 {
		t.Fatal("expected Verify.StatusCode > 0")
	}
}

func TestIntegration_FileUpload_VerifyURLScope(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	_, err := VerifyFileUpload(FileUploadConfig{
		URL:         ts.URL + "/upload",
		FieldName:   "file",
		Filename:    "test.txt",
		Content:     "test",
		MIMEType:    "text/plain",
		Technique:   "extension_bypass",
		VerifyURL:   "http://evil.com/uploaded.txt",
		Method:      "POST",
		ProbeConfig: baseProbeConfig(),
	})
	if err == nil {
		t.Fatal("expected scope error for out-of-scope verify-url")
	}
	var scopeErr *ScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("expected ScopeError, got: %v", err)
	}
}
