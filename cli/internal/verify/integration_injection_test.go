package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestIntegration_SQLi_BlindTime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, delayHandler(150*time.Millisecond))

	cfg := SQLiConfig{
		URL:         ts.URL + "/api",
		Param:       "id",
		Technique:   "blind_time",
		Method:      "GET",
		Boundary:    "single_quote",
		ProbeConfig: baseProbeConfig(),
	}
	cfg.TimeoutSec = 10

	result, err := VerifySQLi(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.VulnType != "sqli" {
		t.Fatalf("expected VulnType sqli, got %s", result.VulnType)
	}
	if result.Technique != "blind_time" {
		t.Fatalf("expected Technique blind_time, got %s", result.Technique)
	}

	m, ok := result.Measurements.(SQLiTimeMeasurements)
	if !ok {
		t.Fatalf("expected SQLiTimeMeasurements, got %T", result.Measurements)
	}
	if m.PayloadAvgMs <= m.BaselineAvgMs {
		t.Fatalf("expected PayloadAvgMs > BaselineAvgMs, got %d <= %d", m.PayloadAvgMs, m.BaselineAvgMs)
	}
	if m.DeltaMs <= 0 {
		t.Fatalf("expected DeltaMs > 0, got %d", m.DeltaMs)
	}
	if len(m.BaselineRounds) == 0 {
		t.Fatal("expected non-empty BaselineRounds")
	}
	if len(m.PayloadRounds) == 0 {
		t.Fatal("expected non-empty PayloadRounds")
	}
}

func TestIntegration_SQLi_BlindBoolean(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Return different bodies for true vs false conditions
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "1%3D1") || strings.Contains(q, "1=1") {
			w.WriteHeader(200)
			fmt.Fprint(w, "found results: user1, user2, user3")
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, "no results found")
		}
	}))

	cfg := SQLiConfig{
		URL:         ts.URL + "/api",
		Param:       "id",
		Technique:   "blind_boolean",
		Method:      "GET",
		Boundary:    "single_quote",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifySQLi(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(SQLiBooleanMeasurements)
	if !ok {
		t.Fatalf("expected SQLiBooleanMeasurements, got %T", result.Measurements)
	}
	if m.HashesMatch {
		t.Fatal("expected HashesMatch == false (true/false give different bodies)")
	}
}

func TestIntegration_SQLi_ErrorBased(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, "ERROR: invalid input syntax for type integer")
	}))

	cfg := SQLiConfig{
		URL:         ts.URL + "/api",
		Param:       "id",
		Technique:   "error_based",
		Method:      "GET",
		Boundary:    "single_quote",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifySQLi(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(SQLiErrorMeasurements)
	if !ok {
		t.Fatalf("expected SQLiErrorMeasurements, got %T", result.Measurements)
	}
	if len(m.MatchedPatterns) == 0 {
		t.Fatal("expected non-empty MatchedPatterns")
	}
}

func TestIntegration_XSS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Handler that reflects URL-decoded query param values in the body
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "search results for: %s", r.URL.Query().Get("q"))
	}))

	cfg := XSSConfig{
		URL:         ts.URL + "/search",
		Param:       "q",
		Payload:     "<script>alert(1)</script>",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyXSS(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(XSSMeasurements)
	if !ok {
		t.Fatalf("expected XSSMeasurements, got %T", result.Measurements)
	}
	if !m.Reflected {
		t.Fatal("expected Reflected == true")
	}
}

func TestIntegration_CMDi(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, delayHandler(150*time.Millisecond))

	cfg := CMDiConfig{
		URL:         ts.URL + "/api",
		Param:       "cmd",
		OS:          "linux",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}
	cfg.TimeoutSec = 10

	result, err := VerifyCMDi(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(CMDiTimeMeasurements)
	if !ok {
		t.Fatalf("expected CMDiTimeMeasurements, got %T", result.Measurements)
	}
	if m.PayloadAvgMs <= m.BaselineAvgMs {
		t.Fatalf("expected PayloadAvgMs > BaselineAvgMs, got %d <= %d", m.PayloadAvgMs, m.BaselineAvgMs)
	}
}

func TestIntegration_LFI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, signatureHandler("root:x:0:0"))

	cfg := LFIConfig{
		URL:         ts.URL + "/api",
		Param:       "file",
		OS:          "linux",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyLFI(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(LFIMeasurements)
	if !ok {
		t.Fatalf("expected LFIMeasurements, got %T", result.Measurements)
	}
	if len(m.MatchedSignatures) == 0 {
		t.Fatal("expected non-empty MatchedSignatures")
	}
}

func TestIntegration_SSTI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		// Simulate template evaluation: {{7*7}} → 49
		if strings.Contains(q, "7*7") || strings.Contains(q, "7%2A7") {
			w.WriteHeader(200)
			fmt.Fprint(w, "result: 49 end")
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, "template output")
		}
	}))

	cfg := SSTIConfig{
		URL:         ts.URL + "/render",
		Param:       "tpl",
		Engine:      "auto",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifySSTI(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(SSTIMeasurements)
	if !ok {
		t.Fatalf("expected SSTIMeasurements, got %T", result.Measurements)
	}
	foundAny := false
	for _, p := range m.Probes {
		if p.Found {
			foundAny = true
			break
		}
	}
	if !foundAny {
		t.Fatal("expected at least one SSTI probe to find its expected value")
	}
}

func TestIntegration_XXE(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "xxe") || strings.Contains(string(body), "SYSTEM") {
			w.WriteHeader(200)
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, "ok")
		}
	}))

	cfg := XXEConfig{
		URL:         ts.URL + "/xml",
		Method:      "POST",
		Technique:   "file_read",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyXXE(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(XXEMeasurements)
	if !ok {
		t.Fatalf("expected XXEMeasurements, got %T", result.Measurements)
	}
	if len(m.MatchedSignatures) == 0 {
		t.Fatal("expected non-empty MatchedSignatures")
	}
}

func TestIntegration_NoSQL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err == nil {
			if user, ok := payload["user"]; ok {
				if m, ok := user.(map[string]interface{}); ok {
					if gt, ok := m["$gt"]; ok {
						if s, ok := gt.(string); ok && s == "" {
							w.WriteHeader(200)
							fmt.Fprint(w, `[{"user":"admin"},{"user":"test"}]`)
							return
						}
					}
				}
			}
		}
		w.WriteHeader(200)
		fmt.Fprint(w, `[]`)
	}))

	cfg := NoSQLConfig{
		URL:         ts.URL + "/api",
		Param:       "user",
		Technique:   "operator_injection",
		Method:      "POST",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyNoSQL(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(NoSQLMeasurements)
	if !ok {
		t.Fatalf("expected NoSQLMeasurements, got %T", result.Measurements)
	}
	if m.HashesMatch == nil {
		t.Fatal("expected HashesMatch to be non-nil")
	}
	if *m.HashesMatch {
		t.Fatal("expected HashesMatch == false (true/false give different bodies)")
	}
}

func TestIntegration_CSVInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/export", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "name,email\n=CMD(\"ensphere_csv_test\"),user@test.com\n")
	})
	ts := newTestServer(t, mux)

	cfg := CSVInjectionConfig{
		SubmitURL:   ts.URL + "/submit",
		ExportURL:   ts.URL + "/export",
		Param:       "name",
		Method:      "POST",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyCSVInjection(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(CSVInjectionMeasurements)
	if !ok {
		t.Fatalf("expected CSVInjectionMeasurements, got %T", result.Measurements)
	}
	if !m.FormulaFound {
		t.Fatal("expected FormulaFound == true")
	}
}

func TestIntegration_LDAP_FilterInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "uid") && (strings.Contains(q, "%2A") || strings.Contains(q, "*")) {
			w.WriteHeader(200)
			fmt.Fprint(w, `[{"uid":"admin"},{"uid":"guest"}]`)
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, `[]`)
		}
	}))

	cfg := LDAPConfig{
		URL:         ts.URL + "/ldap",
		Param:       "uid",
		Technique:   "ldap_filter_injection",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyLDAP(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(LDAPMeasurements)
	if !ok {
		t.Fatalf("expected LDAPMeasurements, got %T", result.Measurements)
	}
	if m.HashesMatch == nil {
		t.Fatal("expected HashesMatch to be non-nil")
	}
	if *m.HashesMatch {
		t.Fatal("expected HashesMatch == false")
	}
}

func TestIntegration_LDAP_BlindBoolean(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "cn%3Da") || strings.Contains(q, "cn=a") {
			w.WriteHeader(200)
			fmt.Fprint(w, `[{"cn":"admin"}]`)
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, `[]`)
		}
	}))

	cfg := LDAPConfig{
		URL:         ts.URL + "/ldap",
		Param:       "uid",
		Technique:   "ldap_blind_boolean",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyLDAP(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(LDAPMeasurements)
	if !ok {
		t.Fatalf("expected LDAPMeasurements, got %T", result.Measurements)
	}
	if m.HashesMatch == nil {
		t.Fatal("expected HashesMatch to be non-nil")
	}
	if *m.HashesMatch {
		t.Fatal("expected HashesMatch == false (true/false should differ)")
	}
}

func TestIntegration_LDAP_BlindError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "%28%28%28") || strings.Contains(q, "(((") {
			w.WriteHeader(500)
			fmt.Fprint(w, "Error: LDAP_FILTER_ERROR: Invalid filter syntax")
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, `{"result":"ok"}`)
		}
	}))

	cfg := LDAPConfig{
		URL:         ts.URL + "/ldap",
		Param:       "uid",
		Technique:   "ldap_blind_error",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyLDAP(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(LDAPMeasurements)
	if !ok {
		t.Fatalf("expected LDAPMeasurements, got %T", result.Measurements)
	}
	if len(m.MatchedPatterns) == 0 {
		t.Fatal("expected non-empty MatchedPatterns")
	}
}

func TestIntegration_XPath_Injection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "1%27%3D%271") || strings.Contains(q, "1'='1") {
			w.WriteHeader(200)
			fmt.Fprint(w, `<results><user>admin</user><user>guest</user></results>`)
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, `<results></results>`)
		}
	}))

	cfg := XPathConfig{
		URL:         ts.URL + "/xml",
		Param:       "q",
		Technique:   "xpath_injection",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyXPath(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(XPathMeasurements)
	if !ok {
		t.Fatalf("expected XPathMeasurements, got %T", result.Measurements)
	}
	if m.HashesMatch == nil {
		t.Fatal("expected HashesMatch to be non-nil")
	}
	if *m.HashesMatch {
		t.Fatal("expected HashesMatch == false")
	}
}

func TestIntegration_XPath_BlindError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "%27%5D%5B1") || strings.Contains(q, "'][1") {
			w.WriteHeader(500)
			fmt.Fprint(w, "XPathException: Invalid expression")
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, `<result>ok</result>`)
		}
	}))

	cfg := XPathConfig{
		URL:         ts.URL + "/xml",
		Param:       "q",
		Technique:   "xpath_blind_error",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyXPath(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(XPathMeasurements)
	if !ok {
		t.Fatalf("expected XPathMeasurements, got %T", result.Measurements)
	}
	if len(m.MatchedPatterns) == 0 {
		t.Fatal("expected non-empty MatchedPatterns")
	}
}

func TestIntegration_FileUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(10 << 20)
		file, header, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"no file"}`)
			return
		}
		defer file.Close()
		w.WriteHeader(200)
		fmt.Fprintf(w, `{"uploaded":"%s","size":%d}`, header.Filename, header.Size)
	}))

	cfg := FileUploadConfig{
		URL:         ts.URL + "/upload",
		FieldName:   "file",
		Filename:    "shell.php.jpg",
		Content:     "ensphere_upload_test",
		MIMEType:    "image/jpeg",
		Technique:   "extension_bypass",
		Method:      "POST",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyFileUpload(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(FileUploadMeasurements)
	if !ok {
		t.Fatalf("expected FileUploadMeasurements, got %T", result.Measurements)
	}
	if !m.UploadAccepted {
		t.Fatal("expected UploadAccepted == true")
	}
	if !m.FilenameInResponse {
		t.Fatal("expected FilenameInResponse == true")
	}
}

func TestIntegration_SQLi_POST(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	// Handler delays only when POST body contains timing keyword
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)
		if r.Method == "POST" && strings.Contains(bodyStr, "pg_sleep") {
			time.Sleep(150 * time.Millisecond)
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))
	cfg := SQLiConfig{
		URL:         ts.URL + "/api",
		Param:       "id",
		Technique:   "blind_time",
		Method:      "POST",
		Boundary:    "single_quote",
		ProbeConfig: baseProbeConfig(),
	}
	cfg.TimeoutSec = 10
	result, err := VerifySQLi(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.Measurements.(SQLiTimeMeasurements)
	if !ok {
		t.Fatal("unexpected measurements type")
	}
	if m.PayloadAvgMs <= m.BaselineAvgMs {
		t.Errorf("POST mode: payload avg (%d) should be > baseline avg (%d)", m.PayloadAvgMs, m.BaselineAvgMs)
	}
}
