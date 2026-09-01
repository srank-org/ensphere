package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestIntegration_Auth_NoToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, authGateHandler("valid-token"))

	cfg := AuthConfig{
		URL:         ts.URL + "/api",
		Method:      "GET",
		Token:       "valid-token",
		Technique:   "no_token",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyAuth(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(AuthMeasurements)
	if !ok {
		t.Fatalf("expected AuthMeasurements, got %T", result.Measurements)
	}
	if m.Baseline.StatusCode != 200 {
		t.Fatalf("expected baseline status 200, got %d", m.Baseline.StatusCode)
	}
	if m.Probe.StatusCode != 401 {
		t.Fatalf("expected probe status 401, got %d", m.Probe.StatusCode)
	}
}

func TestIntegration_AuthZ(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer high-token" {
			w.WriteHeader(200)
			fmt.Fprint(w, `{"role":"admin","data":"secret"}`)
		} else {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"error":"forbidden"}`)
		}
	}))

	cfg := AuthZConfig{
		URL:           ts.URL + "/admin",
		Method:        "GET",
		LowPrivToken:  "low-token",
		HighPrivToken: "high-token",
		ProbeConfig:   baseProbeConfig(),
	}

	result, err := VerifyAuthZ(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(AuthZMeasurements)
	if !ok {
		t.Fatalf("expected AuthZMeasurements, got %T", result.Measurements)
	}
	if m.HighPriv.StatusCode == m.LowPriv.StatusCode {
		t.Fatalf("expected different status codes, both got %d", m.HighPriv.StatusCode)
	}
}

func TestIntegration_RLS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	const jwtSecret = "test-secret-at-least-32-chars-long"

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/rest/v1/") {
			w.WriteHeader(404)
			return
		}

		// Parse JWT from Authorization header
		auth := r.Header.Get("Authorization")
		tokenStr := strings.TrimPrefix(auth, "Bearer ")

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil {
			w.WriteHeader(401)
			fmt.Fprintf(w, `{"error":"invalid token: %v"}`, err)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			w.WriteHeader(401)
			return
		}

		tokenCompanyID, _ := claims["company_id"].(string)
		queryCompanyID := r.URL.Query().Get("company_id")
		// Extract from "eq.VALUE"
		if strings.HasPrefix(queryCompanyID, "eq.") {
			queryCompanyID = strings.TrimPrefix(queryCompanyID, "eq.")
		}

		// Simulate RLS: only return rows if token company matches query company
		if tokenCompanyID == queryCompanyID {
			w.WriteHeader(200)
			fmt.Fprintf(w, `[{"id":1,"company_id":"%s","data":"row1"}]`, queryCompanyID)
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, `[]`)
		}
	}))

	cfg := RLSConfig{
		ProjectURL:  ts.URL,
		AnonKey:     "test-anon-key",
		JWTSecret:   jwtSecret,
		Table:       "projects",
		TenantA:     "company-a",
		TenantB:     "company-b",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyRLS(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(RLSMeasurements)
	if !ok {
		t.Fatalf("expected RLSMeasurements, got %T", result.Measurements)
	}
	if m.TenantAOwn.StatusCode == 0 {
		t.Fatal("expected TenantAOwn.StatusCode > 0")
	}
	if m.TenantBOwn.StatusCode == 0 {
		t.Fatal("expected TenantBOwn.StatusCode > 0")
	}
	if m.CrossTenant.StatusCode == 0 {
		t.Fatal("expected CrossTenant.StatusCode > 0")
	}
}

func TestCountJSONRows(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{"empty array", "[]", 0},
		{"one row", `[{"id":1}]`, 1},
		{"two rows", `[{"id":1},{"id":2}]`, 2},
		{"html error page", "<html>403 Forbidden</html>", -1},
		{"json object not array", `{"error":"unauthorized"}`, -1},
		{"empty string", "", -1},
		{"plain text", "Internal Server Error", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countJSONRows(tt.body)
			if got != tt.want {
				t.Errorf("countJSONRows(%q) = %d, want %d", tt.body, got, tt.want)
			}
		})
	}
}

func TestIntegration_JWT(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	const validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	ts := newTestServer(t, authGateHandler(validToken))

	cfg := JWTConfig{
		URL:         ts.URL + "/api",
		Token:       validToken,
		Technique:   "alg_none",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyJWT(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(JWTMeasurements)
	if !ok {
		t.Fatalf("expected JWTMeasurements, got %T", result.Measurements)
	}
	if m.Baseline.StatusCode != 200 {
		t.Fatalf("expected baseline status 200, got %d", m.Baseline.StatusCode)
	}
	if m.ModifiedToken == "" {
		t.Fatal("expected non-empty ModifiedToken")
	}
}

func TestIntegration_CORS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))

	cfg := CORSConfig{
		URL:         ts.URL + "/api",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyCORS(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(CORSMeasurements)
	if !ok {
		t.Fatalf("expected CORSMeasurements, got %T", result.Measurements)
	}
	if !m.EvilOrigin.OriginReflected {
		t.Fatal("expected EvilOrigin.OriginReflected == true")
	}
}

func TestIntegration_CSRF(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc123; SameSite=Lax; Secure")
		w.WriteHeader(200)
		fmt.Fprint(w, `<form><input type="hidden" name="csrf_token" value="xyz"></form>`)
	}))

	cfg := CSRFConfig{
		URL:         ts.URL + "/form",
		Method:      "POST",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyCSRF(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(CSRFMeasurements)
	if !ok {
		t.Fatalf("expected CSRFMeasurements, got %T", result.Measurements)
	}
	if m.NoOrigin.StatusCode == 0 {
		t.Fatal("expected NoOrigin.StatusCode > 0")
	}
	if m.MismatchOrigin.StatusCode == 0 {
		t.Fatal("expected MismatchOrigin.StatusCode > 0")
	}
	if m.Baseline.StatusCode == 0 {
		t.Fatal("expected Baseline.StatusCode > 0")
	}
}

func TestIntegration_IDOR(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Return resource data regardless of auth (simulates IDOR)
		fmt.Fprint(w, `{"id":"123","name":"private resource"}`)
	}))

	cfg := IDORConfig{
		URL:         ts.URL + "/api/resource/{id}",
		ID:          "123",
		Token:       "attacker-token",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyIDOR(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(IDORMeasurements)
	if !ok {
		t.Fatalf("expected IDORMeasurements, got %T", result.Measurements)
	}
	if m.ProbeRound.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", m.ProbeRound.StatusCode)
	}
	if m.ResourceID != "123" {
		t.Fatalf("expected ResourceID 123, got %s", m.ResourceID)
	}
}

func TestIntegration_MassAssignment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Simulate an API that accepts mass assignment
	var storedRole string
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			w.WriteHeader(200)
			if storedRole != "" {
				fmt.Fprintf(w, `{"name":"test","role":"%s"}`, storedRole)
			} else {
				fmt.Fprint(w, `{"name":"test"}`)
			}
		case "PUT":
			body, _ := io.ReadAll(r.Body)
			var obj map[string]interface{}
			json.Unmarshal(body, &obj)
			if role, ok := obj["role"]; ok {
				storedRole = fmt.Sprintf("%v", role)
			}
			w.WriteHeader(200)
			fmt.Fprint(w, `{"status":"updated"}`)
		default:
			w.WriteHeader(405)
		}
	}))

	cfg := MassAssignmentConfig{
		URL:         ts.URL + "/api/user",
		Method:      "PUT",
		Body:        `{"name":"test"}`,
		WatchFields: []string{"role"},
		Token:       "test-token",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyMassAssignment(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(MassAssignmentMeasurements)
	if !ok {
		t.Fatalf("expected MassAssignmentMeasurements, got %T", result.Measurements)
	}
	// After injection, the follow-up GET should show "role" field appeared
	if m.HashesMatch {
		t.Fatal("expected HashesMatch == false (body should change after injection)")
	}
	if len(m.InjectedFields) == 0 {
		t.Fatal("expected non-empty InjectedFields")
	}
	if m.InjectedFields[0].Name != "role" {
		t.Fatalf("expected field name 'role', got %s", m.InjectedFields[0].Name)
	}
	if !m.InjectedFields[0].InFollowUp {
		t.Fatal("expected role field to be present in follow-up")
	}
}

func TestIntegration_Auth_RedirectPreservation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	// Server returns 302 for unauthenticated, 200 for authenticated
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "authed")
	}))
	result, err := VerifyAuth(AuthConfig{
		URL:         ts.URL + "/protected",
		Method:      "GET",
		Token:       "valid-token",
		Technique:   "no_token",
		ProbeConfig: baseProbeConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.Measurements.(AuthMeasurements)
	if !ok {
		t.Fatal("unexpected measurements type")
	}
	// Without redirect following, probe (no token) should see 302
	if m.Probe.StatusCode == 200 {
		t.Error("auth probe should not follow redirect; expected 302, got 200")
	}
}
