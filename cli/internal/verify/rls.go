package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/srank/ensphere/internal/evidence"
)

// RLSConfig holds configuration for Supabase RLS verification.
type RLSConfig struct {
	ProjectURL string
	AnonKey    string
	JWTSecret  string
	Table      string
	TenantA    string
	TenantB    string
	Select     string
	ProbeConfig
}

// VerifyRLS runs the Supabase RLS cross-tenant probe.
func VerifyRLS(cfg RLSConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.ProjectURL, cfg.InScope); err != nil {
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

	selectCols := cfg.Select
	if selectCols == "" {
		selectCols = "*"
	}

	probeCount := 0

	// Build JWT for tenant A
	tokenA, err := buildSupabaseJWT(cfg.JWTSecret, cfg.TenantA)
	if err != nil {
		return nil, fmt.Errorf("build JWT for tenant A: %w", err)
	}

	// Build JWT for tenant B
	tokenB, err := buildSupabaseJWT(cfg.JWTSecret, cfg.TenantB)
	if err != nil {
		return nil, fmt.Errorf("build JWT for tenant B: %w", err)
	}

	// Step 1: Tenant A queries own data
	throttle.Wait()
	probeCount++
	ownURL := fmt.Sprintf("%s/rest/v1/%s?select=%s&company_id=eq.%s", cfg.ProjectURL, cfg.Table, selectCols, cfg.TenantA)
	ownResp := HTTPProbe("GET", ownURL, "", map[string]string{
		"apikey":        cfg.AnonKey,
		"Authorization": "Bearer " + tokenA,
	}, cfg.TimeoutSec, cfg.InScope)
	if ownResp.Error != nil {
		return nil, fmt.Errorf("tenant A own query: %w", ownResp.Error)
	}
	ownRows := countJSONRows(ownResp.Body)
	fmt.Fprintf(os.Stderr, "[TENANT A OWN] %d rows, status=%d\n", ownRows, ownResp.StatusCode)
	writeEvidence(ew, "authz", "rls_isolation", ownURL, "", ownResp.StatusCode,
		fmt.Sprintf("%dms", ownResp.ElapsedMs), "tenant_a_own", fmt.Sprintf("%d rows", ownRows))

	// Step 2: Tenant B queries own data
	throttle.Wait()
	probeCount++
	bOwnURL := fmt.Sprintf("%s/rest/v1/%s?select=%s&company_id=eq.%s", cfg.ProjectURL, cfg.Table, selectCols, cfg.TenantB)
	bOwnResp := HTTPProbe("GET", bOwnURL, "", map[string]string{
		"apikey":        cfg.AnonKey,
		"Authorization": "Bearer " + tokenB,
	}, cfg.TimeoutSec, cfg.InScope)
	if bOwnResp.Error != nil {
		return nil, fmt.Errorf("tenant B own query: %w", bOwnResp.Error)
	}
	bOwnRows := countJSONRows(bOwnResp.Body)
	fmt.Fprintf(os.Stderr, "[TENANT B OWN] %d rows, status=%d\n", bOwnRows, bOwnResp.StatusCode)
	writeEvidence(ew, "authz", "rls_isolation", bOwnURL, "", bOwnResp.StatusCode,
		fmt.Sprintf("%dms", bOwnResp.ElapsedMs), "tenant_b_own", fmt.Sprintf("%d rows", bOwnRows))

	// Step 3: Tenant A tries to access tenant B's data (cross-tenant)
	throttle.Wait()
	probeCount++
	crossURL := fmt.Sprintf("%s/rest/v1/%s?select=%s&company_id=eq.%s", cfg.ProjectURL, cfg.Table, selectCols, cfg.TenantB)
	crossResp := HTTPProbe("GET", crossURL, "", map[string]string{
		"apikey":        cfg.AnonKey,
		"Authorization": "Bearer " + tokenA,
	}, cfg.TimeoutSec, cfg.InScope)
	if crossResp.Error != nil {
		return nil, fmt.Errorf("cross-tenant query: %w", crossResp.Error)
	}
	crossRows := countJSONRows(crossResp.Body)
	fmt.Fprintf(os.Stderr, "[CROSS-TENANT] %d rows, status=%d\n", crossRows, crossResp.StatusCode)
	writeEvidence(ew, "authz", "rls_isolation", crossURL, "", crossResp.StatusCode,
		fmt.Sprintf("%dms", crossResp.ElapsedMs), "cross_tenant", fmt.Sprintf("%d rows", crossRows))

	tenantAOwnRound := RoundResult{
		StatusCode: ownResp.StatusCode, ElapsedMs: ownResp.ElapsedMs,
		BodyHash: ownResp.BodyHash, BodyLength: len(ownResp.Body),
	}
	tenantBOwnRound := RoundResult{
		StatusCode: bOwnResp.StatusCode, ElapsedMs: bOwnResp.ElapsedMs,
		BodyHash: bOwnResp.BodyHash, BodyLength: len(bOwnResp.Body),
	}
	crossTenantRound := RoundResult{
		StatusCode: crossResp.StatusCode, ElapsedMs: crossResp.ElapsedMs,
		BodyHash: crossResp.BodyHash, BodyLength: len(crossResp.Body),
	}

	return &ProbeResult{
		VulnType:   "authz",
		Technique:  "rls_isolation",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: RLSMeasurements{
			Table:           cfg.Table,
			TenantAOwn:      tenantAOwnRound,
			TenantAOwnRows:  ownRows,
			TenantBOwn:      tenantBOwnRound,
			TenantBOwnRows:  bOwnRows,
			CrossTenant:     crossTenantRound,
			CrossTenantRows: crossRows,
		},
	}, nil
}

func buildSupabaseJWT(secret, companyID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"role":       "authenticated",
		"iss":        "supabase",
		"iat":        now.Unix(),
		"exp":        now.Add(1 * time.Hour).Unix(),
		"company_id": companyID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// countJSONRows returns the number of rows in a JSON array response body.
// Returns -1 if the body is not a valid JSON array (e.g., HTML error page,
// JSON object, or malformed response). Callers should treat -1 as
// "response was not parseable" rather than "zero rows returned".
func countJSONRows(body string) int {
	var rows []json.RawMessage
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		return -1
	}
	return len(rows)
}
