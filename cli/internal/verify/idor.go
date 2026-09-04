package verify

import (
	"fmt"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// IDORConfig holds configuration for IDOR verification.
type IDORConfig struct {
	URL        string // URL with {id} placeholder
	ID         string // Resource ID to access
	Token      string // Attacker's auth token
	OwnerToken string // optional: owner's auth token for the baseline round
	Method     string // HTTP method (default GET)
	ProbeConfig
}

// VerifyIDOR runs the IDOR verification probe.
func VerifyIDOR(cfg IDORConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
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

	targetURL := strings.ReplaceAll(cfg.URL, "{id}", cfg.ID)

	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	headers["Authorization"] = "Bearer " + cfg.Token

	probeCount := 0

	// Optional baseline: the same object read with the owner's token. This is
	// the control that separates "the object exists and is readable by its
	// owner" from "the attacker token was accepted".
	var ownerRound *RoundResult
	var hashesMatch, statusMatch *bool
	if cfg.OwnerToken != "" {
		ownerHeaders := make(map[string]string)
		for k, v := range cfg.Headers {
			ownerHeaders[k] = v
		}
		ownerHeaders["Authorization"] = "Bearer " + cfg.OwnerToken
		throttle.Wait()
		probeCount++
		ownerResp := HTTPProbeNoRedirect(cfg.Method, targetURL, "", ownerHeaders, cfg.TimeoutSec, cfg.InScope)
		if ownerResp.Error != nil {
			return nil, fmt.Errorf("idor owner baseline: %w", ownerResp.Error)
		}
		fmt.Fprintf(os.Stderr, "[OWNER] status=%d len=%d\n", ownerResp.StatusCode, len(ownerResp.Body))
		writeEvidence(ew, "idor", "idor_uuid", cfg.URL, cfg.ID, ownerResp.StatusCode,
			fmt.Sprintf("%dms", ownerResp.ElapsedMs), "owner",
			fmt.Sprintf("method=%s resource_id=%s identity=owner", cfg.Method, cfg.ID))
		or := RoundResult{
			StatusCode: ownerResp.StatusCode,
			ElapsedMs:  ownerResp.ElapsedMs,
			BodyHash:   ownerResp.BodyHash,
			BodyLength: len(ownerResp.Body),
		}
		ownerRound = &or
	}

	// Probe: the same object read with the attacker's token.
	throttle.Wait()
	probeCount++
	resp := HTTPProbeNoRedirect(cfg.Method, targetURL, "", headers, cfg.TimeoutSec, cfg.InScope)
	if resp.Error != nil {
		return nil, fmt.Errorf("idor probe: %w", resp.Error)
	}

	fmt.Fprintf(os.Stderr, "[PROBE] status=%d len=%d\n", resp.StatusCode, len(resp.Body))
	writeEvidence(ew, "idor", "idor_uuid", cfg.URL, cfg.ID, resp.StatusCode,
		fmt.Sprintf("%dms", resp.ElapsedMs), "probe",
		fmt.Sprintf("method=%s resource_id=%s identity=other", cfg.Method, cfg.ID))

	probeRound := RoundResult{
		StatusCode: resp.StatusCode,
		ElapsedMs:  resp.ElapsedMs,
		BodyHash:   resp.BodyHash,
		BodyLength: len(resp.Body),
	}
	if ownerRound != nil {
		hm := ownerRound.BodyHash == probeRound.BodyHash
		sm := ownerRound.StatusCode == probeRound.StatusCode
		hashesMatch = &hm
		statusMatch = &sm
	}

	snippet := resp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	return &ProbeResult{
		VulnType:   "idor",
		Technique:  "idor_uuid",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: IDORMeasurements{
			ProbeRound:      probeRound,
			OwnerRound:      ownerRound,
			HashesMatch:     hashesMatch,
			StatusMatch:     statusMatch,
			ResourceID:      cfg.ID,
			ResponseSnippet: snippet,
		},
	}, nil
}
