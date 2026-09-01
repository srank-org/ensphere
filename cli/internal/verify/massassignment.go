package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
)

// MassAssignmentConfig holds configuration for mass assignment verification.
type MassAssignmentConfig struct {
	URL         string
	Method      string   // PUT | PATCH | POST
	Body        string   // base JSON body (legitimate request)
	WatchFields []string // fields to inject (e.g., "role", "is_admin", "price")
	Token       string   // auth token for requests
	ProbeConfig
}

// VerifyMassAssignment runs the mass assignment verification probe.
func VerifyMassAssignment(cfg MassAssignmentConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if len(cfg.WatchFields) == 0 {
		return nil, &ScopeError{Msg: "watch-fields required"}
	}

	var bodyCheck map[string]interface{}
	if err := json.Unmarshal([]byte(cfg.Body), &bodyCheck); err != nil {
		return nil, fmt.Errorf("invalid JSON body: %w", err)
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

	// Step 1 — Baseline GET
	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	headers["Authorization"] = "Bearer " + cfg.Token

	throttle.Wait()
	probeCount++
	baselineResp := HTTPProbeNoRedirect("GET", cfg.URL, "", headers, cfg.TimeoutSec, cfg.InScope)
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline GET: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d len=%d\n", baselineResp.StatusCode, len(baselineResp.Body))
	writeEvidence(ew, "mass_assignment", "mass_assignment", cfg.URL, strings.Join(cfg.WatchFields, ","),
		baselineResp.StatusCode, fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "GET before mutation")

	baselineKeys, baselineObj := extractJSONKeys(baselineResp.Body)

	// Step 2 — Mutation (PUT/PATCH/POST)
	var baseBody map[string]interface{}
	json.Unmarshal([]byte(cfg.Body), &baseBody)
	for _, field := range cfg.WatchFields {
		baseBody[field] = "ensphere_test"
	}
	mutBody, _ := json.Marshal(baseBody)
	headers["Content-Type"] = "application/json"

	throttle.Wait()
	probeCount++
	mutResp := HTTPProbeNoRedirect(cfg.Method, cfg.URL, string(mutBody), headers, cfg.TimeoutSec, cfg.InScope)
	if mutResp.Error != nil {
		return nil, fmt.Errorf("mutation %s: %w", cfg.Method, mutResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[MUTATION] status=%d len=%d\n", mutResp.StatusCode, len(mutResp.Body))
	writeEvidence(ew, "mass_assignment", "mass_assignment", cfg.URL, strings.Join(cfg.WatchFields, ","),
		mutResp.StatusCode, fmt.Sprintf("%dms", mutResp.ElapsedMs), "probe", cfg.Method+" with injected fields")

	// Step 3 — Follow-up GET
	delete(headers, "Content-Type")

	throttle.Wait()
	probeCount++
	followUpResp := HTTPProbeNoRedirect("GET", cfg.URL, "", headers, cfg.TimeoutSec, cfg.InScope)
	if followUpResp.Error != nil {
		return nil, fmt.Errorf("follow-up GET: %w", followUpResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[FOLLOWUP] status=%d len=%d\n", followUpResp.StatusCode, len(followUpResp.Body))
	writeEvidence(ew, "mass_assignment", "mass_assignment", cfg.URL, strings.Join(cfg.WatchFields, ","),
		followUpResp.StatusCode, fmt.Sprintf("%dms", followUpResp.ElapsedMs), "probe", "GET after mutation")

	followUpKeys, followUpObj := extractJSONKeys(followUpResp.Body)

	// Build field results
	baselineSet := make(map[string]bool)
	if baselineObj != nil {
		for k := range baselineObj {
			baselineSet[k] = true
		}
	}

	followUpSet := make(map[string]bool)
	for _, k := range followUpKeys {
		followUpSet[k] = true
	}

	var fieldResults []MassAssignFieldResult
	for _, field := range cfg.WatchFields {
		fr := MassAssignFieldResult{
			Name:       field,
			InBaseline: baselineSet[field],
			InFollowUp: followUpSet[field],
		}
		if baselineObj != nil {
			if v, ok := baselineObj[field]; ok {
				fr.BaselineValue = v
			}
		}
		if followUpObj != nil {
			if v, ok := followUpObj[field]; ok {
				fr.FollowUpValue = v
			}
		}
		fieldResults = append(fieldResults, fr)
	}

	baselineRound := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	mutRound := RoundResult{
		StatusCode: mutResp.StatusCode,
		ElapsedMs:  mutResp.ElapsedMs,
		BodyHash:   mutResp.BodyHash,
		BodyLength: len(mutResp.Body),
	}
	followUpRound := RoundResult{
		StatusCode: followUpResp.StatusCode,
		ElapsedMs:  followUpResp.ElapsedMs,
		BodyHash:   followUpResp.BodyHash,
		BodyLength: len(followUpResp.Body),
	}

	hashesMatch := baselineResp.BodyHash == followUpResp.BodyHash

	return &ProbeResult{
		VulnType:   "mass_assignment",
		Technique:  "mass_assignment",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: MassAssignmentMeasurements{
			BaselineGET:    baselineRound,
			MutationProbe:  mutRound,
			FollowUpGET:    followUpRound,
			BaselineFields: baselineKeys,
			FollowUpFields: followUpKeys,
			InjectedFields: fieldResults,
			HashesMatch:    hashesMatch,
			PayloadUsed:    string(mutBody),
		},
	}, nil
}

// extractJSONKeys parses a JSON object and returns sorted top-level keys plus the parsed map.
func extractJSONKeys(body string) ([]string, map[string]interface{}) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return nil, nil
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, obj
}
