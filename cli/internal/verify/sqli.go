package verify

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
	"github.com/srank/ensphere/internal/payloads"
)

const defaultRounds = 3
const defaultSQLiDBEngine = "postgres"

var validSQLiDBEngines = map[string]bool{
	"postgres": true,
	"mysql":    true,
	"mssql":    true,
	"sqlite":   true,
}

var sqlErrorPatterns = map[string][]*regexp.Regexp{
	"postgres": {
		regexp.MustCompile(`(?i)ERROR:`),
		regexp.MustCompile(`(?i)syntax error at or near`),
		regexp.MustCompile(`(?i)invalid input syntax`),
		regexp.MustCompile(`(?i)unterminated quoted string`),
		regexp.MustCompile(`(?i)column .+ does not exist`),
		regexp.MustCompile(`(?i)PostgreSQL`),
		regexp.MustCompile(`(?i)pq:`),
	},
	"mysql": {
		regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
		regexp.MustCompile(`(?i)MySQL`),
		regexp.MustCompile(`(?i)MariaDB`),
		regexp.MustCompile(`(?i)XPATH syntax error`),
		regexp.MustCompile(`(?i)Truncated incorrect`),
		regexp.MustCompile(`(?i)Duplicate entry`),
	},
	"mssql": {
		regexp.MustCompile(`(?i)Microsoft SQL Server`),
		regexp.MustCompile(`(?i)SQL Server`),
		regexp.MustCompile(`(?i)ODBC`),
		regexp.MustCompile(`(?i)Unclosed quotation mark`),
		regexp.MustCompile(`(?i)Incorrect syntax near`),
		regexp.MustCompile(`(?i)Conversion failed`),
	},
	"sqlite": {
		regexp.MustCompile(`(?i)SQLite`),
		regexp.MustCompile(`(?i)sqlite3`),
		regexp.MustCompile(`(?i)near ".+": syntax error`),
		regexp.MustCompile(`(?i)unrecognized token`),
		regexp.MustCompile(`(?i)no such column`),
		regexp.MustCompile(`(?i)datatype mismatch`),
	},
}

// SQLiConfig holds configuration specific to SQLi verification.
type SQLiConfig struct {
	URL       string
	Param     string
	DBEngine  string // postgres | mysql | mssql | sqlite (default postgres)
	Technique string // blind_time | blind_boolean | error_based
	Method    string // GET | POST
	Boundary  string // single_quote | double_quote | numeric
	ProbeConfig
}

// VerifySQLi runs the SQLi verification probe.
func VerifySQLi(cfg SQLiConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
		return nil, err
	}

	dbEngine, err := normalizeSQLiDBEngine(cfg.DBEngine)
	if err != nil {
		return nil, err
	}
	cfg.DBEngine = dbEngine

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

	switch cfg.Technique {
	case "blind_time":
		return verifySQLiBlindTime(cfg, throttle, timer, ew)
	case "blind_boolean":
		return verifySQLiBlindBoolean(cfg, throttle, timer, ew)
	case "error_based":
		return verifySQLiErrorBased(cfg, throttle, timer, ew)
	default:
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: blind_time, blind_boolean, error_based", cfg.Technique)}
	}
}

func verifySQLiBlindTime(cfg SQLiConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	if cfg.TimeoutSec < 5 {
		return nil, fmt.Errorf("timeout must be >= 5 for time-based probes, got %d", cfg.TimeoutSec)
	}
	sleepSec := cfg.TimeoutSec / 2
	if sleepSec < 3 {
		sleepSec = 3
	}
	if sleepSec > cfg.TimeoutSec-2 {
		sleepSec = cfg.TimeoutSec - 2
	}

	payload, err := selectSQLiPayload(cfg, "blind_time", func(p payloads.PayloadResult) bool {
		return placeholdersAllowed(p.Placeholders, map[string]bool{"SLEEP_SECONDS": true})
	})
	if err != nil {
		return nil, err
	}
	payload = strings.ReplaceAll(payload, "SLEEP_SECONDS", strconv.Itoa(sleepSec))

	probeCount := 0

	// Baseline probes
	var baselineRounds []RoundResult
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		resp := probeWithParam(cfg, "1")
		if resp.Error != nil {
			return nil, fmt.Errorf("baseline probe %d: %w", i+1, resp.Error)
		}
		baselineRounds = append(baselineRounds, RoundResult{
			StatusCode: resp.StatusCode,
			ElapsedMs:  resp.ElapsedMs,
			BodyHash:   resp.BodyHash,
			BodyLength: len(resp.Body),
		})
		fmt.Fprintf(os.Stderr, "[BASELINE %d] %dms\n", i+1, resp.ElapsedMs)
		writeEvidence(ew, "sqli", "blind_time", cfg.URL, cfg.Param, resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "baseline", fmt.Sprintf("round %d", i+1))
	}

	var payloadRounds []RoundResult
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		resp := probeWithParam(cfg, payload)
		if resp.Error != nil {
			fmt.Fprintf(os.Stderr, "[PAYLOAD %d] error: %v\n", i+1, resp.Error)
			continue
		}
		payloadRounds = append(payloadRounds, RoundResult{
			StatusCode: resp.StatusCode,
			ElapsedMs:  resp.ElapsedMs,
			BodyHash:   resp.BodyHash,
			BodyLength: len(resp.Body),
		})
		fmt.Fprintf(os.Stderr, "[PAYLOAD %d] %dms\n", i+1, resp.ElapsedMs)
		writeEvidence(ew, "sqli", "blind_time", cfg.URL, cfg.Param, resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "payload", fmt.Sprintf("round %d, payload: %s", i+1, payload))
	}

	if len(payloadRounds) == 0 {
		return nil, fmt.Errorf("all payload probes failed")
	}

	baselineAvg := avgFromRounds(baselineRounds)
	payloadAvg := avgFromRounds(payloadRounds)

	return &ProbeResult{
		VulnType:   "sqli",
		Technique:  "blind_time",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: SQLiTimeMeasurements{
			DBEngine:       cfg.DBEngine,
			SleepSeconds:   sleepSec,
			BaselineRounds: baselineRounds,
			PayloadRounds:  payloadRounds,
			BaselineAvgMs:  baselineAvg,
			PayloadAvgMs:   payloadAvg,
			DeltaMs:        payloadAvg - baselineAvg,
			PayloadUsed:    payload,
			StringBoundary: cfg.Boundary,
		},
	}, nil
}

func verifySQLiBlindBoolean(cfg SQLiConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	truePayload, falsePayload, err := selectSQLiBooleanPayloads(cfg)
	if err != nil {
		return nil, err
	}

	probeCount := 0

	// Baseline
	throttle.Wait()
	probeCount++
	baselineResp := probeWithParam(cfg, "1")
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline: %w", baselineResp.Error)
	}
	baselineRound := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] hash=%s\n", baselineResp.BodyHash[:16])
	writeEvidence(ew, "sqli", "blind_boolean", cfg.URL, cfg.Param, baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "")

	// True/False probes across rounds
	var trueRounds, falseRounds []RoundResult
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		trueResp := probeWithParam(cfg, truePayload)
		if trueResp.Error != nil {
			continue
		}
		throttle.Wait()
		probeCount++
		falseResp := probeWithParam(cfg, falsePayload)
		if falseResp.Error != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "[ROUND %d] true=%s false=%s\n", i+1, trueResp.BodyHash[:16], falseResp.BodyHash[:16])
		writeEvidence(ew, "sqli", "blind_boolean", cfg.URL, cfg.Param, trueResp.StatusCode,
			fmt.Sprintf("%dms", trueResp.ElapsedMs), "true_probe", fmt.Sprintf("round %d", i+1))
		writeEvidence(ew, "sqli", "blind_boolean", cfg.URL, cfg.Param, falseResp.StatusCode,
			fmt.Sprintf("%dms", falseResp.ElapsedMs), "false_probe", fmt.Sprintf("round %d", i+1))
		trueRounds = append(trueRounds, RoundResult{
			StatusCode: trueResp.StatusCode, ElapsedMs: trueResp.ElapsedMs,
			BodyHash: trueResp.BodyHash, BodyLength: len(trueResp.Body),
		})
		falseRounds = append(falseRounds, RoundResult{
			StatusCode: falseResp.StatusCode, ElapsedMs: falseResp.ElapsedMs,
			BodyHash: falseResp.BodyHash, BodyLength: len(falseResp.Body),
		})
	}

	if len(trueRounds) == 0 || len(falseRounds) == 0 {
		return nil, fmt.Errorf("all boolean probes failed")
	}

	hashesMatch := trueRounds[0].BodyHash == falseRounds[0].BodyHash

	return &ProbeResult{
		VulnType:   "sqli",
		Technique:  "blind_boolean",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: SQLiBooleanMeasurements{
			DBEngine:       cfg.DBEngine,
			BaselineRound:  baselineRound,
			TrueRounds:     trueRounds,
			FalseRounds:    falseRounds,
			HashesMatch:    hashesMatch,
			TruePayload:    truePayload,
			FalsePayload:   falsePayload,
			StringBoundary: cfg.Boundary,
		},
	}, nil
}

func verifySQLiErrorBased(cfg SQLiConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	payload, err := selectSQLiPayload(cfg, "error_based", func(p payloads.PayloadResult) bool {
		return len(p.Placeholders) == 0
	})
	if err != nil {
		return nil, err
	}

	probeCount := 0

	throttle.Wait()
	probeCount++
	resp := probeWithParam(cfg, payload)
	if resp.Error != nil {
		return nil, fmt.Errorf("error_based probe: %w", resp.Error)
	}

	fmt.Fprintf(os.Stderr, "[PROBE] status=%d len=%d\n", resp.StatusCode, len(resp.Body))
	writeEvidence(ew, "sqli", "error_based", cfg.URL, cfg.Param, resp.StatusCode,
		fmt.Sprintf("%dms", resp.ElapsedMs), "probe", payload)

	// Check for DB-specific error signatures and collect all matches.
	var matchedPatterns []string
	for _, re := range sqlErrorPatterns[cfg.DBEngine] {
		if re.MatchString(resp.Body) {
			matchedPatterns = append(matchedPatterns, re.String())
		}
	}

	snippet := resp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	probeRound := RoundResult{
		StatusCode: resp.StatusCode,
		ElapsedMs:  resp.ElapsedMs,
		BodyHash:   resp.BodyHash,
		BodyLength: len(resp.Body),
	}

	return &ProbeResult{
		VulnType:   "sqli",
		Technique:  "error_based",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: SQLiErrorMeasurements{
			DBEngine:        cfg.DBEngine,
			ProbeRound:      probeRound,
			MatchedPatterns: matchedPatterns,
			PayloadUsed:     payload,
			StringBoundary:  cfg.Boundary,
			ResponseSnippet: snippet,
		},
	}, nil
}

// probeWithParam injects a value into the target URL parameter and sends the request.
func probeWithParam(cfg SQLiConfig, value string) ProbeResponse {
	if strings.ToUpper(cfg.Method) == "POST" {
		body := url.Values{cfg.Param: {value}}.Encode()
		headers := make(map[string]string)
		for k, v := range cfg.Headers {
			headers[k] = v
		}
		headers["Content-Type"] = "application/x-www-form-urlencoded"
		return HTTPProbe("POST", cfg.URL, body, headers, cfg.TimeoutSec, cfg.InScope)
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return ProbeResponse{Error: fmt.Errorf("parse URL: %w", err)}
	}
	params := parsed.Query()
	params.Set(cfg.Param, value)
	parsed.RawQuery = params.Encode()
	return HTTPProbe(cfg.Method, parsed.String(), "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
}

func normalizeSQLiDBEngine(dbEngine string) (string, error) {
	dbEngine = strings.ToLower(strings.TrimSpace(dbEngine))
	if dbEngine == "" {
		dbEngine = defaultSQLiDBEngine
	}
	if !validSQLiDBEngines[dbEngine] {
		return "", &ScopeError{Msg: fmt.Sprintf("unsupported db %q — use: postgres, mysql, mssql, sqlite", dbEngine)}
	}
	return dbEngine, nil
}

func sqliSurfaceForMethod(method string) string {
	if strings.ToUpper(method) == "POST" {
		return "form_body"
	}
	return "query"
}

func selectSQLiPayload(cfg SQLiConfig, technique string, accept func(payloads.PayloadResult) bool) (string, error) {
	results, err := querySQLiPayloads(cfg, technique)
	if err != nil {
		return "", err
	}
	for _, p := range results {
		if accept == nil || accept(p) {
			return p.Payload, nil
		}
	}
	return "", &ScopeError{Msg: fmt.Sprintf("no %s payload for db %q boundary %q", technique, cfg.DBEngine, cfg.Boundary)}
}

func selectSQLiBooleanPayloads(cfg SQLiConfig) (string, string, error) {
	results, err := querySQLiPayloads(cfg, "blind_boolean")
	if err != nil {
		return "", "", err
	}

	var truePayload, falsePayload string
	for _, p := range results {
		if len(p.Placeholders) > 0 {
			continue
		}
		normalized := normalizeSQLiCondition(p.Payload)
		if truePayload == "" && strings.Contains(normalized, "1=1") {
			truePayload = p.Payload
		}
		if falsePayload == "" && strings.Contains(normalized, "1=2") {
			falsePayload = p.Payload
		}
	}
	if truePayload == "" || falsePayload == "" {
		return "", "", &ScopeError{Msg: fmt.Sprintf("no blind_boolean true/false payload pair for db %q boundary %q", cfg.DBEngine, cfg.Boundary)}
	}
	return truePayload, falsePayload, nil
}

func querySQLiPayloads(cfg SQLiConfig, technique string) ([]payloads.PayloadResult, error) {
	store, err := payloads.Load()
	if err != nil {
		return nil, fmt.Errorf("load payload seeds: %w", err)
	}

	surfaces := []string{sqliSurfaceForMethod(cfg.Method)}
	if surfaces[0] != "query" {
		surfaces = append(surfaces, "query")
	}
	surfaces = append(surfaces, "")

	var results []payloads.PayloadResult
	seen := make(map[string]bool)
	for _, surface := range surfaces {
		out := store.Query(payloads.PayloadFilter{
			VulnType:  "sqli",
			DBEngine:  cfg.DBEngine,
			Technique: technique,
			Surface:   surface,
			Encoding:  "raw",
			Boundary:  cfg.Boundary,
			MaxRisk:   cfg.MaxRisk,
			Limit:     50,
		})
		for _, result := range out.Results {
			if seen[result.ID] {
				continue
			}
			seen[result.ID] = true
			results = append(results, result)
		}
	}

	if len(results) > 0 {
		return results, nil
	}

	return nil, &ScopeError{Msg: fmt.Sprintf("no %s payloads for db %q boundary %q", technique, cfg.DBEngine, cfg.Boundary)}
}

func placeholdersAllowed(placeholders []string, allowed map[string]bool) bool {
	for _, ph := range placeholders {
		if !allowed[ph] {
			return false
		}
	}
	return true
}

func normalizeSQLiCondition(payload string) string {
	payload = strings.ToLower(payload)
	replacer := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "")
	return replacer.Replace(payload)
}

func writeEvidence(ew *evidence.Writer, probeType, technique, url, param string, statusCode int, duration, result, notes string) {
	if ew == nil {
		return
	}
	result, notes = normalizeEvidenceStage(result, notes)
	entry := evidence.NewEntry(probeType, technique, url, param, statusCode, duration, result, notes)
	if err := ew.Write(entry); err != nil {
		fmt.Fprintf(os.Stderr, "warning: evidence write failed: %v\n", err)
	}
}

func normalizeEvidenceStage(result, notes string) (string, string) {
	if evidence.ValidResult(result) {
		return result, notes
	}
	stageNote := "stage=" + result
	if notes == "" {
		return evidence.ResultProbe, stageNote
	}
	return evidence.ResultProbe, stageNote + "; " + notes
}

func avgFromRounds(rounds []RoundResult) int64 {
	if len(rounds) == 0 {
		return 0
	}
	var sum int64
	for _, r := range rounds {
		sum += r.ElapsedMs
	}
	return sum / int64(len(rounds))
}
