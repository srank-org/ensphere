package verify

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// CSVInjectionConfig holds configuration for CSV injection verification.
type CSVInjectionConfig struct {
	SubmitURL string // URL to submit data
	ExportURL string // URL to download CSV
	Param     string // field to inject into
	Method    string
	ProbeConfig
}

var csvFormulaPayload = `=CMD("ensphere_csv_test")`

// VerifyCSVInjection runs the CSV injection verification probe.
func VerifyCSVInjection(cfg CSVInjectionConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.SubmitURL, cfg.InScope); err != nil {
		return nil, err
	}
	if err := CheckScope(cfg.ExportURL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(3, cfg.MaxRisk); err != nil {
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

	probeCount := 0

	// Submit formula payload
	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	headers["Content-Type"] = "application/x-www-form-urlencoded"

	submitBody := url.Values{cfg.Param: {csvFormulaPayload}}.Encode()

	throttle.Wait()
	probeCount++
	submitResp := HTTPProbe(cfg.Method, cfg.SubmitURL, submitBody, headers, cfg.TimeoutSec, cfg.InScope)
	if submitResp.Error != nil {
		return nil, fmt.Errorf("submit probe: %w", submitResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[SUBMIT] status=%d\n", submitResp.StatusCode)
	writeEvidence(ew, "csv_injection", "formula_injection", cfg.SubmitURL, cfg.Param, submitResp.StatusCode,
		fmt.Sprintf("%dms", submitResp.ElapsedMs), "probe", fmt.Sprintf("payload=%s", csvFormulaPayload))

	// Download export
	throttle.Wait()
	probeCount++
	exportResp := HTTPProbe("GET", cfg.ExportURL, "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
	if exportResp.Error != nil {
		return nil, fmt.Errorf("export probe: %w", exportResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[EXPORT] status=%d len=%d\n", exportResp.StatusCode, len(exportResp.Body))

	formulaFound := strings.Contains(exportResp.Body, `=CMD(`)
	formulaEscaped := strings.Contains(exportResp.Body, `'=CMD(`) ||
		strings.Contains(exportResp.Body, `"=CMD(`)

	writeEvidence(ew, "csv_injection", "formula_injection", cfg.ExportURL, cfg.Param, exportResp.StatusCode,
		fmt.Sprintf("%dms", exportResp.ElapsedMs), "probe",
		fmt.Sprintf("formula_found=%v escaped=%v", formulaFound, formulaEscaped))

	snippet := exportResp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	submitRound := RoundResult{
		StatusCode: submitResp.StatusCode,
		ElapsedMs:  submitResp.ElapsedMs,
		BodyHash:   submitResp.BodyHash,
		BodyLength: len(submitResp.Body),
	}
	exportRound := RoundResult{
		StatusCode: exportResp.StatusCode,
		ElapsedMs:  exportResp.ElapsedMs,
		BodyHash:   exportResp.BodyHash,
		BodyLength: len(exportResp.Body),
	}

	return &ProbeResult{
		VulnType:   "csv_injection",
		Technique:  "formula_injection",
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: CSVInjectionMeasurements{
			SubmitProbe:     submitRound,
			ExportProbe:     exportRound,
			FormulaFound:    formulaFound,
			FormulaEscaped:  formulaEscaped,
			PayloadUsed:     csvFormulaPayload,
			ResponseSnippet: snippet,
		},
	}, nil
}
