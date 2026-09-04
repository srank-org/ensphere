package cloud

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/srank-org/ensphere/internal/verify"
)

// LoggingConfig holds configuration for cloud logging verification.
type LoggingConfig struct {
	Provider  string
	AccountID string
	verify.ProbeConfig
}

// LoggingMeasurements holds cloud logging probe results.
type LoggingMeasurements struct {
	Provider      string      `json:"provider"`
	Trails        []TrailInfo `json:"trails"`
	TotalTrails   int         `json:"total_trails"`
	ActiveTrails  int         `json:"active_trails"`
	MultiRegion   *bool       `json:"multi_region"`
	LogValidation *bool       `json:"log_validation"`
	CLIOutputs    []CLIResult `json:"cli_outputs"`
	ElapsedMs     int64       `json:"elapsed_ms"`
}

// TrailInfo holds metadata about a single audit trail/log sink.
type TrailInfo struct {
	Name          string `json:"name"`
	IsActive      *bool  `json:"is_active"`
	IsMultiRegion *bool  `json:"is_multi_region"`
	LogValidation *bool  `json:"log_file_validation"`
	IsRecording   *bool  `json:"is_recording"`
}

// VerifyCloudLogging runs cloud logging security checks.
func VerifyCloudLogging(cfg LoggingConfig) (*verify.ProbeResult, error) {
	if err := verify.CheckCloudScope(cfg.Provider, cfg.AccountID, cfg.InScope); err != nil {
		return nil, err
	}
	if err := verify.CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	timer := verify.NewTimer()
	start := time.Now()

	var cliOutputs []CLIResult
	var trails []TrailInfo
	activeTrails := 0
	var multiRegion *bool
	var logValidation *bool

	timeout := cfg.TimeoutSec
	if timeout < 1 {
		timeout = 30
	}

	switch cfg.Provider {
	case "aws":
		cliName := "aws"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("aws CLI required: %w", err)
		}

		args := []string{"cloudtrail", "describe-trails", "--output", "json"}
		descResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, descResult)
		if descResult.ExitCode == 0 {
			trails = parseAWSCloudTrails(descResult.Stdout)
		}

		for i, trail := range trails {
			args = []string{"cloudtrail", "get-trail-status", "--name", trail.Name, "--output", "json"}
			statusResult := RunCLI(cliName, args, timeout)
			cliOutputs = append(cliOutputs, statusResult)
			if statusResult.ExitCode == 0 {
				recording := parseAWSTrailStatus(statusResult.Stdout)
				trails[i].IsRecording = &recording
				if recording {
					activeTrails++
				}
			}
		}

		for _, t := range trails {
			if t.IsMultiRegion != nil && *t.IsMultiRegion {
				mr := true
				multiRegion = &mr
			}
			if t.LogValidation != nil && *t.LogValidation {
				lv := true
				logValidation = &lv
			}
		}

	case "gcp":
		cliName := "gcloud"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("gcloud CLI required: %w", err)
		}
		args := []string{"logging", "sinks", "list", "--format=json", "--project=" + cfg.AccountID}
		result := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, result)
		if result.ExitCode == 0 {
			trails, activeTrails = parseGCPLoggingSinks(result.Stdout)
		}

	case "azure":
		cliName := "az"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("az CLI required: %w", err)
		}
		args := []string{"monitor", "diagnostic-settings", "subscription", "list", "--output", "json"}
		result := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, result)
		if result.ExitCode == 0 {
			trails, activeTrails = parseAzureDiagnosticSettings(result.Stdout)
		}

	default:
		return nil, &verify.ScopeError{Msg: fmt.Sprintf("unsupported provider %q (aws, gcp, azure)", cfg.Provider)}
	}

	elapsed := time.Since(start).Milliseconds()

	return &verify.ProbeResult{
		VulnType:   "cloud_logging",
		Technique:  "cloud_audit",
		StartedAt:  timer.StartedAt(),
		ProbeCount: len(cliOutputs),
		Duration:   timer.Elapsed(),
		Measurements: LoggingMeasurements{
			Provider:      cfg.Provider,
			Trails:        trails,
			TotalTrails:   len(trails),
			ActiveTrails:  activeTrails,
			MultiRegion:   multiRegion,
			LogValidation: logValidation,
			CLIOutputs:    cliOutputs,
			ElapsedMs:     elapsed,
		},
	}, nil
}

func parseAWSCloudTrails(stdout string) []TrailInfo {
	var result struct {
		TrailList []struct {
			Name                     string `json:"Name"`
			IsMultiRegionTrail       bool   `json:"IsMultiRegionTrail"`
			LogFileValidationEnabled bool   `json:"LogFileValidationEnabled"`
		} `json:"TrailList"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	var trails []TrailInfo
	for _, t := range result.TrailList {
		mr := t.IsMultiRegionTrail
		lv := t.LogFileValidationEnabled
		trails = append(trails, TrailInfo{
			Name:          t.Name,
			IsMultiRegion: &mr,
			LogValidation: &lv,
		})
	}
	return trails
}

func parseAWSTrailStatus(stdout string) bool {
	var result struct {
		IsLogging bool `json:"IsLogging"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return false
	}
	return result.IsLogging
}

func parseGCPLoggingSinks(stdout string) ([]TrailInfo, int) {
	var sinks []struct {
		Name        string `json:"name"`
		Destination string `json:"destination"`
		Disabled    bool   `json:"disabled"`
	}
	if err := json.Unmarshal([]byte(stdout), &sinks); err != nil {
		return nil, 0
	}
	var trails []TrailInfo
	active := 0
	for _, s := range sinks {
		isActive := !s.Disabled
		trails = append(trails, TrailInfo{
			Name:     s.Name,
			IsActive: &isActive,
		})
		if isActive {
			active++
		}
	}
	return trails, active
}

func parseAzureDiagnosticSettings(stdout string) ([]TrailInfo, int) {
	var settings []struct {
		Name string `json:"name"`
		Logs []struct {
			Enabled bool `json:"enabled"`
		} `json:"logs"`
	}
	if err := json.Unmarshal([]byte(stdout), &settings); err != nil {
		return nil, 0
	}
	var trails []TrailInfo
	active := 0
	for _, s := range settings {
		hasActive := false
		for _, l := range s.Logs {
			if l.Enabled {
				hasActive = true
				break
			}
		}
		trails = append(trails, TrailInfo{
			Name:     s.Name,
			IsActive: &hasActive,
		})
		if hasActive {
			active++
		}
	}
	return trails, active
}
