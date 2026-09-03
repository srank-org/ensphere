package cloud

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/srank/ensphere/internal/verify"
)

// ComputeConfig holds configuration for cloud compute verification.
type ComputeConfig struct {
	Provider  string
	AccountID string
	Region    string
	verify.ProbeConfig
}

// ComputeMeasurements holds cloud compute probe results.
type ComputeMeasurements struct {
	Provider                string         `json:"provider"`
	Functions               []FunctionInfo `json:"functions"`
	TotalFunctions          int            `json:"total_functions"`
	EndpointConfiguredCount int            `json:"endpoint_configured_count"`
	EnvVarPatterns          []string       `json:"env_var_patterns"`
	CLIOutputs              []CLIResult    `json:"cli_outputs"`
	ElapsedMs               int64          `json:"elapsed_ms"`
}

// FunctionInfo holds metadata about a single serverless function.
type FunctionInfo struct {
	Name                 string   `json:"name"`
	Runtime              string   `json:"runtime"`
	EndpointConfigured   *bool    `json:"endpoint_configured"`
	EndpointURL          string   `json:"endpoint_url,omitempty"`
	EndpointAuthMode     string   `json:"endpoint_auth_mode,omitempty"`
	IngressSetting       string   `json:"ingress_setting,omitempty"`
	VPCAttached          *bool    `json:"vpc_attached"`
	EnvVarSecretPatterns []string `json:"env_var_secret_patterns,omitempty"`
}

// secretPatterns matches common secret-like environment variable names.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)`),
	regexp.MustCompile(`(?i)(DATABASE_URL|DB_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)`),
	regexp.MustCompile(`(?i)(API_KEY|SECRET_KEY|PRIVATE_KEY|AUTH_TOKEN)`),
}

// VerifyCloudCompute runs cloud compute security checks.
func VerifyCloudCompute(cfg ComputeConfig) (*verify.ProbeResult, error) {
	if err := verify.CheckCloudScope(cfg.Provider, cfg.AccountID, cfg.InScope); err != nil {
		return nil, err
	}
	if err := verify.CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	timer := verify.NewTimer()
	start := time.Now()

	var cliOutputs []CLIResult
	var functions []FunctionInfo
	var envVarPatterns []string
	endpointConfiguredCount := 0

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
		args := []string{"lambda", "list-functions", "--output", "json"}
		if cfg.Region != "" {
			args = append(args, "--region", cfg.Region)
		}
		result := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, result)
		if result.ExitCode == 0 {
			functions, envVarPatterns, endpointConfiguredCount = parseAWSLambdaFunctions(result.Stdout)
		}

	case "gcp":
		cliName := "gcloud"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("gcloud CLI required: %w", err)
		}
		args := []string{"functions", "list", "--format=json"}
		result := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, result)
		if result.ExitCode == 0 {
			fns, patterns, pub := parseGCPFunctions(result.Stdout)
			functions = append(functions, fns...)
			envVarPatterns = append(envVarPatterns, patterns...)
			endpointConfiguredCount += pub
		}
		args = []string{"run", "services", "list", "--format=json"}
		runResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, runResult)
		if runResult.ExitCode == 0 {
			fns, pub := parseGCPCloudRunServices(runResult.Stdout)
			functions = append(functions, fns...)
			endpointConfiguredCount += pub
		}

	case "azure":
		cliName := "az"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("az CLI required: %w", err)
		}
		args := []string{"functionapp", "list", "--output", "json"}
		result := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, result)
		if result.ExitCode == 0 {
			functions = parseAzureFunctionApps(result.Stdout)
		}

	default:
		return nil, &verify.ScopeError{Msg: fmt.Sprintf("unsupported provider %q (aws, gcp, azure)", cfg.Provider)}
	}

	elapsed := time.Since(start).Milliseconds()

	return &verify.ProbeResult{
		VulnType:   "cloud_compute",
		Technique:  "cloud_audit",
		StartedAt:  timer.StartedAt(),
		ProbeCount: len(cliOutputs),
		Duration:   timer.Elapsed(),
		Measurements: ComputeMeasurements{
			Provider:                cfg.Provider,
			Functions:               functions,
			TotalFunctions:          len(functions),
			EndpointConfiguredCount: endpointConfiguredCount,
			EnvVarPatterns:          envVarPatterns,
			CLIOutputs:              cliOutputs,
			ElapsedMs:               elapsed,
		},
	}, nil
}

func parseAWSLambdaFunctions(stdout string) ([]FunctionInfo, []string, int) {
	var result struct {
		Functions []struct {
			FunctionName string `json:"FunctionName"`
			Runtime      string `json:"Runtime"`
			VpcConfig    *struct {
				SubnetIds []string `json:"SubnetIds"`
			} `json:"VpcConfig"`
			FunctionUrlConfig *struct {
				AuthType string `json:"AuthType"`
			} `json:"FunctionUrlConfig"`
			Environment *struct {
				Variables map[string]string `json:"Variables"`
			} `json:"Environment"`
		} `json:"Functions"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil, nil, 0
	}

	var functions []FunctionInfo
	var allPatterns []string
	patternSet := make(map[string]bool)
	endpointConfiguredCount := 0

	for _, f := range result.Functions {
		fi := FunctionInfo{
			Name:    f.FunctionName,
			Runtime: f.Runtime,
		}
		if f.VpcConfig != nil {
			attached := len(f.VpcConfig.SubnetIds) > 0
			fi.VPCAttached = &attached
		}
		if f.FunctionUrlConfig != nil {
			configured := true
			fi.EndpointConfigured = &configured
			fi.EndpointAuthMode = f.FunctionUrlConfig.AuthType
			endpointConfiguredCount++
		}
		if f.Environment != nil {
			for key := range f.Environment.Variables {
				for _, re := range secretPatterns {
					if re.MatchString(key) {
						pName := re.String()
						fi.EnvVarSecretPatterns = append(fi.EnvVarSecretPatterns, pName)
						if !patternSet[pName] {
							patternSet[pName] = true
							allPatterns = append(allPatterns, pName)
						}
					}
				}
			}
		}
		functions = append(functions, fi)
	}
	return functions, allPatterns, endpointConfiguredCount
}

func parseGCPFunctions(stdout string) ([]FunctionInfo, []string, int) {
	var fns []struct {
		Name         string `json:"name"`
		Runtime      string `json:"runtime"`
		HttpsTrigger *struct {
			URL string `json:"url"`
		} `json:"httpsTrigger"`
		IngressSettings      string            `json:"ingressSettings"`
		EnvironmentVariables map[string]string `json:"environmentVariables"`
	}
	if err := json.Unmarshal([]byte(stdout), &fns); err != nil {
		return nil, nil, 0
	}

	var functions []FunctionInfo
	var allPatterns []string
	patternSet := make(map[string]bool)
	endpointConfiguredCount := 0

	for _, f := range fns {
		fi := FunctionInfo{
			Name:    f.Name,
			Runtime: f.Runtime,
		}
		if f.HttpsTrigger != nil {
			configured := true
			fi.EndpointConfigured = &configured
			fi.EndpointURL = f.HttpsTrigger.URL
			fi.IngressSetting = f.IngressSettings
			endpointConfiguredCount++
		}
		for key := range f.EnvironmentVariables {
			for _, re := range secretPatterns {
				if re.MatchString(key) {
					pName := re.String()
					fi.EnvVarSecretPatterns = append(fi.EnvVarSecretPatterns, pName)
					if !patternSet[pName] {
						patternSet[pName] = true
						allPatterns = append(allPatterns, pName)
					}
				}
			}
		}
		functions = append(functions, fi)
	}
	return functions, allPatterns, endpointConfiguredCount
}

func parseGCPCloudRunServices(stdout string) ([]FunctionInfo, int) {
	var services []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			URL string `json:"url"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(stdout), &services); err != nil {
		return nil, 0
	}
	var functions []FunctionInfo
	endpointConfiguredCount := 0
	for _, s := range services {
		configured := s.Status.URL != ""
		fi := FunctionInfo{
			Name:               s.Metadata.Name,
			Runtime:            "cloud-run",
			EndpointConfigured: &configured,
			EndpointURL:        s.Status.URL,
		}
		if configured {
			endpointConfiguredCount++
		}
		functions = append(functions, fi)
	}
	return functions, endpointConfiguredCount
}

func parseAzureFunctionApps(stdout string) []FunctionInfo {
	var apps []struct {
		Name            string `json:"name"`
		DefaultHostName string `json:"defaultHostName"`
		HttpsOnly       bool   `json:"httpsOnly"`
		State           string `json:"state"`
	}
	if err := json.Unmarshal([]byte(stdout), &apps); err != nil {
		return nil
	}
	var functions []FunctionInfo
	for _, a := range apps {
		configured := a.DefaultHostName != ""
		functions = append(functions, FunctionInfo{
			Name:               a.Name,
			Runtime:            "azure-functions",
			EndpointConfigured: &configured,
			EndpointURL:        a.DefaultHostName,
		})
	}
	return functions
}
