package cloud

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/srank-org/ensphere/internal/verify"
)

// SecretsConfig holds configuration for cloud secrets verification.
type SecretsConfig struct {
	Provider  string
	AccountID string
	verify.ProbeConfig
}

// SecretsMeasurements holds cloud secrets probe results.
type SecretsMeasurements struct {
	Provider              string       `json:"provider"`
	Secrets               []SecretInfo `json:"secrets"`
	TotalSecrets          int          `json:"total_secrets"`
	RotationObservedTrue  int          `json:"rotation_observed_true_count"`
	RotationObservedFalse int          `json:"rotation_observed_false_count"`
	RotationUnobserved    int          `json:"rotation_unobserved_count"`
	CLIOutputs            []CLIResult  `json:"cli_outputs"`
	ElapsedMs             int64        `json:"elapsed_ms"`
}

// SecretInfo holds metadata about a single secret.
type SecretInfo struct {
	Name                   string `json:"name"`
	RotationEnabled        *bool  `json:"rotation_enabled,omitempty"`
	LastRotated            string `json:"last_rotated,omitempty"`
	KMSKeyID               string `json:"kms_key_id,omitempty"`
	SoftDeleteEnabled      *bool  `json:"soft_delete_enabled,omitempty"`
	PurgeProtectionEnabled *bool  `json:"purge_protection_enabled,omitempty"`
}

// VerifyCloudSecrets runs cloud secrets security checks.
func VerifyCloudSecrets(cfg SecretsConfig) (*verify.ProbeResult, error) {
	if err := verify.CheckCloudScope(cfg.Provider, cfg.AccountID, cfg.InScope); err != nil {
		return nil, err
	}
	if err := verify.CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	timer := verify.NewTimer()
	start := time.Now()

	var cliOutputs []CLIResult
	var secrets []SecretInfo
	rotEnabled := 0
	rotDisabled := 0

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
		args := []string{"secretsmanager", "list-secrets", "--output", "json"}
		result := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, result)
		if result.ExitCode == 0 {
			secrets, rotEnabled, rotDisabled = parseAWSSecrets(result.Stdout)
		}

	case "gcp":
		cliName := "gcloud"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("gcloud CLI required: %w", err)
		}
		args := []string{"secrets", "list", "--format=json", "--project=" + cfg.AccountID}
		result := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, result)
		if result.ExitCode == 0 {
			secrets, rotEnabled, rotDisabled = parseGCPSecrets(result.Stdout)
		}

	case "azure":
		cliName := "az"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("az CLI required: %w", err)
		}
		args := []string{"keyvault", "list", "--output", "json"}
		result := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, result)
		if result.ExitCode == 0 {
			secrets, rotEnabled, rotDisabled = parseAzureKeyVaults(result.Stdout)
		}

	default:
		return nil, &verify.ScopeError{Msg: fmt.Sprintf("unsupported provider %q (aws, gcp, azure)", cfg.Provider)}
	}

	elapsed := time.Since(start).Milliseconds()

	return &verify.ProbeResult{
		VulnType:   "cloud_secrets",
		Technique:  "cloud_audit",
		StartedAt:  timer.StartedAt(),
		ProbeCount: len(cliOutputs),
		Duration:   timer.Elapsed(),
		Measurements: SecretsMeasurements{
			Provider:              cfg.Provider,
			Secrets:               secrets,
			TotalSecrets:          len(secrets),
			RotationObservedTrue:  rotEnabled,
			RotationObservedFalse: rotDisabled,
			RotationUnobserved:    len(secrets) - rotEnabled - rotDisabled,
			CLIOutputs:            cliOutputs,
			ElapsedMs:             elapsed,
		},
	}, nil
}

func parseAWSSecrets(stdout string) ([]SecretInfo, int, int) {
	var result struct {
		SecretList []struct {
			Name            string `json:"Name"`
			RotationEnabled bool   `json:"RotationEnabled"`
			LastRotatedDate string `json:"LastRotatedDate"`
			KmsKeyId        string `json:"KmsKeyId"`
		} `json:"SecretList"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil, 0, 0
	}
	var secrets []SecretInfo
	rotEnabled := 0
	rotDisabled := 0
	for _, s := range result.SecretList {
		rot := s.RotationEnabled
		secrets = append(secrets, SecretInfo{
			Name:            s.Name,
			RotationEnabled: &rot,
			LastRotated:     s.LastRotatedDate,
			KMSKeyID:        s.KmsKeyId,
		})
		if rot {
			rotEnabled++
		} else {
			rotDisabled++
		}
	}
	return secrets, rotEnabled, rotDisabled
}

func parseGCPSecrets(stdout string) ([]SecretInfo, int, int) {
	var gcpSecrets []struct {
		Name     string `json:"name"`
		Rotation *struct {
			NextRotationTime string `json:"nextRotationTime"`
			RotationPeriod   string `json:"rotationPeriod"`
		} `json:"rotation"`
	}
	if err := json.Unmarshal([]byte(stdout), &gcpSecrets); err != nil {
		return nil, 0, 0
	}
	var secrets []SecretInfo
	rotEnabled := 0
	rotDisabled := 0
	for _, s := range gcpSecrets {
		rot := s.Rotation != nil && s.Rotation.RotationPeriod != ""
		secrets = append(secrets, SecretInfo{
			Name:            s.Name,
			RotationEnabled: &rot,
		})
		if rot {
			rotEnabled++
		} else {
			rotDisabled++
		}
	}
	return secrets, rotEnabled, rotDisabled
}

func parseAzureKeyVaults(stdout string) ([]SecretInfo, int, int) {
	var vaults []struct {
		Name       string `json:"name"`
		Properties struct {
			EnableSoftDelete      bool `json:"enableSoftDelete"`
			EnablePurgeProtection bool `json:"enablePurgeProtection"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(stdout), &vaults); err != nil {
		return nil, 0, 0
	}
	var secrets []SecretInfo
	for _, v := range vaults {
		softDelete := v.Properties.EnableSoftDelete
		purgeProtection := v.Properties.EnablePurgeProtection
		secrets = append(secrets, SecretInfo{
			Name:                   v.Name,
			SoftDeleteEnabled:      &softDelete,
			PurgeProtectionEnabled: &purgeProtection,
		})
	}
	return secrets, 0, 0
}
