package cloud

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/srank-org/ensphere/internal/verify"
)

// StorageConfig holds configuration for cloud storage verification.
type StorageConfig struct {
	Provider    string // aws, gcp, azure
	Bucket      string
	Region      string
	AccountID   string
	AccountName string
	verify.ProbeConfig
}

// StorageMeasurements holds cloud storage probe results.
type StorageMeasurements struct {
	Provider                   string                `json:"provider"`
	Bucket                     string                `json:"bucket"`
	AWSPublicAccessBlock       *AWSPublicAccessBlock `json:"aws_public_access_block,omitempty"`
	GCPPublicAccessPrevention  string                `json:"gcp_public_access_prevention,omitempty"`
	AzureAllowBlobPublicAccess *bool                 `json:"azure_allow_blob_public_access,omitempty"`
	Encryption                 string                `json:"encryption"`
	Versioning                 string                `json:"versioning"`
	Logging                    string                `json:"logging"`
	ACLEntries                 []string              `json:"acl_entries"`
	CLIOutputs                 []CLIResult           `json:"cli_outputs"`
	ElapsedMs                  int64                 `json:"elapsed_ms"`
}

// AWSPublicAccessBlock preserves the four provider-supplied S3 settings.
type AWSPublicAccessBlock struct {
	BlockPublicACLs       bool `json:"block_public_acls"`
	IgnorePublicACLs      bool `json:"ignore_public_acls"`
	BlockPublicPolicy     bool `json:"block_public_policy"`
	RestrictPublicBuckets bool `json:"restrict_public_buckets"`
}

// VerifyCloudStorage runs cloud storage security checks.
func VerifyCloudStorage(cfg StorageConfig) (*verify.ProbeResult, error) {
	if err := verify.CheckCloudScope(cfg.Provider, cfg.AccountID, cfg.InScope); err != nil {
		return nil, err
	}
	if err := verify.CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	timer := verify.NewTimer()
	start := time.Now()

	var cliOutputs []CLIResult
	var aclEntries []string
	encryption := "unknown"
	versioning := "unknown"
	logging := "unknown"
	var awsPublicAccessBlock *AWSPublicAccessBlock
	var gcpPublicAccessPrevention string
	var azureAllowBlobPublicAccess *bool

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

		regionArgs := []string{}
		if cfg.Region != "" {
			regionArgs = []string{"--region", cfg.Region}
		}

		args := append([]string{"s3api", "get-bucket-acl", "--bucket", cfg.Bucket, "--output", "json"}, regionArgs...)
		aclResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, aclResult)
		if aclResult.ExitCode == 0 {
			aclEntries = parseAWSACL(aclResult.Stdout)
		}

		args = append([]string{"s3api", "get-bucket-encryption", "--bucket", cfg.Bucket, "--output", "json"}, regionArgs...)
		encResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, encResult)
		if encResult.ExitCode == 0 {
			encryption = parseAWSEncryption(encResult.Stdout)
		} else {
			encryption = "none"
		}

		args = append([]string{"s3api", "get-bucket-versioning", "--bucket", cfg.Bucket, "--output", "json"}, regionArgs...)
		verResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, verResult)
		if verResult.ExitCode == 0 {
			versioning = parseAWSVersioning(verResult.Stdout)
		}

		args = append([]string{"s3api", "get-bucket-logging", "--bucket", cfg.Bucket, "--output", "json"}, regionArgs...)
		logResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, logResult)
		if logResult.ExitCode == 0 {
			logging = parseAWSLogging(logResult.Stdout)
		}

		args = append([]string{"s3api", "get-public-access-block", "--bucket", cfg.Bucket, "--output", "json"}, regionArgs...)
		pubResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, pubResult)
		if pubResult.ExitCode == 0 {
			awsPublicAccessBlock = parseAWSPublicAccessBlock(pubResult.Stdout)
		}

	case "gcp":
		cliName := "gcloud"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("gcloud CLI required: %w", err)
		}
		args := []string{"storage", "buckets", "describe", "gs://" + cfg.Bucket, "--format=json"}
		descResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, descResult)
		if descResult.ExitCode == 0 {
			enc, ver, log, prevention := parseGCPBucketDescribe(descResult.Stdout)
			if enc != "" {
				encryption = enc
			}
			if ver != "" {
				versioning = ver
			}
			if log != "" {
				logging = log
			}
			gcpPublicAccessPrevention = prevention
		}
		args = []string{"storage", "buckets", "get-iam-policy", "gs://" + cfg.Bucket, "--format=json"}
		iamResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, iamResult)
		if iamResult.ExitCode == 0 {
			aclEntries = parseGCPBucketIAMPolicy(iamResult.Stdout)
		}

	case "azure":
		cliName := "az"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("az CLI required: %w", err)
		}
		args := []string{"storage", "container", "show", "--name", cfg.Bucket, "--output", "json"}
		result := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, result)

		if cfg.AccountName != "" {
			args = []string{"storage", "account", "show", "--name", cfg.AccountName, "--output", "json"}
			acctResult := RunCLI(cliName, args, timeout)
			cliOutputs = append(cliOutputs, acctResult)
			if acctResult.ExitCode == 0 {
				enc, allowBlobPublicAccess := parseAzureStorageAccount(acctResult.Stdout)
				encryption = enc
				azureAllowBlobPublicAccess = allowBlobPublicAccess
			}

			args = []string{"storage", "account", "blob-service-properties", "show", "--account-name", cfg.AccountName, "--output", "json"}
			blobResult := RunCLI(cliName, args, timeout)
			cliOutputs = append(cliOutputs, blobResult)
			if blobResult.ExitCode == 0 {
				ver, log := parseAzureBlobServiceProps(blobResult.Stdout)
				versioning = ver
				logging = log
			}
		}

	default:
		return nil, &verify.ScopeError{Msg: fmt.Sprintf("unsupported provider %q (aws, gcp, azure)", cfg.Provider)}
	}

	elapsed := time.Since(start).Milliseconds()

	return &verify.ProbeResult{
		VulnType:   "cloud_storage",
		Technique:  "cloud_audit",
		StartedAt:  timer.StartedAt(),
		ProbeCount: len(cliOutputs),
		Duration:   timer.Elapsed(),
		Measurements: StorageMeasurements{
			Provider:                   cfg.Provider,
			Bucket:                     cfg.Bucket,
			AWSPublicAccessBlock:       awsPublicAccessBlock,
			GCPPublicAccessPrevention:  gcpPublicAccessPrevention,
			AzureAllowBlobPublicAccess: azureAllowBlobPublicAccess,
			Encryption:                 encryption,
			Versioning:                 versioning,
			Logging:                    logging,
			ACLEntries:                 aclEntries,
			CLIOutputs:                 cliOutputs,
			ElapsedMs:                  elapsed,
		},
	}, nil
}

func parseAWSACL(stdout string) []string {
	var result struct {
		Grants []struct {
			Grantee struct {
				URI  string `json:"URI"`
				Type string `json:"Type"`
			} `json:"Grantee"`
			Permission string `json:"Permission"`
		} `json:"Grants"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	var entries []string
	for _, g := range result.Grants {
		id := g.Grantee.URI
		if id == "" {
			id = g.Grantee.Type
		}
		entries = append(entries, fmt.Sprintf("%s:%s", id, g.Permission))
	}
	return entries
}

func parseAWSEncryption(stdout string) string {
	var result struct {
		ServerSideEncryptionConfiguration struct {
			Rules []struct {
				ApplyServerSideEncryptionByDefault struct {
					SSEAlgorithm string `json:"SSEAlgorithm"`
				} `json:"ApplyServerSideEncryptionByDefault"`
			} `json:"Rules"`
		} `json:"ServerSideEncryptionConfiguration"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return "unknown"
	}
	if len(result.ServerSideEncryptionConfiguration.Rules) > 0 {
		return result.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
	}
	return "none"
}

func parseAWSVersioning(stdout string) string {
	var result struct {
		Status string `json:"Status"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return "unknown"
	}
	if result.Status == "" {
		return "disabled"
	}
	return result.Status
}

func parseAWSLogging(stdout string) string {
	var result struct {
		LoggingEnabled *struct{} `json:"LoggingEnabled"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return "unknown"
	}
	if result.LoggingEnabled != nil {
		return "enabled"
	}
	return "disabled"
}

func parseAWSPublicAccessBlock(stdout string) *AWSPublicAccessBlock {
	var result struct {
		PublicAccessBlockConfiguration struct {
			BlockPublicAcls       bool `json:"BlockPublicAcls"`
			IgnorePublicAcls      bool `json:"IgnorePublicAcls"`
			BlockPublicPolicy     bool `json:"BlockPublicPolicy"`
			RestrictPublicBuckets bool `json:"RestrictPublicBuckets"`
		} `json:"PublicAccessBlockConfiguration"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	cfg := result.PublicAccessBlockConfiguration
	return &AWSPublicAccessBlock{
		BlockPublicACLs:       cfg.BlockPublicAcls,
		IgnorePublicACLs:      cfg.IgnorePublicAcls,
		BlockPublicPolicy:     cfg.BlockPublicPolicy,
		RestrictPublicBuckets: cfg.RestrictPublicBuckets,
	}
}

func parseGCPBucketDescribe(stdout string) (encryption, versioning, logging, publicAccessPrevention string) {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return "unknown", "unknown", "unknown", ""
	}
	// encryption: check defaultKmsKeyName or encryption key
	if enc, ok := result["encryption"]; ok {
		if m, ok := enc.(map[string]interface{}); ok {
			if _, ok := m["defaultKmsKeyName"]; ok {
				encryption = "kms"
			}
		}
	}
	if encryption == "" {
		encryption = "google-managed"
	}

	if v, ok := result["versioning"]; ok {
		if m, ok := v.(map[string]interface{}); ok {
			if enabled, ok := m["enabled"].(bool); ok && enabled {
				versioning = "Enabled"
			} else {
				versioning = "disabled"
			}
		}
	} else {
		versioning = "disabled"
	}

	if l, ok := result["logging"]; ok {
		if m, ok := l.(map[string]interface{}); ok {
			if _, ok := m["logBucket"]; ok {
				logging = "enabled"
			}
		}
	}
	if logging == "" {
		logging = "disabled"
	}

	// Preserve the provider's publicAccessPrevention value without interpreting it.
	if iam, ok := result["iamConfiguration"]; ok {
		if m, ok := iam.(map[string]interface{}); ok {
			if pap, ok := m["publicAccessPrevention"].(string); ok {
				publicAccessPrevention = pap
			}
		}
	}
	return
}

func parseGCPBucketIAMPolicy(stdout string) []string {
	var result struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	var entries []string
	for _, b := range result.Bindings {
		for _, m := range b.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				entries = append(entries, fmt.Sprintf("%s:%s", m, b.Role))
			}
		}
	}
	return entries
}

func parseAzureStorageAccount(stdout string) (encryption string, publicAccess *bool) {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return "unknown", nil
	}
	if enc, ok := result["encryption"]; ok {
		if m, ok := enc.(map[string]interface{}); ok {
			if services, ok := m["services"]; ok {
				if _, ok := services.(map[string]interface{}); ok {
					encryption = "microsoft-managed"
				}
			}
			if keySource, ok := m["keySource"].(string); ok && keySource == "Microsoft.Keyvault" {
				encryption = "customer-managed"
			}
		}
	}
	if encryption == "" {
		encryption = "unknown"
	}
	if allow, ok := result["allowBlobPublicAccess"].(bool); ok {
		publicAccess = &allow
	}
	return
}

func parseAzureBlobServiceProps(stdout string) (versioning, logging string) {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return "unknown", "unknown"
	}
	if v, ok := result["isVersioningEnabled"].(bool); ok {
		if v {
			versioning = "Enabled"
		} else {
			versioning = "disabled"
		}
	} else {
		versioning = "unknown"
	}
	if drp, ok := result["deleteRetentionPolicy"]; ok {
		if m, ok := drp.(map[string]interface{}); ok {
			if enabled, ok := m["enabled"].(bool); ok && enabled {
				logging = "enabled"
			}
		}
	}
	if logging == "" {
		logging = "disabled"
	}
	return
}
