package cloud

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/srank/ensphere/internal/verify"
)

// IAMConfig holds configuration for cloud IAM verification.
type IAMConfig struct {
	Provider  string
	Principal string // ARN, email, or service account
	AccountID string
	verify.ProbeConfig
}

// IAMMeasurements holds cloud IAM probe results.
type IAMMeasurements struct {
	Provider          string      `json:"provider"`
	Principal         string      `json:"principal"`
	AttachedPolicies  []string    `json:"attached_policies"`
	InlinePolicies    []string    `json:"inline_policies"`
	MFAEnabled        *bool       `json:"mfa_enabled"`
	LastUsed          string      `json:"last_used"`
	PermissionActions []string    `json:"permission_actions"`
	CLIOutputs        []CLIResult `json:"cli_outputs"`
	ElapsedMs         int64       `json:"elapsed_ms"`
}

// VerifyCloudIAM runs cloud IAM security checks.
func VerifyCloudIAM(cfg IAMConfig) (*verify.ProbeResult, error) {
	if err := verify.CheckCloudScope(cfg.Provider, cfg.AccountID, cfg.InScope); err != nil {
		return nil, err
	}
	if err := verify.CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	timer := verify.NewTimer()
	start := time.Now()

	var cliOutputs []CLIResult
	var attachedPolicies, inlinePolicies []string
	var mfaEnabled *bool
	lastUsed := "unknown"
	var allActions []string

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

		username := cfg.Principal
		if strings.Contains(username, ":user/") {
			parts := strings.Split(username, "/")
			username = parts[len(parts)-1]
		}

		args := []string{"iam", "list-attached-user-policies", "--user-name", username, "--output", "json"}
		attachedResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, attachedResult)
		if attachedResult.ExitCode == 0 {
			attachedPolicies = parseAWSAttachedPolicies(attachedResult.Stdout)
		}

		args = []string{"iam", "list-user-policies", "--user-name", username, "--output", "json"}
		inlineResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, inlineResult)
		if inlineResult.ExitCode == 0 {
			inlinePolicies = parseAWSInlinePolicies(inlineResult.Stdout)
		}

		args = []string{"iam", "list-mfa-devices", "--user-name", username, "--output", "json"}
		mfaResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, mfaResult)
		if mfaResult.ExitCode == 0 {
			m := parseAWSMFA(mfaResult.Stdout)
			mfaEnabled = &m
		}

		args = []string{"iam", "get-user", "--user-name", username, "--output", "json"}
		userResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, userResult)
		if userResult.ExitCode == 0 {
			lastUsed = parseAWSLastUsed(userResult.Stdout)
		}

		// Collect actions from each attached policy document, preserving the provider-supplied action list
		for _, policyARN := range attachedPolicies {
			policyActions, pResult := extractActionsFromPolicy(cliName, policyARN, timeout)
			cliOutputs = append(cliOutputs, pResult)
			allActions = append(allActions, policyActions...)
		}

	case "gcp":
		cliName := "gcloud"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("gcloud CLI required: %w", err)
		}
		args := []string{"projects", "get-iam-policy", cfg.AccountID, "--format=json"}
		iamResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, iamResult)
		if iamResult.ExitCode == 0 {
			attachedPolicies = parseGCPIAMPolicy(iamResult.Stdout)
		}

		if strings.Contains(cfg.Principal, "iam.gserviceaccount.com") {
			args = []string{"iam", "service-accounts", "keys", "list", "--iam-account", cfg.Principal, "--format=json"}
			keysResult := RunCLI(cliName, args, timeout)
			cliOutputs = append(cliOutputs, keysResult)
		}

	case "azure":
		cliName := "az"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("az CLI required: %w", err)
		}
		args := []string{"role", "assignment", "list", "--assignee", cfg.Principal, "--output", "json"}
		roleResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, roleResult)
		if roleResult.ExitCode == 0 {
			attachedPolicies = parseAzureRoleAssignments(roleResult.Stdout)
		}

		args = []string{"role", "definition", "list", "--custom-role-only", "true", "--output", "json"}
		customResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, customResult)

	default:
		return nil, &verify.ScopeError{Msg: fmt.Sprintf("unsupported provider %q (aws, gcp, azure)", cfg.Provider)}
	}

	elapsed := time.Since(start).Milliseconds()

	return &verify.ProbeResult{
		VulnType:   "cloud_iam",
		Technique:  "cloud_audit",
		StartedAt:  timer.StartedAt(),
		ProbeCount: len(cliOutputs),
		Duration:   timer.Elapsed(),
		Measurements: IAMMeasurements{
			Provider:          cfg.Provider,
			Principal:         cfg.Principal,
			AttachedPolicies:  attachedPolicies,
			InlinePolicies:    inlinePolicies,
			MFAEnabled:        mfaEnabled,
			LastUsed:          lastUsed,
			PermissionActions: cleanStrings(allActions),
			CLIOutputs:        cliOutputs,
			ElapsedMs:         elapsed,
		},
	}, nil
}

func parseAWSAttachedPolicies(stdout string) []string {
	var result struct {
		AttachedPolicies []struct {
			PolicyArn string `json:"PolicyArn"`
		} `json:"AttachedPolicies"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	var policies []string
	for _, p := range result.AttachedPolicies {
		policies = append(policies, p.PolicyArn)
	}
	return policies
}

func parseAWSInlinePolicies(stdout string) []string {
	var result struct {
		PolicyNames []string `json:"PolicyNames"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	return result.PolicyNames
}

func parseAWSMFA(stdout string) bool {
	var result struct {
		MFADevices []struct{} `json:"MFADevices"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return false
	}
	return len(result.MFADevices) > 0
}

func parseAWSLastUsed(stdout string) string {
	var result struct {
		User struct {
			PasswordLastUsed string `json:"PasswordLastUsed"`
		} `json:"User"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return "unknown"
	}
	if result.User.PasswordLastUsed == "" {
		return "never"
	}
	return result.User.PasswordLastUsed
}

func extractActionsFromPolicy(cliName, policyARN string, timeout int) ([]string, CLIResult) {
	// Step 1: get-policy to find DefaultVersionId
	args := []string{"iam", "get-policy", "--policy-arn", policyARN, "--output", "json"}
	policyResult := RunCLI(cliName, args, timeout)
	if policyResult.ExitCode != 0 {
		return nil, policyResult
	}

	var policyInfo struct {
		Policy struct {
			DefaultVersionId string `json:"DefaultVersionId"`
		} `json:"Policy"`
	}
	if err := json.Unmarshal([]byte(policyResult.Stdout), &policyInfo); err != nil || policyInfo.Policy.DefaultVersionId == "" {
		return nil, policyResult
	}

	// Step 2: get-policy-version
	args = []string{"iam", "get-policy-version", "--policy-arn", policyARN, "--version-id", policyInfo.Policy.DefaultVersionId, "--output", "json"}
	versionResult := RunCLI(cliName, args, timeout)
	if versionResult.ExitCode != 0 {
		return nil, versionResult
	}

	return parseActionsFromPolicyVersion(versionResult.Stdout), versionResult
}

func parseActionsFromPolicyVersion(stdout string) []string {
	var result struct {
		PolicyVersion struct {
			Document string `json:"Document"`
		} `json:"PolicyVersion"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	// Document is URL-encoded JSON
	doc := result.PolicyVersion.Document
	if decoded, err := url.QueryUnescape(doc); err == nil {
		doc = decoded
	}
	var policy struct {
		Statement []struct {
			Action interface{} `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &policy); err != nil {
		return nil
	}
	var actions []string
	for _, stmt := range policy.Statement {
		switch a := stmt.Action.(type) {
		case string:
			actions = append(actions, a)
		case []interface{}:
			for _, v := range a {
				if s, ok := v.(string); ok {
					actions = append(actions, s)
				}
			}
		}
	}
	return actions
}

func parseGCPIAMPolicy(stdout string) []string {
	var result struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	var roles []string
	for _, b := range result.Bindings {
		roles = append(roles, b.Role)
	}
	return roles
}

func parseAzureRoleAssignments(stdout string) []string {
	var result []struct {
		RoleDefinitionName string `json:"roleDefinitionName"`
		Scope              string `json:"scope"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	var roles []string
	for _, r := range result {
		roles = append(roles, r.RoleDefinitionName)
	}
	return roles
}

func cleanStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
	}
	return cleaned
}
