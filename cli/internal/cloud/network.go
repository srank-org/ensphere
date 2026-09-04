package cloud

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/srank-org/ensphere/internal/verify"
)

// NetworkConfig holds configuration for cloud network verification.
type NetworkConfig struct {
	Provider  string
	VPCID     string // optional
	AccountID string
	verify.ProbeConfig
}

// NetworkMeasurements holds cloud network probe results.
type NetworkMeasurements struct {
	Provider        string              `json:"provider"`
	OpenIngress     []SecurityGroupRule `json:"open_ingress"`
	TotalSGs        int                 `json:"total_sgs"`
	FlowLogsEnabled *bool               `json:"flow_logs_enabled"`
	PublicIPs       []string            `json:"public_ips"`
	CLIOutputs      []CLIResult         `json:"cli_outputs"`
	ElapsedMs       int64               `json:"elapsed_ms"`
}

// SecurityGroupRule represents a single open ingress rule.
type SecurityGroupRule struct {
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name"`
	Port      string `json:"port"`
	Protocol  string `json:"protocol"`
	Source    string `json:"source"`
}

// VerifyCloudNetwork runs cloud network security checks.
func VerifyCloudNetwork(cfg NetworkConfig) (*verify.ProbeResult, error) {
	if err := verify.CheckCloudScope(cfg.Provider, cfg.AccountID, cfg.InScope); err != nil {
		return nil, err
	}
	if err := verify.CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	timer := verify.NewTimer()
	start := time.Now()

	var cliOutputs []CLIResult
	var openIngress []SecurityGroupRule
	totalSGs := 0
	var flowLogsEnabled *bool
	var publicIPs []string

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

		sgArgs := []string{"ec2", "describe-security-groups", "--output", "json"}
		if cfg.VPCID != "" {
			sgArgs = append(sgArgs, "--filters", "Name=vpc-id,Values="+cfg.VPCID)
		}
		sgResult := RunCLI(cliName, sgArgs, timeout)
		cliOutputs = append(cliOutputs, sgResult)
		if sgResult.ExitCode == 0 {
			openIngress, totalSGs = parseAWSSGs(sgResult.Stdout)
		}

		flArgs := []string{"ec2", "describe-flow-logs", "--output", "json"}
		if cfg.VPCID != "" {
			flArgs = append(flArgs, "--filter", "Name=resource-id,Values="+cfg.VPCID)
		}
		flResult := RunCLI(cliName, flArgs, timeout)
		cliOutputs = append(cliOutputs, flResult)
		if flResult.ExitCode == 0 {
			fl := parseAWSFlowLogs(flResult.Stdout)
			flowLogsEnabled = &fl
		}

		eipResult := RunCLI(cliName, []string{"ec2", "describe-addresses", "--output", "json"}, timeout)
		cliOutputs = append(cliOutputs, eipResult)
		if eipResult.ExitCode == 0 {
			publicIPs = parseAWSPublicIPs(eipResult.Stdout)
		}

	case "gcp":
		cliName := "gcloud"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("gcloud CLI required: %w", err)
		}
		fwArgs := []string{"compute", "firewall-rules", "list", "--format=json"}
		fwResult := RunCLI(cliName, fwArgs, timeout)
		cliOutputs = append(cliOutputs, fwResult)
		if fwResult.ExitCode == 0 {
			openIngress, totalSGs = parseGCPFirewallRules(fwResult.Stdout)
		}
		subArgs := []string{"compute", "networks", "subnets", "list", "--format=json"}
		subResult := RunCLI(cliName, subArgs, timeout)
		cliOutputs = append(cliOutputs, subResult)
		if subResult.ExitCode == 0 {
			fl := parseGCPSubnetsFlowLogs(subResult.Stdout)
			flowLogsEnabled = &fl
		}
		addrArgs := []string{"compute", "addresses", "list", "--format=json"}
		addrResult := RunCLI(cliName, addrArgs, timeout)
		cliOutputs = append(cliOutputs, addrResult)
		if addrResult.ExitCode == 0 {
			publicIPs = parseGCPAddresses(addrResult.Stdout)
		}

	case "azure":
		cliName := "az"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("az CLI required: %w", err)
		}
		nsgArgs := []string{"network", "nsg", "list", "--output", "json"}
		nsgResult := RunCLI(cliName, nsgArgs, timeout)
		cliOutputs = append(cliOutputs, nsgResult)
		if nsgResult.ExitCode == 0 {
			openIngress, totalSGs = parseAzureNSGs(nsgResult.Stdout)
		}
		flArgs := []string{"network", "watcher", "flow-log", "list", "--output", "json"}
		flResult := RunCLI(cliName, flArgs, timeout)
		cliOutputs = append(cliOutputs, flResult)
		if flResult.ExitCode == 0 {
			fl := parseAzureFlowLogs(flResult.Stdout)
			flowLogsEnabled = &fl
		}
		ipArgs := []string{"network", "public-ip", "list", "--output", "json"}
		ipResult := RunCLI(cliName, ipArgs, timeout)
		cliOutputs = append(cliOutputs, ipResult)
		if ipResult.ExitCode == 0 {
			publicIPs = parseAzurePublicIPs(ipResult.Stdout)
		}

	default:
		return nil, &verify.ScopeError{Msg: fmt.Sprintf("unsupported provider %q (aws, gcp, azure)", cfg.Provider)}
	}

	elapsed := time.Since(start).Milliseconds()

	return &verify.ProbeResult{
		VulnType:   "cloud_network",
		Technique:  "cloud_audit",
		StartedAt:  timer.StartedAt(),
		ProbeCount: len(cliOutputs),
		Duration:   timer.Elapsed(),
		Measurements: NetworkMeasurements{
			Provider:        cfg.Provider,
			OpenIngress:     openIngress,
			TotalSGs:        totalSGs,
			FlowLogsEnabled: flowLogsEnabled,
			PublicIPs:       publicIPs,
			CLIOutputs:      cliOutputs,
			ElapsedMs:       elapsed,
		},
	}, nil
}

func parseAWSSGs(stdout string) ([]SecurityGroupRule, int) {
	var result struct {
		SecurityGroups []struct {
			GroupId       string `json:"GroupId"`
			GroupName     string `json:"GroupName"`
			IpPermissions []struct {
				FromPort   *int   `json:"FromPort"`
				ToPort     *int   `json:"ToPort"`
				IpProtocol string `json:"IpProtocol"`
				IpRanges   []struct {
					CidrIp string `json:"CidrIp"`
				} `json:"IpRanges"`
				Ipv6Ranges []struct {
					CidrIpv6 string `json:"CidrIpv6"`
				} `json:"Ipv6Ranges"`
			} `json:"IpPermissions"`
		} `json:"SecurityGroups"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil, 0
	}

	var openRules []SecurityGroupRule
	for _, sg := range result.SecurityGroups {
		for _, perm := range sg.IpPermissions {
			for _, r := range perm.IpRanges {
				if r.CidrIp == "0.0.0.0/0" {
					port := portRange(perm.FromPort, perm.ToPort)
					openRules = append(openRules, SecurityGroupRule{
						GroupID:   sg.GroupId,
						GroupName: sg.GroupName,
						Port:      port,
						Protocol:  perm.IpProtocol,
						Source:    r.CidrIp,
					})
				}
			}
			for _, r := range perm.Ipv6Ranges {
				if r.CidrIpv6 == "::/0" {
					port := portRange(perm.FromPort, perm.ToPort)
					openRules = append(openRules, SecurityGroupRule{
						GroupID:   sg.GroupId,
						GroupName: sg.GroupName,
						Port:      port,
						Protocol:  perm.IpProtocol,
						Source:    r.CidrIpv6,
					})
				}
			}
		}
	}

	return openRules, len(result.SecurityGroups)
}

func portRange(from, to *int) string {
	if from == nil && to == nil {
		return "all"
	}
	if from != nil && to != nil {
		if *from == *to {
			return fmt.Sprintf("%d", *from)
		}
		return fmt.Sprintf("%d-%d", *from, *to)
	}
	if from != nil {
		return fmt.Sprintf("%d", *from)
	}
	return fmt.Sprintf("%d", *to)
}

func parseAWSFlowLogs(stdout string) bool {
	var result struct {
		FlowLogs []struct{} `json:"FlowLogs"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return false
	}
	return len(result.FlowLogs) > 0
}

func parseAWSPublicIPs(stdout string) []string {
	var result struct {
		Addresses []struct {
			PublicIp string `json:"PublicIp"`
		} `json:"Addresses"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	var ips []string
	for _, a := range result.Addresses {
		ips = append(ips, a.PublicIp)
	}
	return ips
}

func parseGCPFirewallRules(stdout string) ([]SecurityGroupRule, int) {
	var rules []struct {
		Name         string   `json:"name"`
		Direction    string   `json:"direction"`
		SourceRanges []string `json:"sourceRanges"`
		Allowed      []struct {
			IPProtocol string   `json:"IPProtocol"`
			Ports      []string `json:"ports"`
		} `json:"allowed"`
	}
	if err := json.Unmarshal([]byte(stdout), &rules); err != nil {
		return nil, 0
	}
	var open []SecurityGroupRule
	for _, r := range rules {
		if r.Direction != "INGRESS" {
			continue
		}
		for _, src := range r.SourceRanges {
			if src == "0.0.0.0/0" || src == "::/0" {
				for _, a := range r.Allowed {
					port := "all"
					if len(a.Ports) > 0 {
						port = strings.Join(a.Ports, ",")
					}
					open = append(open, SecurityGroupRule{
						GroupID:   r.Name,
						GroupName: r.Name,
						Port:      port,
						Protocol:  a.IPProtocol,
						Source:    src,
					})
				}
			}
		}
	}
	return open, len(rules)
}

func parseGCPSubnetsFlowLogs(stdout string) bool {
	var subnets []struct {
		LogConfig struct {
			Enable bool `json:"enable"`
		} `json:"logConfig"`
	}
	if err := json.Unmarshal([]byte(stdout), &subnets); err != nil {
		return false
	}
	for _, s := range subnets {
		if s.LogConfig.Enable {
			return true
		}
	}
	return false
}

func parseGCPAddresses(stdout string) []string {
	var addrs []struct {
		Address     string `json:"address"`
		AddressType string `json:"addressType"`
	}
	if err := json.Unmarshal([]byte(stdout), &addrs); err != nil {
		return nil
	}
	var ips []string
	for _, a := range addrs {
		if a.AddressType == "EXTERNAL" {
			ips = append(ips, a.Address)
		}
	}
	return ips
}

func parseAzureNSGs(stdout string) ([]SecurityGroupRule, int) {
	var nsgs []struct {
		Name          string `json:"name"`
		SecurityRules []struct {
			Name                 string `json:"name"`
			Direction            string `json:"direction"`
			Access               string `json:"access"`
			SourceAddressPrefix  string `json:"sourceAddressPrefix"`
			DestinationPortRange string `json:"destinationPortRange"`
			Protocol             string `json:"protocol"`
		} `json:"securityRules"`
	}
	if err := json.Unmarshal([]byte(stdout), &nsgs); err != nil {
		return nil, 0
	}
	var open []SecurityGroupRule
	total := 0
	for _, nsg := range nsgs {
		total++
		for _, rule := range nsg.SecurityRules {
			if rule.Direction != "Inbound" || rule.Access != "Allow" {
				continue
			}
			if rule.SourceAddressPrefix == "*" || rule.SourceAddressPrefix == "0.0.0.0/0" || rule.SourceAddressPrefix == "Internet" {
				open = append(open, SecurityGroupRule{
					GroupID:   nsg.Name,
					GroupName: nsg.Name,
					Port:      rule.DestinationPortRange,
					Protocol:  rule.Protocol,
					Source:    rule.SourceAddressPrefix,
				})
			}
		}
	}
	return open, total
}

func parseAzureFlowLogs(stdout string) bool {
	var logs []struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(stdout), &logs); err != nil {
		return false
	}
	for _, l := range logs {
		if l.Enabled {
			return true
		}
	}
	return false
}

func parseAzurePublicIPs(stdout string) []string {
	var ips []struct {
		IpAddress string `json:"ipAddress"`
	}
	if err := json.Unmarshal([]byte(stdout), &ips); err != nil {
		return nil
	}
	var result []string
	for _, ip := range ips {
		if ip.IpAddress != "" {
			result = append(result, ip.IpAddress)
		}
	}
	return result
}
