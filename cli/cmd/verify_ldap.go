package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	ldapURL       string
	ldapParam     string
	ldapTechnique string
	ldapMethod    string
	ldapProbe     probeFlags
)

var verifyLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Verify LDAP injection vulnerability",
	Long: `Verify LDAP injection with filter injection, blind boolean, or blind error probes.

Techniques:
  ldap_filter_injection  Inject LDAP filter metacharacters and compare responses (default)
  ldap_blind_boolean     Inject true/false LDAP conditions and compare body hashes
  ldap_blind_error       Inject malformed filter (unbalanced parens) and detect error signatures

Examples:
  ensphere verify ldap --url "http://target/search" --param uid --in-scope "*.target.com"
  ensphere verify ldap --url "http://target/search" --param uid --technique ldap_blind_boolean --in-scope "*.target.com"
  ensphere verify ldap --url "http://target/login" --param username --technique ldap_blind_error --method POST --in-scope "*.target.com"`,
	RunE: runVerifyLDAP,
}

func init() {
	verifyLDAPCmd.Flags().StringVar(&ldapURL, "url", "", "Target URL (required)")
	verifyLDAPCmd.Flags().StringVar(&ldapParam, "param", "", "Parameter/field name (required)")
	verifyLDAPCmd.Flags().StringVar(&ldapTechnique, "technique", "ldap_filter_injection", "Technique: ldap_filter_injection, ldap_blind_boolean, ldap_blind_error")
	verifyLDAPCmd.Flags().StringVar(&ldapMethod, "method", "GET", "HTTP method")

	_ = verifyLDAPCmd.MarkFlagRequired("url")
	_ = verifyLDAPCmd.MarkFlagRequired("param")

	addProbeFlags(verifyLDAPCmd, &ldapProbe)

	verifyCmd.AddCommand(verifyLDAPCmd)
}

func runVerifyLDAP(cmd *cobra.Command, args []string) error {

	cfg := verify.LDAPConfig{
		URL:         ldapURL,
		Param:       ldapParam,
		Technique:   ldapTechnique,
		Method:      ldapMethod,
		ProbeConfig: buildProbeConfig(&ldapProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyLDAP(cfg)
	})
}
