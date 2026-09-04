package cmd

import (
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify vulnerabilities with targeted probes",
	Long: `Run scoped measurement probes for one vulnerability category. Output is raw
measurements (status, timing, hashes, headers, counts); it never contains a
verdict. Every subcommand requires --in-scope.

Available subcommands:
  request         Send one analyst-constructed request through scope and the ledger
  sqli            Verify SQL injection (blind_time, blind_boolean, error_based)
  xss             Verify reflected cross-site scripting
  idor            Verify insecure direct object reference
  ssrf            Verify server-side request forgery
  auth            Verify authentication bypass
  rls             Verify Supabase RLS tenant isolation
  cmdi            Verify command injection
  lfi             Verify local file inclusion
  limits          Measure size and volume limits
  ssti            Verify server-side template injection
  xxe             Verify XML external entity injection
  csrf            Verify cross-site request forgery
  nosql           Verify NoSQL injection
  jwt             Verify JWT manipulation
  cors            Verify CORS misconfiguration
  protopollution  Verify prototype pollution
  graphql         Verify GraphQL abuse
  race            Verify race condition
  cachepoisoning  Verify cache poisoning
  redirect        Verify open redirect
  csvinjection    Verify CSV injection
  authz           Verify authorization bypass
  clickjacking    Verify clickjacking protection (X-Frame-Options, CSP frame-ancestors)
  headerinjection Verify CRLF header injection
  propertyauthz   Verify property-level authorization
  ratelimit       Verify rate limiting behavior
  websocket       Verify WebSocket security
  grpc            Verify gRPC security
  ldap            Verify LDAP injection
  xpath           Verify XPath injection
  fileupload      Verify file upload vulnerability
  massassignment  Verify mass assignment vulnerability`,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
