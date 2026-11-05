package runner

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"

	"github.com/srank-org/ensphere/internal/verify"
)

// ErrInvalidScope marks a run init --in-scope value that is not a list of
// host patterns. The cmd layer maps it to a usage exit.
var ErrInvalidScope = errors.New("invalid --in-scope")

// ParseScopeList parses a comma-separated list of host patterns: hostnames,
// globs such as *.example.com, IPs, and CIDRs. Tokens are trimmed and
// lowercased; an empty value yields an empty list.
func ParseScopeList(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var tokens []string
	for _, raw := range strings.Split(value, ",") {
		token := strings.ToLower(strings.TrimSpace(raw))
		if !validScopeToken(token) {
			return nil, fmt.Errorf("%w: %q is not a host pattern; expected a comma-separated list of hostnames, globs, IPs, or CIDRs, e.g. --in-scope \"localhost,*.staging.example.com,10.0.0.0/8\"", ErrInvalidScope, strings.TrimSpace(raw))
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func validScopeToken(token string) bool {
	if token == "" || strings.ContainsFunc(token, unicode.IsSpace) || strings.Contains(token, "://") {
		return false
	}
	if strings.Contains(token, "/") {
		_, _, err := net.ParseCIDR(token)
		return err == nil
	}
	return true
}

// scopeTokens reads the In scope value of a config.md without validating it,
// so a hand-edited config still yields the list it states.
func scopeTokens(value string) []string {
	tokens := []string{}
	for _, raw := range strings.Split(value, ",") {
		if token := strings.ToLower(strings.TrimSpace(raw)); token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func targetHost(targetURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// CheckScopeApproved returns a *verify.ScopeError unless every pattern is in
// the scope list of the workspace's config.md. The operator approves scope
// there; a verify command's --in-scope may only name patterns from it.
func CheckScopeApproved(workspace string, patterns []string) error {
	cfg, err := readConfig(workspace)
	if err != nil {
		return err
	}
	approved := scopeTokens(cfg.InScope)
	if len(approved) == 0 {
		return &verify.ScopeError{Msg: fmt.Sprintf("the workspace at %s has no live-target scope; a source-only assessment sends no requests", workspace)}
	}
	set := make(map[string]struct{}, len(approved))
	for _, token := range approved {
		set[token] = struct{}{}
	}
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if _, ok := set[pattern]; !ok {
			return &verify.ScopeError{Msg: fmt.Sprintf("--in-scope %s is not in the workspace scope approved in %s (%s); scope is operator-approved there, not on the command line", pattern, configPath(workspace), strings.Join(approved, ", "))}
		}
	}
	return nil
}
