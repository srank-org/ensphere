package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

// maxRequestBodyBytes bounds the body a scoped request may carry. Larger
// bodies belong to verify limits, which measures upload caps deliberately.
const maxRequestBodyBytes = 256 * 1024

// requestSnippetBytes bounds the redacted response excerpt in the output.
const requestSnippetBytes = 512

var requestMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
	http.MethodOptions: true,
}

// requestStages are the roles one scoped request may play in the
// controlled-validation cycle. The analyst declares the role; the ledger
// records it; the report gate checks that every probed row has all three.
var requestStages = map[string]bool{
	evidence.ResultBaseline: true,
	evidence.ResultProbe:    true,
	evidence.ResultControl:  true,
}

// redactedResponseHeaders are recorded by name only. Their values are
// credentials by construction.
var redactedResponseHeaders = map[string]bool{
	"set-cookie":       true,
	"authorization":    true,
	"www-authenticate": true,
}

// RequestConfig holds configuration for one analyst-constructed scoped
// request. Nothing about the request shape is anticipated by the CLI; the
// CLI contributes scope enforcement, the risk ceiling, timing, hashing, and
// the ledger entry.
type RequestConfig struct {
	URL             string
	Method          string
	Body            string
	Result          string // baseline | probe | control
	Note            string // what this request is for, in the analyst's words
	Risk            int    // the analyst's declared payload risk, 1 to 5
	FollowRedirects bool
	ProbeConfig
}

// VerifyRequest sends one scoped request and records it in the ledger with
// the stage the analyst declared.
func VerifyRequest(cfg RequestConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(cfg.Method))
	if method == "" {
		method = http.MethodGet
	}
	if !requestMethods[method] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported method %q; use GET, HEAD, POST, PUT, PATCH, DELETE, or OPTIONS", cfg.Method)}
	}
	result := strings.TrimSpace(cfg.Result)
	if !requestStages[result] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported result %q; declare the request's role: baseline, probe, or control", cfg.Result)}
	}
	if cfg.Risk == 0 {
		cfg.Risk = 3
	}
	if cfg.Risk < 1 || cfg.Risk > 5 {
		return nil, &ScopeError{Msg: fmt.Sprintf("declared risk %d must be between 1 and 5", cfg.Risk)}
	}
	if err := CheckMaxRisk(cfg.Risk, cfg.MaxRisk); err != nil {
		return nil, err
	}
	if len(cfg.Body) > maxRequestBodyBytes {
		return nil, &ScopeError{Msg: fmt.Sprintf("request body is %d bytes; the limit is %d. Use ensphere verify limits to measure size caps", len(cfg.Body), maxRequestBodyBytes)}
	}

	timer := NewTimer()

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

	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}

	fmt.Fprintf(os.Stderr, "[REQUEST] %s %s %s\n", result, method, cfg.URL)
	var resp ProbeResponse
	if cfg.FollowRedirects {
		resp = HTTPProbe(method, cfg.URL, cfg.Body, headers, cfg.TimeoutSec, cfg.InScope)
	} else {
		resp = HTTPProbeNoRedirect(method, cfg.URL, cfg.Body, headers, cfg.TimeoutSec, cfg.InScope)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("request failed: %w", resp.Error)
	}

	requestHash := hashRequest(method, cfg.URL, cfg.Body)
	measurements := RequestMeasurements{
		Method:            method,
		URL:               cfg.URL,
		Result:            result,
		DeclaredRisk:      cfg.Risk,
		RequestBodyBytes:  len(cfg.Body),
		RequestHash:       requestHash,
		RedirectsFollowed: cfg.FollowRedirects,
		Round: RoundResult{
			StatusCode: resp.StatusCode,
			ElapsedMs:  resp.ElapsedMs,
			BodyHash:   resp.BodyHash,
			BodyLength: len(resp.Body),
			Headers:    recordedResponseHeaders(resp.Headers),
		},
		ResponseSnippet: responseSnippet(resp.Body),
	}

	if ew != nil {
		entry := evidence.NewEntry("request", "scoped_request", cfg.URL, "", resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), result, cfg.Note).WithHashes(requestHash, resp.BodyHash)
		written, err := ew.WriteEntry(entry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: evidence write failed: %v\n", err)
		} else {
			measurements.EvidenceID = written.ID
		}
	}

	return &ProbeResult{
		VulnType:     "request",
		Technique:    "scoped_request",
		StartedAt:    timer.StartedAt(),
		ProbeCount:   1,
		Duration:     timer.Elapsed(),
		Measurements: measurements,
	}, nil
}

func hashRequest(method, url, body string) string {
	sum := sha256.Sum256([]byte(method + "\n" + url + "\n" + body))
	return hex.EncodeToString(sum[:])
}

// recordedResponseHeaders lowercases header names, keeps the first value,
// redacts known secret shapes, and replaces credential-bearing headers with
// a marker so the ledger never carries a session cookie.
func recordedResponseHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for key, values := range h {
		if len(values) == 0 {
			continue
		}
		lk := strings.ToLower(key)
		if redactedResponseHeaders[lk] {
			out[lk] = "[REDACTED]"
			continue
		}
		out[lk] = evidence.RedactSecrets(values[0])
	}
	return out
}

func responseSnippet(body string) string {
	if body == "" {
		return ""
	}
	if len(body) > requestSnippetBytes {
		body = body[:requestSnippetBytes]
	}
	return evidence.RedactSecrets(body)
}
