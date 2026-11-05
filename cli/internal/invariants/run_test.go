package invariants

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// newTestServer creates an httptest.Server bound to IPv4 127.0.0.1 only.
func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	ts := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: handler},
	}
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

func parseInvariant(t *testing.T, raw string) Invariant {
	t.Helper()
	var inv Invariant
	if err := decodeStrictYAML([]byte(raw), &inv); err != nil {
		t.Fatalf("parse invariant: %v\n%s", err, raw)
	}
	if issues := Validate([]Invariant{inv}, ".", nil); len(issues) != 0 {
		t.Fatalf("test invariant does not validate: %+v", issues)
	}
	return inv
}

func testConfig(target, source string) RunConfig {
	return RunConfig{
		Target:     target,
		SourcePath: source,
		Scope:      []string{"127.0.0.1"},
		TimeoutSec: 5,
		Getenv:     func(string) string { return "" },
	}
}

func runSingle(t *testing.T, inv Invariant, cfg RunConfig) Result {
	t.Helper()
	report := Run([]Invariant{inv}, cfg)
	if len(report.Invariants) != 1 {
		t.Fatalf("expected one result, got %+v", report.Invariants)
	}
	return report.Invariants[0]
}

func assertResult(t *testing.T, r Result, want string) {
	t.Helper()
	if r.Result != want {
		t.Fatalf("expected %s, got %s: %s (measured %+v)", want, r.Result, r.Message, r.Measured)
	}
}

func headerServer(t *testing.T) *httptest.Server {
	return newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.Header().Set("X-Frame-Options", "DENY")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "not found")
		case "/invoices/b":
			w.Header().Set("X-Frame-Options", "ALLOWALL")
			fmt.Fprint(w, `{"invoice":"tenant-b-marker-77"}`)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
}

const httpInvariant = `id: INV-010
title: "http check"
origin: {kind: vulnerability, ref: VULN-010}
kind: http
request: {path: %s}
expect: {%s}
`

func TestRunHTTPPassAndFail(t *testing.T) {
	srv := headerServer(t)
	cases := []struct {
		name, path, expect, want string
	}{
		{"status pass", "/admin", "status: 404", ResultPass},
		{"status fail", "/invoices/b", "status: 404", ResultFail},
		{"header_matches pass", "/admin", `header_matches: {x-frame-options: "(?i)^(deny|sameorigin)$"}`, ResultPass},
		{"header_matches fail", "/invoices/b", `header_matches: {X-Frame-Options: "(?i)^(deny|sameorigin)$"}`, ResultFail},
		{"header_matches absent header fails", "/other", `header_matches: {x-frame-options: ".*"}`, ResultFail},
		{"body_not_contains pass", "/admin", `body_not_contains: "tenant-b-marker"`, ResultPass},
		{"body_not_contains fail", "/invoices/b", `body_not_contains: "tenant-b-marker"`, ResultFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv := parseInvariant(t, fmt.Sprintf(httpInvariant, tc.path, tc.expect))
			r := runSingle(t, inv, testConfig(srv.URL, "."))
			assertResult(t, r, tc.want)
			m, ok := r.Measured.(HTTPMeasured)
			if !ok || m.StatusCode == 0 || m.BodyLength == 0 || len(m.Checks) != 1 {
				t.Fatalf("expected status, body length, and one check measured, got %+v", r.Measured)
			}
			if m.Checks[0].Held != (tc.want == ResultPass) {
				t.Fatalf("check held=%t disagrees with result %s", m.Checks[0].Held, r.Result)
			}
		})
	}
}

func TestRunHTTPDoesNotFollowRedirects(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			fmt.Fprint(w, "login page")
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	inv := parseInvariant(t, fmt.Sprintf(httpInvariant, "/account", "status: 302"))
	assertResult(t, runSingle(t, inv, testConfig(srv.URL, ".")), ResultPass)
}

func TestRunHTTPScopeFailureIsErrorWithoutRequest(t *testing.T) {
	var hits atomic.Int32
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	inv := parseInvariant(t, fmt.Sprintf(httpInvariant, "/admin", "status: 404"))
	cfg := testConfig(srv.URL, ".")
	cfg.Scope = []string{"example.com"}
	r := runSingle(t, inv, cfg)
	assertResult(t, r, ResultError)
	if hits.Load() != 0 {
		t.Fatalf("an out-of-scope invariant sent %d requests", hits.Load())
	}

	cfg = testConfig("", ".")
	assertResult(t, runSingle(t, inv, cfg), ResultError)
}

func TestRunSubstitutesEnvironmentAndErrorsOnUnsetVariable(t *testing.T) {
	var gotAuth atomic.Value
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		fmt.Fprint(w, `{"invoice":"tenant-b-marker-77"}`)
	}))
	raw := `id: INV-011
title: "Tenant A cannot read tenant B's invoice"
origin: {kind: vulnerability, ref: VULN-011}
kind: http
request:
  path: /invoices/b
  headers: {Authorization: "Bearer ${TENANT_A_TOKEN}"}
expect: {body_not_contains: "${TENANT_B_MARKER}"}
`
	inv := parseInvariant(t, raw)

	r := runSingle(t, inv, testConfig(srv.URL, "."))
	assertResult(t, r, ResultError)
	if !strings.Contains(r.Message, "TENANT_A_TOKEN") || !strings.Contains(r.Message, "TENANT_B_MARKER") {
		t.Fatalf("expected both unset variables named, got %q", r.Message)
	}
	if gotAuth.Load() != nil {
		t.Fatal("an invariant with an unset variable must not send a request")
	}

	cfg := testConfig(srv.URL, ".")
	env := map[string]string{"TENANT_A_TOKEN": "tok-a", "TENANT_B_MARKER": "tenant-b-marker-77"}
	cfg.Getenv = func(k string) string { return env[k] }
	r = runSingle(t, inv, cfg)
	assertResult(t, r, ResultFail)
	if gotAuth.Load() != "Bearer tok-a" {
		t.Fatalf("expected the substituted token, got %v", gotAuth.Load())
	}
	if r.Expect.BodyNotContains != "${TENANT_B_MARKER}" {
		t.Fatalf("the expect echo must keep the reference, got %q", r.Expect.BodyNotContains)
	}
}

const rateInvariant = `id: INV-020
title: "OTP send throttles"
origin: {kind: missing_control, ref: CTRL-001}
kind: rate_limit
request: {method: POST, path: /otp, body: "{}"}
burst: 5
window_sec: 10
expect: {throttled_within: 4, retry_after_header: true}
`

func TestRunRateLimitPassWhenThrottledWithinAndRetryAfter(t *testing.T) {
	var count atomic.Int32
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) >= 4 {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, "sent")
	}))
	r := runSingle(t, parseInvariant(t, rateInvariant), testConfig(srv.URL, "."))
	assertResult(t, r, ResultPass)
	m := r.Measured.(RateLimitMeasured)
	if m.FirstThrottleAt != 4 || m.ThrottledCount != 2 || m.StatusCodes[429] != 2 || m.RetryAfter != "30" {
		t.Fatalf("unexpected measurements %+v", m)
	}
}

func TestRunRateLimitFailWhenNeverThrottledOrNoRetryAfter(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "sent") }))
	r := runSingle(t, parseInvariant(t, rateInvariant), testConfig(srv.URL, "."))
	assertResult(t, r, ResultFail)
	if m := r.Measured.(RateLimitMeasured); m.FirstThrottleAt != 0 || m.RequestsSent != 5 {
		t.Fatalf("unexpected measurements %+v", m)
	}

	var count atomic.Int32
	noHeader := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) >= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	r = runSingle(t, parseInvariant(t, rateInvariant), testConfig(noHeader.URL, "."))
	assertResult(t, r, ResultFail)
	if !strings.Contains(r.Message, "retry_after_header") || strings.Contains(r.Message, "throttled_within") {
		t.Fatalf("expected only the retry-after check to fail, got %q", r.Message)
	}
}

const sizeInvariant = `id: INV-030
title: "Upload rejects oversize files"
origin: {kind: missing_control, ref: CTRL-003}
kind: size_limit
request: {path: /upload}
size_bytes: 4096
expect: {status_in: [413]}
`

func TestRunSizeLimitPassAndFail(t *testing.T) {
	capped := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	r := runSingle(t, parseInvariant(t, sizeInvariant), testConfig(capped.URL, "."))
	assertResult(t, r, ResultPass)
	if m := r.Measured.(SizeLimitMeasured); m.StatusCode != 413 || m.SizeBytes != 4096 {
		t.Fatalf("unexpected measurements %+v", m)
	}

	accepting := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	r = runSingle(t, parseInvariant(t, sizeInvariant), testConfig(accepting.URL, "."))
	assertResult(t, r, ResultFail)
	if m := r.Measured.(SizeLimitMeasured); m.StatusCode != 201 {
		t.Fatalf("unexpected measurements %+v", m)
	}
}

func sourceTree(t *testing.T) string {
	t.Helper()
	return writeFiles(t, map[string]string{
		"apps/web/routes/api/users.ts":               "requireAuth(req)\nexport const x = 1\n",
		"apps/web/routes/api/admin.ts":               "export const y = dangerouslySetInnerHTML // token=abc123\n",
		"apps/web/routes/api/users.test.ts":          "dangerouslySetInnerHTML\n",
		"apps/web/routes/page.ts":                    "dangerouslySetInnerHTML\n",
		"ensphere-pentest/apps/x/routes/api/leak.ts": "dangerouslySetInnerHTML\n",
		"node_modules/apps/a/routes/api/dep.ts":      "dangerouslySetInnerHTML\n",
	})
}

const sourceInvariant = `id: INV-040
title: "source check"
origin: {kind: vulnerability, ref: VULN-040}
kind: source
include: ["apps/**/routes/api/**/*.ts", "**/leak.ts", "**/dep.ts"]
exclude: ["**/*.test.ts"]
%s
`

func TestRunSourcePatternHonoursExcludeAndSkipsWorkspace(t *testing.T) {
	root := sourceTree(t)
	inv := parseInvariant(t, fmt.Sprintf(sourceInvariant, "pattern: 'dangerouslySetInnerHTML'\nexpect: {matches: 1}"))
	r := runSingle(t, inv, testConfig("", root))
	assertResult(t, r, ResultPass)
	m := r.Measured.(SourceMeasured)
	if m.FilesScanned != 2 || m.Matches != 1 || len(m.Samples) != 1 {
		t.Fatalf("expected users.ts and admin.ts scanned with one match, got %+v", m)
	}
	s := m.Samples[0]
	if s.File != "apps/web/routes/api/admin.ts" || s.Line != 1 || strings.Contains(s.Snippet, "abc123") || !strings.Contains(s.Snippet, "[REDACTED]") {
		t.Fatalf("unexpected sample %+v", s)
	}

	inv = parseInvariant(t, fmt.Sprintf(sourceInvariant, "pattern: 'dangerouslySetInnerHTML'\nexpect: {matches: 0}"))
	assertResult(t, runSingle(t, inv, testConfig("", root)), ResultFail)
}

func TestRunSourceRequirePassAndFail(t *testing.T) {
	root := sourceTree(t)
	inv := parseInvariant(t, fmt.Sprintf(sourceInvariant, "require: 'requireAuth\\('\nexpect: {every_file_matches: true}"))
	r := runSingle(t, inv, testConfig("", root))
	assertResult(t, r, ResultFail)
	m := r.Measured.(SourceMeasured)
	if m.FilesScanned != 2 || m.Matches != 1 || m.FilesWithoutMatch != 1 || m.Samples[0].File != "apps/web/routes/api/admin.ts" {
		t.Fatalf("unexpected measurements %+v", m)
	}

	if err := os.WriteFile(filepath.Join(root, "apps/web/routes/api/admin.ts"), []byte("requireAuth(req)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	assertResult(t, runSingle(t, inv, testConfig("", root)), ResultPass)
}

const commandInvariant = `id: INV-050
title: "command check"
origin: {kind: missing_control, ref: CTRL-050}
kind: command
run: '%s'
timeout_sec: 1
expect: {%s}
`

func TestRunCommandOutcomes(t *testing.T) {
	root := writeFiles(t, map[string]string{"marker.txt": "0\n"})
	cases := []struct {
		name, run, expect, want string
	}{
		{"pass from source path", "cat marker.txt", `exit_code: 0, stdout_equals: "0", stdout_matches: "^0$"`, ResultPass},
		{"fail on exit code", "echo 0; exit 3", "exit_code: 0", ResultFail},
		{"pass on declared exit code", "exit 3", "exit_code: 3", ResultPass},
		{"fail on stdout", "echo 2", `stdout_equals: "0"`, ResultFail},
		{"fail on stdout regex", "echo 20", `stdout_matches: "^0$"`, ResultFail},
		{"error on timeout", "sleep 5", "exit_code: 0", ResultError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runSingle(t, parseInvariant(t, fmt.Sprintf(commandInvariant, tc.run, tc.expect)), testConfig("", root))
			assertResult(t, r, tc.want)
			if tc.want == ResultError && !strings.Contains(r.Message, "timed out") {
				t.Fatalf("expected a timeout message, got %q", r.Message)
			}
			if tc.want == ResultError && r.DurationMs > 4000 {
				t.Fatalf("timeout took %dms", r.DurationMs)
			}
		})
	}
}

func TestRunOnlySummaryAndMessage(t *testing.T) {
	srv := headerServer(t)
	root := writeFiles(t, map[string]string{"a.txt": "x\n"})
	pass := parseInvariant(t, strings.Replace(fmt.Sprintf(httpInvariant, "/admin", "status: 404"), "INV-010", "INV-101", 1))
	enforcedFail := parseInvariant(t, strings.Replace(fmt.Sprintf(commandInvariant, "exit 1", "exit_code: 0"), "INV-050", "INV-102", 1)+"enforce: true\n")
	unenforcedFail := parseInvariant(t, strings.Replace(fmt.Sprintf(commandInvariant, "exit 1", "exit_code: 0"), "INV-050", "INV-103", 1))
	errored := parseInvariant(t, strings.Replace(fmt.Sprintf(commandInvariant, "echo ${UNSET_VAR}", "exit_code: 0"), "INV-050", "INV-104", 1))
	all := []Invariant{pass, enforcedFail, unenforcedFail, errored}

	report := Run(all, testConfig(srv.URL, root))
	want := Summary{Total: 4, Pass: 1, Fail: 2, Error: 1, EnforcedFail: 1, UnenforcedFail: 1, UnenforcedPass: 1}
	if report.Summary != want {
		t.Fatalf("summary %+v, want %+v", report.Summary, want)
	}
	for i, r := range report.Invariants {
		if r.ID != all[i].ID {
			t.Fatalf("results out of loaded order: %d is %s", i, r.ID)
		}
	}
	if report.Passed() {
		t.Fatal("an enforced failure and an error must not pass")
	}
	lower := strings.ToLower(report.Message)
	for _, word := range []string{"secure", "safe"} {
		if strings.Contains(lower, word) {
			t.Fatalf("message contains %q: %s", word, report.Message)
		}
	}
	for _, r := range report.Invariants {
		if strings.Contains(strings.ToLower(r.Message), "secure") || strings.Contains(strings.ToLower(r.Message), "safe") {
			t.Fatalf("result message contains a forbidden word: %s", r.Message)
		}
	}

	cfg := testConfig(srv.URL, root)
	cfg.Only = []string{"INV-101", "INV-103"}
	report = Run(all, cfg)
	if len(report.Invariants) != 2 || report.Invariants[1].ID != "INV-103" {
		t.Fatalf("--only should keep INV-101 and INV-103, got %+v", report.Invariants)
	}
	if !report.Passed() || report.Summary.UnenforcedFail != 1 {
		t.Fatalf("an unenforced failure alone passes the CI rule, got %+v", report.Summary)
	}
	if unknown := UnknownIDs(all, []string{"INV-101", "INV-999"}); len(unknown) != 1 || unknown[0] != "INV-999" {
		t.Fatalf("expected INV-999 unknown, got %v", unknown)
	}
}

func guardedSource(t *testing.T, sandbox string) string {
	t.Helper()
	return writeFiles(t, map[string]string{
		"ensphere-pentest/config.md": "# Config\n\n## Sandbox\n\n" + sandbox + "\n",
		"curl":                       "#!/bin/sh\necho fake\n",
	})
}

func makeFakeCurlExecutable(t *testing.T, root string) {
	t.Helper()
	if err := os.Chmod(filepath.Join(root, "curl"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestRunCommandGuardDeniesNetworkToolInWorkspace(t *testing.T) {
	root := guardedSource(t, "- Start: docker compose up -d")
	makeFakeCurlExecutable(t, root)
	cfg := testConfig("", root)
	for _, run := range []string{"curl http://x/", "./curl http://x/"} {
		inv := parseInvariant(t, fmt.Sprintf(commandInvariant, run, "exit_code: 0"))
		report := Run([]Invariant{inv}, cfg)
		if !report.Guarded {
			t.Fatalf("a workspace in the source path should guard the run")
		}
		r := report.Invariants[0]
		assertResult(t, r, ResultError)
		if !strings.Contains(r.Message, "Ensphere guard") || r.Measured != nil {
			t.Fatalf("expected the guard reason and no execution for %q, got %q %+v", run, r.Message, r.Measured)
		}
	}
}

func TestRunCommandUnguardedWithoutWorkspace(t *testing.T) {
	root := writeFiles(t, map[string]string{"curl": "#!/bin/sh\necho fake\n"})
	makeFakeCurlExecutable(t, root)
	inv := parseInvariant(t, fmt.Sprintf(commandInvariant, "./curl http://x/", `stdout_equals: "fake"`))
	report := Run([]Invariant{inv}, testConfig("", root))
	if report.Guarded {
		t.Fatal("no workspace means an unguarded run")
	}
	assertResult(t, report.Invariants[0], ResultPass)
}

func TestRunCommandGuardAllowsApprovedSandboxCommand(t *testing.T) {
	root := guardedSource(t, "- Seed: ./curl http://x/")
	makeFakeCurlExecutable(t, root)
	inv := parseInvariant(t, fmt.Sprintf(commandInvariant, "./curl http://x/", `stdout_equals: "fake"`))
	report := Run([]Invariant{inv}, testConfig("", root))
	if !report.Guarded {
		t.Fatal("a workspace in the source path should guard the run")
	}
	assertResult(t, report.Invariants[0], ResultPass)
}

func TestRunCommandGuardOff(t *testing.T) {
	root := guardedSource(t, "- Start: docker compose up -d")
	cfg := testConfig("", root)
	cfg.Getenv = func(k string) string {
		if k == "ENSPHERE_GUARD" {
			return "off"
		}
		return ""
	}
	inv := parseInvariant(t, fmt.Sprintf(commandInvariant, "curl http://x/", "exit_code: 0"))
	report := Run([]Invariant{inv}, cfg)
	if report.Guarded {
		t.Fatal("ENSPHERE_GUARD=off means an unguarded run")
	}
	if r := report.Invariants[0]; strings.Contains(r.Message, "Ensphere guard") {
		t.Fatalf("ENSPHERE_GUARD=off must not apply the guard, got %q", r.Message)
	}
}
