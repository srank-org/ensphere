package invariants

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validHTTP = `id: INV-001
title: "Admin route answers 404 without a session"
origin: {kind: vulnerability, ref: VULN-001}
kind: http
request: {method: GET, path: /admin}
expect: {status_in: [403, 404], header_absent: [x-powered-by]}
`

const validRateLimit = `id: INV-002
title: "OTP send throttles a burst"
surface: SURF-001
origin: {kind: missing_control, ref: CTRL-001, evidence: [EVID-088]}
enforce: true
kind: rate_limit
request:
  method: POST
  path: /api/auth/otp
  headers: {"Content-Type": "application/json"}
  body: '{"phone": "+60100000001"}'
burst: 8
window_sec: 60
expect: {throttled_within: 6, retry_after_header: true}
`

const validSizeLimit = `id: INV-003
title: "Upload rejects 25 MiB"
origin: {kind: tested_defense, ref: COV-08.5-003}
kind: size_limit
request: {path: /api/upload}
size_bytes: 26214401
field: file
expect: {status_in: [413]}
`

const validSource = `id: INV-004
title: "No dangerouslySetInnerHTML"
origin: {kind: vulnerability, ref: VULN-002}
kind: source
include: ["apps/**/*.tsx"]
exclude: ["**/*.test.tsx"]
pattern: 'dangerouslySetInnerHTML'
expect: {matches: 0}
`

const validCommand = `id: INV-005
title: "No public bucket"
origin: {kind: missing_control, ref: CTRL-002}
kind: command
run: 'echo 0'
timeout_sec: 5
expect: {exit_code: 0, stdout_equals: "0", stdout_matches: "^0$"}
`

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func loadValid(t *testing.T, files map[string]string) []Invariant {
	t.Helper()
	invs, issues, err := Load(writeFiles(t, files))
	if err != nil || len(issues) != 0 {
		t.Fatalf("load: err=%v issues=%+v", err, issues)
	}
	return invs
}

func codes(issues []Issue) []string {
	var out []string
	for _, issue := range issues {
		out = append(out, issue.Code)
	}
	return out
}

func hasCode(issues []Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func TestLoadAndValidateAcceptOneInvariantPerKind(t *testing.T) {
	invs := loadValid(t, map[string]string{
		"http.yaml":   validHTTP,
		"rate.yml":    validRateLimit,
		"size.yaml":   validSizeLimit,
		"source.yaml": validSource,
		"cmd.yaml":    validCommand,
	})
	if len(invs) != 5 {
		t.Fatalf("expected 5 invariants, got %d", len(invs))
	}
	if issues := Validate(invs, ".", []string{"SURF-001"}); len(issues) != 0 {
		t.Fatalf("expected no issues, got %+v", issues)
	}
	if invs[0].ID != "INV-005" || invs[len(invs)-1].ID != "INV-004" {
		t.Fatalf("expected filename order cmd, http, rate, size, source; got %s first and %s last", invs[0].ID, invs[len(invs)-1].ID)
	}
}

func TestLoadReportsParseFailuresAsIssuesAndIgnoresOtherFiles(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"a.yaml":      validHTTP,
		"b.yaml":      validHTTP + "unknown_field: 1\n",
		"c.yaml":      "",
		"d.yaml":      validHTTP + "---\n" + validHTTP,
		"notes.txt":   "not an invariant",
		"sub/e.yaml":  validCommand,
		"f.yaml":      "id: [unclosed\n",
		"g.YML":       validCommand,
		"h.yaml.bak":  validCommand,
		"i.yaml":      validSource,
		"zz/nested.y": "x",
	})
	invs, issues, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(invs) != 3 {
		t.Fatalf("expected a.yaml, g.YML, and i.yaml to load, got %d", len(invs))
	}
	if len(issues) != 4 {
		t.Fatalf("expected four parse issues (b, c, d, f), got %+v", issues)
	}
	for _, issue := range issues {
		if issue.Code != "invariant_yaml_invalid" || issue.Severity != SeverityError || issue.Path == "" {
			t.Fatalf("unexpected issue %+v", issue)
		}
	}
	if !strings.Contains(issues[1].Message, "empty") {
		t.Fatalf("expected the empty file to say so, got %q", issues[1].Message)
	}
}

func TestLoadUnreadableDirectoryIsAnError(t *testing.T) {
	if _, _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}

func TestValidateIssueCodes(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		code string
	}{
		{"id pattern", strings.Replace(validHTTP, "INV-001", "INV-1", 1), "invariant_id_invalid"},
		{"title empty", strings.Replace(validHTTP, `"Admin route answers 404 without a session"`, `""`, 1), "invariant_title_missing"},
		{"kind unknown", strings.Replace(validHTTP, "kind: http", "kind: graphql", 1), "invariant_kind_invalid"},
		{"origin kind", strings.Replace(validHTTP, "kind: vulnerability", "kind: hunch", 1), "invariant_origin_invalid"},
		{"origin ref", strings.Replace(validHTTP, "ref: VULN-001", `ref: ""`, 1), "invariant_origin_invalid"},
		{"request missing", strings.Replace(validHTTP, "request: {method: GET, path: /admin}\n", "", 1), "invariant_field_missing"},
		{"burst missing", strings.Replace(validRateLimit, "burst: 8\n", "", 1), "invariant_field_missing"},
		{"size missing", strings.Replace(validSizeLimit, "size_bytes: 26214401\n", "", 1), "invariant_field_missing"},
		{"include missing", strings.Replace(validSource, `include: ["apps/**/*.tsx"]`+"\n", "", 1), "invariant_field_missing"},
		{"pattern and require missing", strings.Replace(validSource, "pattern: 'dangerouslySetInnerHTML'\n", "", 1), "invariant_field_missing"},
		{"run missing", strings.Replace(validCommand, "run: 'echo 0'\n", "", 1), "invariant_field_missing"},
		{"foreign field", validHTTP + "burst: 3\n", "invariant_field_foreign"},
		{"foreign run on source", validSource + "run: 'true'\n", "invariant_field_foreign"},
		{"pattern and require", validSource + "require: 'x'\n", "invariant_field_foreign"},
		{"size_limit body", strings.Replace(validSizeLimit, "request: {path: /api/upload}", "request: {path: /api/upload, body: x}", 1), "invariant_field_foreign"},
		{"path without slash", strings.Replace(validHTTP, "path: /admin", "path: admin", 1), "invariant_field_invalid"},
		{"window out of range", strings.Replace(validRateLimit, "window_sec: 60", "window_sec: 0", 1), "invariant_field_invalid"},
		{"size out of range", strings.Replace(validSizeLimit, "size_bytes: 26214401", "size_bytes: 104857601", 1), "invariant_field_invalid"},
		{"timeout out of range", strings.Replace(validCommand, "timeout_sec: 5", "timeout_sec: 0", 1), "invariant_field_invalid"},
		{"empty glob", strings.Replace(validSource, `exclude: ["**/*.test.tsx"]`, `exclude: [""]`, 1), "invariant_field_invalid"},
		{"absolute glob", strings.Replace(validSource, `"apps/**/*.tsx"`, `"/etc/*"`, 1), "invariant_field_invalid"},
		{"burst zero", strings.Replace(validRateLimit, "burst: 8", "burst: 0", 1), "invariant_burst_out_of_range"},
		{"burst above cap", strings.Replace(validRateLimit, "burst: 8", "burst: 51", 1), "invariant_burst_out_of_range"},
		{"http no expectation", strings.Replace(validHTTP, "expect: {status_in: [403, 404], header_absent: [x-powered-by]}", "expect: {}", 1), "invariant_expect_missing"},
		{"rate_limit no throttled_within", strings.Replace(validRateLimit, "throttled_within: 6, ", "", 1), "invariant_expect_missing"},
		{"pattern without matches", strings.Replace(validSource, "expect: {matches: 0}", "expect: {}", 1), "invariant_expect_missing"},
		{"require without every_file_matches", strings.Replace(strings.Replace(validSource, "pattern:", "require:", 1), "expect: {matches: 0}", "expect: {}", 1), "invariant_expect_missing"},
		{"http expect on rate_limit", strings.Replace(validRateLimit, "retry_after_header: true", "status: 429", 1), "invariant_expect_foreign"},
		{"stdout on http", strings.Replace(validHTTP, "header_absent: [x-powered-by]", "stdout_equals: x", 1), "invariant_expect_foreign"},
		{"every_file_matches with pattern", strings.Replace(validSource, "expect: {matches: 0}", "expect: {matches: 0, every_file_matches: true}", 1), "invariant_expect_foreign"},
		{"throttled_within above burst", strings.Replace(validRateLimit, "throttled_within: 6", "throttled_within: 9", 1), "invariant_expect_invalid"},
		{"status out of range", strings.Replace(validHTTP, "status_in: [403, 404]", "status_in: [4040]", 1), "invariant_expect_invalid"},
		{"every_file_matches false", strings.Replace(strings.Replace(validSource, "pattern:", "require:", 1), "expect: {matches: 0}", "expect: {every_file_matches: false}", 1), "invariant_expect_invalid"},
		{"pattern regex", strings.Replace(validSource, "'dangerouslySetInnerHTML'", "'(unclosed'", 1), "invariant_regex_invalid"},
		{"header regex", strings.Replace(validHTTP, "header_absent: [x-powered-by]", `header_matches: {x-frame-options: "[z-a]"}`, 1), "invariant_regex_invalid"},
		{"stdout regex", strings.Replace(validCommand, `"^0$"`, `"(?<bad>"`, 1), "invariant_regex_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invs := loadValid(t, map[string]string{"inv.yaml": tc.yaml})
			issues := Validate(invs, ".", nil)
			if !hasCode(issues, tc.code) {
				t.Fatalf("expected %s, got %v", tc.code, codes(issues))
			}
			for _, issue := range issues {
				if issue.Severity != SeverityError || !strings.HasSuffix(issue.Path, "inv.yaml") || issue.Message == "" {
					t.Fatalf("issue missing severity, path, or message: %+v", issue)
				}
			}
		})
	}
}

func TestValidateDuplicateIDAcrossFiles(t *testing.T) {
	invs := loadValid(t, map[string]string{"a.yaml": validHTTP, "b.yaml": validHTTP})
	issues := Validate(invs, ".", nil)
	if len(issues) != 1 || issues[0].Code != "invariant_id_duplicate" {
		t.Fatalf("expected one duplicate issue, got %+v", issues)
	}
	if !strings.HasSuffix(issues[0].Path, "b.yaml") || !strings.Contains(issues[0].Message, "a.yaml") {
		t.Fatalf("expected the issue on b.yaml naming a.yaml, got %+v", issues[0])
	}
}

func TestValidateSurfaceAgainstKnownSurfaces(t *testing.T) {
	invs := loadValid(t, map[string]string{"rate.yaml": validRateLimit, "http.yaml": validHTTP})
	if issues := Validate(invs, ".", nil); len(issues) != 0 {
		t.Fatalf("nil known surfaces should skip the check, got %+v", issues)
	}
	if issues := Validate(invs, ".", []string{"SURF-001"}); len(issues) != 0 {
		t.Fatalf("a known surface should pass, got %+v", issues)
	}
	issues := Validate(invs, ".", []string{})
	if len(issues) != 1 || issues[0].Code != "invariant_surface_unknown" || !strings.HasSuffix(issues[0].Path, "rate.yaml") {
		t.Fatalf("expected one surface issue on rate.yaml (http.yaml names no surface), got %+v", issues)
	}
}

func TestValidateSortsByPathThenCode(t *testing.T) {
	bad := strings.Replace(strings.Replace(validHTTP, "INV-001", "bad", 1), "kind: vulnerability", "kind: hunch", 1)
	invs := loadValid(t, map[string]string{"b.yaml": bad, "a.yaml": strings.Replace(bad, "path: /admin", "path: admin", 1)})
	issues := Validate(invs, ".", nil)
	for i := 1; i < len(issues); i++ {
		prev, cur := issues[i-1], issues[i]
		if prev.Path > cur.Path || (prev.Path == cur.Path && prev.Code > cur.Code) {
			t.Fatalf("issues not sorted by path then code: %+v", issues)
		}
	}
	if len(issues) != 5 {
		t.Fatalf("expected 3 issues on a.yaml and 2 on b.yaml, got %+v", issues)
	}
}

func TestResolveSurfaces(t *testing.T) {
	source := t.TempDir()
	if ids, err := ResolveSurfaces(source, ""); err != nil || ids != nil {
		t.Fatalf("no map should give nil, got %v %v", ids, err)
	}
	mapYAML := "version: 1\nsurfaces:\n  - id: SURF-001\n    kind: route\n  - id: SURF-002\n"
	if err := os.MkdirAll(filepath.Join(source, ".ensphere"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, DefaultSurfaceMap), []byte(mapYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	ids, err := ResolveSurfaces(source, "")
	if err != nil || len(ids) != 2 || ids[1] != "SURF-002" {
		t.Fatalf("expected the default map's two ids, got %v %v", ids, err)
	}
	other := filepath.Join(t.TempDir(), "map.yaml")
	if err := os.WriteFile(other, []byte("surfaces: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ids, err = ResolveSurfaces(source, other)
	if err != nil || ids == nil || len(ids) != 0 {
		t.Fatalf("an explicit empty map should give an empty non-nil list, got %v %v", ids, err)
	}
	if _, err := ResolveSurfaces(source, filepath.Join(source, "missing.yaml")); err == nil {
		t.Fatal("expected an error for a missing explicit map")
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, rel string
		want         bool
	}{
		{"apps/**/routes/api/**/*.ts", "apps/web/routes/api/users/list.ts", true},
		{"apps/**/routes/api/**/*.ts", "apps/routes/api/list.ts", true},
		{"apps/**/routes/api/**/*.ts", "apps/web/routes/list.ts", false},
		{"**/*.test.ts", "a.test.ts", true},
		{"**/*.test.ts", "src/deep/a.test.ts", true},
		{"src/*.go", "src/sub/a.go", false},
		{"**", "anything/at/all", true},
		{"src/*.go", "src/a.go", true},
	}
	for _, tc := range cases {
		if got := matchGlob(tc.pattern, tc.rel); got != tc.want {
			t.Fatalf("matchGlob(%q, %q) = %t, want %t", tc.pattern, tc.rel, got, tc.want)
		}
	}
}
