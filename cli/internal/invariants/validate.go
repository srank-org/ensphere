package invariants

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	maxBurst      = 50
	maxWindowSec  = 3600
	maxTimeoutSec = 600
	maxSizeBytes  = 104857600
)

var idPattern = regexp.MustCompile(`^INV-[0-9]{3,}$`)

var originKinds = map[string]bool{
	"vulnerability":   true,
	"missing_control": true,
	"tested_defense":  true,
}

// allowedFields lists the kind-specific fields each kind may carry.
var allowedFields = map[string]map[string]bool{
	KindHTTP:      {"request": true, "timeout_sec": true},
	KindRateLimit: {"request": true, "burst": true, "window_sec": true},
	KindSizeLimit: {"request": true, "size_bytes": true, "field": true},
	KindSource:    {"include": true, "exclude": true, "pattern": true, "require": true},
	KindCommand:   {"run": true, "timeout_sec": true},
}

// allowedExpect lists the expectation fields each kind may carry.
var allowedExpect = map[string]map[string]bool{
	KindHTTP: {"status": true, "status_in": true, "header_present": true, "header_absent": true,
		"header_matches": true, "body_contains": true, "body_not_contains": true},
	KindRateLimit: {"throttled_within": true, "retry_after_header": true},
	KindSizeLimit: {"rejected": true, "status_in": true},
	KindSource:    {"matches": true, "every_file_matches": true},
	KindCommand:   {"exit_code": true, "stdout_equals": true, "stdout_matches": true},
}

// Validate checks every invariant against the schema and returns the issues
// sorted by path then code. knownSurfaces nil turns the surface check off.
func Validate(invs []Invariant, sourcePath string, knownSurfaces []string) []Issue {
	var issues []Issue
	seen := make(map[string]string)
	var surfaces map[string]bool
	if knownSurfaces != nil {
		surfaces = make(map[string]bool, len(knownSurfaces))
		for _, id := range knownSurfaces {
			surfaces[id] = true
		}
	}

	for _, inv := range invs {
		add := func(code, format string, args ...any) {
			issues = append(issues, newIssue(code, inv.Path, fmt.Sprintf(format, args...)))
		}

		if !idPattern.MatchString(inv.ID) {
			add("invariant_id_invalid", "id %q must match %s", inv.ID, idPattern.String())
		} else if first, ok := seen[inv.ID]; ok {
			add("invariant_id_duplicate", "id %s is already declared in %s", inv.ID, first)
		} else {
			seen[inv.ID] = inv.Path
		}
		if strings.TrimSpace(inv.Title) == "" {
			add("invariant_title_missing", "title is empty")
		}
		if !originKinds[inv.Origin.Kind] || strings.TrimSpace(inv.Origin.Ref) == "" {
			add("invariant_origin_invalid", "origin.kind must be vulnerability, missing_control, or tested_defense and origin.ref must be set (got kind %q, ref %q)", inv.Origin.Kind, inv.Origin.Ref)
		}
		if surfaces != nil && inv.Surface != "" && !surfaces[inv.Surface] {
			add("invariant_surface_unknown", "surface %s is not in the system map", inv.Surface)
		}

		allowed, ok := allowedFields[inv.Kind]
		if !ok {
			add("invariant_kind_invalid", "kind %q must be http, rate_limit, size_limit, source, or command", inv.Kind)
			continue
		}
		for _, name := range presentFields(inv) {
			if !allowed[name] {
				add("invariant_field_foreign", "%s does not apply to kind %s", name, inv.Kind)
			}
		}
		for _, name := range presentExpect(inv.Expect) {
			if !allowedExpect[inv.Kind][name] {
				add("invariant_expect_foreign", "expect.%s does not apply to kind %s", name, inv.Kind)
			}
		}

		switch inv.Kind {
		case KindHTTP:
			validateRequest(inv, add)
			validateTimeout(inv, add)
			e := inv.Expect
			if e.Status == nil && len(e.StatusIn) == 0 && len(e.HeaderPresent) == 0 && len(e.HeaderAbsent) == 0 &&
				len(e.HeaderMatches) == 0 && e.BodyContains == "" && e.BodyNotContains == "" {
				add("invariant_expect_missing", "kind http needs at least one expectation")
			}
			validateStatuses(e, add)
			for _, name := range sortedKeys(e.HeaderMatches) {
				validateRegex("expect.header_matches."+name, e.HeaderMatches[name], add)
			}
		case KindRateLimit:
			validateRequest(inv, add)
			if inv.Burst == nil {
				add("invariant_field_missing", "kind rate_limit needs burst")
			} else if *inv.Burst < 1 || *inv.Burst > maxBurst {
				add("invariant_burst_out_of_range", "burst %d must be between 1 and %d", *inv.Burst, maxBurst)
			}
			if inv.WindowSec != nil && (*inv.WindowSec < 1 || *inv.WindowSec > maxWindowSec) {
				add("invariant_field_invalid", "window_sec %d must be between 1 and %d", *inv.WindowSec, maxWindowSec)
			}
			if inv.Expect.ThrottledWithin == nil {
				add("invariant_expect_missing", "kind rate_limit needs expect.throttled_within")
			} else if n := *inv.Expect.ThrottledWithin; n < 1 || (inv.Burst != nil && n > *inv.Burst) {
				add("invariant_expect_invalid", "expect.throttled_within %d must be between 1 and burst", n)
			}
		case KindSizeLimit:
			validateRequest(inv, add)
			if inv.Request != nil && inv.Request.Body != "" {
				add("invariant_field_foreign", "request.body does not apply to kind size_limit; the body is a generated multipart file")
			}
			if inv.SizeBytes == nil {
				add("invariant_field_missing", "kind size_limit needs size_bytes")
			} else if *inv.SizeBytes < 1 || *inv.SizeBytes > maxSizeBytes {
				add("invariant_field_invalid", "size_bytes %d must be between 1 and %d", *inv.SizeBytes, maxSizeBytes)
			}
			validateStatuses(inv.Expect, add)
		case KindSource:
			if len(inv.Include) == 0 {
				add("invariant_field_missing", "kind source needs include globs")
			}
			for _, glob := range append(append([]string{}, inv.Include...), inv.Exclude...) {
				if strings.TrimSpace(glob) == "" || strings.HasPrefix(glob, "/") || !validGlob(glob) {
					add("invariant_field_invalid", "glob %q must be a non-empty pattern relative to the source path", glob)
				}
			}
			switch {
			case inv.Pattern == "" && inv.Require == "":
				add("invariant_field_missing", "kind source needs pattern or require")
			case inv.Pattern != "" && inv.Require != "":
				add("invariant_field_foreign", "kind source takes pattern or require, not both")
			case inv.Pattern != "":
				validateRegex("pattern", inv.Pattern, add)
				if inv.Expect.Matches == nil {
					add("invariant_expect_missing", "pattern needs expect.matches")
				} else if *inv.Expect.Matches < 0 {
					add("invariant_expect_invalid", "expect.matches %d must not be negative", *inv.Expect.Matches)
				}
				if inv.Expect.EveryFileMatches != nil {
					add("invariant_expect_foreign", "expect.every_file_matches goes with require, not pattern")
				}
			default:
				validateRegex("require", inv.Require, add)
				if inv.Expect.EveryFileMatches == nil {
					add("invariant_expect_missing", "require needs expect.every_file_matches: true")
				} else if !*inv.Expect.EveryFileMatches {
					add("invariant_expect_invalid", "expect.every_file_matches must be true")
				}
				if inv.Expect.Matches != nil {
					add("invariant_expect_foreign", "expect.matches goes with pattern, not require")
				}
			}
		case KindCommand:
			if strings.TrimSpace(inv.Run) == "" {
				add("invariant_field_missing", "kind command needs run")
			}
			validateTimeout(inv, add)
			if inv.Expect.StdoutMatches != "" {
				validateRegex("expect.stdout_matches", inv.Expect.StdoutMatches, add)
			}
		}
	}

	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Path != issues[j].Path {
			return issues[i].Path < issues[j].Path
		}
		return issues[i].Code < issues[j].Code
	})
	return issues
}

type addFunc func(code, format string, args ...any)

func validateRequest(inv Invariant, add addFunc) {
	if inv.Request == nil {
		add("invariant_field_missing", "kind %s needs request", inv.Kind)
		return
	}
	if !strings.HasPrefix(inv.Request.Path, "/") {
		add("invariant_field_invalid", "request.path %q must start with /", inv.Request.Path)
	}
	if strings.ContainsAny(inv.Request.Method, " \t\r\n") {
		add("invariant_field_invalid", "request.method %q must be a single token", inv.Request.Method)
	}
}

func validateTimeout(inv Invariant, add addFunc) {
	if inv.TimeoutSec != nil && (*inv.TimeoutSec < 1 || *inv.TimeoutSec > maxTimeoutSec) {
		add("invariant_field_invalid", "timeout_sec %d must be between 1 and %d", *inv.TimeoutSec, maxTimeoutSec)
	}
}

func validateStatuses(e Expect, add addFunc) {
	statuses := append([]int{}, e.StatusIn...)
	if e.Status != nil {
		statuses = append(statuses, *e.Status)
	}
	for _, code := range statuses {
		if code < 100 || code > 599 {
			add("invariant_expect_invalid", "status %d must be between 100 and 599", code)
		}
	}
}

func validateRegex(field, pattern string, add addFunc) {
	if _, err := regexp.Compile(pattern); err != nil {
		add("invariant_regex_invalid", "%s does not compile: %v", field, err)
	}
}

func presentFields(inv Invariant) []string {
	var names []string
	if inv.Request != nil {
		names = append(names, "request")
	}
	if inv.Burst != nil {
		names = append(names, "burst")
	}
	if inv.WindowSec != nil {
		names = append(names, "window_sec")
	}
	if inv.SizeBytes != nil {
		names = append(names, "size_bytes")
	}
	if inv.Field != "" {
		names = append(names, "field")
	}
	if inv.Include != nil {
		names = append(names, "include")
	}
	if inv.Exclude != nil {
		names = append(names, "exclude")
	}
	if inv.Pattern != "" {
		names = append(names, "pattern")
	}
	if inv.Require != "" {
		names = append(names, "require")
	}
	if inv.Run != "" {
		names = append(names, "run")
	}
	if inv.TimeoutSec != nil {
		names = append(names, "timeout_sec")
	}
	return names
}

func presentExpect(e Expect) []string {
	var names []string
	if e.Status != nil {
		names = append(names, "status")
	}
	if e.StatusIn != nil {
		names = append(names, "status_in")
	}
	if e.HeaderPresent != nil {
		names = append(names, "header_present")
	}
	if e.HeaderAbsent != nil {
		names = append(names, "header_absent")
	}
	if e.HeaderMatches != nil {
		names = append(names, "header_matches")
	}
	if e.BodyContains != "" {
		names = append(names, "body_contains")
	}
	if e.BodyNotContains != "" {
		names = append(names, "body_not_contains")
	}
	if e.ThrottledWithin != nil {
		names = append(names, "throttled_within")
	}
	if e.RetryAfterHeader {
		names = append(names, "retry_after_header")
	}
	if e.Rejected != nil {
		names = append(names, "rejected")
	}
	if e.Matches != nil {
		names = append(names, "matches")
	}
	if e.EveryFileMatches != nil {
		names = append(names, "every_file_matches")
	}
	if e.ExitCode != nil {
		names = append(names, "exit_code")
	}
	if e.StdoutEquals != "" {
		names = append(names, "stdout_equals")
	}
	if e.StdoutMatches != "" {
		names = append(names, "stdout_matches")
	}
	return names
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
