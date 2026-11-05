package invariants

import (
	"regexp"
	"sort"
)

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// substituter replaces ${VAR} references and records every variable that is
// unset or empty, so the caller can report them all at once.
type substituter struct {
	getenv  func(string) string
	missing map[string]bool
}

func (s *substituter) text(in string) string {
	return s.replace(in, func(v string) string { return v })
}

// regex substitutes into a regular expression, quoting each value so it
// matches literally.
func (s *substituter) regex(in string) string {
	return s.replace(in, regexp.QuoteMeta)
}

func (s *substituter) replace(in string, quote func(string) string) string {
	return envRef.ReplaceAllStringFunc(in, func(ref string) string {
		name := envRef.FindStringSubmatch(ref)[1]
		value := s.getenv(name)
		if value == "" {
			s.missing[name] = true
			return ""
		}
		return quote(value)
	})
}

func (s *substituter) missingNames() []string {
	names := make([]string, 0, len(s.missing))
	for name := range s.missing {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// substitute returns a copy of inv with ${VAR} replaced in the request, run,
// and expect strings, and the names of variables that were not set.
func substitute(inv Invariant, getenv func(string) string) (Invariant, []string) {
	s := &substituter{getenv: getenv, missing: map[string]bool{}}
	out := inv
	if inv.Request != nil {
		req := *inv.Request
		req.Method = s.text(req.Method)
		req.Path = s.text(req.Path)
		req.Body = s.text(req.Body)
		if inv.Request.Headers != nil {
			req.Headers = make(map[string]string, len(inv.Request.Headers))
			for k, v := range inv.Request.Headers {
				req.Headers[s.text(k)] = s.text(v)
			}
		}
		out.Request = &req
	}
	out.Run = s.text(inv.Run)

	e := inv.Expect
	e.BodyContains = s.text(e.BodyContains)
	e.BodyNotContains = s.text(e.BodyNotContains)
	e.StdoutEquals = s.text(e.StdoutEquals)
	e.StdoutMatches = s.regex(e.StdoutMatches)
	if inv.Expect.HeaderMatches != nil {
		e.HeaderMatches = make(map[string]string, len(inv.Expect.HeaderMatches))
		for k, v := range inv.Expect.HeaderMatches {
			e.HeaderMatches[k] = s.regex(v)
		}
	}
	out.Expect = e
	return out, s.missingNames()
}
