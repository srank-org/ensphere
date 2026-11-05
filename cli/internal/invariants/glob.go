package invariants

import (
	"path"
	"strings"
)

// matchGlob reports whether the slash-separated relative path rel matches
// pattern, where a "**" segment matches zero or more path segments and every
// other segment follows path.Match.
func matchGlob(pattern, rel string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(rel, "/"))
}

func matchSegments(pattern, parts []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			rest := pattern[1:]
			for i := 0; i <= len(parts); i++ {
				if matchSegments(rest, parts[i:]) {
					return true
				}
			}
			return false
		}
		if len(parts) == 0 {
			return false
		}
		ok, err := path.Match(pattern[0], parts[0])
		if err != nil || !ok {
			return false
		}
		pattern, parts = pattern[1:], parts[1:]
	}
	return len(parts) == 0
}

func validGlob(pattern string) bool {
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, ""); err != nil {
			return false
		}
	}
	return true
}
