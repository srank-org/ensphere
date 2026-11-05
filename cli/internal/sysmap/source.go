package sysmap

import (
	"strings"
)

// SourceState is what git says about the source tree: the commit it is at
// and the files that differ from it. Ensphere's own artifacts and any extra
// prefixes the caller names are left out, as in Changed.
type SourceState struct {
	// Git is false when sourcePath is not inside a git repository; the other
	// fields are then empty.
	Git bool `json:"git" yaml:"git"`
	// Commit is HEAD.
	Commit string `json:"commit,omitempty" yaml:"commit,omitempty"`
	// Modified lists tracked files whose working-tree content differs from
	// HEAD, including staged changes and deletions.
	Modified []string `json:"modified" yaml:"modified"`
	// Untracked lists files git does not track and does not ignore.
	Untracked []string `json:"untracked" yaml:"untracked"`
}

// Clean reports whether no tracked file differs from the commit. Untracked
// files do not count: they are not part of the commit the tree describes.
func (s *SourceState) Clean() bool { return len(s.Modified) == 0 }

// ReadSourceState inspects sourcePath with git. A path outside any repository
// yields Git false and no error; a git failure inside one is an error.
func ReadSourceState(sourcePath string, exclude ...string) (*SourceState, error) {
	state := &SourceState{Modified: []string{}, Untracked: []string{}}
	inside, err := runGit(sourcePath, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(inside) != "true" {
		return state, nil
	}
	state.Git = true
	head, err := runGit(sourcePath, "rev-parse", "HEAD")
	if err != nil {
		// A repository with no commit yet has nothing to describe.
		return state, nil
	}
	state.Commit = strings.TrimSpace(head)
	modified, err := runGit(sourcePath, "diff", "--name-only", "--no-renames", "--relative", "-z", "HEAD", "--")
	if err != nil {
		return nil, err
	}
	untracked, err := runGit(sourcePath, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	skip := func(path string) bool {
		if excluded(path) {
			return true
		}
		for _, prefix := range exclude {
			prefix = normalize(prefix)
			if prefix != "" && (path == prefix || strings.HasPrefix(path, prefix+"/")) {
				return true
			}
		}
		return false
	}
	for _, path := range uniqueSorted(splitNUL(modified)) {
		if !skip(path) {
			state.Modified = append(state.Modified, path)
		}
	}
	for _, path := range uniqueSorted(splitNUL(untracked)) {
		if !skip(path) {
			state.Untracked = append(state.Untracked, path)
		}
	}
	return state, nil
}
