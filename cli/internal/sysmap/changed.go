package sysmap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const gitTimeout = 30 * time.Second

// excludedPrefixes are Ensphere's own artifacts in the source tree: the map,
// its invariants, and the default assessment workspace. They change on every
// assessment by design, so counting them would cancel every delta skip.
var excludedPrefixes = []string{".ensphere/", "ensphere-pentest/"}

// ChangeSet is what changed in the source tree since a commit, joined to the
// surfaces that claim each file. It is the result of ensphere map changed.
type ChangeSet struct {
	Since                string           `json:"since" yaml:"since"`
	Head                 string           `json:"head" yaml:"head"`
	ChangedFiles         []string         `json:"changed_files" yaml:"changed_files"`
	ChangedSurfaces      []ChangedSurface `json:"changed_surfaces" yaml:"changed_surfaces"`
	UnmappedChangedFiles []string         `json:"unmapped_changed_files" yaml:"unmapped_changed_files"`
	MissingFiles         []MissingFile    `json:"missing_files" yaml:"missing_files"`
	SessionsAffected     []string         `json:"sessions_affected" yaml:"sessions_affected"`
}

type ChangedSurface struct {
	ID           string   `json:"id" yaml:"id"`
	Name         string   `json:"name" yaml:"name"`
	Kind         string   `json:"kind" yaml:"kind"`
	Sessions     []string `json:"sessions" yaml:"sessions"`
	ChangedFiles []string `json:"changed_files" yaml:"changed_files"`
}

// MissingFile is a file a surface claims that no longer exists.
type MissingFile struct {
	SurfaceID string `json:"surface_id" yaml:"surface_id"`
	File      string `json:"file" yaml:"file"`
}

// Changed compares the working tree at sourcePath with the commit since
// (m.ReconciledAt when since is empty). Changed files are those git diff
// reports against the working tree plus untracked files git does not
// ignore, relative to sourcePath, minus anything under excludedPrefixes. A
// file is claimed by a surface that lists it or a directory above it.
func Changed(m *Map, sourcePath, since string) (*ChangeSet, error) {
	since = strings.TrimSpace(since)
	if since == "" {
		since = strings.TrimSpace(m.ReconciledAt)
	}
	if since == "" {
		return nil, fmt.Errorf("no commit to compare against: pass --since or set reconciled_at in the system map")
	}
	if strings.HasPrefix(since, "-") {
		return nil, fmt.Errorf("commit %q must not start with '-'", since)
	}
	head, err := runGit(sourcePath, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	diff, err := runGit(sourcePath, "diff", "--name-only", "--no-renames", "--relative", "-z", since, "--")
	if err != nil {
		return nil, err
	}
	untracked, err := runGit(sourcePath, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	var changed []string
	for _, path := range uniqueSorted(append(splitNUL(diff), splitNUL(untracked)...)) {
		if !excluded(path) {
			changed = append(changed, path)
		}
	}
	if changed == nil {
		changed = []string{}
	}

	set := &ChangeSet{
		Since:                since,
		Head:                 strings.TrimSpace(head),
		ChangedFiles:         changed,
		ChangedSurfaces:      []ChangedSurface{},
		UnmappedChangedFiles: []string{},
		MissingFiles:         []MissingFile{},
		SessionsAffected:     []string{},
	}
	claimed := map[string]bool{}
	var sessions []string
	for _, surface := range m.Surfaces {
		id := strings.TrimSpace(surface.ID)
		var hits []string
		for _, file := range surface.Files {
			file = normalize(file)
			if file == "" {
				continue
			}
			for _, path := range changed {
				if path == file || strings.HasPrefix(path, file+"/") {
					hits = append(hits, path)
					claimed[path] = true
				}
			}
			if _, err := os.Stat(filepath.Join(sourcePath, filepath.FromSlash(file))); os.IsNotExist(err) {
				set.MissingFiles = append(set.MissingFiles, MissingFile{SurfaceID: id, File: file})
			}
		}
		if len(hits) == 0 {
			continue
		}
		surfaceSessions := uniqueSorted(surface.Sessions)
		sessions = append(sessions, surfaceSessions...)
		set.ChangedSurfaces = append(set.ChangedSurfaces, ChangedSurface{
			ID:           id,
			Name:         strings.TrimSpace(surface.Name),
			Kind:         strings.TrimSpace(surface.Kind),
			Sessions:     surfaceSessions,
			ChangedFiles: uniqueSorted(hits),
		})
	}
	for _, path := range changed {
		if !claimed[path] {
			set.UnmappedChangedFiles = append(set.UnmappedChangedFiles, path)
		}
	}
	set.SessionsAffected = uniqueSorted(sessions)
	return set, nil
}

func excluded(path string) bool {
	for _, prefix := range excludedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func runGit(dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func splitNUL(out string) []string {
	var paths []string
	for _, path := range strings.Split(out, "\x00") {
		if path = normalize(path); path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func normalize(path string) string {
	path = strings.TrimSpace(filepath.ToSlash(path))
	path = strings.TrimPrefix(path, "./")
	return strings.TrimSuffix(path, "/")
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
