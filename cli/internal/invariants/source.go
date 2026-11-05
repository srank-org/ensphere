package invariants

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
)

const (
	maxSamples      = 20
	maxSnippetBytes = 200
)

// skippedDirs are never walked: version control, dependencies, and the
// assessment workspace.
var skippedDirs = map[string]bool{
	".git":             true,
	"node_modules":     true,
	"ensphere-pentest": true,
}

func runSource(inv Invariant, sourcePath string) outcome {
	expr := inv.Pattern
	if expr == "" {
		expr = inv.Require
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return errorOutcome("regex does not compile: %v", err)
	}
	files, err := sourceFiles(sourcePath, inv.Include, inv.Exclude)
	if err != nil {
		return errorOutcome("walk %s: %v", sourcePath, err)
	}

	measured := SourceMeasured{FilesScanned: len(files), Samples: []SourceSample{}}
	for _, rel := range files {
		content, err := os.ReadFile(filepath.Join(sourcePath, filepath.FromSlash(rel)))
		if err != nil {
			return errorOutcome("read %s: %v", rel, err)
		}
		locs := re.FindAllIndex(content, -1)
		if inv.Pattern != "" {
			measured.Matches += len(locs)
			for _, loc := range locs {
				if len(measured.Samples) == maxSamples {
					break
				}
				measured.Samples = append(measured.Samples, sampleAt(rel, content, loc[0]))
			}
			continue
		}
		if len(locs) > 0 {
			measured.Matches++
			continue
		}
		measured.FilesWithoutMatch++
		if len(measured.Samples) < maxSamples {
			measured.Samples = append(measured.Samples, SourceSample{File: rel})
		}
	}

	var check Check
	if inv.Pattern != "" {
		want := *inv.Expect.Matches
		check = Check{Check: fmt.Sprintf("matches %d (got %d in %d files)", want, measured.Matches, measured.FilesScanned), Held: measured.Matches == want}
	} else {
		check = Check{Check: fmt.Sprintf("every_file_matches (%d of %d files without a match)", measured.FilesWithoutMatch, measured.FilesScanned), Held: measured.FilesWithoutMatch == 0}
	}
	return fromChecks([]Check{check}, measured)
}

// sourceFiles returns the slash-separated paths under root, relative to it,
// that match an include glob and no exclude glob, in walk order.
func sourceFiles(root string, include, exclude []string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if matchesAny(include, rel) && !matchesAny(exclude, rel) {
			files = append(files, rel)
		}
		return nil
	})
	return files, err
}

func matchesAny(globs []string, rel string) bool {
	for _, glob := range globs {
		if matchGlob(glob, rel) {
			return true
		}
	}
	return false
}

func sampleAt(rel string, content []byte, offset int) SourceSample {
	line := bytes.Count(content[:offset], []byte("\n")) + 1
	start := bytes.LastIndexByte(content[:offset], '\n') + 1
	end := bytes.IndexByte(content[offset:], '\n')
	if end < 0 {
		end = len(content)
	} else {
		end += offset
	}
	snippet := strings.TrimSpace(string(content[start:end]))
	if len(snippet) > maxSnippetBytes {
		snippet = snippet[:maxSnippetBytes]
	}
	return SourceSample{File: rel, Line: line, Snippet: evidence.RedactSecrets(snippet)}
}
