package scan

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/srank-org/ensphere/internal/evidence"
	"github.com/srank-org/ensphere/internal/sinks"
)

const (
	AnalysisDepthPatternMatch = "pattern_match"
	MaxContextLines           = 5
)

// DefaultExcludes are directories always skipped during scanning.
var DefaultExcludes = []string{
	".git", "node_modules", "vendor", "dist", "build",
	".next", "__pycache__", ".venv", "target", "bin", "obj",
}

// compiledPattern holds a pre-compiled regex with metadata.
type compiledPattern struct {
	re         *regexp.Regexp
	name       string
	category   string
	extensions map[string]bool
	filenames  map[string]bool
}

// RunScan scans a directory for sink patterns and returns results.
func RunScan(cfg ScanConfig) (*ScanResult, error) {
	start := time.Now()
	if cfg.ContextLines < 0 || cfg.ContextLines > MaxContextLines {
		return nil, fmt.Errorf("context lines must be between 0 and %d", MaxContextLines)
	}

	allPatterns, err := sinks.AllPatterns()
	if err != nil {
		return nil, fmt.Errorf("load sink patterns: %w", err)
	}

	categoryFilter := make(map[string]bool)
	for _, c := range cfg.Categories {
		categoryFilter[c] = true
	}

	var compiled []compiledPattern
	extUnion := make(map[string]bool)
	filenameUnion := make(map[string]bool)

	for cat, patterns := range allPatterns {
		if len(categoryFilter) > 0 && !categoryFilter[cat] {
			continue
		}
		for _, p := range patterns {
			re, err := regexp.Compile(p.Pattern)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: skip invalid pattern %q in %s: %v\n", p.Name, cat, err)
				continue
			}
			exts := make(map[string]bool)
			for _, ext := range p.Extensions {
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				exts[ext] = true
				extUnion[ext] = true
			}
			fnames := make(map[string]bool)
			for _, fn := range p.Filenames {
				fnames[fn] = true
				filenameUnion[fn] = true
			}
			compiled = append(compiled, compiledPattern{
				re:         re,
				name:       p.Name,
				category:   cat,
				extensions: exts,
				filenames:  fnames,
			})
		}
	}

	var absenceRules []compiledAbsenceRule
	if cfg.AbsenceCheck {
		absRules, absErr := sinks.AllAbsenceRules()
		if absErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not load absence rules: %v\n", absErr)
		} else {
			for cat, rules := range absRules {
				for _, r := range rules {
					re, err := regexp.Compile(r.Pattern)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Warning: skip invalid absence pattern %q: %v\n", r.Name, err)
						continue
					}
					secRe, err := regexp.Compile(r.SecurityPattern)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Warning: skip invalid security pattern %q: %v\n", r.Name, err)
						continue
					}
					exts := make(map[string]bool)
					for _, ext := range r.Extensions {
						if !strings.HasPrefix(ext, ".") {
							ext = "." + ext
						}
						exts[ext] = true
						extUnion[ext] = true
					}
					absenceRules = append(absenceRules, compiledAbsenceRule{
						re:         re,
						securityRe: secRe,
						name:       r.Name,
						category:   cat,
						window:     r.Window,
						extensions: exts,
					})
				}
			}
		}
	}

	if len(compiled) == 0 && len(absenceRules) == 0 {
		return &ScanResult{
			Directory:     cfg.Directory,
			AnalysisDepth: AnalysisDepthPatternMatch,
			Duration:      time.Since(start).Round(time.Millisecond).String(),
			Matches:       []ScanMatch{},
			Summary:       []CategoryHit{},
		}, nil
	}

	// Override extensions if specified (merge with absence rule extensions)
	if len(cfg.Extensions) > 0 {
		overrideExts := make(map[string]bool)
		absExts := make(map[string]bool)
		for _, r := range absenceRules {
			for ext := range r.extensions {
				absExts[ext] = true
			}
		}
		extUnion = make(map[string]bool)
		for _, ext := range cfg.Extensions {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			extUnion[ext] = true
			overrideExts[ext] = true
		}
		for ext := range absExts {
			extUnion[ext] = true
		}
		for i := range compiled {
			compiled[i].extensions = overrideExts
			compiled[i].filenames = nil
		}
	}

	// Build exclude set for default directory names (fast exact match)
	excludeSet := make(map[string]bool)
	for _, d := range DefaultExcludes {
		excludeSet[d] = true
	}

	var files []string
	err = filepath.WalkDir(cfg.Directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible
		}
		relPath, _ := filepath.Rel(cfg.Directory, path)
		if d.IsDir() {
			if excludeSet[d.Name()] {
				return filepath.SkipDir
			}
			for _, pattern := range cfg.Excludes {
				if matchExclude(pattern, d.Name(), relPath) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		for _, pattern := range cfg.Excludes {
			if matchExclude(pattern, filepath.Base(path), relPath) {
				return nil
			}
		}
		ext := filepath.Ext(path)
		if extUnion[ext] || filenameUnion[filepath.Base(path)] {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8
	}
	if numWorkers < 1 {
		numWorkers = 1
	}

	fileCh := make(chan string, len(files))
	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)

	var mu sync.Mutex
	var allMatches []ScanMatch

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileCh {
				matches := scanFile(path, cfg.Directory, compiled, cfg.ContextLines)
				if len(matches) > 0 {
					mu.Lock()
					allMatches = append(allMatches, matches...)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	if cfg.AbsenceCheck && len(absenceRules) > 0 {
		for _, path := range files {
			absMatches := scanFileAbsence(path, cfg.Directory, absenceRules, cfg.ContextLines)
			allMatches = append(allMatches, absMatches...)
		}
	}

	sort.Slice(allMatches, func(i, j int) bool {
		if allMatches[i].File != allMatches[j].File {
			return allMatches[i].File < allMatches[j].File
		}
		return allMatches[i].Line < allMatches[j].Line
	})

	catCounts := make(map[string]int)
	for _, m := range allMatches {
		catCounts[m.Category]++
	}

	var summary []CategoryHit
	for cat, count := range catCounts {
		summary = append(summary, CategoryHit{
			Category: cat,
			Count:    count,
		})
	}
	sort.Slice(summary, func(i, j int) bool {
		return summary[i].Category < summary[j].Category
	})

	if allMatches == nil {
		allMatches = []ScanMatch{}
	}
	if summary == nil {
		summary = []CategoryHit{}
	}

	return &ScanResult{
		Directory:     cfg.Directory,
		AnalysisDepth: AnalysisDepthPatternMatch,
		FilesScanned:  len(files),
		TotalMatches:  len(allMatches),
		Duration:      time.Since(start).Round(time.Millisecond).String(),
		Matches:       allMatches,
		Summary:       summary,
	}, nil
}

// scanFile scans a single file against applicable patterns.
func scanFile(path, baseDir string, patterns []compiledPattern, contextLines int) []ScanMatch {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	ext := filepath.Ext(path)
	relPath, err := filepath.Rel(baseDir, path)
	if err != nil {
		relPath = path
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024) // 1MB max line
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	var matches []ScanMatch
	for lineIdx, line := range lines {
		baseName := filepath.Base(path)
		for _, p := range patterns {
			if len(p.extensions) > 0 && !p.extensions[ext] && !p.filenames[baseName] {
				continue
			}
			if len(p.extensions) == 0 && len(p.filenames) > 0 && !p.filenames[baseName] {
				continue
			}
			loc := p.re.FindStringIndex(line)
			if loc == nil {
				continue
			}

			matched := redactedSnippet(line[loc[0]:loc[1]])
			context := redactedContext(lines, lineIdx, contextLines)

			matches = append(matches, ScanMatch{
				File:        relPath,
				Line:        lineIdx + 1,
				Column:      loc[0] + 1,
				PatternName: p.name,
				Category:    p.category,
				MatchedText: matched,
				Context:     context,
			})
		}
	}

	return matches
}

// compiledAbsenceRule holds a pre-compiled absence rule.
type compiledAbsenceRule struct {
	re         *regexp.Regexp
	securityRe *regexp.Regexp
	name       string
	category   string
	window     int
	extensions map[string]bool
}

// scanFileAbsence scans a file for resource declarations missing security configuration.
func scanFileAbsence(path, baseDir string, rules []compiledAbsenceRule, contextLines int) []ScanMatch {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	ext := filepath.Ext(path)
	relPath, err := filepath.Rel(baseDir, path)
	if err != nil {
		relPath = path
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	var matches []ScanMatch
	for lineIdx, line := range lines {
		for _, r := range rules {
			if len(r.extensions) > 0 && !r.extensions[ext] {
				continue
			}
			if !r.re.MatchString(line) {
				continue
			}
			// Found resource declaration — search next N lines for security pattern
			windowEnd := lineIdx + r.window
			if windowEnd > len(lines) {
				windowEnd = len(lines)
			}
			found := false
			for i := lineIdx; i < windowEnd; i++ {
				if r.securityRe.MatchString(lines[i]) {
					found = true
					break
				}
			}
			if !found {
				matched := redactedSnippet(line)
				context := redactedContext(lines, lineIdx, contextLines)
				matches = append(matches, ScanMatch{
					File:        relPath,
					Line:        lineIdx + 1,
					Column:      1,
					PatternName: r.name,
					Category:    r.category,
					MatchedText: matched,
					Context:     context,
					MatchType:   "absence",
				})
			}
		}
	}
	return matches
}

func redactedSnippet(s string) string {
	if len(s) > 100 {
		s = s[:100]
	}
	return evidence.RedactSecrets(s)
}

func redactedContext(lines []string, lineIdx, contextLines int) string {
	ctxStart := lineIdx - contextLines
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := lineIdx + contextLines + 1
	if ctxEnd > len(lines) {
		ctxEnd = len(lines)
	}
	return evidence.RedactSecrets(strings.Join(lines[ctxStart:ctxEnd], "\n"))
}

// matchExclude checks if name or relPath matches an exclude pattern.
// Supports ** for recursive directory matching (e.g. "test/**").
func matchExclude(pattern, name, relPath string) bool {
	// Handle "prefix/**" — match the prefix directory and anything under it
	if strings.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3] // strip "/**"
		if name == prefix || relPath == prefix {
			return true
		}
		if strings.HasPrefix(relPath, prefix+string(filepath.Separator)) {
			return true
		}
		return false
	}
	// Handle "**/suffix" — match name at any depth
	if strings.HasPrefix(pattern, "**/") {
		suffix := pattern[3:] // strip "**/"
		if name == suffix || strings.HasSuffix(relPath, string(filepath.Separator)+suffix) {
			return true
		}
		return false
	}
	if matched, _ := filepath.Match(pattern, name); matched {
		return true
	}
	if matched, _ := filepath.Match(pattern, relPath); matched {
		return true
	}
	return false
}
