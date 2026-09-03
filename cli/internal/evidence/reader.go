package evidence

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// EntryFilter specifies criteria for filtering evidence entries.
type EntryFilter struct {
	ID         string
	Result     string
	ProbeType  string
	FindingRef string
	After      string // RFC3339 timestamp
	Before     string // RFC3339 timestamp
	Limit      int
}

// ReadAll reads all entries from a JSONL evidence file.
// Returns valid entries and count of malformed lines that were skipped.
func ReadAll(path string) ([]Entry, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open evidence file: %w", err)
	}
	defer f.Close()

	var entries []Entry
	skipped := 0
	lineNum := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping malformed evidence line %d: %v\n", lineNum, err)
			skipped++
			continue
		}
		if _, ok := parseEvidenceID(e.ID); !ok {
			return nil, skipped, fmt.Errorf("invalid evidence ID %q on line %d", e.ID, lineNum)
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, skipped, fmt.Errorf("read evidence file: %w", err)
	}
	return entries, skipped, nil
}

// ReadFiltered reads entries matching the given filter.
func ReadFiltered(path string, filter EntryFilter) ([]Entry, error) {
	all, _, err := ReadAll(path)
	if err != nil {
		return nil, err
	}

	var afterTime, beforeTime time.Time
	if filter.After != "" {
		afterTime, _ = time.Parse(time.RFC3339, filter.After)
	}
	if filter.Before != "" {
		beforeTime, _ = time.Parse(time.RFC3339, filter.Before)
	}

	var result []Entry
	for _, e := range all {
		if filter.ID != "" && e.ID != filter.ID {
			continue
		}
		if filter.Result != "" && e.Result != filter.Result {
			continue
		}
		if filter.ProbeType != "" && e.ProbeType != filter.ProbeType {
			continue
		}
		if filter.FindingRef != "" && e.FindingRef != filter.FindingRef {
			continue
		}
		if !afterTime.IsZero() {
			t, err := time.Parse(time.RFC3339, e.Timestamp)
			if err == nil && t.Before(afterTime) {
				continue
			}
		}
		if !beforeTime.IsZero() {
			t, err := time.Parse(time.RFC3339, e.Timestamp)
			if err == nil && t.After(beforeTime) {
				continue
			}
		}
		result = append(result, e)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result, nil
}

// CountByResult returns counts grouped by result type.
func CountByResult(path string) (map[string]int, error) {
	entries, _, err := ReadAll(path)
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int)
	for _, e := range entries {
		counts[e.Result]++
	}
	return counts, nil
}

// NextID reads the file and returns the next ID after the max numeric EVID-XXX value.
func NextID(path string) (string, error) {
	entries, _, err := ReadAll(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "EVID-001", nil
		}
		return "", err
	}
	maxID := 0
	for _, e := range entries {
		if n, ok := parseEvidenceID(e.ID); ok && n > maxID {
			maxID = n
		}
	}
	return fmt.Sprintf("EVID-%03d", maxID+1), nil
}

// ChainResult holds the result of evidence chain verification.
type ChainResult struct {
	Valid          bool   `json:"valid"`
	EntriesChecked int    `json:"entries_checked"`
	SkippedLines   int    `json:"skipped_lines"`
	BrokenAt       string `json:"broken_at,omitempty"`
	Error          string `json:"error,omitempty"`
}

// VerifyChain reads an evidence file and validates the hash chain integrity.
func VerifyChain(path string) (*ChainResult, error) {
	entries, skipped, err := ReadAll(path)
	if err != nil {
		return nil, err
	}

	result := &ChainResult{EntriesChecked: len(entries), SkippedLines: skipped}

	if len(entries) == 0 {
		result.Valid = true
		return result, nil
	}

	for i, e := range entries {
		if e.Hash == "" {
			result.BrokenAt = e.ID
			result.Error = "missing hash"
			return result, nil
		}

		expected := ComputeHash(e)
		if e.Hash != expected {
			result.BrokenAt = e.ID
			result.Error = "hash mismatch"
			return result, nil
		}

		if i == 0 {
			if e.PrevHash != "" {
				result.BrokenAt = e.ID
				result.Error = "first entry has non-empty prev_hash"
				return result, nil
			}
		} else {
			if e.PrevHash != entries[i-1].Hash {
				result.BrokenAt = e.ID
				result.Error = "prev_hash does not match previous entry hash"
				return result, nil
			}
		}
	}

	result.Valid = true
	return result, nil
}
