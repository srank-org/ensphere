package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var locationLineSuffix = regexp.MustCompile(`:[0-9]+(:[0-9]+)?$`)

func normalizeText(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(value)), " ")
}

// normalizeLocation drops a trailing :line or :line:col so a finding still
// matches after a refactor moves it within the same file.
func normalizeLocation(value string) string {
	return locationLineSuffix.ReplaceAllString(normalizeText(value), "")
}

// findingKey identifies a finding across assessments. The diff matches on it
// and the SARIF fingerprint hashes it, so both agree on what "the same
// finding" means.
func findingKey(finding FindingSummary) string {
	return normalizeText(finding.Kind) + "|" + normalizeText(finding.Category) + "|" + normalizeText(finding.Title)
}

func findingFingerprint(finding FindingSummary) string {
	sum := sha256.Sum256([]byte(findingKey(finding)))
	return hex.EncodeToString(sum[:])
}

func coverageRowKey(session string, row CoverageRow) string {
	return session + "|" + normalizeText(row.Surface) + "|" + normalizeText(row.Check) + "|" + normalizeText(row.Identity)
}

func writeIndentedJSON(path string, value any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
