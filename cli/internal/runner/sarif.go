package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	sarifSchema         = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion        = "2.1.0"
	sarifSourceRoot     = "%SRCROOT%"
	sarifFingerprintKey = "ensphere/finding/v1"
	ensphereRepoURL     = "https://github.com/srank-org/ensphere"
)

var sourcePathLocation = regexp.MustCompile(`^([^\s:]+)(?::([0-9]+)(?::([0-9]+))?)?$`)

var categoryMethodology = map[string]string{
	"injection":      "skills/ensphere/methodology/02-injection.md",
	"authentication": "skills/ensphere/methodology/03-auth.md",
	"authorization":  "skills/ensphere/methodology/04-authz.md",
	"xss":            "skills/ensphere/methodology/05-xss.md",
	"ssrf":           "skills/ensphere/methodology/06-ssrf.md",
	"cloud":          "skills/ensphere/methodology/07-cloud.md",
	"api":            "skills/ensphere/methodology/08-api.md",
	"abuse_and_cost": "skills/ensphere/methodology/08.5-abuse.md",
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool                    `json:"tool"`
	AutomationDetails  sarifAutomationDetails       `json:"automationDetails"`
	OriginalURIBaseIDs map[string]sarifURIBaseEntry `json:"originalUriBaseIds"`
	Results            []sarifResult                `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	HelpURI          string            `json:"helpUri"`
	Properties       map[string]string `json:"properties"`
}

type sarifAutomationDetails struct {
	ID string `json:"id"`
}

type sarifURIBaseEntry struct {
	Description sarifMessage `json:"description"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	RuleIndex           int                   `json:"ruleIndex"`
	Level               string                `json:"level"`
	Message             sarifMessage          `json:"message"`
	Locations           []sarifLocation       `json:"locations"`
	PartialFingerprints map[string]string     `json:"partialFingerprints"`
	Properties          sarifResultProperties `json:"properties"`
}

type sarifResultProperties struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	Category         string   `json:"category"`
	Status           string   `json:"status"`
	Confidence       string   `json:"confidence"`
	EvidenceStrength string   `json:"evidence_strength"`
	Severity         string   `json:"severity"`
	Priority         string   `json:"priority"`
	EvidenceIDs      []string `json:"evidence_ids"`
	AffectedAssets   []string `json:"affected_assets"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifLogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
}

func sarifPath(workspace string) string {
	return filepath.Join(workspace, "09-report", "findings.sarif")
}

// RunSARIF exports the reportable findings in the registry as SARIF 2.1.0 at
// 09-report/findings.sarif. Identical inputs produce identical bytes.
func RunSARIF(workspace, version string) (*SARIFOutput, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	if err := ensureWorkspaceInitialized(workspace); err != nil {
		return nil, err
	}
	cfg, err := readConfig(workspace)
	if err != nil {
		return nil, err
	}
	registryPath := findingRegistryPath(workspace)
	rawRegistry, err := os.ReadFile(registryPath)
	if err != nil {
		return nil, fmt.Errorf("read finding registry: %w", err)
	}
	registry, err := parseFindingRegistry(rawRegistry)
	if err != nil {
		return nil, err
	}

	findings := make([]FindingSummary, 0, len(registry.Findings))
	for _, finding := range registry.Findings {
		if reportableFindingStatus(finding.Status) {
			findings = append(findings, finding)
		}
	}
	findings = sortedFindings(findings)

	ruleIDs := make(map[string]FindingSummary)
	for _, finding := range findings {
		id := sarifRuleID(finding)
		if _, ok := ruleIDs[id]; !ok {
			ruleIDs[id] = finding
		}
	}
	ids := make([]string, 0, len(ruleIDs))
	for id := range ruleIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	ruleIndex := make(map[string]int, len(ids))
	for i, id := range ids {
		ruleIndex[id] = i
		rules = append(rules, sarifRuleFor(id, ruleIDs[id]))
	}

	registryURI := sarifRegistryURI(cfg.SourcePath, registryPath)
	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		id := sarifRuleID(finding)
		result := sarifResult{
			RuleID:              id,
			RuleIndex:           ruleIndex[id],
			Level:               sarifLevel(finding.Severity),
			Message:             sarifMessage{Text: sarifResultText(finding)},
			Locations:           sarifLocations(finding.AffectedLocations),
			PartialFingerprints: map[string]string{sarifFingerprintKey: findingFingerprint(finding)},
			Properties: sarifResultProperties{
				ID:               strings.TrimSpace(finding.ID),
				Kind:             strings.TrimSpace(finding.Kind),
				Category:         strings.TrimSpace(finding.Category),
				Status:           strings.TrimSpace(finding.Status),
				Confidence:       strings.TrimSpace(finding.Confidence),
				EvidenceStrength: strings.TrimSpace(finding.EvidenceStrength),
				Severity:         strings.TrimSpace(finding.Severity),
				Priority:         strings.TrimSpace(finding.Priority),
				EvidenceIDs:      cleanStrings(finding.EvidenceIDs),
				AffectedAssets:   cleanStrings(finding.AffectedAssets),
			},
		}
		// GitHub code scanning drops a result without a physical location,
		// so a finding located only by endpoint points at its registry entry.
		if !hasPhysicalLocation(result.Locations) {
			registryLocation := sarifLocation{PhysicalLocation: &sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: registryURI, URIBaseID: sarifSourceRoot},
				Region:           &sarifRegion{StartLine: registryLine(rawRegistry, finding.ID)},
			}}
			result.Locations = append([]sarifLocation{registryLocation}, result.Locations...)
		}
		results = append(results, result)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "ensphere",
				Version:        version,
				InformationURI: ensphereRepoURL,
				Rules:          rules,
			}},
			AutomationDetails: sarifAutomationDetails{ID: "ensphere/assessment"},
			OriginalURIBaseIDs: map[string]sarifURIBaseEntry{
				sarifSourceRoot: {Description: sarifMessage{Text: "the source tree under assessment"}},
			},
			Results: results,
		}},
	}
	out := &SARIFOutput{
		Workspace: workspace,
		SARIFPath: sarifPath(workspace),
		Results:   len(results),
		Rules:     len(rules),
		Message:   "Reportable findings exported as SARIF 2.1.0. Levels translate the analyst's severity; upload findings.sarif to code scanning.",
	}
	if err := writeIndentedJSON(out.SARIFPath, log); err != nil {
		return nil, err
	}
	return out, nil
}

func sarifRuleID(finding FindingSummary) string {
	return "ensphere/" + normalizeText(finding.Kind) + "/" + normalizeText(finding.Category)
}

func sarifRuleFor(id string, finding FindingSummary) sarifRule {
	kind, category := normalizeText(finding.Kind), normalizeText(finding.Category)
	methodology, ok := categoryMethodology[category]
	if !ok {
		methodology = "skills/ensphere/shared/contract.md"
	}
	return sarifRule{
		ID:               id,
		Name:             upperCamel(kind) + upperCamel(category),
		ShortDescription: sarifMessage{Text: sentenceCase(kind) + ": " + strings.ReplaceAll(category, "_", " ")},
		HelpURI:          ensphereRepoURL + "/blob/main/" + methodology,
		Properties:       map[string]string{"kind": kind, "category": category},
	}
}

func upperCamel(value string) string {
	var b strings.Builder
	for _, part := range strings.Split(value, "_") {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

func sentenceCase(value string) string {
	value = strings.ReplaceAll(value, "_", " ")
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

// sarifLevel is a format translation of the severity the analyst already
// assigned; it judges nothing.
func sarifLevel(severity string) string {
	switch strings.TrimSpace(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func sarifResultText(finding FindingSummary) string {
	text := fmt.Sprintf("%s [%s, %s, severity %s, priority %s].",
		strings.TrimSpace(finding.Title), strings.TrimSpace(finding.ID), strings.TrimSpace(finding.Status),
		strings.TrimSpace(finding.Severity), strings.TrimSpace(finding.Priority))
	if rootCause := strings.TrimRight(strings.TrimSpace(finding.RootCause), "."); rootCause != "" {
		text += " Root cause: " + rootCause + "."
	}
	if remediation := strings.TrimRight(strings.TrimSpace(finding.Remediation), "."); remediation != "" {
		text += " Remediation: " + remediation + "."
	}
	return text
}

func sarifLocations(locations []string) []sarifLocation {
	out := []sarifLocation{}
	for _, location := range locations {
		location = strings.TrimSpace(location)
		if location == "" {
			continue
		}
		if physical := sourceFileLocation(location); physical != nil {
			out = append(out, sarifLocation{PhysicalLocation: physical})
			continue
		}
		out = append(out, sarifLocation{LogicalLocations: []sarifLogicalLocation{{FullyQualifiedName: location}}})
	}
	return out
}

// sourceFileLocation reads "path", "path:line", or "path:line:col" as a file
// under the source root. Anything with a scheme, whitespace, or a leading
// slash (a URL, "GET /x", "/api/x") is not a source path.
func sourceFileLocation(location string) *sarifPhysicalLocation {
	if strings.Contains(location, "://") || strings.HasPrefix(location, "/") {
		return nil
	}
	match := sourcePathLocation.FindStringSubmatch(location)
	if match == nil || !strings.ContainsAny(match[1], "/.") {
		return nil
	}
	physical := &sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{
		URI:       strings.TrimPrefix(match[1], "./"),
		URIBaseID: sarifSourceRoot,
	}}
	if line, _ := strconv.Atoi(match[2]); line > 0 {
		physical.Region = &sarifRegion{StartLine: line}
		if column, _ := strconv.Atoi(match[3]); column > 0 {
			physical.Region.StartColumn = column
		}
	}
	return physical
}

func hasPhysicalLocation(locations []sarifLocation) bool {
	for _, location := range locations {
		if location.PhysicalLocation != nil {
			return true
		}
	}
	return false
}

func sarifRegistryURI(sourcePath, registryPath string) string {
	source, errSource := filepath.Abs(sourcePath)
	registry, errRegistry := filepath.Abs(registryPath)
	if errSource == nil && errRegistry == nil {
		if rel, err := filepath.Rel(source, registry); err == nil {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(registryPath)
}

// registryLine returns the 1-based line of the registry entry for id, or 1
// when the entry cannot be found.
func registryLine(raw []byte, id string) int {
	id = strings.TrimSpace(id)
	fallback := 0
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		listItem := strings.HasPrefix(line, "- ")
		line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
		value, ok := strings.CutPrefix(line, "id:")
		if !ok || strings.Trim(strings.TrimSpace(value), `"'`) != id {
			continue
		}
		if listItem {
			return i + 1
		}
		if fallback == 0 {
			fallback = i + 1
		}
	}
	if fallback == 0 {
		return 1
	}
	return fallback
}
