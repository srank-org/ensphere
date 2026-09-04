package compliance

import (
	"fmt"
	"io/fs"
	"sort"
	"sync"

	"github.com/srank-org/ensphere/internal/enums"
	"gopkg.in/yaml.v3"
)

// mappingsFile is the intermediate struct for YAML parsing.
type mappingsFile struct {
	Mappings map[string][]FrameworkEntry `yaml:"mappings"`
}

var (
	cached   *mappingsFile
	cacheErr error
	once     sync.Once
)

// loadMappings reads and parses the embedded mappings.yaml file once.
func loadMappings() (*mappingsFile, error) {
	once.Do(func() {
		data, err := fs.ReadFile(embeddedData, "data/mappings.yaml")
		if err != nil {
			cacheErr = fmt.Errorf("read compliance mappings: %w", err)
			return
		}
		var mf mappingsFile
		if err := yaml.Unmarshal(data, &mf); err != nil {
			cacheErr = fmt.Errorf("parse compliance mappings: %w", err)
			return
		}
		cached = &mf
	})
	return cached, cacheErr
}

// ListMappings returns a summary of all vuln_types with framework counts.
func ListMappings() (*ComplianceListOutput, error) {
	mf, err := loadMappings()
	if err != nil {
		return nil, err
	}

	var summaries []ComplianceSummary
	for vulnType, entries := range mf.Mappings {
		summaries = append(summaries, ComplianceSummary{
			VulnType:       vulnType,
			FrameworkCount: len(entries),
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].VulnType < summaries[j].VulnType
	})

	return &ComplianceListOutput{VulnTypes: summaries}, nil
}

// GetMapping returns compliance mappings for a specific vuln_type.
func GetMapping(vulnType string) (*ComplianceMapping, error) {
	if !enums.ValidVulnTypes[vulnType] {
		return nil, fmt.Errorf("invalid vuln_type %q — valid: %s", vulnType, enums.SortedKeys(enums.ValidVulnTypes))
	}

	mf, err := loadMappings()
	if err != nil {
		return nil, err
	}

	entries, ok := mf.Mappings[vulnType]
	if !ok {
		return nil, fmt.Errorf("no compliance mappings for vuln_type %q", vulnType)
	}

	return &ComplianceMapping{
		VulnType:       vulnType,
		FrameworkCount: len(entries),
		Mappings:       entries,
	}, nil
}

// ValidVulnTypes returns a sorted list of vuln_types that have compliance mappings.
func ValidVulnTypes() []string {
	mf, err := loadMappings()
	if err != nil {
		return nil
	}

	keys := make([]string, 0, len(mf.Mappings))
	for k := range mf.Mappings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
