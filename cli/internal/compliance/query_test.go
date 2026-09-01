package compliance

import (
	"sort"
	"strings"
	"testing"
)

func TestListMappingsSortedAndPopulated(t *testing.T) {
	out, err := ListMappings()
	if err != nil {
		t.Fatalf("ListMappings: %v", err)
	}
	if len(out.VulnTypes) == 0 {
		t.Fatal("expected mappings")
	}
	for i := 1; i < len(out.VulnTypes); i++ {
		if out.VulnTypes[i-1].VulnType > out.VulnTypes[i].VulnType {
			t.Fatalf("mappings are not sorted: %s before %s", out.VulnTypes[i-1].VulnType, out.VulnTypes[i].VulnType)
		}
	}
}

func TestGetMappingValidInvalidAndNoMapping(t *testing.T) {
	mapping, err := GetMapping("sqli")
	if err != nil {
		t.Fatalf("GetMapping: %v", err)
	}
	if mapping.VulnType != "sqli" || mapping.FrameworkCount == 0 || len(mapping.Mappings) == 0 {
		t.Fatalf("unexpected mapping: %+v", mapping)
	}

	if _, err := GetMapping("not-a-vuln"); err == nil || !strings.Contains(err.Error(), "invalid vuln_type") {
		t.Fatalf("expected invalid vuln_type error, got %v", err)
	}
	// rate_limit and limits are resource-consumption controls that must carry
	// compliance mappings (OWASP API4, PCI-DSS 6.x, SOC 2, ISO 27001).
	for _, vt := range []string{"rate_limit", "limits"} {
		m, err := GetMapping(vt)
		if err != nil {
			t.Fatalf("GetMapping(%q): %v", vt, err)
		}
		if m.FrameworkCount == 0 || len(m.Mappings) == 0 {
			t.Fatalf("expected framework mappings for %q, got %+v", vt, m)
		}
	}
}

func TestValidVulnTypesSorted(t *testing.T) {
	names := ValidVulnTypes()
	if len(names) == 0 {
		t.Fatal("expected vuln types")
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("valid vuln types are not sorted: %v", names)
	}
}
