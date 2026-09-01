package payloads

import (
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/srank/ensphere/internal/enums"
)

// Canary values: these counts are tied to docs (docs/cli-reference.md,
// docs/testing.md). When payloads are added or removed, update this test AND the
// documentation.
const (
	expectedPayloadCount  = 956
	expectedVulnTypeCount = 25
)

func TestPayloadCount_MatchesDocs(t *testing.T) {
	store, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(store.payloads); got != expectedPayloadCount {
		t.Fatalf("payload count %d != expected %d — update this test AND docs if payloads changed", got, expectedPayloadCount)
	}
}

func TestVulnTypes_MatchesDocs(t *testing.T) {
	store, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	set := make(map[string]bool)
	for _, p := range store.payloads {
		set[p.VulnType] = true
	}

	if len(set) != expectedVulnTypeCount {
		t.Fatalf("vuln type count %d != expected %d — update this test AND docs if types changed", len(set), expectedVulnTypeCount)
	}

	var got []string
	for vt := range set {
		if !enums.ValidVulnTypes[vt] {
			t.Errorf("seed vuln_type %q not found in enums.ValidVulnTypes", vt)
		}
		got = append(got, vt)
	}

	expected := []string{
		"auth_bypass", "authz", "cache_poisoning", "cmdi", "cors", "csrf",
		"csv_injection", "file_upload", "graphql",
		"header_injection", "idor", "jwt", "ldap", "lfi", "mass_assignment",
		"nosql", "prototype_pollution", "race_condition", "redirect",
		"sqli", "ssrf", "ssti", "xpath", "xss", "xxe",
	}
	sort.Strings(got)
	sort.Strings(expected)
	if len(got) != len(expected) {
		t.Fatalf("set size mismatch: seeds have %d, expected %d", len(got), len(expected))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("mismatch at index %d: seeds=%q expected=%q", i, got[i], expected[i])
		}
	}
}

// TestEmbeddedSeedsAreValid asserts every embedded seed row applies its
// defaults, satisfies required fields, and carries only valid enum values. Load
// returns an error the moment any seed file violates an enum, so a bad value in
// any assets/seeds/*.yaml fails this test.
func TestEmbeddedSeedsAreValid(t *testing.T) {
	if _, err := Load(); err != nil {
		t.Fatalf("embedded seeds failed validation: %v", err)
	}
}

func TestLoadRejectsInvalidEnum(t *testing.T) {
	fsys := fstest.MapFS{
		"data/bad.yaml": &fstest.MapFile{Data: []byte(`defaults:
  vuln_type: sqli
  db_engine: postgres
  encoding: raw
payloads:
  - technique: not_a_real_technique
    injection_surface: query
    evidence_type: timing
    risk: 3
    payload: "' OR 1=1--"
`)},
	}

	_, err := loadFromFS(fsys, "data")
	if err == nil || !strings.Contains(err.Error(), "invalid enum values") {
		t.Fatalf("expected invalid enum error, got %v", err)
	}
}

func TestLoadRejectsInvalidRisk(t *testing.T) {
	fsys := fstest.MapFS{
		"data/bad.yaml": &fstest.MapFile{Data: []byte(`defaults:
  vuln_type: sqli
  db_engine: postgres
  encoding: raw
payloads:
  - technique: blind_time
    injection_surface: query
    evidence_type: timing
    risk: 9
    payload: "' OR 1=1--"
`)},
	}

	_, err := loadFromFS(fsys, "data")
	if err == nil || !strings.Contains(err.Error(), "risk must be 1-5") {
		t.Fatalf("expected invalid risk error, got %v", err)
	}
}

func TestLoadRejectsDuplicateID(t *testing.T) {
	row := `defaults:
  vuln_type: sqli
  db_engine: postgres
  encoding: raw
payloads:
  - technique: blind_time
    injection_surface: query
    evidence_type: timing
    risk: 3
    payload: "' OR pg_sleep(5)--"
`
	fsys := fstest.MapFS{
		"data/a.yaml": &fstest.MapFile{Data: []byte(row)},
		"data/b.yaml": &fstest.MapFile{Data: []byte(row)},
	}

	_, err := loadFromFS(fsys, "data")
	if err == nil || !strings.Contains(err.Error(), "duplicate payload ID") {
		t.Fatalf("expected duplicate payload ID error, got %v", err)
	}
}
