package payloads

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// goldenQueries maps a golden fixture file (captured from the former
// SQLite-backed `ensphere payloads ...` command) to the filter that produced
// it. MaxRisk and Limit carry the command's flag defaults (3 and 20). The YAML
// store must reproduce each fixture byte-for-byte.
//
// Ordering: results are sorted by broadening rank, then risk, then the unique
// payload id. The id is a content hash and therefore a fully deterministic
// final tiebreaker, so there are no true ties to break.
var goldenQueries = map[string]PayloadFilter{
	"sqli.json":                {VulnType: "sqli", DBEngine: "postgres", Technique: "blind_time", MaxRisk: 3, Limit: 20},
	"xss.json":                 {VulnType: "xss", Technique: "reflected", MaxRisk: 3, Limit: 20},
	"ssrf.json":                {VulnType: "ssrf", MaxRisk: 2, Limit: 20},
	"csv_injection.json":       {VulnType: "csv_injection", MaxRisk: 3, Limit: 20},
	"cmdi.json":                {VulnType: "cmdi", MaxRisk: 3, Limit: 20},
	"lfi.json":                 {VulnType: "lfi", MaxRisk: 3, Limit: 20},
	"ssti.json":                {VulnType: "ssti", MaxRisk: 3, Limit: 20},
	"xxe.json":                 {VulnType: "xxe", MaxRisk: 3, Limit: 20},
	"idor.json":                {VulnType: "idor", MaxRisk: 3, Limit: 20},
	"authz.json":               {VulnType: "authz", MaxRisk: 3, Limit: 20},
	"redirect.json":            {VulnType: "redirect", MaxRisk: 3, Limit: 20},
	"csrf.json":                {VulnType: "csrf", MaxRisk: 3, Limit: 20},
	"nosql.json":               {VulnType: "nosql", MaxRisk: 3, Limit: 20},
	"auth_bypass.json":         {VulnType: "auth_bypass", MaxRisk: 3, Limit: 20},
	"prototype_pollution.json": {VulnType: "prototype_pollution", MaxRisk: 3, Limit: 20},
	"graphql.json":             {VulnType: "graphql", MaxRisk: 3, Limit: 20},
	"jwt.json":                 {VulnType: "jwt", MaxRisk: 3, Limit: 20},
	"cors.json":                {VulnType: "cors", MaxRisk: 3, Limit: 20},
	"race_condition.json":      {VulnType: "race_condition", MaxRisk: 3, Limit: 20},
	"cache_poisoning.json":     {VulnType: "cache_poisoning", MaxRisk: 3, Limit: 20},
	"ldap.json":                {VulnType: "ldap", MaxRisk: 3, Limit: 20},
	"xpath.json":               {VulnType: "xpath", MaxRisk: 3, Limit: 20},
	"header_injection.json":    {VulnType: "header_injection", MaxRisk: 3, Limit: 20},
	"file_upload.json":         {VulnType: "file_upload", MaxRisk: 3, Limit: 20},
	"mass_assignment.json":     {VulnType: "mass_assignment", MaxRisk: 3, Limit: 20},
	"sqli_pg_blindtime.json":   {VulnType: "sqli", DBEngine: "postgres", Technique: "blind_time", MaxRisk: 3, Limit: 5},
	"sqli_tag.json":            {VulnType: "sqli", Tag: "pg_sleep", MaxRisk: 3, Limit: 5},
}

func TestQueryReproducesGoldens(t *testing.T) {
	store, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for name, filter := range goldenQueries {
		t.Run(name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}

			// Reproduce the command's exact serialization: indented JSON with a
			// trailing newline from json.Encoder.
			var got bytes.Buffer
			enc := json.NewEncoder(&got)
			enc.SetIndent("", "  ")
			if err := enc.Encode(store.Query(filter)); err != nil {
				t.Fatalf("encode: %v", err)
			}

			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("output does not match golden %s\n--- got ---\n%s\n--- want ---\n%s", name, got.String(), want)
			}
		})
	}
}
