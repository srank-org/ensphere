package verify

import (
	"strings"
	"testing"

	"github.com/srank-org/ensphere/internal/payloads"
)

func TestNormalizeSQLiDBEngine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "default", input: "", want: "postgres"},
		{name: "case and space", input: " MySQL ", want: "mysql"},
		{name: "invalid", input: "oracle", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeSQLiDBEngine(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSelectSQLiBlindTimePayloadsAreDBSpecific(t *testing.T) {
	tests := []struct {
		name        string
		db          string
		containsAny []string
	}{
		{name: "postgres", db: "postgres", containsAny: []string{"pg_sleep"}},
		{name: "mysql", db: "mysql", containsAny: []string{"SLEEP(", "BENCHMARK("}},
		{name: "mssql", db: "mssql", containsAny: []string{"WAITFOR DELAY"}},
		{name: "sqlite", db: "sqlite", containsAny: []string{"SELECT COUNT(*)", "randomblob("}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := SQLiConfig{
				DBEngine: tt.db,
				Method:   "GET",
				Boundary: "single_quote",
				ProbeConfig: ProbeConfig{
					MaxRisk: 3,
				},
			}
			got, err := selectSQLiPayload(cfg, "blind_time", func(p payloads.PayloadResult) bool {
				return placeholdersAllowed(p.Placeholders, map[string]bool{"SLEEP_SECONDS": true})
			})
			if err != nil {
				t.Fatalf("select payload: %v", err)
			}
			matched := false
			for _, want := range tt.containsAny {
				if strings.Contains(got, want) {
					matched = true
					break
				}
			}
			if !matched {
				t.Fatalf("payload %q does not contain any of %v", got, tt.containsAny)
			}
		})
	}
}

func TestSelectSQLiBooleanPayloadsUseRequestedDB(t *testing.T) {
	cfg := SQLiConfig{
		DBEngine: "sqlite",
		Method:   "GET",
		Boundary: "single_quote",
		ProbeConfig: ProbeConfig{
			MaxRisk: 3,
		},
	}

	truePayload, falsePayload, err := selectSQLiBooleanPayloads(cfg)
	if err != nil {
		t.Fatalf("select boolean payloads: %v", err)
	}
	if !strings.Contains(normalizeSQLiCondition(truePayload), "1=1") {
		t.Fatalf("true payload %q does not contain true condition", truePayload)
	}
	if !strings.Contains(normalizeSQLiCondition(falsePayload), "1=2") {
		t.Fatalf("false payload %q does not contain false condition", falsePayload)
	}
	if strings.Contains(truePayload, "pg_sleep") || strings.Contains(falsePayload, "pg_sleep") {
		t.Fatalf("sqlite boolean payloads should not use postgres payloads: %q / %q", truePayload, falsePayload)
	}
}
