package invariants

import (
	"reflect"
	"testing"
)

func TestAffectedBySurfacesKeepsFileOrder(t *testing.T) {
	invs := []Invariant{
		{ID: "INV-001", Surface: "SURF-001", Enforce: false, Path: "a.yaml"},
		{ID: "INV-002", Surface: "SURF-002", Enforce: true, Path: "b.yaml"},
		{ID: "INV-003", Path: "c.yaml"},
		{ID: "INV-004", Surface: "SURF-001", Enforce: true, Path: "d.yaml"},
	}
	got := AffectedBySurfaces(invs, []string{" SURF-001", "SURF-009"})
	want := []Affected{
		{ID: "INV-001", Surface: "SURF-001", Enforce: false, Path: "a.yaml"},
		{ID: "INV-004", Surface: "SURF-001", Enforce: true, Path: "d.yaml"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AffectedBySurfaces = %+v, want %+v", got, want)
	}
	if got := AffectedBySurfaces(invs, nil); len(got) != 0 {
		t.Fatalf("no changed surfaces means no affected invariants, got %+v", got)
	}
}

func TestRunMarksInvariantsWhoseSurfaceChanged(t *testing.T) {
	root := writeFiles(t, map[string]string{"src/a.ts": "const a = 1\n"})
	changed := parseInvariant(t, "id: INV-060\ntitle: changed\nsurface: SURF-001\norigin: {kind: tested_defense, ref: COV-02-001}\nkind: source\ninclude: ['src/**/*.ts']\npattern: 'eval\\('\nexpect: {matches: 0}\n")
	other := parseInvariant(t, "id: INV-061\ntitle: other\nsurface: SURF-002\norigin: {kind: tested_defense, ref: COV-02-002}\nkind: source\ninclude: ['src/**/*.ts']\npattern: 'eval\\('\nexpect: {matches: 0}\n")
	cfg := testConfig("", root)
	cfg.Since = "abc123"
	cfg.ChangedSurfaces = []string{"SURF-001"}
	report := Run([]Invariant{changed, other}, cfg)
	if report.Since != "abc123" || report.Summary.SurfaceChanged != 1 {
		t.Fatalf("report %+v", report.Summary)
	}
	if !report.Invariants[0].SurfaceChanged || report.Invariants[1].SurfaceChanged {
		t.Fatalf("only INV-060 covers a changed surface, got %+v", report.Invariants)
	}
	if !contains(report.Message, "1 invariant(s) cover a surface whose files changed since abc123") {
		t.Fatalf("message %q", report.Message)
	}
	plain := Run([]Invariant{changed, other}, testConfig("", root))
	if plain.Since != "" || plain.Summary.SurfaceChanged != 0 || plain.Invariants[0].SurfaceChanged {
		t.Fatalf("without a ref nothing is marked, got %+v", plain.Summary)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
