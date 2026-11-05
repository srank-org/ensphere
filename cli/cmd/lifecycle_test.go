package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// This test drives the real binary through one whole assessment with no
// model: the deterministic half of Ensphere proven end to end. It starts
// from the worked example under templates/dot-ensphere, stands up a target
// that behaves as that example's invariants expect, and runs doctor, init,
// plan, the request primitive into a ledger, the report gate, the
// statement, SARIF, the one-commit rule, the change set, the invariants
// with --since, and a delta run.

// exampleTarget answers the way templates/dot-ensphere's invariants expect.
func exampleTarget(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	otp := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/auth/otp":
			mu.Lock()
			otp++
			n := otp
			mu.Unlock()
			if n >= 6 {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/invoices/"):
			if r.Header.Get("Authorization") == "Bearer token-a" && strings.HasSuffix(r.URL.Path, "/inv-a") {
				fmt.Fprint(w, `{"id":"inv-a","tenant":"a"}`)
				return
			}
			w.WriteHeader(http.StatusForbidden)
		case r.Method == http.MethodPost && r.URL.Path == "/api/upload":
			if r.ContentLength > 26214400 {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// exampleSource is a committed git repository holding the files the example
// map claims, the example .ensphere/ directory with reconciled_at set, and a
// fake psql on PATH for the command invariant.
func exampleSource(t *testing.T) (root, head string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root = t.TempDir()
	write := func(rel, content string) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range []string{"src/routes/auth.ts", "src/lib/otp.ts", "src/routes/invoices.ts", "supabase/migrations/0003_invoices.sql", "src/routes/upload.ts", "wrangler.toml"} {
		write(rel, "// "+rel+"\n")
	}
	write("src/components/posts/Post.tsx", "export const Post = () => <article />\n")
	write(".gitignore", "ensphere-pentest*/\n")
	example := filepath.Join(cliRoot, "..", "templates", "dot-ensphere")
	if err := filepath.WalkDir(example, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(example, path)
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		write(filepath.ToSlash(filepath.Join(".ensphere", rel)), string(raw))
		return nil
	}); err != nil {
		t.Fatalf("copy example: %v", err)
	}
	gitIn(t, root, "init", "-q")
	gitIn(t, root, "add", ".")
	gitIn(t, root, "commit", "-q", "-m", "base")
	head = gitIn(t, root, "rev-parse", "HEAD")
	mapPath := filepath.Join(root, ".ensphere", "surfaces.yaml")
	raw, err := os.ReadFile(mapPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mapPath, []byte(strings.Replace(string(raw), "<git rev-parse HEAD at reconciliation>", head, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, root, "commit", "-q", "-am", "reconcile")
	head = gitIn(t, root, "rev-parse", "HEAD")

	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "psql"), []byte("#!/bin/sh\nprintf '0'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return root, head
}

func TestCLILifecycleWithoutAModel(t *testing.T) {
	server := exampleTarget(t)
	root, head := exampleSource(t)
	workspace := "ensphere-pentest"
	run := func(args ...string) commandResult { return runCLIIn(t, root, "", args...) }
	mustRun := func(args ...string) commandResult {
		t.Helper()
		result := run(args...)
		if result.code != 0 {
			t.Fatalf("ensphere %s exit %d\nstdout=%s\nstderr=%s", strings.Join(args, " "), result.code, result.stdout, result.stderr)
		}
		return result
	}
	t.Setenv("TENANT_A_TOKEN", "token-a")
	t.Setenv("TENANT_B_INVOICE_ID", "inv-b")
	t.Setenv("TENANT_B_INVOICE_MARKER", "tenant-b-secret")
	t.Setenv("DATABASE_URL", "postgres://sandbox")

	// Before the workspace exists the doctor already checks the tree.
	if result := run("run", "doctor", "--plugin-version", "0.0.0"); result.code != 1 || !strings.Contains(result.stdout, `"name": "map"`) {
		t.Fatalf("doctor without a workspace: exit %d stdout=%s", result.code, result.stdout)
	}

	mustRun("run", "init",
		"--target", server.URL, "--environment", "sandbox", "--source-path", ".", "--target-type", "api_backend",
		"--in-scope", "127.0.0.1", "--assessed-by", "lifecycle test", "--operator", "Test Operator",
		"--sandbox-start", "true", "--sandbox-seed", "true", "--sandbox-reset", "true",
		"--approved-bursts", "POST /api/auth/otp: 8/60s")
	doctor := mustRun("run", "doctor")
	var doc struct {
		Ready  bool `json:"ready"`
		Checks []struct {
			Name, State, Detail string
		} `json:"checks"`
	}
	decodeJSON(t, doctor.stdout, &doc)
	for _, check := range doc.Checks {
		switch check.Name {
		case "workspace", "source", "map", "invariants", "target", "sandbox":
			if check.State != "ok" {
				t.Fatalf("doctor %s: %s %s", check.Name, check.State, check.Detail)
			}
		}
	}
	mustRun("run", "plan")

	// Session 02 resolves one row with the request primitive: baseline,
	// probe, control, every request through scope and into the ledger.
	ledger := filepath.Join(workspace, "02-injection", "evidence.jsonl")
	var ids []string
	for _, stage := range []string{"baseline", "probe", "control"} {
		result := mustRun("verify", "request", "--url", server.URL+"/api/invoices/inv-a", "--header", "Authorization: Bearer token-a",
			"--result", stage, "--note", "lifecycle "+stage, "--in-scope", "127.0.0.1", "--evidence", ledger, "--throttle", "0")
		var out struct {
			Measurements struct {
				EvidenceID string `json:"evidence_id"`
			} `json:"measurements"`
		}
		decodeJSON(t, result.stdout, &out)
		if out.Measurements.EvidenceID == "" {
			t.Fatalf("verify request wrote no evidence id:\n%s", result.stdout)
		}
		ids = append(ids, out.Measurements.EvidenceID)
	}
	mustRun("evidence", "verify", "--file", ledger)
	if result := run("verify", "request", "--url", "http://example.com/", "--result", "probe", "--in-scope", "example.com", "--evidence", ledger); result.code != 2 {
		t.Fatalf("a scope the workspace did not approve must exit 2, got %d stderr=%s", result.code, result.stderr)
	}

	writeLifecycleSessions(t, filepath.Join(root, workspace), ids)

	report := mustRun("run", "report")
	var gate struct {
		Ready  bool `json:"ready"`
		Issues []struct {
			Code string `json:"code"`
		} `json:"issues"`
	}
	decodeJSON(t, report.stdout, &gate)
	if !gate.Ready {
		t.Fatalf("gate not ready:\n%s", report.stdout)
	}
	mustRun("run", "statement")
	statement, err := os.ReadFile(filepath.Join(root, workspace, "09-report", "statement.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(statement), "source_commit: "+head) {
		t.Fatalf("statement must name the commit %s:\n%s", head, statement)
	}
	md, _ := os.ReadFile(filepath.Join(root, workspace, "09-report", "statement.md"))
	if !strings.Contains(string(md), "It is not an independent audit, attestation, or certification.") {
		t.Fatalf("statement.md lacks the closing sentence:\n%s", md)
	}
	mustRun("run", "sarif")
	if _, err := os.Stat(filepath.Join(root, workspace, "09-report", "findings.sarif")); err != nil {
		t.Fatal(err)
	}
	mustRun("run", "report")

	// The tree moves: the gate refuses, the change set names the surface and
	// its invariant, and the invariants still hold against the target.
	if err := os.WriteFile(filepath.Join(root, "src", "lib", "otp.ts"), []byte("// edited during the run\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	moved := run("run", "report")
	decodeJSON(t, moved.stdout, &gate)
	if gate.Ready || !hasCode(gate.Issues, "source_tree_modified") {
		t.Fatalf("a modified tree must block the gate:\n%s", moved.stdout)
	}
	if result := run("run", "statement"); result.code != 2 {
		t.Fatalf("statement must refuse on a modified tree, got %d", result.code)
	}
	changed := mustRun("map", "changed")
	var changes struct {
		ChangedSurfaces []struct {
			ID string `json:"id"`
		} `json:"changed_surfaces"`
		InvariantsAffected []struct {
			ID string `json:"id"`
		} `json:"invariants_affected"`
	}
	decodeJSON(t, changed.stdout, &changes)
	if len(changes.ChangedSurfaces) != 1 || changes.ChangedSurfaces[0].ID != "SURF-001" || len(changes.InvariantsAffected) != 1 || changes.InvariantsAffected[0].ID != "INV-001" {
		t.Fatalf("unexpected change set:\n%s", changed.stdout)
	}
	inv := mustRun("invariants", "run", "--target", server.URL, "--in-scope", "127.0.0.1", "--since", head, "--throttle", "0")
	var invReport struct {
		Guarded    bool `json:"guarded"`
		Invariants []struct {
			ID             string `json:"id"`
			Result         string `json:"result"`
			Message        string `json:"message"`
			SurfaceChanged bool   `json:"surface_changed"`
		} `json:"invariants"`
		Summary struct {
			Pass           int `json:"pass"`
			Fail           int `json:"fail"`
			Error          int `json:"error"`
			SurfaceChanged int `json:"surface_changed"`
		} `json:"summary"`
	}
	decodeJSON(t, inv.stdout, &invReport)
	if !invReport.Guarded || invReport.Summary.Pass != 5 || invReport.Summary.SurfaceChanged != 1 {
		t.Fatalf("expected every example invariant to hold, guarded, with INV-001 marked:\n%s", inv.stdout)
	}
	for _, r := range invReport.Invariants {
		if r.ID == "INV-001" && !r.SurfaceChanged {
			t.Fatalf("INV-001 covers the changed surface:\n%s", inv.stdout)
		}
	}
	gitIn(t, root, "checkout", "--", "src/lib/otp.ts")
	mustRun("run", "report")

	// A delta run after a commit that touches one surface (the invoices
	// table, owned by Sessions 04 and 07) skips every other check session.
	if err := os.WriteFile(filepath.Join(root, "supabase", "migrations", "0003_invoices.sql"), []byte("-- v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, root, "commit", "-q", "-am", "migration")
	delta := "ensphere-pentest-delta"
	mustRun("run", "--workspace", delta, "init", "--target", server.URL, "--in-scope", "127.0.0.1", "--delta-since", head, "--sandbox-start", "true", "--operator", "Test Operator")
	plan := mustRun("run", "--workspace", delta, "plan")
	var planOut struct {
		Plan struct {
			Sessions map[string]struct {
				Decision string `json:"decision"`
			} `json:"sessions"`
		} `json:"assessment_plan"`
	}
	decodeJSON(t, plan.stdout, &planOut)
	raw, _ := os.ReadFile(filepath.Join(root, delta, "assessment-plan.yaml"))
	text := string(raw)
	if !strings.Contains(text, "delta run since "+head) || strings.Count(text, "decision: skip") < 5 {
		t.Fatalf("a delta run must skip the sessions no changed surface owns:\n%s", raw)
	}
	authz := text[strings.Index(text, "04-authz:"):]
	if strings.HasPrefix(strings.TrimSpace(authz[strings.Index(authz, "decision:"):]), "decision: skip") {
		t.Fatalf("Session 04 owns the changed surface and must keep its draft:\n%s", raw)
	}
}

func hasCode(issues []struct {
	Code string `json:"code"`
}, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

// writeLifecycleSessions fills the workspace the way a run would leave it:
// every session DONE with a report, coverage rows that cite the ledger,
// the registry with one confirmed missing control that the example's
// INV-001 promotes, and the Session 09 artifacts.
func writeLifecycleSessions(t *testing.T, workspace string, ids []string) {
	t.Helper()
	write := func(rel, content string) {
		path := filepath.Join(workspace, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("progress.md", `# Assessment Progress

| Session | Category | Status | Findings |
|---------|----------|--------|----------|
| 01 | Recon | DONE | |
| 01.5 | Plan | DONE | |
| 02 | Injection | DONE | |
| 03 | Authentication | DONE | |
| 04 | Authorization | DONE | |
| 05 | Cross-Site Scripting | DONE | |
| 06 | Server-Side Request Forgery | DONE | |
| 07 | Cloud and Platform | DONE | plan: skip |
| 08 | API Security | DONE | |
| 08.5 | Abuse and Cost Controls | DONE | |
| 08.7 | Chains and Workflows | DONE | plan: blocked |
| 09 | Report | PENDING | |
`)
	dirs := map[string]string{"01": "01-recon", "01.5": "01.5-session-plan", "02": "02-injection", "03": "03-auth", "04": "04-authz", "05": "05-xss", "06": "06-ssrf", "07": "07-cloud", "08": "08-api", "08.5": "08.5-abuse", "08.7": "08.7-chains"}
	for _, dir := range dirs {
		write(dir+"/report.md", "# Session Report\n\nFixture session.\n\n## Needs from you\n\nNothing.\n")
	}
	write("02-injection/coverage.yaml", fmt.Sprintf(`session: "02"
rows:
  - id: COV-02-001
    surface: "GET /api/invoices/{id}"
    surface_id: SURF-002
    check: "object_authz"
    identity: "[TENANT_A_USER]"
    state: tested
    evidence_ids: [%s]
`, strings.Join(ids, ", ")))
	for _, id := range []string{"03", "05", "06", "08", "08.5"} {
		write(dirs[id]+"/coverage.yaml", fmt.Sprintf("session: \"%s\"\nrows:\n  - id: COV-%s-001\n    surface: \"POST /api/auth/otp\"\n    surface_id: SURF-001\n    check: \"rate_limit_burst\"\n    identity: anonymous\n    state: not_tested\n    reason: \"fixture\"\n", id, id))
	}
	for _, id := range []string{"04", "08.7"} {
		write(dirs[id]+"/coverage.yaml", fmt.Sprintf("session: \"%s\"\nrows:\n  - id: COV-%s-001\n    surface: \"GET /api/invoices/{id}\"\n    check: \"object_authz\"\n    identity: anonymous\n    state: blocked\n    reason: \"plan decision blocked\"\n", id, id))
	}
	write("09-report/finding-registry.yaml", fmt.Sprintf(`generated_from: Session 09
findings:
  - id: CTRL-001
    kind: missing_control
    title: OTP send has no limiter keyed on the phone number
    category: abuse_and_cost
    status: confirmed
    confidence: high
    evidence_strength: direct
    severity: medium
    priority: P1
    affected_assets: [sandbox]
    affected_locations: ["src/lib/otp.ts:1", "POST /api/auth/otp"]
    observed_facts: [Eight requests in a burst all returned 200]
    root_cause: No limiter on the route
    security_impact: SMS cost abuse
    remediation: Add a per-number limiter
    validation_criteria: [A burst of eight is throttled by the sixth request with Retry-After]
    evidence_ids: [%s]
    evidence_categories: [ensphere_measurement, agent_judgment]
`, ids[1]))
	write("09-report/report.md", "# Assessment Report\n\n## Summary\n\nFixture.\n\n## Checks executed\n\nSee coverage.\n")
	write("09-report/evidence-appendix.md", "# Evidence Appendix\n\nClaim-to-evidence provenance.\n")
}
