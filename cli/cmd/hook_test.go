package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func hookInputJSON(command, cwd string) string {
	return fmt.Sprintf(`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":%s},"cwd":%s}`, strconv.Quote(command), strconv.Quote(cwd))
}

func initCLIWorkspaceIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	workspace := filepath.Join(dir, "ensphere-pentest")
	result := runCLISplit(t, append([]string{"run", "--workspace", workspace, "init"}, args...)...)
	if result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	return workspace
}

func TestCLIHookPreToolUse(t *testing.T) {
	project := t.TempDir()
	initCLIWorkspaceIn(t, project, "--target", "http://localhost:3000")

	deny := runCLIIn(t, project, hookInputJSON("curl http://localhost:3000/", project), "hook", "pre-tool-use")
	if deny.code != 0 {
		t.Fatalf("deny exit %d stderr=%s", deny.code, deny.stderr)
	}
	var out struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	decodeJSON(t, deny.stdout, &out)
	if out.HookSpecificOutput.HookEventName != "PreToolUse" || out.HookSpecificOutput.PermissionDecision != "deny" ||
		!strings.HasPrefix(out.HookSpecificOutput.PermissionDecisionReason, "Ensphere guard: `curl` is a raw network tool") {
		t.Fatalf("unexpected deny output: %s", deny.stdout)
	}

	allow := runCLIIn(t, project, hookInputJSON("ensphere verify request --url http://localhost:3000/ --in-scope localhost", project), "hook", "pre-tool-use")
	if allow.code != 0 {
		t.Fatalf("allow exit %d stderr=%s", allow.code, allow.stderr)
	}
	decodeJSON(t, allow.stdout, &out)
	if out.HookSpecificOutput.PermissionDecision != "allow" || out.HookSpecificOutput.PermissionDecisionReason != "Ensphere guard: ensphere command" {
		t.Fatalf("unexpected allow output: %s", allow.stdout)
	}

	none := runCLIIn(t, project, hookInputJSON("ls -la", project), "hook", "pre-tool-use")
	if none.code != 0 || none.stdout != "" {
		t.Fatalf("expected no output for ls, exit %d stdout=%q", none.code, none.stdout)
	}

	elsewhere := t.TempDir()
	outside := runCLIIn(t, elsewhere, hookInputJSON("curl http://localhost:3000/", elsewhere), "hook", "pre-tool-use")
	if outside.code != 0 || outside.stdout != "" {
		t.Fatalf("expected no output without a workspace, exit %d stdout=%q", outside.code, outside.stdout)
	}

	malformed := runCLIIn(t, project, "not json", "hook", "pre-tool-use")
	if malformed.code != 0 || malformed.stdout != "" {
		t.Fatalf("expected malformed input to pass silently with exit 0, exit %d stdout=%q", malformed.code, malformed.stdout)
	}
}

func TestCLIHookSessionStart(t *testing.T) {
	project := t.TempDir()
	workspace, err := filepath.EvalSymlinks(initCLIWorkspaceIn(t, project, "--target", "http://localhost:3000"))
	if err != nil {
		t.Fatal(err)
	}

	with := runCLIIn(t, project, `{"hook_event_name":"SessionStart"}`, "hook", "session-start", "--plugin-version", "0.2.0")
	if with.code != 0 {
		t.Fatalf("session-start exit %d stderr=%s", with.code, with.stderr)
	}
	if !strings.HasPrefix(with.stdout, "Ensphere assessment workspace: "+workspace+"\n# Next Action") ||
		!strings.Contains(with.stdout, "\nProgress: 01 PENDING,") ||
		!strings.Contains(with.stdout, "plugin is v0.2.0") {
		t.Fatalf("unexpected session-start output:\n%s", with.stdout)
	}

	without := runCLIIn(t, t.TempDir(), `{}`, "hook", "session-start", "--plugin-version", "0.2.0")
	if without.code != 0 || without.stdout != "" {
		t.Fatalf("expected no output without a workspace, exit %d stdout=%q", without.code, without.stdout)
	}
}

func TestCLIVerifyRefusesScopeOutsideWorkspaceApproval(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	unapproved := t.TempDir()
	initCLIWorkspaceIn(t, unapproved, "--target", "http://sandbox.test", "--in-scope", "sandbox.test")
	args := []string{"verify", "cors", "--url", server.URL + "/", "--in-scope", "127.0.0.1", "--throttle", "0", "--evidence", filepath.Join(t.TempDir(), "evidence.jsonl")}
	refused := runCLIIn(t, unapproved, "", args...)
	if refused.code != 2 {
		t.Fatalf("expected exit 2, got %d stderr=%s", refused.code, refused.stderr)
	}
	if !strings.Contains(refused.stderr, "--in-scope 127.0.0.1 is not in the workspace scope approved in") ||
		!strings.Contains(refused.stderr, "(sandbox.test); scope is operator-approved there, not on the command line") {
		t.Fatalf("unexpected refusal message: %s", refused.stderr)
	}
	if hits.Load() != 0 {
		t.Fatalf("a refused command sent %d requests", hits.Load())
	}

	approved := t.TempDir()
	initCLIWorkspaceIn(t, approved, "--target", server.URL, "--in-scope", "127.0.0.1")
	proceeded := runCLIIn(t, approved, "", args...)
	if proceeded.code != 0 {
		t.Fatalf("expected the approved scope to proceed, exit %d stderr=%s", proceeded.code, proceeded.stderr)
	}
	if hits.Load() == 0 {
		t.Fatal("the approved command sent no request")
	}

	outOfScope := runCLIIn(t, approved, "", "verify", "cors", "--url", "http://example.com/", "--in-scope", "127.0.0.1", "--evidence", filepath.Join(t.TempDir(), "evidence.jsonl"))
	if outOfScope.code != 2 || !strings.Contains(outOfScope.stderr, "is not in scope") {
		t.Fatalf("expected the normal scope check after approval, exit %d stderr=%s", outOfScope.code, outOfScope.stderr)
	}

	sourceOnly := t.TempDir()
	initCLIWorkspaceIn(t, sourceOnly)
	empty := runCLIIn(t, sourceOnly, "", args...)
	if empty.code != 2 || !strings.Contains(empty.stderr, "has no live-target scope; a source-only assessment sends no requests") {
		t.Fatalf("expected the source-only refusal, exit %d stderr=%s", empty.code, empty.stderr)
	}
}

func TestCLIRunInitRejectsMalformedScope(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "http://localhost", "--in-scope", "a b")
	if result.code != 2 {
		t.Fatalf("expected usage exit 2, got %d stderr=%s", result.code, result.stderr)
	}
	if !strings.HasPrefix(result.stderr, `usage error: invalid --in-scope: "a b" is not a host pattern`) || strings.Count(result.stderr, "usage error") != 1 {
		t.Fatalf("expected one usage error prefix and the token, got %s", result.stderr)
	}
	if !strings.Contains(result.stderr, "comma-separated list of hostnames, globs, IPs, or CIDRs") {
		t.Fatalf("expected the expected form in the message, got %s", result.stderr)
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatalf("a rejected init wrote the workspace: %v", err)
	}
}

func TestCLIRunInitSandboxFlagsApproveGuardCommands(t *testing.T) {
	project := t.TempDir()
	start := "docker compose -f compose.sandbox.yml up -d --wait"
	initCLIWorkspaceIn(t, project, "--target", "http://localhost:3000",
		"--sandbox-start", start,
		"--sandbox-seed", "npm run seed",
		"--sandbox-reset", "npm run reset",
	)
	raw, err := os.ReadFile(filepath.Join(project, "ensphere-pentest", "config.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "## Sandbox\n- Start: "+start+"\n- Seed: npm run seed\n- Reset: npm run reset\n") {
		t.Fatalf("config.md lacks the Sandbox section:\n%s", raw)
	}
	for _, command := range []string{start, "npm run seed", "npm run reset"} {
		result := runCLIIn(t, project, hookInputJSON(command, project), "hook", "pre-tool-use")
		if result.code != 0 || !strings.Contains(result.stdout, "Ensphere guard: sandbox command approved in config.md") {
			t.Fatalf("expected %q to be allowed, exit %d stdout=%s", command, result.code, result.stdout)
		}
	}
	appended := runCLIIn(t, project, hookInputJSON("npm run seed && curl x", project), "hook", "pre-tool-use")
	if !strings.Contains(appended.stdout, `"permissionDecision": "deny"`) {
		t.Fatalf("expected text appended to an approved command to be judged on its own, got %s", appended.stdout)
	}
}
