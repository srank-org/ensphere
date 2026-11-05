package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecide(t *testing.T) {
	approved := []string{"docker compose up -d --wait", "  npm run seed  "}
	cases := []struct {
		name      string
		command   string
		verdict   string
		offending string
	}{
		{"ensphere command", "ensphere verify request --url http://localhost:3000/ --in-scope localhost", VerdictAllow, ""},
		{"ensphere by path", "./bin/ensphere evidence log --note x", VerdictAllow, ""},
		{"ensphere chain", "ensphere run status && ensphere run next", VerdictAllow, ""},
		{"approved sandbox command", "docker compose up -d --wait", VerdictAllow, ""},
		{"approved sandbox command trimmed", "  npm run seed\n", VerdictAllow, ""},
		{"approved sandbox command with text appended", "docker compose up -d --wait && echo ok", VerdictNone, ""},
		{"ensphere piped to jq", "ensphere run status | jq .", VerdictNone, ""},
		{"ls", "ls -la", VerdictNone, ""},
		{"git status", "git status", VerdictNone, ""},
		{"psql", "psql -c 'select 1'", VerdictNone, ""},
		{"python script", "python3 script.py", VerdictNone, ""},
		{"python module on stdin", "cat x.json | python3 -m json.tool", VerdictNone, ""},
		{"docker compose ps", "docker compose ps", VerdictNone, ""},
		{"openssl x509", "openssl x509 -in f", VerdictNone, ""},
		{"command -v", "command -v curl", VerdictNone, ""},
		{"quoted curl is data", "echo 'curl x' > notes.txt", VerdictNone, ""},
		{"comment", "ls # then curl x", VerdictNone, ""},
		{"heredoc commit message", "git commit -m \"$(cat <<'EOF'\nit's done (really)\nEOF\n)\"", VerdictNone, ""},
		{"stderr redirect", "make test 2>&1 | tail -5", VerdictNone, ""},
		{"curl", "curl x", VerdictDeny, "curl"},
		{"curl by path", "/usr/bin/curl x", VerdictDeny, "curl"},
		{"curl after and", "ls && curl x", VerdictDeny, "curl"},
		{"curl after semicolon", "ls; wget x", VerdictDeny, "wget"},
		{"curl in background", "sleep 1 & nc -l 80", VerdictDeny, "nc"},
		{"command substitution", "echo $(curl x)", VerdictDeny, "curl"},
		{"command substitution in double quotes", `echo "$(curl x)"`, VerdictDeny, "curl"},
		{"backticks", "echo `wget x`", VerdictDeny, "wget"},
		{"bash -c", `bash -c "curl x"`, VerdictDeny, "curl"},
		{"sh -ec", `sh -ec 'ls; nmap h'`, VerdictDeny, "nmap"},
		{"env assignment", "FOO=1 curl x", VerdictDeny, "curl"},
		{"sudo", "sudo curl x", VerdictDeny, "curl"},
		{"sudo -u", "sudo -u alice curl x", VerdictDeny, "curl"},
		{"timeout", "timeout 5 curl x", VerdictDeny, "curl"},
		{"env wrapper", "env -i FOO=1 nohup curl x", VerdictDeny, "curl"},
		{"subshell", "(cd /tmp && curl x)", VerdictDeny, "curl"},
		{"if keyword", "if curl x; then echo up; fi", VerdictDeny, "curl"},
		{"unquoted heredoc substitution", "cat <<EOF\n$(curl x)\nEOF", VerdictDeny, "curl"},
		{"find -exec", "find . -name '*.txt' -exec curl -d @{} x \\;", VerdictDeny, "curl"},
		{"python -c", "python3 -c 'print(1)'", VerdictDeny, "python3 -c"},
		{"node -e", "node -e 'x'", VerdictDeny, "node -e"},
		{"node -pe", "node -pe 'x'", VerdictDeny, "node -pe"},
		{"perl -ne", "perl -ne 'print' f", VerdictDeny, "perl -ne"},
		{"deno eval", "deno eval 'x'", VerdictDeny, "deno eval"},
		{"python on piped stdin", "echo 'import urllib' | python3", VerdictDeny, "python3"},
		{"shell on piped stdin", "echo 'curl x' | bash", VerdictDeny, "bash"},
		{"openssl s_client", "openssl s_client -connect h:443", VerdictDeny, "openssl s_client"},
		{"eval", `eval "$x"`, VerdictDeny, "eval"},
		{"xargs", "xargs curl", VerdictDeny, "xargs"},
		{"source", "source env.sh", VerdictDeny, "source"},
		{"dot", ". env.sh", VerdictDeny, "."},
		{"variable command word", "$TOOL http://x", VerdictDeny, "$TOOL"},
		{"process substitution", "diff <(ls a) <(ls b)", VerdictDeny, "<("},
		{"unterminated single quote", "echo 'abc", VerdictDeny, "'abc"},
		{"unterminated double quote", `echo "abc`, VerdictDeny, `"abc`},
		{"unterminated substitution", "echo $(ls", VerdictDeny, "$("},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(tc.command, approved)
			if got.Verdict != tc.verdict {
				t.Fatalf("Decide(%q) verdict = %q (%s), want %q", tc.command, got.Verdict, got.Reason, tc.verdict)
			}
			if got.Offending != tc.offending {
				t.Fatalf("Decide(%q) offending = %q, want %q", tc.command, got.Offending, tc.offending)
			}
			switch got.Verdict {
			case VerdictDeny:
				if !strings.HasPrefix(got.Reason, "Ensphere guard: `"+tc.offending+"` ") || !strings.Contains(got.Reason, "ENSPHERE_GUARD=off") {
					t.Fatalf("deny reason does not name %q and the way forward: %s", tc.offending, got.Reason)
				}
			case VerdictAllow:
				if got.Reason != reasonEnsphere && got.Reason != reasonSandbox {
					t.Fatalf("unexpected allow reason %q", got.Reason)
				}
			case VerdictNone:
				if got.Reason != "" {
					t.Fatalf("none carries a reason: %q", got.Reason)
				}
			}
		})
	}
}

func TestDecideReasonNamesTheKindOfRefusal(t *testing.T) {
	cases := map[string]string{
		"curl x":                  "is a raw network tool",
		"python3 -c 'print(1)'":   "runs inline code that the guard cannot check",
		"xargs curl":              "cannot be checked by the guard",
		"docker compose up -d":    "",
		"ensphere run status":     "",
		"ensphere run status; ls": "",
	}
	for command, phrase := range cases {
		got := Decide(command, nil)
		if phrase == "" {
			if strings.Contains(got.Reason, "guard cannot") || strings.Contains(got.Reason, "raw network") {
				t.Fatalf("Decide(%q) refused: %s", command, got.Reason)
			}
			continue
		}
		if !strings.Contains(got.Reason, phrase) {
			t.Fatalf("Decide(%q) reason %q lacks %q", command, got.Reason, phrase)
		}
	}
}

func TestPreToolUse(t *testing.T) {
	project := t.TempDir()
	workspace := filepath.Join(project, "ensphere-pentest")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	config := "# Assessment Configuration\n\n## Sandbox\n- Start: docker compose up -d --wait\n\n## Scope\n- In scope: localhost\n"
	if err := os.WriteFile(filepath.Join(workspace, "config.md"), []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	getenv := func(key string) string { return env[key] }
	input := func(tool, command, cwd string) *strings.Reader {
		return strings.NewReader(`{"session_id":"s","tool_name":"` + tool + `","tool_input":{"command":` + quoteJSON(command) + `,"description":"d"},"cwd":"` + cwd + `"}`)
	}

	out, err := PreToolUse(input("Bash", "curl x", project), "", getenv)
	if err != nil || out == nil || out.HookSpecificOutput.PermissionDecision != VerdictDeny || out.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Fatalf("expected deny, got %+v err=%v", out, err)
	}
	out, err = PreToolUse(input("Bash", "docker compose up -d --wait", project), "", getenv)
	if err != nil || out == nil || out.HookSpecificOutput.PermissionDecision != VerdictAllow {
		t.Fatalf("expected allow for the approved sandbox command, got %+v err=%v", out, err)
	}
	out, err = PreToolUse(input("Bash", "ls", project), "", getenv)
	if err != nil || out != nil {
		t.Fatalf("expected no opinion for ls, got %+v err=%v", out, err)
	}
	out, err = PreToolUse(input("Read", "curl x", project), "", getenv)
	if err != nil || out != nil {
		t.Fatalf("expected no opinion for a non-Bash tool, got %+v err=%v", out, err)
	}
	out, err = PreToolUse(input("Bash", "curl x", t.TempDir()), "", getenv)
	if err != nil || out != nil {
		t.Fatalf("expected no opinion outside a workspace, got %+v err=%v", out, err)
	}
	out, err = PreToolUse(input("Bash", "curl x", ""), project, getenv)
	if err != nil || out == nil {
		t.Fatalf("expected the fallback cwd to find the workspace, got %+v err=%v", out, err)
	}
	env["ENSPHERE_GUARD"] = "off"
	out, err = PreToolUse(input("Bash", "curl x", project), "", getenv)
	if err != nil || out != nil {
		t.Fatalf("expected no opinion with the guard off, got %+v err=%v", out, err)
	}
}

func quoteJSON(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}
