package guard

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/srank-org/ensphere/internal/runner"
)

// HookOutput is the Claude Code PreToolUse hook response.
type HookOutput struct {
	HookSpecificOutput HookDecision `json:"hookSpecificOutput"`
}

type HookDecision struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

type hookInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
	Cwd string `json:"cwd"`
}

// PreToolUse reads one PreToolUse hook input and returns the response to
// print, or nil when the guard has no opinion. cwd is used when the input
// names none.
func PreToolUse(input io.Reader, cwd string, getenv func(string) string) (*HookOutput, error) {
	if getenv("ENSPHERE_GUARD") == "off" {
		return nil, nil
	}
	var in hookInput
	if err := json.NewDecoder(input).Decode(&in); err != nil {
		return nil, fmt.Errorf("decode hook input: %w", err)
	}
	if in.ToolName != "Bash" || in.ToolInput.Command == "" {
		return nil, nil
	}
	if in.Cwd != "" {
		cwd = in.Cwd
	}
	workspace, ok := runner.FindWorkspace(cwd, getenv)
	if !ok {
		return nil, nil
	}
	var approved []string
	if raw, err := os.ReadFile(runner.ConfigPath(workspace)); err == nil {
		approved = runner.SandboxCommands(string(raw))
	}
	decision := Decide(in.ToolInput.Command, approved)
	if decision.Verdict == VerdictNone {
		return nil, nil
	}
	return &HookOutput{HookSpecificOutput: HookDecision{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision.Verdict,
		PermissionDecisionReason: decision.Reason,
	}}, nil
}
