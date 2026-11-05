package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var sandboxCommandLine = regexp.MustCompile(`^-\s+[A-Za-z]+:\s*(.+)$`)
var releaseVersion = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// FindWorkspace returns the first workspace directory holding a config.md:
// $ENSPHERE_WORKSPACE, then <cwd>/ensphere-pentest, then
// <CLAUDE_PROJECT_DIR>/ensphere-pentest.
func FindWorkspace(cwd string, getenv func(string) string) (string, bool) {
	candidates := []string{getenv("ENSPHERE_WORKSPACE")}
	if cwd != "" {
		candidates = append(candidates, filepath.Join(cwd, defaultWorkspace))
	}
	if dir := getenv("CLAUDE_PROJECT_DIR"); dir != "" {
		candidates = append(candidates, filepath.Join(dir, defaultWorkspace))
	}
	for _, candidate := range candidates {
		if candidate != "" && fileExists(configPath(candidate)) {
			return candidate, true
		}
	}
	return "", false
}

// ConfigPath returns the path of a workspace's config.md.
func ConfigPath(workspace string) string { return configPath(workspace) }

// SandboxCommands returns the operator-approved commands listed as
// "- <Label>: <command>" under the ## Sandbox heading of a config.md.
func SandboxCommands(configMarkdown string) []string {
	var commands []string
	inSandbox := false
	for _, line := range strings.Split(configMarkdown, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "## ") {
			inSandbox = strings.TrimSpace(strings.TrimPrefix(line, "## ")) == "Sandbox"
			continue
		}
		if !inSandbox {
			continue
		}
		if match := sandboxCommandLine.FindStringSubmatch(line); match != nil {
			if command := strings.TrimSpace(match[1]); command != "" {
				commands = append(commands, command)
			}
		}
	}
	return commands
}

// SessionStartContext is the text a Claude Code SessionStart hook adds to a
// session that opens inside an assessment: where the workspace is, the next
// action, progress, and whether the binary matches the plugin.
func SessionStartContext(workspace, binaryVersion, pluginVersion string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Ensphere assessment workspace: %s\n", workspace)
	if action, err := os.ReadFile(filepath.Join(workspace, "next-action.md")); err == nil {
		b.Write(action)
		if !strings.HasSuffix(string(action), "\n") {
			b.WriteString("\n")
		}
	} else {
		b.WriteString("No next-action.md yet; run ensphere run status.\n")
	}
	if states, err := readProgress(workspace); err == nil {
		parts := make([]string, 0, len(Sessions))
		for _, session := range Sessions {
			parts = append(parts, session.ID+" "+states[session.ID])
		}
		fmt.Fprintf(&b, "Progress: %s\n", strings.Join(parts, ", "))
	}
	b.WriteString(versionLine(binaryVersion, pluginVersion))
	b.WriteString("\n")
	return b.String()
}

func versionLine(binaryVersion, pluginVersion string) string {
	binary := strings.TrimPrefix(strings.TrimSpace(binaryVersion), "v")
	plugin := strings.TrimPrefix(strings.TrimSpace(pluginVersion), "v")
	if binaryVersion == "" {
		binaryVersion = `""`
	}
	switch {
	case !releaseVersion.MatchString(binary):
		return fmt.Sprintf("ensphere binary reports %s, which is not a release version; plugin is v%s. Run the ensphere-setup skill to install the matching release.", binaryVersion, plugin)
	case binary == plugin:
		return fmt.Sprintf("ensphere v%s matches plugin v%s.", binary, plugin)
	default:
		return fmt.Sprintf("ensphere binary v%s does not match plugin v%s. Run the ensphere-setup skill before continuing the assessment.", binary, plugin)
	}
}
