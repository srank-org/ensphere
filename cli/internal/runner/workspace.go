package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultWorkspace = "ensphere-pentest"
	statePending     = "PENDING"
	stateSkipped     = "SKIPPED"
	stateDone        = "DONE"
	stateBlocked     = "BLOCKED"
	stateNA          = "NOT_APPLICABLE"
)

func DefaultWorkspace() string { return defaultWorkspace }

func InitWorkspace(cfg InitConfig) (*Status, error) {
	if cfg.Workspace == "" {
		cfg.Workspace = defaultWorkspace
	}
	if cfg.TargetType == "" {
		cfg.TargetType = "auto"
	}
	if cfg.SourcePath == "" {
		cfg.SourcePath = "."
	}
	cfg.Environment = defaultEnvironment(cfg.Environment, cfg.TargetURL)
	if cfg.Cloud == "" {
		cfg.Cloud = "none"
	}
	if cfg.InScope == "" {
		cfg.InScope = "All network-reachable endpoints of the target application"
	}
	if cfg.OutOfScope == "" {
		cfg.OutOfScope = "Third-party services, production systems"
	}
	if fileExists(configPath(cfg.Workspace)) || fileExists(progressPath(cfg.Workspace)) {
		return nil, fmt.Errorf("workspace already initialized at %s; use ensphere run status or ensphere run next to resume", cfg.Workspace)
	}
	if err := os.MkdirAll(cfg.Workspace, 0755); err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	for _, session := range Sessions {
		if err := os.MkdirAll(filepath.Join(cfg.Workspace, session.Directory), 0755); err != nil {
			return nil, fmt.Errorf("create session directory %s: %w", session.Directory, err)
		}
	}
	if err := os.WriteFile(configPath(cfg.Workspace), []byte(renderConfig(cfg)), 0644); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}
	if err := os.WriteFile(progressPath(cfg.Workspace), []byte(renderProgress(cfg.Workspace)), 0644); err != nil {
		return nil, fmt.Errorf("write progress: %w", err)
	}
	if _, err := WriteNextAction(cfg.Workspace); err != nil {
		return nil, err
	}
	return WorkspaceStatus(cfg.Workspace)
}

func WorkspaceStatus(workspace string) (*Status, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	states, err := readProgress(workspace)
	if err != nil {
		return nil, err
	}
	next := nextSession(states)
	planSummary := loadPlanSummary(workspace)
	nextDecision, validation := planDecisionForSession(workspace, next)
	if planSummary != nil && len(validation) > 0 {
		planSummary.Validation = validation
		planSummary.Valid = false
	}
	return &Status{
		Workspace:            workspace,
		ConfigPath:           configPath(workspace),
		ProgressPath:         progressPath(workspace),
		AssessmentPlanPath:   assessmentPlanPath(workspace),
		AssessmentPlanExists: fileExists(assessmentPlanPath(workspace)),
		AssessmentPlan:       planSummary,
		NextSession:          next,
		NextPlanDecision:     nextDecision,
		Sessions:             states,
	}, nil
}

func WriteNextAction(workspace string) (*NextAction, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	status, err := WorkspaceStatus(workspace)
	if err != nil {
		return nil, err
	}
	action := &NextAction{
		Workspace:    workspace,
		Session:      status.NextSession,
		PlanDecision: status.NextPlanDecision,
		ActionPath:   filepath.Join(workspace, "next-action.md"),
		PromptPath:   filepath.Join(workspace, "agent-prompt.md"),
	}
	if status.AssessmentPlan != nil {
		action.PlanValidation = status.AssessmentPlan.Validation
	}
	if status.NextSession == nil {
		action.Message = "No next session. The assessment is complete."
	} else {
		action.Message = fmt.Sprintf("Next session: %s - %s", status.NextSession.ID, status.NextSession.Name)
	}
	if err := os.WriteFile(action.ActionPath, []byte(renderNextAction(action)), 0644); err != nil {
		return nil, fmt.Errorf("write next action: %w", err)
	}
	if err := os.WriteFile(action.PromptPath, []byte(renderAgentPrompt(action)), 0644); err != nil {
		return nil, fmt.Errorf("write agent prompt: %w", err)
	}
	return action, nil
}

func renderConfig(cfg InitConfig) string {
	return fmt.Sprintf(`# Assessment Configuration

## Target
- URL: %s
- Environment: %s
- Source path: %s
- Target type: %s
- Cloud: %s

## Authentication
- Login URL: %s
- Username: %s
- Password: %s
- (Add additional accounts and a second tenant for authorization and rate-limit key testing)

## Scope
- In scope: %s
- Out of scope: %s
- Rules to avoid: no load testing, no data destruction
- Approved rate-limit bursts: %s
- Approved upload sizes: %s
- Areas to focus:

## Authorization
This assessment is authorized against the environment named above by its owner.
It does not authorize exploitation, data extraction, or testing of any other system.
`, cfg.TargetURL, cfg.Environment, cfg.SourcePath, cfg.TargetType, cfg.Cloud, cfg.LoginURL, cfg.Username, cfg.Password, cfg.InScope, cfg.OutOfScope, cfg.ApprovedBursts, cfg.ApprovedUploadSizes)
}

func renderProgress(workspace string) string {
	var b strings.Builder
	b.WriteString("# Assessment Progress\n\n")
	b.WriteString(fmt.Sprintf("**Assessment Plan**: %s\n\n", assessmentPlanPath(workspace)))
	b.WriteString("| Session | Category | Status | Findings |\n")
	b.WriteString("|---------|----------|--------|----------|\n")
	for _, session := range Sessions {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | |\n", session.ID, session.Name, statePending))
	}
	return b.String()
}

func renderNextAction(action *NextAction) string {
	if action.Session == nil {
		return "# Next Action\n\nNo next session. The assessment is complete.\n"
	}
	var planBlock string
	if action.PlanDecision != nil {
		planBlock = fmt.Sprintf(`
## Assessment Plan Decision
- **Session Key**: %s
- **Decision**: %s
- **Applicability**: %s
- **Coverage Label**: %s
- **Reason**: %s
`, action.PlanDecision.SessionKey, action.PlanDecision.Decision, action.PlanDecision.Applicability, action.PlanDecision.CoverageLabel, action.PlanDecision.Reason)
		if len(action.PlanDecision.RequiredInput) > 0 {
			planBlock += "- **Required Input**:\n"
			for _, item := range action.PlanDecision.RequiredInput {
				planBlock += fmt.Sprintf("  - %s\n", item)
			}
		}
		if len(action.PlanDecision.Checklists) > 0 {
			planBlock += "- **Checklists**:\n"
			for _, item := range action.PlanDecision.Checklists {
				planBlock += fmt.Sprintf("  - skills/checklists/%s.md\n", item)
			}
		}
	} else if len(action.PlanValidation) > 0 {
		planBlock = "\n## Assessment Plan Validation\n"
		for _, issue := range action.PlanValidation {
			planBlock += fmt.Sprintf("- %s\n", issue)
		}
	}
	instruction := `Open the Ensphere skill, read the methodology file above and the checklists
listed for this session, and run the session against the configured target.
Keep evidence factual, update progress when the session completes, then run
ensphere run next and continue with the next session unless a human gate
applies.`
	return fmt.Sprintf(`# Next Action

## Session
- **ID**: %s
- **Name**: %s
- **Methodology**: %s
- **Directory**: %s
- **Generated**: %s
%s

## Instruction
%s
`, action.Session.ID, action.Session.Name, action.Session.Methodology, action.Session.Directory, time.Now().UTC().Format(time.RFC3339), planBlock, instruction)
}

func renderAgentPrompt(action *NextAction) string {
	if action.Session == nil {
		return "ensphere status\n"
	}
	return fmt.Sprintf("ensphere %s\n\nRead %s and execute the session using %s and %s.\n", action.Session.ID, action.Session.Methodology, configPath(action.Workspace), progressPath(action.Workspace))
}

func readProgress(workspace string) (map[string]string, error) {
	raw, err := os.ReadFile(progressPath(workspace))
	if err != nil {
		return nil, fmt.Errorf("read progress: %w", err)
	}
	states := make(map[string]string, len(Sessions))
	for _, session := range Sessions {
		states[session.ID] = statePending
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || strings.Contains(line, "---") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}
		id := strings.TrimSpace(parts[1])
		if id == "Session" {
			continue
		}
		status := strings.TrimSpace(parts[3])
		if id != "" && status != "" {
			states[id] = status
		}
	}
	return states, nil
}

func cleanStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
	}
	return cleaned
}

func nextSession(states map[string]string) *Session {
	for _, session := range Sessions {
		state := strings.ToUpper(states[session.ID])
		switch state {
		case stateDone, stateSkipped, stateBlocked, stateNA:
			continue
		default:
			s := session
			return &s
		}
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func configPath(workspace string) string   { return filepath.Join(workspace, "config.md") }
func progressPath(workspace string) string { return filepath.Join(workspace, "progress.md") }
func assessmentPlanPath(workspace string) string {
	return filepath.Join(workspace, "assessment-plan.yaml")
}
