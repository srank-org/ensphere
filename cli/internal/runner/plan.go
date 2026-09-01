package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	decisionRun           = "run"
	decisionSkip          = "skip"
	decisionLimited       = "limited"
	decisionBlocked       = "blocked"
	decisionUncertain     = "uncertain"
	decisionNotApplicable = "not_applicable"

	applicabilityApplicable    = "applicable"
	applicabilityUncertain     = "uncertain"
	applicabilityNotApplicable = "not_applicable"

	coverageFull       = "full"
	coveragePartial    = "partial"
	coverageBlocked    = "blocked"
	coverageSourceOnly = "source_only"
	coverageClientOnly = "client_only"
	coverageCloudOnly  = "cloud_only"
)

var planSessionKeys = []string{
	"02-injection",
	"03-auth",
	"04-authz",
	"05-xss",
	"06-ssrf",
	"07-cloud",
	"08-api",
	"08.5-abuse",
	"08.7-chains",
}

var checklistNamePattern = regexp.MustCompile(`^[a-z0-9-]+$`)
var stackValuePattern = regexp.MustCompile(`^[a-z0-9_]+$`)

func RunPlan(workspace string, force bool) (*PlanOutput, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	if err := ensureWorkspaceInitialized(workspace); err != nil {
		return nil, err
	}

	path := assessmentPlanPath(workspace)
	mirrorPath := assessmentPlanMirrorPath(workspace)
	written := false

	var plan *AssessmentPlan
	if fileExists(path) && !force {
		existing, err := ReadAssessmentPlan(path)
		if err != nil {
			return &PlanOutput{
				Workspace:  workspace,
				PlanPath:   path,
				MirrorPath: mirrorPath,
				Written:    false,
				Valid:      false,
				Validation: []string{err.Error()},
				Message:    "Existing assessment plan could not be parsed. Use --force to regenerate a draft from config.",
			}, nil
		}
		plan = existing
		if err := mirrorExistingAssessmentPlan(path, mirrorPath); err != nil {
			return nil, err
		}
	} else {
		cfg, err := readConfig(workspace)
		if err != nil {
			return nil, err
		}
		plan = BuildAssessmentPlan(cfg, workspace)
		if err := writeAssessmentPlan(workspace, plan); err != nil {
			return nil, err
		}
		written = true
	}

	validation := ValidateAssessmentPlan(plan)
	validation = append(validation, validateReconTargetProfileFile(workspace)...)
	sort.Strings(validation)
	message := "Existing assessment plan validated."
	if written {
		message = "Draft assessment plan written. Session 01.5 should review and update it after Recon evidence."
	} else if len(validation) > 0 {
		message = "Existing assessment plan has validation issues."
	}

	action, err := WriteNextAction(workspace)
	if err != nil {
		return nil, err
	}

	out := &PlanOutput{
		Workspace:  workspace,
		PlanPath:   path,
		MirrorPath: mirrorPath,
		Written:    written,
		Valid:      len(validation) == 0,
		Validation: validation,
		Message:    message,
		Plan:       plan,
	}
	out.NextActionPath = action.ActionPath
	out.PromptPath = action.PromptPath
	return out, nil
}

func BuildAssessmentPlan(cfg InitConfig, workspace string) *AssessmentPlan {
	profile, _ := readReconTargetProfile(reconTargetProfilePath(workspace))
	targetType := normalizeTargetType(cfg.TargetType)
	liveTarget := strings.TrimSpace(cfg.TargetURL) != ""
	cloud := parseList(cfg.Cloud)
	scope := parseList(cfg.InScope)
	if len(scope) == 0 {
		scope = []string{cfg.InScope}
	}
	coverage := targetCoverageLabel(targetType, liveTarget)
	if cfg.InScope == "" {
		scope = []string{"All network-reachable endpoints of the target application"}
	}
	classificationSource := "config"
	classificationConfidence := "low"
	rationale := []string{
		"Deterministic runner draft derived from config.md only.",
		"Session 01.5 must update decisions after Recon evidence.",
	}
	var backendInventory []BackendInventoryEntry
	var clientExposureReview []string
	var signals *TargetSignals
	var stack *StackProfile
	if profile != nil && validTargetType(profile.Target.Type) {
		targetType = normalizeTargetType(profile.Target.Type)
		coverage = targetCoverageLabel(targetType, liveTarget)
		if validCoverageLabel(profile.Target.CoverageLabel) {
			coverage = profile.Target.CoverageLabel
		}
		classificationSource = "01-recon/target-profile.yaml"
		classificationConfidence = strings.TrimSpace(profile.Target.ClassificationConfidence)
		rationale = append([]string{}, profile.Target.Rationale...)
		if len(profile.Target.EvidenceRefs) > 0 {
			rationale = append(rationale, "Evidence: "+strings.Join(profile.Target.EvidenceRefs, ", "))
		}
		if len(rationale) == 0 {
			rationale = []string{"Session 01 target profile supplied target classification without rationale."}
		}
		backendInventory = profile.BackendInventory
		clientExposureReview = cleanStrings(profile.ClientExposureReview)
		signalsCopy := profile.Signals
		signals = &signalsCopy
		if profile.Stack != nil {
			stackCopy := *profile.Stack
			stack = &stackCopy
		}
	}

	environment := strings.TrimSpace(cfg.Environment)
	profileEnvironment := ""
	if profile != nil {
		profileEnvironment = strings.TrimSpace(profile.Target.Environment)
	}
	if validEnvironment(profileEnvironment) {
		environment = profileEnvironment
	}

	hasCredentials := strings.TrimSpace(cfg.Username) != "" || strings.TrimSpace(cfg.Password) != "" || strings.TrimSpace(cfg.LoginURL) != ""
	plan := &AssessmentPlan{
		Draft: true,
		Target: PlanTarget{
			Type:                     targetType,
			URL:                      cfg.TargetURL,
			Environment:              environment,
			CoverageLabel:            coverage,
			ClassificationSource:     classificationSource,
			ClassificationConfidence: classificationConfidence,
			ReconProfilePath:         profilePathForPlan(workspace, profile),
			Cloud:                    cloud,
			Scope:                    scope,
			Rationale:                rationale,
			BackendInventory:         backendInventory,
			ClientExposureReview:     clientExposureReview,
			Signals:                  signals,
			Stack:                    stack,
		},
		Checklists:     []string{},
		UncoveredStack: []string{},
		Sessions:       make(map[string]PlanSession, len(planSessionKeys)),
		HumanOverrides: []string{},
		CreatedBy:      "Ensphere runner deterministic draft",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}

	for _, key := range planSessionKeys {
		plan.Sessions[key] = draftSessionDecision(key, targetType, profileEnvironment, liveTarget, cloud, hasCredentials)
	}
	applyReconProfileDecisions(plan, profile, hasCredentials, cloud)
	return plan
}

func validateChecklistNames(field string, names []string) []string {
	var problems []string
	for _, name := range names {
		if !checklistNamePattern.MatchString(strings.TrimSpace(name)) {
			problems = append(problems, fmt.Sprintf("%s entry %q must be a lowercase checklist file name without the .md suffix", field, name))
		}
	}
	return problems
}

func validateStackProfile(field string, stack *StackProfile) []string {
	if stack == nil {
		return nil
	}
	var problems []string
	lists := map[string][]string{
		"languages":                stack.Languages,
		"frameworks":               stack.Frameworks,
		"data_layers":              stack.DataLayers,
		"auth_providers":           stack.AuthProviders,
		"hosting":                  stack.Hosting,
		"storage":                  stack.Storage,
		"edge":                     stack.Edge,
		"billing_exposed_services": stack.BillingExposedServices,
		"clients":                  stack.Clients,
	}
	populated := false
	for name, values := range lists {
		for _, value := range values {
			populated = true
			if !stackValuePattern.MatchString(strings.TrimSpace(value)) {
				problems = append(problems, fmt.Sprintf("%s.%s value %q must be a lowercase identifier (letters, digits, underscore)", field, name, value))
			}
		}
	}
	if populated && len(stack.EvidenceRefs) == 0 {
		problems = append(problems, field+".evidence_refs is required when any stack value is recorded")
	}
	problems = append(problems, validateWorkspaceRelativeRefs(field+".evidence_refs", stack.EvidenceRefs)...)
	return problems
}

func stackValues(stack *StackProfile) []string {
	if stack == nil {
		return nil
	}
	var values []string
	for _, list := range [][]string{stack.Languages, stack.Frameworks, stack.DataLayers, stack.AuthProviders, stack.Hosting, stack.Storage, stack.Edge, stack.BillingExposedServices, stack.Clients} {
		values = append(values, list...)
	}
	return cleanStrings(values)
}

func ReadAssessmentPlan(path string) (*AssessmentPlan, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read assessment plan: %w", err)
	}
	var plan AssessmentPlan
	if err := decodeStrictYAML(raw, &plan); err != nil {
		return nil, fmt.Errorf("parse assessment plan: %w", err)
	}
	return &plan, nil
}

func ValidateAssessmentPlan(plan *AssessmentPlan) []string {
	if plan == nil {
		return []string{"assessment plan is nil"}
	}
	var problems []string
	if !validTargetType(plan.Target.Type) {
		problems = append(problems, fmt.Sprintf("target.type %q is invalid", plan.Target.Type))
	}
	if plan.Target.URL == "" && !coverageAllowsNoLiveTarget(plan.Target.CoverageLabel) {
		problems = append(problems, "target.url is required unless target.coverage_label is source_only, client_only, or cloud_only")
	}
	if !validCoverageLabel(plan.Target.CoverageLabel) {
		problems = append(problems, fmt.Sprintf("target.coverage_label %q is invalid", plan.Target.CoverageLabel))
	}
	problems = append(problems, validatePlanEnvironment(plan.Target.Environment, plan.Target.URL)...)
	if plan.Target.ClassificationConfidence != "" && !validClassificationConfidence(plan.Target.ClassificationConfidence) {
		problems = append(problems, fmt.Sprintf("target.classification_confidence %q is invalid", plan.Target.ClassificationConfidence))
	}
	for i, backend := range plan.Target.BackendInventory {
		ref := fmt.Sprintf("target.backend_inventory[%d]", i)
		if strings.TrimSpace(backend.Name) == "" {
			problems = append(problems, ref+".name is required")
		}
		if strings.TrimSpace(backend.BaseURL) == "" {
			problems = append(problems, ref+".base_url is required")
		}
		if strings.TrimSpace(backend.Kind) == "" {
			problems = append(problems, ref+".kind is required")
		}
		if strings.TrimSpace(backend.Source) == "" {
			problems = append(problems, ref+".source is required")
		}
		if len(backend.EvidenceRefs) == 0 {
			problems = append(problems, ref+".evidence_refs is required")
		}
		problems = append(problems, validateWorkspaceRelativeRefs(ref+".evidence_refs", backend.EvidenceRefs)...)
	}
	problems = append(problems, validateStackProfile("target.stack", plan.Target.Stack)...)
	problems = append(problems, validateChecklistNames("checklists", plan.Checklists)...)
	for _, value := range plan.UncoveredStack {
		if !stackValuePattern.MatchString(strings.TrimSpace(value)) {
			problems = append(problems, fmt.Sprintf("uncovered_stack value %q must be a lowercase identifier", value))
		}
	}
	for _, key := range planSessionKeys {
		session, ok := plan.Sessions[key]
		if !ok {
			problems = append(problems, fmt.Sprintf("sessions.%s is required", key))
			continue
		}
		if !validDecision(session.Decision) {
			problems = append(problems, fmt.Sprintf("sessions.%s.decision %q is invalid", key, session.Decision))
		}
		if !validApplicability(session.Applicability) {
			problems = append(problems, fmt.Sprintf("sessions.%s.applicability %q is invalid", key, session.Applicability))
		}
		if !validCoverageLabel(session.CoverageLabel) {
			problems = append(problems, fmt.Sprintf("sessions.%s.coverage_label %q is invalid", key, session.CoverageLabel))
		}
		if strings.TrimSpace(session.Reason) == "" {
			problems = append(problems, fmt.Sprintf("sessions.%s.reason is required", key))
		}
		if len(session.EvidenceRefs) == 0 {
			problems = append(problems, fmt.Sprintf("sessions.%s.evidence_refs is required", key))
		}
		problems = append(problems, validateWorkspaceRelativeRefs(fmt.Sprintf("sessions.%s.evidence_refs", key), session.EvidenceRefs)...)
		problems = append(problems, validateChecklistNames(fmt.Sprintf("sessions.%s.checklists", key), session.Checklists)...)
	}
	sort.Strings(problems)
	return problems
}

func readReconTargetProfile(path string) (*ReconTargetProfile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var profile ReconTargetProfile
	if err := decodeStrictYAML(raw, &profile); err != nil {
		return nil, fmt.Errorf("parse recon target profile: %w", err)
	}
	return &profile, nil
}

func validateReconTargetProfileFile(workspace string) []string {
	path := reconTargetProfilePath(workspace)
	if !fileExists(path) {
		return nil
	}
	profile, err := readReconTargetProfile(path)
	if err != nil {
		return []string{err.Error()}
	}
	return ValidateReconTargetProfile(profile)
}

func ValidateReconTargetProfile(profile *ReconTargetProfile) []string {
	if profile == nil {
		return []string{"recon target profile is nil"}
	}
	var problems []string
	if !validTargetType(profile.Target.Type) {
		problems = append(problems, fmt.Sprintf("recon target profile target.type %q is invalid", profile.Target.Type))
	}
	environment := strings.TrimSpace(profile.Target.Environment)
	if environment == "" {
		problems = append(problems, "recon target profile target.environment is required")
	} else if !validEnvironment(environment) {
		problems = append(problems, fmt.Sprintf("recon target profile target.environment %q is invalid", profile.Target.Environment))
	}
	if profile.Target.CoverageLabel != "" && !validCoverageLabel(profile.Target.CoverageLabel) {
		problems = append(problems, fmt.Sprintf("recon target profile target.coverage_label %q is invalid", profile.Target.CoverageLabel))
	}
	if strings.TrimSpace(profile.Target.ClassificationConfidence) == "" {
		problems = append(problems, "recon target profile target.classification_confidence is required")
	} else {
		confidence := strings.TrimSpace(profile.Target.ClassificationConfidence)
		if !validClassificationConfidence(confidence) {
			problems = append(problems, fmt.Sprintf("recon target profile target.classification_confidence %q is invalid", profile.Target.ClassificationConfidence))
		}
	}
	if len(profile.Target.Rationale) == 0 {
		problems = append(problems, "recon target profile target.rationale is required")
	}
	if len(profile.Target.EvidenceRefs) == 0 {
		problems = append(problems, "recon target profile target.evidence_refs is required")
	}
	problems = append(problems, validateWorkspaceRelativeRefs("recon target profile target.evidence_refs", profile.Target.EvidenceRefs)...)
	problems = append(problems, validateStackProfile("recon target profile stack", profile.Stack)...)
	for i, backend := range profile.BackendInventory {
		ref := fmt.Sprintf("recon target profile backend_inventory[%d]", i)
		if strings.TrimSpace(backend.Name) == "" {
			problems = append(problems, ref+".name is required")
		}
		if strings.TrimSpace(backend.BaseURL) == "" {
			problems = append(problems, ref+".base_url is required")
		}
		if strings.TrimSpace(backend.Kind) == "" {
			problems = append(problems, ref+".kind is required")
		}
		if strings.TrimSpace(backend.Source) == "" {
			problems = append(problems, ref+".source is required")
		}
		if len(backend.EvidenceRefs) == 0 {
			problems = append(problems, ref+".evidence_refs is required")
		}
		problems = append(problems, validateWorkspaceRelativeRefs(ref+".evidence_refs", backend.EvidenceRefs)...)
	}
	sort.Strings(problems)
	return problems
}

func writeAssessmentPlan(workspace string, plan *AssessmentPlan) error {
	raw, err := yaml.Marshal(plan)
	if err != nil {
		return fmt.Errorf("encode assessment plan: %w", err)
	}
	if err := os.WriteFile(assessmentPlanPath(workspace), raw, 0644); err != nil {
		return fmt.Errorf("write assessment plan: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(assessmentPlanMirrorPath(workspace)), 0755); err != nil {
		return fmt.Errorf("create assessment plan mirror directory: %w", err)
	}
	if err := os.WriteFile(assessmentPlanMirrorPath(workspace), raw, 0644); err != nil {
		return fmt.Errorf("write assessment plan mirror: %w", err)
	}
	return nil
}

func mirrorExistingAssessmentPlan(path, mirrorPath string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read assessment plan for mirror: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(mirrorPath), 0755); err != nil {
		return fmt.Errorf("create assessment plan mirror directory: %w", err)
	}
	if err := os.WriteFile(mirrorPath, raw, 0644); err != nil {
		return fmt.Errorf("write assessment plan mirror: %w", err)
	}
	return nil
}

func loadPlanSummary(workspace string) *PlanSummary {
	path := assessmentPlanPath(workspace)
	if !fileExists(path) {
		return &PlanSummary{Exists: false}
	}
	plan, err := ReadAssessmentPlan(path)
	if err != nil {
		return &PlanSummary{
			Exists:     true,
			Valid:      false,
			Validation: []string{err.Error()},
		}
	}
	validation := ValidateAssessmentPlan(plan)
	decisions := make(map[string]string, len(plan.Sessions))
	for _, key := range planSessionKeys {
		if session, ok := plan.Sessions[key]; ok {
			decisions[key] = session.Decision
		}
	}
	return &PlanSummary{
		Exists:           true,
		Valid:            len(validation) == 0,
		Validation:       validation,
		TargetType:       plan.Target.Type,
		Environment:      plan.Target.Environment,
		CoverageLabel:    plan.Target.CoverageLabel,
		Checklists:       plan.Checklists,
		SessionDecisions: decisions,
	}
}

func planDecisionForSession(workspace string, session *Session) (*PlanDecisionView, []string) {
	if session == nil || session.ID == "01" || session.ID == "01.5" || session.ID == "09" {
		return nil, nil
	}
	plan, err := ReadAssessmentPlan(assessmentPlanPath(workspace))
	if err != nil {
		if fileExists(assessmentPlanPath(workspace)) {
			return nil, []string{err.Error()}
		}
		return nil, nil
	}
	validation := ValidateAssessmentPlan(plan)
	entry, ok := plan.Sessions[session.Directory]
	if !ok {
		return nil, validation
	}
	return &PlanDecisionView{
		SessionKey:    session.Directory,
		Decision:      entry.Decision,
		Applicability: entry.Applicability,
		CoverageLabel: entry.CoverageLabel,
		Reason:        entry.Reason,
		RequiredInput: entry.RequiredInput,
		Checklists:    entry.Checklists,
	}, validation
}

func readConfig(workspace string) (InitConfig, error) {
	raw, err := os.ReadFile(configPath(workspace))
	if err != nil {
		return InitConfig{}, fmt.Errorf("read config: %w", err)
	}
	cfg := parseConfigMarkdown(string(raw))
	cfg.Workspace = workspace
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
	return cfg, nil
}

// defaultEnvironment fills in the environment tier the same way run init does:
// sandbox when a live target URL is configured, none when it is not.
func defaultEnvironment(environment, targetURL string) string {
	if strings.TrimSpace(environment) != "" {
		return strings.TrimSpace(environment)
	}
	if strings.TrimSpace(targetURL) != "" {
		return "sandbox"
	}
	return "none"
}

func parseConfigMarkdown(text string) InitConfig {
	var cfg InitConfig
	section := ""
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimSpace(strings.TrimPrefix(line, "## "))
			continue
		}
		if !strings.HasPrefix(line, "- ") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "- ")), ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch section {
		case "Target":
			switch key {
			case "url":
				cfg.TargetURL = value
			case "source path":
				cfg.SourcePath = value
			case "target type":
				cfg.TargetType = value
			case "environment":
				cfg.Environment = value
			case "cloud":
				cfg.Cloud = value
			}
		case "Authentication":
			switch key {
			case "login url":
				cfg.LoginURL = value
			case "username":
				cfg.Username = value
			case "password":
				cfg.Password = value
			}
		case "Scope":
			switch key {
			case "in scope":
				cfg.InScope = value
			case "out of scope":
				cfg.OutOfScope = value
			case "approved rate-limit bursts":
				cfg.ApprovedBursts = value
			case "approved upload sizes":
				cfg.ApprovedUploadSizes = value
			}
		}
	}
	return cfg
}

// draftSessionDecision drafts one session decision. profileEnvironment is the
// environment tier recorded by Session 01 in the recon target profile, which is
// empty until that file exists.
func draftSessionDecision(key, targetType, profileEnvironment string, liveTarget bool, cloud []string, hasCredentials bool) PlanSession {
	baseCoverage := targetCoverageLabel(targetType, liveTarget)
	if key == "08.7-chains" {
		return draftChainsDecision(profileEnvironment, baseCoverage)
	}
	switch targetType {
	case "cloud_only":
		if key == "07-cloud" {
			return planSession(decisionRun, applicabilityApplicable, coverageCloudOnly, "Cloud-only target; cloud/Kubernetes/IaC checks are the primary workflow.", nil)
		}
		if key == "08.5-abuse" {
			return planSession(decisionLimited, applicabilityApplicable, coverageCloudOnly, "Cloud-only target; check platform-side rate, quota, and spend controls only.", nil)
		}
		return planSession(decisionNotApplicable, applicabilityNotApplicable, coverageCloudOnly, "Cloud-only target has no app HTTP surface in config. Session 01.5 should revise if Recon discovers one.", nil)
	case "mobile_client_offline", "desktop_or_extension_client", "library_or_cli":
		return planSession(decisionNotApplicable, applicabilityNotApplicable, coverageClientOnly, "Configured target type is client/library/CLI-only; server-side sessions are not applicable unless a backend is added to scope.", nil)
	case "static_site":
		return draftStaticSiteDecision(key, baseCoverage, cloud)
	case "mobile_client_remote_backend":
		return draftMobileRemoteDecision(key, baseCoverage, hasCredentials, cloud)
	case "api_backend":
		return draftAPIBackendDecision(key, baseCoverage, hasCredentials, cloud)
	case "web_app":
		return draftWebAppDecision(key, baseCoverage, hasCredentials, cloud)
	default:
		return draftAutoDecision(key, baseCoverage, hasCredentials, cloud)
	}
}

func applyReconProfileDecisions(plan *AssessmentPlan, profile *ReconTargetProfile, hasCredentials bool, cloud []string) {
	if profile == nil {
		return
	}
	targetType := plan.Target.Type
	signals := profile.Signals
	if boolPtrValue(signals.MonorepoAmbiguous) {
		for _, key := range planSessionKeys {
			plan.Sessions[key] = planSession(decisionBlocked, applicabilityUncertain, coverageBlocked, "Recon target profile marked the repository or deployment ambiguous. Choose one deployable before category testing.", []string{"Selected deployable or service boundary."})
		}
		return
	}
	if targetType == "mobile_client_remote_backend" && (len(profile.BackendInventory) == 0 || boolPtrIsFalse(signals.APISurface)) {
		for _, key := range []string{"02-injection", "03-auth", "04-authz", "06-ssrf", "08-api", "08.5-abuse"} {
			plan.Sessions[key] = planSession(decisionBlocked, applicabilityApplicable, coverageBlocked, "Mobile client target references a remote-backend workflow, but Recon did not provide a backend/API inventory.", []string{"Backend/API base URL inventory with source and evidence references."})
		}
	}
	if targetType == "static_site" && boolPtrIsFalse(signals.APISurface) && len(profile.BackendInventory) == 0 {
		plan.Sessions["08-api"] = planSession(decisionNotApplicable, applicabilityNotApplicable, coverageClientOnly, "Recon target profile found no API/backend inventory for this static/client-only target.", nil)
	}
	if boolPtrIsFalse(signals.Authentication) {
		plan.Sessions["03-auth"] = planSession(decisionNotApplicable, applicabilityNotApplicable, plan.Target.CoverageLabel, "Recon target profile found no authentication mechanism in scope.", nil)
		plan.Sessions["04-authz"] = planSession(decisionNotApplicable, applicabilityNotApplicable, plan.Target.CoverageLabel, "Recon target profile found no authentication, role, tenant, or ownership boundary in scope.", nil)
	}
	if boolPtrValue(signals.AuthorizationBoundaries) && !hasCredentials {
		plan.Sessions["04-authz"] = planSession(decisionBlocked, applicabilityApplicable, coverageBlocked, "Recon target profile found authorization boundaries, but required test accounts are missing.", []string{"At least two users, roles, tenants, or owned resources for authorization coverage."})
	}
	if boolPtrIsFalse(signals.OutboundFetchSurface) {
		plan.Sessions["06-ssrf"] = planSession(decisionNotApplicable, applicabilityNotApplicable, plan.Target.CoverageLabel, "Recon target profile found no outbound request sinks, webhook fetchers, importers, proxying, or URL-controlled fetch behavior.", nil)
	}
	if boolPtrValue(signals.CloudSurface) && len(cloud) == 0 {
		plan.Sessions["07-cloud"] = planSession(decisionLimited, applicabilityApplicable, coveragePartial, "Recon target profile found cloud/IaC surface, but cloud scope or credentials were not configured.", []string{"Confirm cloud assets and provide authorized provider credentials or IaC paths."})
	}
	if boolPtrValue(signals.BillingExposedSurface) || boolPtrValue(signals.StorageSurface) || (profile.Stack != nil && (len(profile.Stack.BillingExposedServices) > 0 || len(profile.Stack.Storage) > 0)) {
		plan.Sessions["08.5-abuse"] = planSession(decisionRun, applicabilityApplicable, plan.Target.CoverageLabel, "Recon target profile lists billing-exposed services or storage surface; measure limiters, caps, and quotas.", []string{"Operator-approved burst counts and upload sizes per endpoint."})
	}
}

// draftChainsDecision drafts Session 08.7. Chains are proven end to end, so the
// draft only runs when Session 01 recorded a sandbox environment.
func draftChainsDecision(profileEnvironment, coverage string) PlanSession {
	if profileEnvironment == "sandbox" {
		return planSession(decisionRun, applicabilityApplicable, coverage, "Sandbox environment recorded; chain and workflow candidates are collected from Sessions 02 to 08.5 and this decision is re-confirmed after 08.5.", []string{"At least one likely finding, unresolved chain, or workflow candidate from Sessions 02 to 08.5."})
	}
	return planSession(decisionBlocked, applicabilityUncertain, coverageBlocked, "Session 08.7 proves chains end to end and runs only in a sandbox environment. Record environment: sandbox in 01-recon/target-profile.yaml or report chains as risk scenarios.", []string{"environment: sandbox in 01-recon/target-profile.yaml"})
}

func abuseDecision(coverage string) PlanSession {
	return planSession(decisionRun, applicabilityApplicable, coverage, "Every server component has endpoints that can be abused for cost or resource consumption; measure limiters, caps, and quotas.", []string{"Operator-approved burst counts and upload sizes per endpoint."})
}

func draftWebAppDecision(key, coverage string, hasCredentials bool, cloud []string) PlanSession {
	switch key {
	case "02-injection", "05-xss", "06-ssrf", "08-api":
		return planSession(decisionRun, applicabilityApplicable, coverage, "Web application target; Recon/Session 01.5 should refine exact attack surface.", []string{"01-recon/report.md"})
	case "08.5-abuse":
		return abuseDecision(coverage)
	case "03-auth":
		return planSession(decisionRun, applicabilityApplicable, coverage, "Web application target may include authentication. Measure auth surface and document if none exists.", []string{"01-recon/report.md"})
	case "04-authz":
		if hasCredentials {
			return planSession(decisionLimited, applicabilityApplicable, coveragePartial, "Authorization testing depends on role/object boundaries; supplied credentials allow initial coverage but Session 01.5 should confirm role matrix.", []string{"At least two roles or two owned accounts for full authz coverage."})
		}
		return planSession(decisionBlocked, applicabilityApplicable, coverageBlocked, "Authorization testing requires authenticated test accounts and role/object context.", []string{"Authenticated accounts for at least one role; two roles or tenants for full authz coverage."})
	case "07-cloud":
		return cloudDecision(cloud)
	default:
		return planSession(decisionUncertain, applicabilityUncertain, coveragePartial, "Session applicability requires Recon evidence.", nil)
	}
}

func draftAPIBackendDecision(key, coverage string, hasCredentials bool, cloud []string) PlanSession {
	switch key {
	case "02-injection", "06-ssrf", "08-api":
		return planSession(decisionRun, applicabilityApplicable, coverage, "API backend target; server-side input and protocol surface should be measured.", []string{"01-recon/report.md"})
	case "08.5-abuse":
		return abuseDecision(coverage)
	case "03-auth":
		return planSession(decisionRun, applicabilityApplicable, coverage, "API backend may use tokens, API keys, OAuth, or session cookies. Measure identity surface and document if none exists.", []string{"01-recon/report.md"})
	case "04-authz":
		if hasCredentials {
			return planSession(decisionLimited, applicabilityApplicable, coveragePartial, "Authorization testing depends on object ownership, roles, or tenants; credentials permit initial coverage.", []string{"Second account or role for full horizontal/vertical coverage."})
		}
		return planSession(decisionBlocked, applicabilityApplicable, coverageBlocked, "Authorization testing requires authenticated API credentials and object context.", []string{"Authenticated API credentials and at least two owned resources or roles."})
	case "05-xss":
		return planSession(decisionSkip, applicabilityNotApplicable, coveragePartial, "API backend target has no rendered browser surface in config. Run only if Recon finds rendered HTML, WebViews, or client UI in scope.", nil)
	case "07-cloud":
		return cloudDecision(cloud)
	default:
		return planSession(decisionUncertain, applicabilityUncertain, coveragePartial, "Session applicability requires Recon evidence.", nil)
	}
}

func draftStaticSiteDecision(key, coverage string, cloud []string) PlanSession {
	switch key {
	case "05-xss":
		return planSession(decisionLimited, applicabilityApplicable, coverageClientOnly, "Static/client site can still have DOM XSS or client exposure issues.", nil)
	case "08-api":
		return planSession(decisionUncertain, applicabilityUncertain, coveragePartial, "Static sites may call remote APIs or forms; Session 01 should inventory backend endpoints before deciding.", []string{"Backend/API URL inventory from Recon."})
	case "08.5-abuse":
		return planSession(decisionNotApplicable, applicabilityNotApplicable, coverageClientOnly, "Static/client-only target has no server component to abuse for cost or resource consumption.", nil)
	case "07-cloud":
		return cloudDecision(cloud)
	default:
		return planSession(decisionNotApplicable, applicabilityNotApplicable, coverageClientOnly, "Static/client-only target has no configured server-side surface for this session.", nil)
	}
}

func draftMobileRemoteDecision(key, coverage string, hasCredentials bool, cloud []string) PlanSession {
	switch key {
	case "02-injection", "03-auth", "06-ssrf", "08-api":
		return planSession(decisionLimited, applicabilityApplicable, coveragePartial, "Mobile client with remote backend; coverage depends on extracted backend endpoints and authorized API access.", []string{"Backend endpoint inventory from client traffic or source."})
	case "08.5-abuse":
		return abuseDecision(coveragePartial)
	case "04-authz":
		required := []string{"At least two test users or roles for backend authorization coverage."}
		decision := decisionBlocked
		label := coverageBlocked
		if hasCredentials {
			decision = decisionLimited
			label = coveragePartial
		}
		return planSession(decision, applicabilityApplicable, label, "Remote backend authorization coverage depends on supplied accounts and object ownership context.", required)
	case "05-xss":
		return planSession(decisionLimited, applicabilityApplicable, coverageClientOnly, "Mobile clients may include WebViews or rendered remote content; Session 01.5 should decide whether XSS or client exposure review applies.", nil)
	case "07-cloud":
		return cloudDecision(cloud)
	default:
		return planSession(decisionUncertain, applicabilityUncertain, coveragePartial, "Session applicability requires Recon evidence.", nil)
	}
}

func draftAutoDecision(key, coverage string, hasCredentials bool, cloud []string) PlanSession {
	if key == "07-cloud" && len(cloud) > 0 {
		return cloudDecision(cloud)
	}
	if key == "08.5-abuse" {
		return abuseDecision(coverage)
	}
	if key == "04-authz" && !hasCredentials {
		return planSession(decisionUncertain, applicabilityUncertain, coveragePartial, "Target type is auto and no auth context is configured. Session 01.5 should classify before deciding.", []string{"Target classification and account matrix."})
	}
	return planSession(decisionUncertain, applicabilityUncertain, coverage, "Target type is auto. Session 01 and Session 01.5 must classify before deciding final applicability.", []string{"Recon target classification."})
}

func cloudDecision(cloud []string) PlanSession {
	if len(cloud) == 0 {
		return planSession(decisionSkip, applicabilityNotApplicable, coveragePartial, "Cloud scope is none in config. Write a skipped-session report unless Recon finds cloud/IaC assets in scope.", nil)
	}
	return planSession(decisionRun, applicabilityApplicable, coverageFull, "Cloud scope is configured; run provider/Kubernetes/IaC checks that are authorized and credentialed.", []string{"Cloud provider credentials or IaC files for full coverage."})
}

func planSession(decision, applicability, coverage, reason string, required []string) PlanSession {
	return PlanSession{
		Decision:      decision,
		Applicability: applicability,
		CoverageLabel: coverage,
		Reason:        reason,
		EvidenceRefs:  []string{"config.md"},
		RequiredInput: required,
	}
}

func ensureWorkspaceInitialized(workspace string) error {
	if !fileExists(configPath(workspace)) || !fileExists(progressPath(workspace)) {
		return fmt.Errorf("workspace is not initialized; run ensphere run init first")
	}
	return nil
}

func assessmentPlanMirrorPath(workspace string) string {
	return filepath.Join(workspace, "01.5-session-plan", "assessment-plan.yaml")
}

func normalizeTargetType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	if value == "" {
		return "auto"
	}
	if validTargetType(value) {
		return value
	}
	return "auto"
}

// targetCoverageLabel derives the draft coverage label. Source is always
// available to an Ensphere assessment; a live target is optional. Without one
// the draft is source_only and every measurement row starts not_tested.
func targetCoverageLabel(targetType string, liveTarget bool) string {
	switch targetType {
	case "cloud_only":
		return coverageCloudOnly
	case "static_site", "mobile_client_remote_backend", "mobile_client_offline", "desktop_or_extension_client", "library_or_cli":
		return coverageClientOnly
	}
	if !liveTarget {
		return coverageSourceOnly
	}
	return coverageFull
}

func coverageAllowsNoLiveTarget(label string) bool {
	switch label {
	case coverageSourceOnly, coverageClientOnly, coverageCloudOnly:
		return true
	default:
		return false
	}
}

func parseList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "none") || value == "[]" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.EqualFold(part, "none") {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 && value != "" {
		out = append(out, value)
	}
	return out
}

func profilePathForPlan(workspace string, profile *ReconTargetProfile) string {
	if profile == nil {
		return ""
	}
	return filepath.ToSlash(filepath.Join("01-recon", "target-profile.yaml"))
}

func validClassificationConfidence(value string) bool {
	switch value {
	case "high", "medium", "low", "unknown":
		return true
	default:
		return false
	}
}

func validateWorkspaceRelativeRefs(field string, refs []string) []string {
	var problems []string
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			problems = append(problems, field+" contains an empty reference")
			continue
		}
		if !safeWorkspaceRelativePath(ref) {
			problems = append(problems, fmt.Sprintf("%s reference %q must be workspace-relative and must not escape the workspace", field, ref))
		}
	}
	return problems
}

func boolPtrValue(value *bool) bool {
	return value != nil && *value
}

func boolPtrIsFalse(value *bool) bool {
	return value != nil && !*value
}

func validTargetType(value string) bool {
	switch value {
	case "auto", "web_app", "api_backend", "static_site", "mobile_client_remote_backend", "mobile_client_offline", "desktop_or_extension_client", "cloud_only", "library_or_cli":
		return true
	default:
		return false
	}
}

func validDecision(value string) bool {
	switch value {
	case decisionRun, decisionSkip, "force", decisionLimited, decisionBlocked, decisionUncertain, decisionNotApplicable:
		return true
	default:
		return false
	}
}

func validApplicability(value string) bool {
	switch value {
	case applicabilityApplicable, applicabilityUncertain, applicabilityNotApplicable:
		return true
	default:
		return false
	}
}

// validEnvironment reports whether value is a recognised environment tier.
// sandbox is a disposable copy the operator may prove chains against, staging
// is a shared non-production deployment, and none records that no live target
// is in scope.
func validEnvironment(value string) bool {
	switch value {
	case "sandbox", "staging", "none":
		return true
	default:
		return false
	}
}

// validatePlanEnvironment checks target.environment against target.url. none is
// only recorded when there is no live target; sandbox and staging name a live
// deployment and therefore require a URL.
func validatePlanEnvironment(environment, url string) []string {
	environment = strings.TrimSpace(environment)
	url = strings.TrimSpace(url)
	switch {
	case environment == "":
		if url != "" {
			return []string{"target.environment is required when target.url is set"}
		}
	case !validEnvironment(environment):
		return []string{fmt.Sprintf("target.environment %q is invalid", environment)}
	case environment == "none":
		if url != "" {
			return []string{"target.environment none is only valid when target.url is empty"}
		}
	default:
		if url == "" {
			return []string{fmt.Sprintf("target.environment %s requires a non-empty target.url", environment)}
		}
	}
	return nil
}

func validCoverageLabel(value string) bool {
	switch value {
	case coverageFull, coveragePartial, coverageBlocked, coverageSourceOnly, coverageClientOnly, coverageCloudOnly:
		return true
	default:
		return false
	}
}

func reconTargetProfilePath(workspace string) string {
	return filepath.Join(workspace, "01-recon", "target-profile.yaml")
}
