package runner

type Session struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Methodology string `json:"methodology"`
	Directory   string `json:"directory"`
}

type InitConfig struct {
	Workspace           string
	TargetURL           string
	SourcePath          string
	TargetType          string
	Environment         string
	Cloud               string
	InScope             string
	OutOfScope          string
	LoginURL            string
	Username            string
	Password            string
	ApprovedBursts      string
	ApprovedUploadSizes string
	AssessedBy          string
	Operator            string
}

type Status struct {
	Workspace            string            `json:"workspace"`
	ConfigPath           string            `json:"config_path"`
	ProgressPath         string            `json:"progress_path"`
	AssessmentPlanPath   string            `json:"assessment_plan_path"`
	AssessmentPlanExists bool              `json:"assessment_plan_exists"`
	AssessmentPlan       *PlanSummary      `json:"assessment_plan,omitempty"`
	NextSession          *Session          `json:"next_session,omitempty"`
	NextPlanDecision     *PlanDecisionView `json:"next_plan_decision,omitempty"`
	Sessions             map[string]string `json:"sessions"`
}

type NextAction struct {
	Workspace      string            `json:"workspace"`
	Session        *Session          `json:"session,omitempty"`
	PlanDecision   *PlanDecisionView `json:"plan_decision,omitempty"`
	PlanValidation []string          `json:"plan_validation,omitempty"`
	ActionPath     string            `json:"action_path"`
	PromptPath     string            `json:"prompt_path"`
	Message        string            `json:"message"`
}

type ReportGateOutput struct {
	Workspace            string            `json:"workspace" yaml:"workspace"`
	Ready                bool              `json:"ready" yaml:"ready"`
	GatePath             string            `json:"gate_path" yaml:"gate_path"`
	GateMarkdownPath     string            `json:"gate_markdown_path" yaml:"gate_markdown_path"`
	FindingRegistryPath  string            `json:"finding_registry_path" yaml:"finding_registry_path"`
	FindingRegistryState string            `json:"finding_registry_state" yaml:"finding_registry_state"`
	Issues               []ReportGateIssue `json:"issues,omitempty" yaml:"issues,omitempty"`
	Coverage             *CoverageSummary  `json:"coverage,omitempty" yaml:"coverage,omitempty"`
	StatementPath        string            `json:"statement_path,omitempty" yaml:"statement_path,omitempty"`
	StatementMarkdown    string            `json:"statement_markdown_path,omitempty" yaml:"statement_markdown_path,omitempty"`
	StatementState       string            `json:"statement_state,omitempty" yaml:"statement_state,omitempty"`
	NextActionPath       string            `json:"next_action_path,omitempty" yaml:"next_action_path,omitempty"`
	PromptPath           string            `json:"prompt_path,omitempty" yaml:"prompt_path,omitempty"`
	Message              string            `json:"message" yaml:"message"`
}

type ReportGateIssue struct {
	Severity string `json:"severity" yaml:"severity"`
	Code     string `json:"code" yaml:"code"`
	Path     string `json:"path,omitempty" yaml:"path,omitempty"`
	Message  string `json:"message" yaml:"message"`
}

type FindingRegistry struct {
	GeneratedFrom string           `json:"generated_from" yaml:"generated_from"`
	Findings      []FindingSummary `json:"findings" yaml:"findings"`
}

// FindingSummary is one entry in 09-report/finding-registry.yaml. Kind is
// "vulnerability" or "missing_control"; CVSS is optional and only meaningful
// for vulnerabilities.
type FindingSummary struct {
	ID                 string   `json:"id" yaml:"id"`
	Kind               string   `json:"kind" yaml:"kind"`
	Title              string   `json:"title" yaml:"title"`
	Category           string   `json:"category" yaml:"category"`
	Status             string   `json:"status" yaml:"status"`
	Confidence         string   `json:"confidence" yaml:"confidence"`
	EvidenceStrength   string   `json:"evidence_strength" yaml:"evidence_strength"`
	Severity           string   `json:"severity" yaml:"severity"`
	Priority           string   `json:"priority" yaml:"priority"`
	CVSSV4             string   `json:"cvss_v4,omitempty" yaml:"cvss_v4,omitempty"`
	AffectedAssets     []string `json:"affected_assets" yaml:"affected_assets"`
	AffectedLocations  []string `json:"affected_locations" yaml:"affected_locations"`
	ObservedFacts      []string `json:"observed_facts" yaml:"observed_facts"`
	RootCause          string   `json:"root_cause" yaml:"root_cause"`
	SecurityImpact     string   `json:"security_impact" yaml:"security_impact"`
	BusinessImpact     string   `json:"business_impact,omitempty" yaml:"business_impact,omitempty"`
	Remediation        string   `json:"remediation" yaml:"remediation"`
	ValidationCriteria []string `json:"validation_criteria" yaml:"validation_criteria"`
	EvidenceIDs        []string `json:"evidence_ids" yaml:"evidence_ids"`
	Transcripts        []string `json:"transcripts,omitempty" yaml:"transcripts,omitempty"`
	ArtifactPaths      []string `json:"artifact_paths,omitempty" yaml:"artifact_paths,omitempty"`
	CleanupEvidence    []string `json:"cleanup_evidence,omitempty" yaml:"cleanup_evidence,omitempty"`
	ImportRefs         []string `json:"import_refs,omitempty" yaml:"import_refs,omitempty"`
	ManualNotes        []string `json:"manual_notes,omitempty" yaml:"manual_notes,omitempty"`
	EvidenceCategories []string `json:"evidence_categories" yaml:"evidence_categories"`
	CoverageLabel      string   `json:"coverage_label" yaml:"coverage_label"`
	Notes              string   `json:"notes,omitempty" yaml:"notes,omitempty"`
}

type AssessmentPlan struct {
	Draft          bool                   `json:"draft" yaml:"draft"`
	Target         PlanTarget             `json:"target" yaml:"target"`
	Checklists     []string               `json:"checklists" yaml:"checklists"`
	UncoveredStack []string               `json:"uncovered_stack" yaml:"uncovered_stack"`
	Sessions       map[string]PlanSession `json:"sessions" yaml:"sessions"`
	HumanOverrides []string               `json:"human_overrides" yaml:"human_overrides"`
	CreatedBy      string                 `json:"created_by" yaml:"created_by"`
	CreatedAt      string                 `json:"created_at" yaml:"created_at"`
}

type PlanTarget struct {
	Type                     string                  `json:"type" yaml:"type"`
	URL                      string                  `json:"url" yaml:"url"`
	Environment              string                  `json:"environment" yaml:"environment"`
	CoverageLabel            string                  `json:"coverage_label" yaml:"coverage_label"`
	ClassificationSource     string                  `json:"classification_source" yaml:"classification_source"`
	ClassificationConfidence string                  `json:"classification_confidence" yaml:"classification_confidence"`
	ReconProfilePath         string                  `json:"recon_profile_path,omitempty" yaml:"recon_profile_path,omitempty"`
	Cloud                    []string                `json:"cloud" yaml:"cloud"`
	Scope                    []string                `json:"scope" yaml:"scope"`
	Rationale                []string                `json:"rationale" yaml:"rationale"`
	BackendInventory         []BackendInventoryEntry `json:"backend_inventory,omitempty" yaml:"backend_inventory,omitempty"`
	ClientExposureReview     []string                `json:"client_exposure_review,omitempty" yaml:"client_exposure_review,omitempty"`
	Signals                  *TargetSignals          `json:"signals,omitempty" yaml:"signals,omitempty"`
	Stack                    *StackProfile           `json:"stack,omitempty" yaml:"stack,omitempty"`
}

type PlanSession struct {
	Decision      string   `json:"decision" yaml:"decision"`
	Applicability string   `json:"applicability" yaml:"applicability"`
	CoverageLabel string   `json:"coverage_label" yaml:"coverage_label"`
	Reason        string   `json:"reason" yaml:"reason"`
	EvidenceRefs  []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	RequiredInput []string `json:"required_input,omitempty" yaml:"required_input,omitempty"`
	Checklists    []string `json:"checklists,omitempty" yaml:"checklists,omitempty"`
}

type PlanOutput struct {
	Workspace      string          `json:"workspace"`
	PlanPath       string          `json:"plan_path"`
	MirrorPath     string          `json:"mirror_path"`
	Written        bool            `json:"written"`
	Valid          bool            `json:"valid"`
	Validation     []string        `json:"validation,omitempty"`
	Message        string          `json:"message"`
	Plan           *AssessmentPlan `json:"plan,omitempty"`
	NextActionPath string          `json:"next_action_path,omitempty"`
	PromptPath     string          `json:"prompt_path,omitempty"`
}

type PlanSummary struct {
	Exists           bool              `json:"exists"`
	Valid            bool              `json:"valid"`
	Validation       []string          `json:"validation,omitempty"`
	TargetType       string            `json:"target_type,omitempty"`
	Environment      string            `json:"environment,omitempty"`
	CoverageLabel    string            `json:"coverage_label,omitempty"`
	Checklists       []string          `json:"checklists,omitempty"`
	SessionDecisions map[string]string `json:"session_decisions,omitempty"`
}

type PlanDecisionView struct {
	SessionKey    string   `json:"session_key"`
	Decision      string   `json:"decision"`
	Applicability string   `json:"applicability"`
	CoverageLabel string   `json:"coverage_label"`
	Reason        string   `json:"reason"`
	RequiredInput []string `json:"required_input,omitempty"`
	Checklists    []string `json:"checklists,omitempty"`
}

type ReconTargetProfile struct {
	Target               ReconProfileTarget      `json:"target" yaml:"target"`
	Stack                *StackProfile           `json:"stack,omitempty" yaml:"stack,omitempty"`
	BackendInventory     []BackendInventoryEntry `json:"backend_inventory,omitempty" yaml:"backend_inventory,omitempty"`
	Signals              TargetSignals           `json:"signals,omitempty" yaml:"signals,omitempty"`
	ClientExposureReview []string                `json:"client_exposure_review,omitempty" yaml:"client_exposure_review,omitempty"`
}

// StackProfile records which product fills each role from
// skills/shared/fundamentals.md. Values are free-form lowercase identifiers.
type StackProfile struct {
	Languages              []string `json:"languages,omitempty" yaml:"languages,omitempty"`
	Frameworks             []string `json:"frameworks,omitempty" yaml:"frameworks,omitempty"`
	DataLayers             []string `json:"data_layers,omitempty" yaml:"data_layers,omitempty"`
	AuthProviders          []string `json:"auth_providers,omitempty" yaml:"auth_providers,omitempty"`
	Hosting                []string `json:"hosting,omitempty" yaml:"hosting,omitempty"`
	Storage                []string `json:"storage,omitempty" yaml:"storage,omitempty"`
	Edge                   []string `json:"edge,omitempty" yaml:"edge,omitempty"`
	BillingExposedServices []string `json:"billing_exposed_services,omitempty" yaml:"billing_exposed_services,omitempty"`
	Clients                []string `json:"clients,omitempty" yaml:"clients,omitempty"`
	EvidenceRefs           []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
}

type ReconProfileTarget struct {
	Type                     string   `json:"type" yaml:"type"`
	Environment              string   `json:"environment" yaml:"environment"`
	CoverageLabel            string   `json:"coverage_label,omitempty" yaml:"coverage_label,omitempty"`
	ClassificationConfidence string   `json:"classification_confidence" yaml:"classification_confidence"`
	Rationale                []string `json:"rationale" yaml:"rationale"`
	EvidenceRefs             []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
}

type BackendInventoryEntry struct {
	Name         string   `json:"name" yaml:"name"`
	BaseURL      string   `json:"base_url" yaml:"base_url"`
	Kind         string   `json:"kind" yaml:"kind"`
	Source       string   `json:"source" yaml:"source"`
	EvidenceRefs []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
}

type TargetSignals struct {
	BrowserUI               *bool `json:"browser_ui,omitempty" yaml:"browser_ui,omitempty"`
	APISurface              *bool `json:"api_surface,omitempty" yaml:"api_surface,omitempty"`
	ServerSideSurface       *bool `json:"server_side_surface,omitempty" yaml:"server_side_surface,omitempty"`
	Authentication          *bool `json:"authentication,omitempty" yaml:"authentication,omitempty"`
	AuthorizationBoundaries *bool `json:"authorization_boundaries,omitempty" yaml:"authorization_boundaries,omitempty"`
	OutboundFetchSurface    *bool `json:"outbound_fetch_surface,omitempty" yaml:"outbound_fetch_surface,omitempty"`
	CloudSurface            *bool `json:"cloud_surface,omitempty" yaml:"cloud_surface,omitempty"`
	BillingExposedSurface   *bool `json:"billing_exposed_surface,omitempty" yaml:"billing_exposed_surface,omitempty"`
	StorageSurface          *bool `json:"storage_surface,omitempty" yaml:"storage_surface,omitempty"`
	ClientOnly              *bool `json:"client_only,omitempty" yaml:"client_only,omitempty"`
	MonorepoAmbiguous       *bool `json:"monorepo_ambiguous,omitempty" yaml:"monorepo_ambiguous,omitempty"`
}

var Sessions = []Session{
	{ID: "01", Name: "Recon", Methodology: "skills/methodology/01-recon.md", Directory: "01-recon"},
	{ID: "01.5", Name: "Plan", Methodology: "skills/methodology/01.5-session-plan.md", Directory: "01.5-session-plan"},
	{ID: "02", Name: "Injection", Methodology: "skills/methodology/02-injection.md", Directory: "02-injection"},
	{ID: "03", Name: "Authentication", Methodology: "skills/methodology/03-auth.md", Directory: "03-auth"},
	{ID: "04", Name: "Authorization", Methodology: "skills/methodology/04-authz.md", Directory: "04-authz"},
	{ID: "05", Name: "Cross-Site Scripting", Methodology: "skills/methodology/05-xss.md", Directory: "05-xss"},
	{ID: "06", Name: "Server-Side Request Forgery", Methodology: "skills/methodology/06-ssrf.md", Directory: "06-ssrf"},
	{ID: "07", Name: "Cloud and Platform", Methodology: "skills/methodology/07-cloud.md", Directory: "07-cloud"},
	{ID: "08", Name: "API Security", Methodology: "skills/methodology/08-api.md", Directory: "08-api"},
	{ID: "08.5", Name: "Abuse and Cost Controls", Methodology: "skills/methodology/08.5-abuse.md", Directory: "08.5-abuse"},
	{ID: "08.7", Name: "Chains and Workflows", Methodology: "skills/methodology/08.7-chains.md", Directory: "08.7-chains"},
	{ID: "09", Name: "Report", Methodology: "skills/methodology/09-report.md", Directory: "09-report"},
}

// CoverageFile is <session-dir>/coverage.yaml: the machine-read record of
// every check a session planned and its state. See the contract's "Coverage
// file" section for the schema.
type CoverageFile struct {
	Session string        `json:"session" yaml:"session"`
	Rows    []CoverageRow `json:"rows" yaml:"rows"`
}

type CoverageRow struct {
	ID          string   `json:"id" yaml:"id"`
	Surface     string   `json:"surface" yaml:"surface"`
	Check       string   `json:"check" yaml:"check"`
	Identity    string   `json:"identity,omitempty" yaml:"identity,omitempty"`
	State       string   `json:"state" yaml:"state"`
	EvidenceIDs []string `json:"evidence_ids,omitempty" yaml:"evidence_ids,omitempty"`
	Transcripts []string `json:"transcripts,omitempty" yaml:"transcripts,omitempty"`
	Checklist   string   `json:"checklist,omitempty" yaml:"checklist,omitempty"`
	Reason      string   `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// CoverageCounts counts coverage rows by state.
type CoverageCounts struct {
	Planned       int `json:"planned" yaml:"planned"`
	Tested        int `json:"tested" yaml:"tested"`
	NotTested     int `json:"not_tested" yaml:"not_tested"`
	Blocked       int `json:"blocked" yaml:"blocked"`
	NotApplicable int `json:"not_applicable" yaml:"not_applicable"`
	Total         int `json:"total" yaml:"total"`
}

// SessionCoverage is one session's coverage file summary.
type SessionCoverage struct {
	ID        string         `json:"id" yaml:"id"`
	Directory string         `json:"directory" yaml:"directory"`
	Present   bool           `json:"present" yaml:"present"`
	Counts    CoverageCounts `json:"counts" yaml:"counts"`
}

// CoverageSummary is the report gate's count of every coverage file.
type CoverageSummary struct {
	Sessions []SessionCoverage `json:"sessions" yaml:"sessions"`
	Totals   CoverageCounts    `json:"totals" yaml:"totals"`
}

// Statement is 09-report/statement.yaml: every number in the Statement of
// Assessment, derived from the workspace by ensphere run statement.
type Statement struct {
	GeneratedAt     string             `json:"generated_at" yaml:"generated_at"`
	EnsphereVersion string             `json:"ensphere_version" yaml:"ensphere_version"`
	System          StatementSystem    `json:"system" yaml:"system"`
	Dates           StatementDates     `json:"dates" yaml:"dates"`
	Checklists      []string           `json:"checklists" yaml:"checklists"`
	Sessions        []StatementSession `json:"sessions" yaml:"sessions"`
	Coverage        CoverageSummary    `json:"coverage" yaml:"coverage"`
	Findings        StatementFindings  `json:"findings" yaml:"findings"`
	Ledgers         []StatementLedger  `json:"ledgers" yaml:"ledgers"`
	InputsDigest    string             `json:"inputs_digest" yaml:"inputs_digest"`
}

type StatementSystem struct {
	TargetURL   string   `json:"target_url" yaml:"target_url"`
	Environment string   `json:"environment" yaml:"environment"`
	SourcePath  string   `json:"source_path" yaml:"source_path"`
	TargetType  string   `json:"target_type" yaml:"target_type"`
	Cloud       []string `json:"cloud" yaml:"cloud"`
	InScope     string   `json:"in_scope" yaml:"in_scope"`
	AssessedBy  string   `json:"assessed_by" yaml:"assessed_by"`
	Operator    string   `json:"operator" yaml:"operator"`
}

type StatementDates struct {
	EarliestEvidence string `json:"earliest_evidence" yaml:"earliest_evidence"`
	LatestEvidence   string `json:"latest_evidence" yaml:"latest_evidence"`
}

type StatementSession struct {
	ID            string `json:"id" yaml:"id"`
	Name          string `json:"name" yaml:"name"`
	Decision      string `json:"decision" yaml:"decision"`
	CoverageLabel string `json:"coverage_label" yaml:"coverage_label"`
	State         string `json:"state" yaml:"state"`
}

type StatementFindings struct {
	ByKind     map[string]int      `json:"by_kind" yaml:"by_kind"`
	ByStatus   map[string]int      `json:"by_status" yaml:"by_status"`
	BySeverity map[string]int      `json:"by_severity" yaml:"by_severity"`
	Unresolved []UnresolvedFinding `json:"unresolved" yaml:"unresolved"`
}

type UnresolvedFinding struct {
	ID       string `json:"id" yaml:"id"`
	Kind     string `json:"kind" yaml:"kind"`
	Status   string `json:"status" yaml:"status"`
	Severity string `json:"severity" yaml:"severity"`
	Title    string `json:"title" yaml:"title"`
}

type StatementLedger struct {
	Session   string `json:"session" yaml:"session"`
	Path      string `json:"path" yaml:"path"`
	Entries   int    `json:"entries" yaml:"entries"`
	FinalHash string `json:"final_hash" yaml:"final_hash"`
	Valid     bool   `json:"valid" yaml:"valid"`
}

// StatementOutput is the JSON result of ensphere run statement.
type StatementOutput struct {
	Workspace     string `json:"workspace"`
	StatementPath string `json:"statement_path"`
	MarkdownPath  string `json:"markdown_path"`
	InputsDigest  string `json:"inputs_digest"`
	Message       string `json:"message"`
}
