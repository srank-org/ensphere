package verify

import "time"

// ProbeConfig holds common configuration for all probe types.
type ProbeConfig struct {
	InScope    []string          // Required glob patterns for scope validation
	MaxRisk    int               // Maximum risk level (1-5)
	ThrottleMs int               // Milliseconds between probes
	TimeoutSec int               // HTTP request timeout
	Headers    map[string]string // Custom headers
	Evidence   string            // Evidence file path
}

// ProbeResult is the measurement-only JSON output for all verify commands.
type ProbeResult struct {
	VulnType     string      `json:"vuln_type"`
	Technique    string      `json:"technique"`
	StartedAt    string      `json:"started_at"`
	ProbeCount   int         `json:"probe_count"`
	Duration     string      `json:"duration"`
	Measurements interface{} `json:"measurements"`
}

// RoundResult captures raw measurements from a single HTTP round-trip.
type RoundResult struct {
	StatusCode int               `json:"status_code"`
	ElapsedMs  int64             `json:"elapsed_ms"`
	BodyHash   string            `json:"body_hash"`
	BodyLength int               `json:"body_length"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// SQLiTimeMeasurements holds blind-time SQLi probe measurements.
type SQLiTimeMeasurements struct {
	DBEngine       string        `json:"db_engine"`
	SleepSeconds   int           `json:"sleep_seconds"`
	BaselineRounds []RoundResult `json:"baseline_rounds"`
	PayloadRounds  []RoundResult `json:"payload_rounds"`
	BaselineAvgMs  int64         `json:"baseline_avg_ms"`
	PayloadAvgMs   int64         `json:"payload_avg_ms"`
	DeltaMs        int64         `json:"delta_ms"`
	PayloadUsed    string        `json:"payload_used"`
	StringBoundary string        `json:"string_boundary"`
}

// SQLiBooleanMeasurements holds boolean-based SQLi probe measurements.
type SQLiBooleanMeasurements struct {
	DBEngine       string        `json:"db_engine"`
	BaselineRound  RoundResult   `json:"baseline_round"`
	TrueRounds     []RoundResult `json:"true_rounds"`
	FalseRounds    []RoundResult `json:"false_rounds"`
	HashesMatch    bool          `json:"hashes_match"`
	TruePayload    string        `json:"true_payload"`
	FalsePayload   string        `json:"false_payload"`
	StringBoundary string        `json:"string_boundary"`
}

// SQLiErrorMeasurements holds error-based SQLi probe measurements.
type SQLiErrorMeasurements struct {
	DBEngine        string      `json:"db_engine"`
	ProbeRound      RoundResult `json:"probe_round"`
	MatchedPatterns []string    `json:"matched_patterns"`
	PayloadUsed     string      `json:"payload_used"`
	StringBoundary  string      `json:"string_boundary"`
	ResponseSnippet string      `json:"response_snippet,omitempty"`
}

// XSSMeasurements holds XSS probe measurements.
type XSSMeasurements struct {
	ProbeRound  RoundResult `json:"probe_round"`
	Reflected   bool        `json:"reflected"`
	Encoded     bool        `json:"encoded"`
	Context     string      `json:"context,omitempty"`
	PayloadUsed string      `json:"payload_used"`
}

// IDORMeasurements holds IDOR probe measurements.
type IDORMeasurements struct {
	ProbeRound      RoundResult  `json:"probe_round"`
	OwnerRound      *RoundResult `json:"owner_round,omitempty"`
	HashesMatch     *bool        `json:"hashes_match,omitempty"`
	StatusMatch     *bool        `json:"status_match,omitempty"`
	ResourceID      string       `json:"resource_id"`
	ResponseSnippet string       `json:"response_snippet,omitempty"`
}

// SSRFMeasurements holds SSRF probe measurements.
type SSRFMeasurements struct {
	Baseline          RoundResult `json:"baseline"`
	Probe             RoundResult `json:"probe"`
	HashesMatch       bool        `json:"hashes_match"`
	MatchedSignatures []string    `json:"matched_signatures"`
	CallbackURL       string      `json:"callback_url,omitempty"`
	PayloadUsed       string      `json:"payload_used"`
	ResponseSnippet   string      `json:"response_snippet,omitempty"`
}

// AuthMeasurements holds auth bypass probe measurements.
type AuthMeasurements struct {
	Technique       string      `json:"technique"`
	Baseline        RoundResult `json:"baseline"`
	Probe           RoundResult `json:"probe"`
	BodyLengthDelta int         `json:"body_length_delta"`
}

// RLSMeasurements holds Supabase RLS probe measurements.
// Row count fields use -1 to indicate the response was not a valid JSON array
// (e.g., an HTML error page). 0 means the server returned an empty JSON array.
type RLSMeasurements struct {
	Table           string      `json:"table"`
	TenantAOwn      RoundResult `json:"tenant_a_own"`
	TenantAOwnRows  int         `json:"tenant_a_own_rows"`
	TenantBOwn      RoundResult `json:"tenant_b_own"`
	TenantBOwnRows  int         `json:"tenant_b_own_rows"`
	CrossTenant     RoundResult `json:"cross_tenant"`
	CrossTenantRows int         `json:"cross_tenant_rows"`
}

// CMDiTimeMeasurements holds command injection time-based probe measurements.
type CMDiTimeMeasurements struct {
	SleepSeconds   int           `json:"sleep_seconds"`
	TargetOS       string        `json:"target_os"`
	BaselineRounds []RoundResult `json:"baseline_rounds"`
	PayloadRounds  []RoundResult `json:"payload_rounds"`
	BaselineAvgMs  int64         `json:"baseline_avg_ms"`
	PayloadAvgMs   int64         `json:"payload_avg_ms"`
	DeltaMs        int64         `json:"delta_ms"`
	PayloadUsed    string        `json:"payload_used"`
}

// LFIMeasurements holds local file inclusion probe measurements.
type LFIMeasurements struct {
	Baseline          RoundResult `json:"baseline"`
	Probe             RoundResult `json:"probe"`
	HashesMatch       bool        `json:"hashes_match"`
	MatchedSignatures []string    `json:"matched_signatures"`
	PayloadUsed       string      `json:"payload_used"`
	ResponseSnippet   string      `json:"response_snippet,omitempty"`
}

// SSTIMeasurements holds server-side template injection probe measurements.
type SSTIMeasurements struct {
	Probes []SSTIProbeResult `json:"probes"`
}

// SSTIProbeResult holds a single SSTI probe result.
type SSTIProbeResult struct {
	RoundResult
	PayloadUsed string `json:"payload_used"`
	Expected    string `json:"expected"`
	Found       bool   `json:"found"`
	Context     string `json:"context,omitempty"`
}

// XXEMeasurements holds XML external entity probe measurements.
type XXEMeasurements struct {
	Probe             RoundResult `json:"probe"`
	MatchedSignatures []string    `json:"matched_signatures"`
	PayloadUsed       string      `json:"payload_used"`
	ResponseSnippet   string      `json:"response_snippet,omitempty"`
}

// CSRFMeasurements holds CSRF probe measurements.
type CSRFMeasurements struct {
	NoOrigin        RoundResult `json:"no_origin"`
	MismatchOrigin  RoundResult `json:"mismatch_origin"`
	Baseline        RoundResult `json:"baseline"`
	SameSiteFound   bool        `json:"samesite_found"`
	SameSiteValue   string      `json:"samesite_value,omitempty"`
	CSRFTokenInBody bool        `json:"csrf_token_in_body"`
}

// NoSQLMeasurements holds NoSQL injection probe measurements.
type NoSQLMeasurements struct {
	Technique      string        `json:"technique"`
	TrueProbe      *RoundResult  `json:"true_probe,omitempty"`
	FalseProbe     *RoundResult  `json:"false_probe,omitempty"`
	HashesMatch    *bool         `json:"hashes_match,omitempty"`
	TruePayload    string        `json:"true_payload,omitempty"`
	FalsePayload   string        `json:"false_payload,omitempty"`
	SleepSeconds   *int          `json:"sleep_seconds,omitempty"`
	BaselineRounds []RoundResult `json:"baseline_rounds,omitempty"`
	PayloadRounds  []RoundResult `json:"payload_rounds,omitempty"`
	BaselineAvgMs  *int64        `json:"baseline_avg_ms,omitempty"`
	PayloadAvgMs   *int64        `json:"payload_avg_ms,omitempty"`
	DeltaMs        *int64        `json:"delta_ms,omitempty"`
	PayloadUsed    string        `json:"payload_used"`
}

// JWTMeasurements holds JWT manipulation probe measurements.
type JWTMeasurements struct {
	Technique       string      `json:"technique"`
	Baseline        RoundResult `json:"baseline"`
	Probe           RoundResult `json:"probe"`
	BodyLengthDelta int         `json:"body_length_delta"`
	ModifiedToken   string      `json:"modified_token"`
	PayloadUsed     string      `json:"payload_used"`
}

// CORSMeasurements holds CORS misconfiguration probe measurements.
type CORSMeasurements struct {
	Baseline        CORSProbeResult `json:"baseline"`
	EvilOrigin      CORSProbeResult `json:"evil_origin"`
	NullOrigin      CORSProbeResult `json:"null_origin"`
	SubdomainOrigin CORSProbeResult `json:"subdomain_origin"`
}

// CORSProbeResult holds a single CORS probe result with header details.
type CORSProbeResult struct {
	RoundResult
	OriginSent         string `json:"origin_sent"`
	ACAOHeader         string `json:"acao_header"`
	ACACHeader         string `json:"acac_header"`
	OriginReflected    bool   `json:"origin_reflected"`
	CredentialsAllowed bool   `json:"credentials_allowed"`
}

// ProtoPollutionMeasurements holds prototype pollution probe measurements.
type ProtoPollutionMeasurements struct {
	Technique       string      `json:"technique"`
	Baseline        RoundResult `json:"baseline"`
	InjectionProbe  RoundResult `json:"injection_probe"`
	VerifyProbe     RoundResult `json:"verify_probe"`
	HashesMatch     bool        `json:"hashes_match"`
	MarkerReflected bool        `json:"marker_reflected"`
	PayloadUsed     string      `json:"payload_used"`
	ResponseSnippet string      `json:"response_snippet,omitempty"`
}

// GraphQLMeasurements holds GraphQL abuse probe measurements.
type GraphQLMeasurements struct {
	Technique            string       `json:"technique"`
	Probe                RoundResult  `json:"probe"`
	IntrospectionEnabled *bool        `json:"introspection_enabled,omitempty"`
	TypeCount            *int         `json:"type_count,omitempty"`
	BatchAccepted        *bool        `json:"batch_accepted,omitempty"`
	Baseline             *RoundResult `json:"baseline,omitempty"`
	DeltaMs              *int64       `json:"delta_ms,omitempty"`
	PayloadUsed          string       `json:"payload_used"`
	ResponseSnippet      string       `json:"response_snippet,omitempty"`
}

// RequestMeasurements holds the record of one analyst-constructed scoped
// request. Result is the role the analyst declared (baseline, probe, or
// control) and EvidenceID is the ledger entry the coverage row can cite.
type RequestMeasurements struct {
	Method            string      `json:"method"`
	URL               string      `json:"url"`
	Result            string      `json:"result"`
	DeclaredRisk      int         `json:"declared_risk"`
	RequestBodyBytes  int         `json:"request_body_bytes"`
	RequestHash       string      `json:"request_hash"`
	RedirectsFollowed bool        `json:"redirects_followed"`
	Round             RoundResult `json:"round"`
	ResponseSnippet   string      `json:"response_snippet,omitempty"`
	EvidenceID        string      `json:"evidence_id,omitempty"`
}

// RaceMeasurements holds race condition probe measurements.
type RaceMeasurements struct {
	Concurrency  int           `json:"concurrency"`
	Rounds       []RoundResult `json:"rounds"`
	SuccessCount int           `json:"success_count"`
	UniqueHashes int           `json:"unique_hashes"`
	MinMs        int64         `json:"min_ms"`
	MaxMs        int64         `json:"max_ms"`
	AvgMs        int64         `json:"avg_ms"`
	PayloadUsed  string        `json:"payload_used"`
}

// CachePoisoningMeasurements holds cache poisoning probe measurements.
type CachePoisoningMeasurements struct {
	Technique              string      `json:"technique"`
	Baseline               RoundResult `json:"baseline"`
	Injection              RoundResult `json:"injection"`
	Verify                 RoundResult `json:"verify"`
	BaselineHash           string      `json:"baseline_hash"`
	VerifyHash             string      `json:"verify_hash"`
	VerifyMatchesInjection bool        `json:"verify_matches_injection"`
	VerifyMatchesBaseline  bool        `json:"verify_matches_baseline"`
	HeaderUsed             string      `json:"header_used"`
	PayloadUsed            string      `json:"payload_used"`
	ResponseSnippet        string      `json:"response_snippet,omitempty"`
}

// ClickjackingMeasurements holds clickjacking header probe measurements.
type ClickjackingMeasurements struct {
	Probe             RoundResult `json:"probe"`
	XFrameOptions     string      `json:"x_frame_options"`
	CSPFrameAncestors string      `json:"csp_frame_ancestors"`
	XFOPresent        bool        `json:"xfo_present"`
	CSPFAPresent      bool        `json:"cspfa_present"`
}

// HeaderInjectionMeasurements holds CRLF/header injection probe measurements.
type HeaderInjectionMeasurements struct {
	Baseline        RoundResult `json:"baseline"`
	Probe           RoundResult `json:"probe"`
	InjectedHeader  string      `json:"injected_header"`
	InjectedValue   string      `json:"injected_value"`
	HeaderFound     bool        `json:"header_found"`
	PayloadUsed     string      `json:"payload_used"`
	ResponseSnippet string      `json:"response_snippet,omitempty"`
}

// RedirectMeasurements holds open redirect probe measurements.
type RedirectMeasurements struct {
	Probe            RoundResult `json:"probe"`
	LocationHeader   string      `json:"location_header"`
	RedirectChain    []string    `json:"redirect_chain"`
	PayloadUsed      string      `json:"payload_used"`
	ExternalRedirect bool        `json:"external_redirect"`
}

// CSVInjectionMeasurements holds CSV injection probe measurements.
type CSVInjectionMeasurements struct {
	SubmitProbe     RoundResult `json:"submit_probe"`
	ExportProbe     RoundResult `json:"export_probe"`
	FormulaFound    bool        `json:"formula_found"`
	FormulaEscaped  bool        `json:"formula_escaped"`
	PayloadUsed     string      `json:"payload_used"`
	ResponseSnippet string      `json:"response_snippet,omitempty"`
}

// AuthZMeasurements holds authorization bypass probe measurements.
type AuthZMeasurements struct {
	HighPriv        RoundResult `json:"high_priv"`
	LowPriv         RoundResult `json:"low_priv"`
	StatusMatch     bool        `json:"status_match"`
	BodyLengthDelta int         `json:"body_length_delta"`
	HashesMatch     bool        `json:"hashes_match"`
}

// OriginCheckResult captures the result of a single origin-specific WebSocket upgrade attempt.
type OriginCheckResult struct {
	Origin         string `json:"origin"`
	UpgradeStatus  int    `json:"upgrade_status"`
	UpgradeSuccess bool   `json:"upgrade_success"`
	ElapsedMs      int64  `json:"elapsed_ms"`
}

// WebSocketMeasurements holds WebSocket security probe measurements.
type WebSocketMeasurements struct {
	Technique      string              `json:"technique"`
	UpgradeStatus  int                 `json:"upgrade_status"`
	UpgradeSuccess bool                `json:"upgrade_success"`
	OriginResults  []OriginCheckResult `json:"origin_results,omitempty"`
	Baseline       RoundResult         `json:"baseline"`
	ProbeRounds    []RoundResult       `json:"probe_rounds"`
	FramesSent     int                 `json:"frames_sent"`
	FramesReceived int                 `json:"frames_received"`
	PayloadUsed    string              `json:"payload_used"`
}

// PropertyAuthZMeasurements holds property-level authorization probe measurements.
type PropertyAuthZMeasurements struct {
	HighPriv           RoundResult        `json:"high_priv"`
	LowPriv            RoundResult        `json:"low_priv"`
	HighPrivFields     []string           `json:"high_priv_fields"`
	LowPrivFields      []string           `json:"low_priv_fields"`
	SharedFields       []string           `json:"shared_fields"`
	HighPrivOnlyFields []string           `json:"high_priv_only_fields"`
	LowPrivOnlyFields  []string           `json:"low_priv_only_fields"`
	WatchFieldResults  []WatchFieldResult `json:"watch_field_results,omitempty"`
	BodyLengthDelta    int                `json:"body_length_delta"`
	HashesMatch        bool               `json:"hashes_match"`
}

// WatchFieldResult reports whether a specific field is present in each response.
type WatchFieldResult struct {
	Name       string `json:"name"`
	InHighPriv bool   `json:"in_high_priv"`
	InLowPriv  bool   `json:"in_low_priv"`
}

// RateLimitMeasurements holds rate limit probe measurements.
// RateLimitMeasurementSet groups one or two per-identity bursts. identity_b is
// present only when a second token was supplied.
type RateLimitMeasurementSet struct {
	IdentityA RateLimitMeasurements  `json:"identity_a"`
	IdentityB *RateLimitMeasurements `json:"identity_b,omitempty"`
}

type RateLimitMeasurements struct {
	BurstCount      int           `json:"burst_count"`
	WindowSec       int           `json:"window_sec"`
	SuccessCount    int           `json:"success_count"`
	ThrottledCount  int           `json:"throttled_count"`
	FirstThrottleAt int           `json:"first_throttle_at"`
	StatusCodes     map[int]int   `json:"status_codes"`
	Rounds          []RoundResult `json:"rounds"`
	MinMs           int64         `json:"min_ms"`
	MaxMs           int64         `json:"max_ms"`
	AvgMs           int64         `json:"avg_ms"`
}

// LDAPMeasurements holds LDAP injection probe measurements.
type LDAPMeasurements struct {
	Technique       string       `json:"technique"`
	Baseline        *RoundResult `json:"baseline,omitempty"`
	Probe           *RoundResult `json:"probe,omitempty"`
	TrueProbe       *RoundResult `json:"true_probe,omitempty"`
	FalseProbe      *RoundResult `json:"false_probe,omitempty"`
	HashesMatch     *bool        `json:"hashes_match,omitempty"`
	TruePayload     string       `json:"true_payload,omitempty"`
	FalsePayload    string       `json:"false_payload,omitempty"`
	MatchedPatterns []string     `json:"matched_patterns,omitempty"`
	PayloadUsed     string       `json:"payload_used"`
	ResponseSnippet string       `json:"response_snippet,omitempty"`
}

// GRPCMeasurements holds gRPC security probe measurements.
type GRPCMeasurements struct {
	Technique         string   `json:"technique"`
	ReflectionEnabled bool     `json:"reflection_enabled"`
	ServicesFound     []string `json:"services_found"`
	TLSAccepted       bool     `json:"tls_accepted"`
	PlaintextAccepted bool     `json:"plaintext_accepted"`
	TLSRequired       bool     `json:"tls_required"`
	ElapsedMs         int64    `json:"elapsed_ms"`
}

// XPathMeasurements holds XPath injection probe measurements.
type XPathMeasurements struct {
	Technique       string       `json:"technique"`
	Baseline        *RoundResult `json:"baseline,omitempty"`
	Probe           *RoundResult `json:"probe,omitempty"`
	TrueProbe       *RoundResult `json:"true_probe,omitempty"`
	FalseProbe      *RoundResult `json:"false_probe,omitempty"`
	HashesMatch     *bool        `json:"hashes_match,omitempty"`
	TruePayload     string       `json:"true_payload,omitempty"`
	FalsePayload    string       `json:"false_payload,omitempty"`
	MatchedPatterns []string     `json:"matched_patterns,omitempty"`
	PayloadUsed     string       `json:"payload_used"`
	ResponseSnippet string       `json:"response_snippet,omitempty"`
}

// FileUploadMeasurements holds file upload vulnerability probe measurements.
type FileUploadMeasurements struct {
	Technique          string       `json:"technique"`
	Construction       string       `json:"construction"`
	UploadProbe        RoundResult  `json:"upload_probe"`
	FilenameInResponse bool         `json:"filename_in_response"`
	UploadAccepted     bool         `json:"upload_accepted"`
	VerifyProbe        *RoundResult `json:"verify_probe,omitempty"`
	VerifyAccessible   *bool        `json:"verify_accessible,omitempty"`
	FilenameSent       string       `json:"filename_sent"`
	MIMETypeSent       string       `json:"mime_type_sent"`
	ContentSent        string       `json:"content_sent"`
	ResponseSnippet    string       `json:"response_snippet,omitempty"`
}

// MassAssignmentMeasurements holds mass assignment probe measurements.
type MassAssignmentMeasurements struct {
	BaselineGET    RoundResult             `json:"baseline_get"`
	MutationProbe  RoundResult             `json:"mutation_probe"`
	FollowUpGET    RoundResult             `json:"followup_get"`
	BaselineFields []string                `json:"baseline_fields"`
	FollowUpFields []string                `json:"followup_fields"`
	InjectedFields []MassAssignFieldResult `json:"injected_fields"`
	HashesMatch    bool                    `json:"hashes_match"`
	PayloadUsed    string                  `json:"payload_used"`
}

// MassAssignFieldResult reports whether a specific field changed after injection.
type MassAssignFieldResult struct {
	Name          string      `json:"name"`
	InBaseline    bool        `json:"in_baseline"`
	InFollowUp    bool        `json:"in_followup"`
	BaselineValue interface{} `json:"baseline_value,omitempty"`
	FollowUpValue interface{} `json:"followup_value,omitempty"`
}

// Timer tracks probe duration.
type Timer struct {
	start time.Time
}

// NewTimer starts a new timer.
func NewTimer() *Timer {
	return &Timer{start: time.Now()}
}

// StartedAt returns the start time formatted as RFC3339.
func (t *Timer) StartedAt() string {
	return t.start.UTC().Format(time.RFC3339)
}

// Elapsed returns formatted elapsed duration.
func (t *Timer) Elapsed() string {
	d := time.Since(t.start)
	return d.Round(100 * time.Millisecond).String()
}
