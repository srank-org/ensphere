// Package invariants loads, validates, and runs the deterministic expectations
// an assessment leaves in the target repository under .ensphere/invariants.
// A result records whether a declared expectation held on one run; it never
// states anything about the system beyond that expectation.
package invariants

// Kinds of invariant.
const (
	KindHTTP      = "http"
	KindRateLimit = "rate_limit"
	KindSizeLimit = "size_limit"
	KindSource    = "source"
	KindCommand   = "command"
)

// Result values.
const (
	ResultPass  = "pass"
	ResultFail  = "fail"
	ResultError = "error"
)

// SeverityError marks an issue that makes the invariant set invalid.
const SeverityError = "error"

// Invariant is one declared expectation, read from one YAML file.
type Invariant struct {
	ID         string   `json:"id" yaml:"id"`
	Title      string   `json:"title" yaml:"title"`
	Surface    string   `json:"surface,omitempty" yaml:"surface,omitempty"`
	Origin     Origin   `json:"origin" yaml:"origin"`
	Enforce    bool     `json:"enforce" yaml:"enforce"`
	Kind       string   `json:"kind" yaml:"kind"`
	Request    *Request `json:"request,omitempty" yaml:"request,omitempty"`
	Burst      *int     `json:"burst,omitempty" yaml:"burst,omitempty"`
	WindowSec  *int     `json:"window_sec,omitempty" yaml:"window_sec,omitempty"`
	SizeBytes  *int     `json:"size_bytes,omitempty" yaml:"size_bytes,omitempty"`
	Field      string   `json:"field,omitempty" yaml:"field,omitempty"`
	Include    []string `json:"include,omitempty" yaml:"include,omitempty"`
	Exclude    []string `json:"exclude,omitempty" yaml:"exclude,omitempty"`
	Pattern    string   `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Require    string   `json:"require,omitempty" yaml:"require,omitempty"`
	Run        string   `json:"run,omitempty" yaml:"run,omitempty"`
	TimeoutSec *int     `json:"timeout_sec,omitempty" yaml:"timeout_sec,omitempty"`
	Expect     Expect   `json:"expect" yaml:"expect"`

	// Path is the file the invariant was read from.
	Path string `json:"-" yaml:"-"`
}

// Origin names the assessment result an invariant was written from.
type Origin struct {
	Kind       string   `json:"kind" yaml:"kind"`
	Ref        string   `json:"ref" yaml:"ref"`
	Assessment string   `json:"assessment,omitempty" yaml:"assessment,omitempty"`
	Evidence   []string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// Request is the HTTP request the http, rate_limit, and size_limit kinds send.
type Request struct {
	Method  string            `json:"method,omitempty" yaml:"method,omitempty"`
	Path    string            `json:"path" yaml:"path"`
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body    string            `json:"body,omitempty" yaml:"body,omitempty"`
}

// Expect holds every expectation field; Validate keeps each kind to its own.
type Expect struct {
	Status          *int              `json:"status,omitempty" yaml:"status,omitempty"`
	StatusIn        []int             `json:"status_in,omitempty" yaml:"status_in,omitempty"`
	HeaderPresent   []string          `json:"header_present,omitempty" yaml:"header_present,omitempty"`
	HeaderAbsent    []string          `json:"header_absent,omitempty" yaml:"header_absent,omitempty"`
	HeaderMatches   map[string]string `json:"header_matches,omitempty" yaml:"header_matches,omitempty"`
	BodyContains    string            `json:"body_contains,omitempty" yaml:"body_contains,omitempty"`
	BodyNotContains string            `json:"body_not_contains,omitempty" yaml:"body_not_contains,omitempty"`

	ThrottledWithin  *int `json:"throttled_within,omitempty" yaml:"throttled_within,omitempty"`
	RetryAfterHeader bool `json:"retry_after_header,omitempty" yaml:"retry_after_header,omitempty"`

	Rejected *bool `json:"rejected,omitempty" yaml:"rejected,omitempty"`

	Matches          *int  `json:"matches,omitempty" yaml:"matches,omitempty"`
	EveryFileMatches *bool `json:"every_file_matches,omitempty" yaml:"every_file_matches,omitempty"`

	ExitCode      *int   `json:"exit_code,omitempty" yaml:"exit_code,omitempty"`
	StdoutEquals  string `json:"stdout_equals,omitempty" yaml:"stdout_equals,omitempty"`
	StdoutMatches string `json:"stdout_matches,omitempty" yaml:"stdout_matches,omitempty"`
}

// Issue is one load or validation problem, tied to the file it came from.
type Issue struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

// RunConfig configures one run of a set of invariants.
type RunConfig struct {
	Target     string
	SourcePath string
	Scope      []string
	MaxRisk    int
	ThrottleMs int
	TimeoutSec int
	Headers    map[string]string
	Only       []string
	Getenv     func(string) string
	// Since and ChangedSurfaces come from ensphere map changed: the ref the
	// working tree was compared with and the surfaces whose files changed.
	// Each result then says whether its surface is one of them.
	Since           string
	ChangedSurfaces []string
	// Guard, when set, classifies a command invariant's substituted shell
	// string before it runs and returns the reason to refuse it, or "" to
	// let it run. The plugin's assessment guard supplies it while a
	// workspace exists; nil runs commands as written, as CI does.
	Guard func(run string) string
}

// Report is the output of Run.
type Report struct {
	Target     string   `json:"target"`
	SourcePath string   `json:"source_path"`
	Since      string   `json:"since,omitempty"`
	Guarded    bool     `json:"guarded"`
	Invariants []Result `json:"invariants"`
	Summary    Summary  `json:"summary"`
	Message    string   `json:"message"`
}

// Result records one invariant's run. Expect echoes the declaration before
// environment substitution, so substituted values never reach the report.
type Result struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Kind    string `json:"kind"`
	Enforce bool   `json:"enforce"`
	Origin  Origin `json:"origin"`
	Surface string `json:"surface,omitempty"`
	// SurfaceChanged is true when the run was given a change set and the
	// invariant's surface is in it.
	SurfaceChanged bool   `json:"surface_changed,omitempty"`
	Result         string `json:"result"`
	Message        string `json:"message"`
	Measured       any    `json:"measured"`
	Expect         Expect `json:"expect"`
	DurationMs     int64  `json:"duration_ms"`
}

// Summary counts results. EnforcedFail and Error are what a CI gate fails on.
type Summary struct {
	Total          int `json:"total"`
	Pass           int `json:"pass"`
	Fail           int `json:"fail"`
	Error          int `json:"error"`
	EnforcedFail   int `json:"enforced_fail"`
	UnenforcedFail int `json:"unenforced_fail"`
	UnenforcedPass int `json:"unenforced_pass"`
	// SurfaceChanged counts the invariants whose surface changed since the
	// ref the run was given; 0 without one.
	SurfaceChanged int `json:"surface_changed"`
}

// Check is one expectation and whether it held.
type Check struct {
	Check string `json:"check"`
	Held  bool   `json:"held"`
}

// HTTPMeasured is what an http invariant measured.
type HTTPMeasured struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyLength int               `json:"body_length"`
	Checks     []Check           `json:"checks"`
}

// RateLimitMeasured is what a rate_limit invariant measured. FirstThrottleAt
// is the 1-based request number of the first 429 or 503, 0 when none.
type RateLimitMeasured struct {
	URL             string      `json:"url"`
	Burst           int         `json:"burst"`
	RequestsSent    int         `json:"requests_sent"`
	FirstThrottleAt int         `json:"first_throttle_at"`
	ThrottledCount  int         `json:"throttled_count"`
	StatusCodes     map[int]int `json:"status_codes"`
	RetryAfter      string      `json:"retry_after,omitempty"`
	Checks          []Check     `json:"checks"`
}

// SizeLimitMeasured is what a size_limit invariant measured.
type SizeLimitMeasured struct {
	URL              string  `json:"url"`
	SizeBytes        int     `json:"size_bytes"`
	StatusCode       int     `json:"status_code"`
	ResponseBytes    int     `json:"response_bytes"`
	ConnectionClosed bool    `json:"connection_closed,omitempty"`
	Checks           []Check `json:"checks"`
}

// SourceMeasured is what a source invariant measured. With pattern, Matches
// counts regex matches and Samples lists where; with require, Matches counts
// files that matched and Samples lists files that did not.
type SourceMeasured struct {
	FilesScanned      int            `json:"files_scanned"`
	Matches           int            `json:"matches"`
	FilesWithoutMatch int            `json:"files_without_match"`
	Samples           []SourceSample `json:"samples"`
}

// SourceSample is one location, with its snippet redacted.
type SourceSample struct {
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Snippet string `json:"snippet,omitempty"`
}

// CommandMeasured is what a command invariant measured; output is truncated
// to 4 KiB and redacted.
type CommandMeasured struct {
	ExitCode int     `json:"exit_code"`
	Stdout   string  `json:"stdout"`
	Stderr   string  `json:"stderr"`
	Checks   []Check `json:"checks"`
}
