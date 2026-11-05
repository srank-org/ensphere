package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/srank-org/ensphere/internal/evidence"
	"github.com/srank-org/ensphere/internal/invariants"
	"github.com/srank-org/ensphere/internal/sysmap"
	"github.com/srank-org/ensphere/internal/verify"
)

// Doctor check states. They describe the tooling's readiness, never the
// system under assessment.
const (
	DoctorOK      = "ok"
	DoctorWarning = "warning"
	DoctorError   = "error"
	DoctorSkipped = "skipped"
)

// DoctorConfig configures one readiness check.
type DoctorConfig struct {
	Workspace     string
	BinaryVersion string
	// PluginVersion is the version of the installed plugin, when known.
	PluginVersion string
	TimeoutSec    int
}

// DoctorCheck is one readiness check and what it saw.
type DoctorCheck struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// DoctorOutput is the result of ensphere run doctor.
type DoctorOutput struct {
	Workspace string        `json:"workspace"`
	Ready     bool          `json:"ready"`
	Checks    []DoctorCheck `json:"checks"`
	Message   string        `json:"message"`
}

// providerCLIs maps a cloud scope value to the CLI the cloud probes call and
// the read-only command that shows whether it is logged in.
var providerCLIs = map[string]struct{ binary, login string }{
	"aws":        {"aws", "aws sts get-caller-identity"},
	"gcp":        {"gcloud", "gcloud auth list"},
	"azure":      {"az", "az account show"},
	"kubernetes": {"kubectl", "kubectl auth whoami"},
	"cloudflare": {"wrangler", "wrangler whoami"},
	"supabase":   {"supabase", "supabase projects list"},
}

// RunDoctor runs every readiness check once, read-only, and reports each
// one. It sends at most one GET to the configured target. It never writes to
// the workspace. Ready is false when any check is an error.
func RunDoctor(cfg DoctorConfig) *DoctorOutput {
	if cfg.Workspace == "" {
		cfg.Workspace = defaultWorkspace
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 10
	}
	out := &DoctorOutput{Workspace: cfg.Workspace, Checks: []DoctorCheck{}}
	add := func(name, state, detail string) {
		out.Checks = append(out.Checks, DoctorCheck{Name: name, State: state, Detail: detail})
	}

	add(doctorBinary(cfg.BinaryVersion, cfg.PluginVersion))

	config, haveWorkspace := doctorWorkspace(cfg.Workspace, add)
	if !haveWorkspace {
		config = InitConfig{SourcePath: ".", Cloud: "none"}
	}

	doctorSource(cfg.Workspace, config, add)
	doctorMap(config.SourcePath, add)
	doctorInvariants(config.SourcePath, add)

	if !haveWorkspace {
		add("target", DoctorSkipped, "no workspace")
		add("sandbox", DoctorSkipped, "no workspace")
		add("providers", DoctorSkipped, "no workspace")
		add("ledgers", DoctorSkipped, "no workspace")
	} else {
		doctorTarget(config, cfg.TimeoutSec, add)
		doctorSandbox(cfg.Workspace, config, add)
		doctorProviders(config, add)
		doctorLedgers(cfg.Workspace, add)
	}

	out.Ready = true
	errors, warnings := 0, 0
	for _, check := range out.Checks {
		switch check.State {
		case DoctorError:
			errors++
			out.Ready = false
		case DoctorWarning:
			warnings++
		}
	}
	switch {
	case errors > 0:
		out.Message = fmt.Sprintf("Not ready: %d check(s) failed and %d warned. Fix each error, then run ensphere run doctor again.", errors, warnings)
	case warnings > 0:
		out.Message = fmt.Sprintf("Ready with %d warning(s); each becomes a stated limitation unless resolved.", warnings)
	default:
		out.Message = "Ready: every check passed."
	}
	return out
}

func doctorBinary(binaryVersion, pluginVersion string) (string, string, string) {
	binary := strings.TrimPrefix(strings.TrimSpace(binaryVersion), "v")
	plugin := strings.TrimPrefix(strings.TrimSpace(pluginVersion), "v")
	switch {
	case plugin == "":
		if releaseVersion.MatchString(binary) {
			return "binary", DoctorSkipped, fmt.Sprintf("ensphere v%s; plugin version unknown, pass --plugin-version to compare", binary)
		}
		return "binary", DoctorWarning, fmt.Sprintf("ensphere reports %q, which is not a release version; plugin version unknown", binaryVersion)
	case !releaseVersion.MatchString(binary):
		return "binary", DoctorWarning, fmt.Sprintf("ensphere reports %q, which is not a release version; plugin is v%s. Run the ensphere-setup skill to install the matching release", binaryVersion, plugin)
	case binary == plugin:
		return "binary", DoctorOK, fmt.Sprintf("ensphere v%s matches plugin v%s", binary, plugin)
	default:
		return "binary", DoctorError, fmt.Sprintf("ensphere v%s does not match plugin v%s. Run the ensphere-setup skill before continuing", binary, plugin)
	}
}

type addFunc func(name, state, detail string)

func doctorWorkspace(workspace string, add addFunc) (InitConfig, bool) {
	if !fileExists(configPath(workspace)) {
		add("workspace", DoctorError, fmt.Sprintf("no workspace at %s; run ensphere run init with the first-run inputs", workspace))
		return InitConfig{}, false
	}
	cfg, err := readConfig(workspace)
	if err != nil {
		add("workspace", DoctorError, err.Error())
		return InitConfig{}, false
	}
	states, err := readProgress(workspace)
	if err != nil {
		add("workspace", DoctorError, err.Error())
		return cfg, true
	}
	detail := fmt.Sprintf("config.md and progress.md read; environment %s", cfg.Environment)
	if next := nextSession(states); next != nil {
		detail += fmt.Sprintf("; next session %s", next.ID)
	} else {
		detail += "; every session is DONE"
	}
	if !fileExists(assessmentPlanPath(workspace)) {
		detail += "; no assessment plan yet (run ensphere run plan after Session 01)"
	}
	add("workspace", DoctorOK, detail)
	return cfg, true
}

func doctorSource(workspace string, cfg InitConfig, add addFunc) {
	if !fileExists(cfg.SourcePath) {
		add("source", DoctorError, fmt.Sprintf("source path %s does not exist", cfg.SourcePath))
		return
	}
	state, err := readSourceState(workspace, cfg)
	if err != nil {
		add("source", DoctorError, err.Error())
		return
	}
	switch {
	case !state.Git:
		add("source", DoctorWarning, fmt.Sprintf("%s is not in a git repository; the statement cannot name the commit it describes", cfg.SourcePath))
	case state.Commit == "":
		add("source", DoctorWarning, fmt.Sprintf("%s has no commit yet", cfg.SourcePath))
	case !state.Clean():
		add("source", DoctorWarning, fmt.Sprintf("commit %s with tracked changes the report gate will refuse: %s", shortCommit(state.Commit), listPaths(state.Modified)))
	case len(state.Untracked) > 0:
		add("source", DoctorOK, fmt.Sprintf("commit %s, clean; untracked files the statement will not describe: %s", shortCommit(state.Commit), listPaths(state.Untracked)))
	default:
		add("source", DoctorOK, fmt.Sprintf("commit %s, clean", shortCommit(state.Commit)))
	}
}

func doctorMap(sourcePath string, add addFunc) {
	path := sysmap.Path(sourcePath)
	if !fileExists(path) {
		add("map", DoctorSkipped, "no .ensphere/surfaces.yaml yet; Session 01 writes it")
		return
	}
	validation, m, err := sysmap.ValidateFile(path, sourcePath, CheckSessionIDs())
	if err != nil {
		add("map", DoctorError, err.Error())
		return
	}
	if !validation.Valid {
		add("map", DoctorError, fmt.Sprintf("%s has %d issue(s); run ensphere map validate", path, len(validation.Issues)))
		return
	}
	add("map", DoctorOK, fmt.Sprintf("%d surface(s), reconciled at %s", len(m.Surfaces), shortCommit(strings.TrimSpace(m.ReconciledAt))))
}

func doctorInvariants(sourcePath string, add addFunc) {
	dir := filepath.Join(sourcePath, invariants.DefaultDir)
	if !fileExists(dir) {
		add("invariants", DoctorSkipped, "no .ensphere/invariants/ yet; Session 09 writes them")
		return
	}
	invs, issues, err := invariants.Load(dir)
	if err != nil {
		add("invariants", DoctorError, err.Error())
		return
	}
	known, err := invariants.ResolveSurfaces(sourcePath, "")
	if err != nil {
		add("invariants", DoctorError, err.Error())
		return
	}
	issues = append(issues, invariants.Validate(invs, sourcePath, known)...)
	if invariants.HasErrors(issues) {
		add("invariants", DoctorError, fmt.Sprintf("%s has %d issue(s); run ensphere invariants validate", dir, len(issues)))
		return
	}
	enforced := 0
	for _, inv := range invs {
		if inv.Enforce {
			enforced++
		}
	}
	add("invariants", DoctorOK, fmt.Sprintf("%d invariant(s), %d enforced", len(invs), enforced))
}

func doctorTarget(cfg InitConfig, timeoutSec int, add addFunc) {
	target := strings.TrimSpace(cfg.TargetURL)
	if target == "" {
		add("target", DoctorSkipped, "no live target; source review only")
		return
	}
	scope, err := ParseScopeList(cfg.InScope)
	if err != nil {
		add("target", DoctorError, fmt.Sprintf("in-scope patterns in config.md: %v", err))
		return
	}
	if len(scope) == 0 {
		add("target", DoctorError, "config.md approves no in-scope pattern, so no verify command can run; add the target's host under In scope")
		return
	}
	if err := verify.CheckScope(target, scope); err != nil {
		add("target", DoctorError, fmt.Sprintf("target %s is outside the approved scope %v: %v", target, scope, err))
		return
	}
	resp := verify.HTTPProbeNoRedirect("GET", target, "", nil, timeoutSec, scope)
	if resp.Error != nil {
		add("target", DoctorError, fmt.Sprintf("GET %s failed: %v. Start the %s and check the URL in config.md", target, resp.Error, cfg.Environment))
		return
	}
	add("target", DoctorOK, fmt.Sprintf("GET %s answered %d in %dms (%s)", target, resp.StatusCode, resp.ElapsedMs, cfg.Environment))
}

func doctorSandbox(workspace string, cfg InitConfig, add addFunc) {
	if cfg.Environment != "sandbox" {
		add("sandbox", DoctorSkipped, fmt.Sprintf("environment is %s", cfg.Environment))
		return
	}
	raw, err := os.ReadFile(configPath(workspace))
	if err != nil {
		add("sandbox", DoctorError, err.Error())
		return
	}
	entries := sandboxEntries(string(raw))
	var approved, missing []string
	for _, label := range []string{"Start", "Seed", "Reset"} {
		if strings.TrimSpace(entries[label]) == "" {
			missing = append(missing, label)
		} else {
			approved = append(approved, label)
		}
	}
	extra := len(entries) - len(approved)
	if len(approved) == 0 && extra == 0 {
		add("sandbox", DoctorWarning, "no sandbox commands under ## Sandbox in config.md; without them the agent cannot start, seed, or reset the sandbox and the guard approves nothing")
		return
	}
	detail := fmt.Sprintf("approved under ## Sandbox: %s", orNone(strings.Join(approved, ", "), "none of Start, Seed, Reset"))
	if extra > 0 {
		detail += fmt.Sprintf(" and %d other command(s)", extra)
	}
	if len(missing) > 0 {
		add("sandbox", DoctorWarning, fmt.Sprintf("%s; not written: %s", detail, strings.Join(missing, ", ")))
		return
	}
	add("sandbox", DoctorOK, detail)
}

// sandboxEntries reads the "- <Label>: <command>" lines under ## Sandbox in
// a config.md, the same lines SandboxCommands approves.
func sandboxEntries(configMarkdown string) map[string]string {
	entries := map[string]string{}
	inSandbox := false
	for _, line := range strings.Split(configMarkdown, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "## "):
			inSandbox = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "## ")), "Sandbox")
		case inSandbox && strings.HasPrefix(line, "- "):
			label, command, ok := strings.Cut(strings.TrimPrefix(line, "- "), ":")
			if ok && strings.TrimSpace(command) != "" {
				entries[strings.TrimSpace(label)] = strings.TrimSpace(command)
			}
		}
	}
	return entries
}

func doctorProviders(cfg InitConfig, add addFunc) {
	clouds := splitList(cfg.Cloud)
	sort.Strings(clouds)
	var present, absent, unknown []string
	for _, cloud := range clouds {
		if cloud == "" || cloud == "none" {
			continue
		}
		cli, ok := providerCLIs[cloud]
		if !ok {
			unknown = append(unknown, cloud)
			continue
		}
		if _, err := exec.LookPath(cli.binary); err != nil {
			absent = append(absent, fmt.Sprintf("%s (%s)", cli.binary, cloud))
			continue
		}
		present = append(present, fmt.Sprintf("%s (check login with: %s)", cli.binary, cli.login))
	}
	if len(present)+len(absent)+len(unknown) == 0 {
		add("providers", DoctorSkipped, "cloud scope is none")
		return
	}
	detail := ""
	if len(present) > 0 {
		detail = "installed: " + strings.Join(present, "; ")
	}
	if len(unknown) > 0 {
		add("providers", DoctorError, fmt.Sprintf("unknown cloud scope %s in config.md", strings.Join(unknown, ", ")))
		return
	}
	if len(absent) > 0 {
		add("providers", DoctorError, strings.TrimSpace(fmt.Sprintf("not on PATH: %s. %s", strings.Join(absent, ", "), detail)))
		return
	}
	add("providers", DoctorOK, detail+". Ensphere never logs in on the operator's behalf")
}

func doctorLedgers(workspace string, add addFunc) {
	var checked, broken []string
	entries := 0
	for _, session := range Sessions {
		path := filepath.Join(workspace, session.Directory, "evidence.jsonl")
		if !fileExists(path) {
			continue
		}
		result, err := evidence.VerifyChain(path)
		if err != nil {
			broken = append(broken, fmt.Sprintf("%s (%v)", session.ID, err))
			continue
		}
		if !result.Valid {
			broken = append(broken, fmt.Sprintf("%s (broken at %s)", session.ID, orNone(result.BrokenAt, "unknown")))
			continue
		}
		checked = append(checked, session.ID)
		entries += result.EntriesChecked
	}
	switch {
	case len(broken) > 0:
		add("ledgers", DoctorError, "evidence chain broken in session "+strings.Join(broken, ", ")+"; a ledger is append-only and never edited")
	case len(checked) == 0:
		add("ledgers", DoctorSkipped, "no evidence ledger yet")
	default:
		add("ledgers", DoctorOK, fmt.Sprintf("%d ledger(s) verified, %d entries", len(checked), entries))
	}
}

// PluginVersion reads the version from <root>/.claude-plugin/plugin.json and
// returns "" when root is empty or the manifest cannot be read.
func PluginVersion(root string) string {
	if strings.TrimSpace(root) == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(root, ".claude-plugin", "plugin.json"))
	if err != nil {
		return ""
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return ""
	}
	return strings.TrimSpace(manifest.Version)
}
