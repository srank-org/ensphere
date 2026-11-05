package invariants

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/srank-org/ensphere/internal/verify"
)

const defaultTimeoutSec = 30

// outcome is what one kind runner returns.
type outcome struct {
	result   string
	message  string
	measured any
}

func errorOutcome(format string, args ...any) outcome {
	return outcome{result: ResultError, message: fmt.Sprintf(format, args...)}
}

// fromChecks turns a list of checks into a pass or a fail naming what did not hold.
func fromChecks(checks []Check, measured any) outcome {
	var failed []string
	for _, c := range checks {
		if !c.Held {
			failed = append(failed, c.Check)
		}
	}
	if len(failed) == 0 {
		return outcome{result: ResultPass, message: "every declared expectation held", measured: measured}
	}
	return outcome{result: ResultFail, message: "did not hold: " + strings.Join(failed, "; "), measured: measured}
}

// Run executes the invariants in order, skipping any whose id is not in
// cfg.Only when Only is set. It assumes invs passed Validate.
//
// When cfg.Guard is set, each command invariant's substituted run string goes
// through it first, and a refusal makes the result error without executing
// it. Otherwise an agent could run a raw network tool during an assessment by
// writing it into an invariant. CI, with no guard, runs commands as written;
// Report.Guarded records which mode ran.
func Run(invs []Invariant, cfg RunConfig) *Report {
	if cfg.Getenv == nil {
		cfg.Getenv = os.Getenv
	}
	if cfg.SourcePath == "" {
		cfg.SourcePath = "."
	}
	only := make(map[string]bool, len(cfg.Only))
	for _, id := range cfg.Only {
		only[id] = true
	}
	throttle := verify.NewThrottle(cfg.ThrottleMs)

	changed := make(map[string]bool, len(cfg.ChangedSurfaces))
	for _, id := range cfg.ChangedSurfaces {
		changed[strings.TrimSpace(id)] = true
	}
	report := &Report{Target: cfg.Target, SourcePath: cfg.SourcePath, Since: cfg.Since, Guarded: cfg.Guard != nil, Invariants: []Result{}}
	for _, inv := range invs {
		if len(only) > 0 && !only[inv.ID] {
			continue
		}
		start := time.Now()
		out := runOne(inv, cfg, throttle)
		report.Invariants = append(report.Invariants, Result{
			ID:             inv.ID,
			Title:          inv.Title,
			Kind:           inv.Kind,
			Enforce:        inv.Enforce,
			Origin:         inv.Origin,
			Surface:        inv.Surface,
			SurfaceChanged: inv.Surface != "" && changed[inv.Surface],
			Result:         out.result,
			Message:        out.message,
			Measured:       out.measured,
			Expect:         inv.Expect,
			DurationMs:     time.Since(start).Milliseconds(),
		})
	}
	report.Summary = summarize(report.Invariants)
	report.Message = summaryMessage(report.Summary)
	if cfg.Since != "" {
		report.Message += fmt.Sprintf(" %d invariant(s) cover a surface whose files changed since %s.", report.Summary.SurfaceChanged, cfg.Since)
	}
	return report
}

func runOne(inv Invariant, cfg RunConfig, throttle *verify.Throttle) outcome {
	resolved, missing := substitute(inv, cfg.Getenv)
	if len(missing) > 0 {
		return errorOutcome("environment variable not set: %s", strings.Join(missing, ", "))
	}
	switch inv.Kind {
	case KindHTTP, KindRateLimit, KindSizeLimit:
		if cfg.Target == "" {
			return errorOutcome("kind %s needs a target base URL", inv.Kind)
		}
		throttle.Wait()
		switch inv.Kind {
		case KindHTTP:
			return runHTTP(resolved, cfg)
		case KindRateLimit:
			return runRateLimit(resolved, cfg)
		default:
			return runSizeLimit(resolved, cfg)
		}
	case KindSource:
		return runSource(resolved, cfg.SourcePath)
	case KindCommand:
		if cfg.Guard != nil {
			if reason := cfg.Guard(resolved.Run); reason != "" {
				return errorOutcome("%s", reason)
			}
		}
		return runCommand(resolved, cfg.SourcePath)
	default:
		return errorOutcome("unknown kind %q", inv.Kind)
	}
}

func summarize(results []Result) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		if r.SurfaceChanged {
			s.SurfaceChanged++
		}
		switch r.Result {
		case ResultPass:
			s.Pass++
			if !r.Enforce {
				s.UnenforcedPass++
			}
		case ResultFail:
			s.Fail++
			if r.Enforce {
				s.EnforcedFail++
			} else {
				s.UnenforcedFail++
			}
		case ResultError:
			s.Error++
		}
	}
	return s
}

func summaryMessage(s Summary) string {
	msg := fmt.Sprintf("%d of %d declared invariants held; %d did not hold (%d enforced, %d not yet enforced); %d could not be run.",
		s.Pass, s.Total, s.Fail, s.EnforcedFail, s.UnenforcedFail, s.Error)
	if s.UnenforcedPass > 0 {
		msg += fmt.Sprintf(" Unenforced invariants that held: %d; each can be set to enforce: true.", s.UnenforcedPass)
	}
	return msg + " A pass records only that the declared expectation held on this run."
}

// Passed reports whether a report meets the CI rule: no enforced failure and
// no error.
func (r *Report) Passed() bool {
	return r.Summary.EnforcedFail == 0 && r.Summary.Error == 0
}
