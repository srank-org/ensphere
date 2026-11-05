package invariants

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/srank-org/ensphere/internal/evidence"
)

const (
	maxOutputBytes   = 4096
	maxCaptureBytes  = 1 << 20
	commandWaitDelay = 2 * time.Second
)

// cappedBuffer keeps the first limit bytes written and discards the rest.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func runCommand(inv Invariant, sourcePath string) outcome {
	timeout := defaultTimeoutSec
	if inv.TimeoutSec != nil {
		timeout = *inv.TimeoutSec
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", inv.Run)
	cmd.Dir = sourcePath
	cmd.Env = os.Environ()
	cmd.WaitDelay = commandWaitDelay
	stdout := &cappedBuffer{limit: maxCaptureBytes}
	stderr := &cappedBuffer{limit: maxCaptureBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errorOutcome("command timed out after %ds", timeout)
	}
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return errorOutcome("run command: %v", err)
		}
		exitCode = exitErr.ExitCode()
	}

	out := stdout.buf.String()
	measured := CommandMeasured{
		ExitCode: exitCode,
		Stdout:   truncateRedact(out),
		Stderr:   truncateRedact(stderr.buf.String()),
	}
	wantExit := 0
	if inv.Expect.ExitCode != nil {
		wantExit = *inv.Expect.ExitCode
	}
	checks := []Check{{Check: fmt.Sprintf("exit_code %d (got %d)", wantExit, exitCode), Held: exitCode == wantExit}}
	trimmed := strings.TrimSpace(out)
	if inv.Expect.StdoutEquals != "" {
		checks = append(checks, Check{Check: "stdout_equals", Held: trimmed == strings.TrimSpace(inv.Expect.StdoutEquals)})
	}
	if inv.Expect.StdoutMatches != "" {
		re, err := regexp.Compile(inv.Expect.StdoutMatches)
		if err != nil {
			return errorOutcome("expect.stdout_matches does not compile after substitution: %v", err)
		}
		checks = append(checks, Check{Check: "stdout_matches", Held: re.MatchString(trimmed)})
	}
	measured.Checks = checks
	return fromChecks(checks, measured)
}

func truncateRedact(s string) string {
	if len(s) > maxOutputBytes {
		s = s[:maxOutputBytes]
	}
	return evidence.RedactSecrets(s)
}
