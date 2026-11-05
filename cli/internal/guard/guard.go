// Package guard decides whether a shell command an agent is about to run in
// an assessment workspace goes through the ensphere CLI, is an operator-
// approved sandbox command, or reaches the network by another route.
package guard

import (
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
)

const (
	VerdictAllow = "allow"
	VerdictDeny  = "deny"
	VerdictNone  = "none"
)

// Decision is the guard's answer for one Bash command. Offending names the
// part of the command a deny refers to.
type Decision struct {
	Verdict   string
	Reason    string
	Offending string
}

// networkTools are command basenames that send traffic outside the ensphere
// CLI's scope and risk checks.
var networkTools = []string{
	"ab", "curl", "dirb", "dirbuster", "ffuf", "ftp", "gobuster", "hey",
	"http", "httpie", "https", "hydra", "k6", "masscan", "medusa", "nc",
	"ncat", "netcat", "nikto", "nmap", "nuclei", "rsync", "scp", "sftp",
	"siege", "socat", "sqlmap", "ssh", "telnet", "tftp", "vegeta", "wfuzz",
	"wget", "wrk", "xh", "zmap",
}

// inlineCodeFlags are the flags with which an interpreter runs code given on
// the command line.
var inlineCodeFlags = map[string][]string{
	"bun":     {"-e", "--eval"},
	"node":    {"-e", "--eval", "-p", "--print"},
	"nodejs":  {"-e", "--eval", "-p", "--print"},
	"perl":    {"-e", "-E"},
	"php":     {"-r"},
	"python":  {"-c"},
	"python2": {"-c"},
	"python3": {"-c"},
	"ruby":    {"-e"},
}

// interpreterValueFlags take a separate value that is not the script.
var interpreterValueFlags = map[string][]string{
	"node":    {"-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions", "--input-type"},
	"nodejs":  {"-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions", "--input-type"},
	"php":     {"-c", "-d", "-z"},
	"python":  {"-W", "-X"},
	"python2": {"-W", "-X"},
	"python3": {"-W", "-X"},
	"ruby":    {"-C", "-E", "-I", "-r"},
}

var shells = []string{"bash", "dash", "sh", "zsh"}

// unfollowable commands run text the guard cannot see.
var unfollowable = []string{".", "eval", "source", "xargs"}

var keywords = []string{"!", "do", "elif", "else", "if", "then", "until", "while", "{", "}"}

var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)

const (
	reasonEnsphere = "Ensphere guard: ensphere command"
	reasonSandbox  = "Ensphere guard: sandbox command approved in config.md"
	reasonTail     = " and an assessment workspace is active. Every request goes through the ensphere CLI: use ensphere verify request (or a verify family) for HTTP and ensphere evidence log for observations. To run it anyway, the operator adds the exact command under ## Sandbox in ensphere-pentest/config.md, or sets ENSPHERE_GUARD=off."
)

func denyNetwork(offending string) Decision {
	return deny(offending, "is a raw network tool")
}

func denyInline(offending string) Decision {
	return deny(offending, "runs inline code that the guard cannot check")
}

func denyUncheckable(offending string) Decision {
	return deny(offending, "cannot be checked by the guard")
}

func deny(offending, what string) Decision {
	return Decision{
		Verdict:   VerdictDeny,
		Reason:    "Ensphere guard: `" + offending + "` " + what + reasonTail,
		Offending: offending,
	}
}

// Decide classifies command. A command that equals an approved sandbox
// command exactly is allowed; otherwise it is deny when any simple command in
// it is deny, allow when every simple command is an ensphere command, and none
// otherwise.
func Decide(command string, approved []string) Decision {
	trimmed := strings.TrimSpace(command)
	for _, candidate := range approved {
		if candidate = strings.TrimSpace(candidate); candidate != "" && candidate == trimmed {
			return Decision{Verdict: VerdictAllow, Reason: reasonSandbox}
		}
	}
	return decideScript(trimmed, 0)
}

func decideScript(src string, depth int) Decision {
	cmds, err := parse(src, depth)
	if err != nil {
		var u *uncheckable
		if errors.As(err, &u) {
			return denyUncheckable(u.what)
		}
		return denyUncheckable(err.Error())
	}
	return combine(cmds, depth)
}

func combine(cmds []command, depth int) Decision {
	if len(cmds) == 0 {
		return Decision{Verdict: VerdictNone}
	}
	allAllow := true
	for _, cmd := range cmds {
		d := classify(cmd, depth)
		if d.Verdict == VerdictDeny {
			return d
		}
		if d.Verdict != VerdictAllow {
			allAllow = false
		}
	}
	if allAllow {
		return Decision{Verdict: VerdictAllow, Reason: reasonEnsphere}
	}
	return Decision{Verdict: VerdictNone}
}

// classify strips assignments, keywords, and wrappers to reach the command
// word, then classifies by its basename.
func classify(cmd command, depth int) Decision {
	words := cmd.words
	i := 0
strip:
	for i < len(words) {
		w := words[i]
		if assignment.MatchString(w) {
			i++
			continue
		}
		if slices.Contains(keywords, w) {
			i++
			continue
		}
		switch path.Base(w) {
		case "sudo":
			i = skipFlags(words, i+1, []string{"-u", "-g", "-C", "-D", "-h", "-p", "-R", "-r", "-t", "-U"})
		case "env":
			i++
			for i < len(words) && strings.HasPrefix(words[i], "-") {
				switch {
				case words[i] == "-S" || words[i] == "--split-string":
					return decideScript(strings.Join(words[i+1:], " "), depth+1)
				case strings.HasPrefix(words[i], "--split-string="):
					rest := append([]string{strings.TrimPrefix(words[i], "--split-string=")}, words[i+1:]...)
					return decideScript(strings.Join(rest, " "), depth+1)
				case words[i] == "-u" || words[i] == "--unset" || words[i] == "-C" || words[i] == "--chdir":
					i += 2
				default:
					i++
				}
			}
		case "nohup", "builtin":
			i++
		case "exec":
			i = skipFlags(words, i+1, []string{"-a"})
		case "time":
			i = skipFlags(words, i+1, nil)
		case "nice":
			i = skipFlags(words, i+1, []string{"-n"})
		case "timeout":
			i = skipFlags(words, i+1, []string{"-s", "-k"})
			i++
		case "command":
			i++
			for i < len(words) && strings.HasPrefix(words[i], "-") {
				if words[i] == "-v" || words[i] == "-V" {
					return Decision{Verdict: VerdictNone}
				}
				i++
			}
		default:
			break strip
		}
	}
	if i >= len(words) {
		return Decision{Verdict: VerdictNone}
	}
	word, args := words[i], words[i+1:]
	name := path.Base(word)
	switch {
	case strings.ContainsAny(name, "$`"):
		return denyUncheckable(word)
	case name == "ensphere":
		return Decision{Verdict: VerdictAllow, Reason: reasonEnsphere}
	case slices.Contains(unfollowable, name):
		return denyUncheckable(name)
	case slices.Contains(networkTools, name):
		return denyNetwork(name)
	case name == "openssl" && len(args) > 0 && args[0] == "s_client":
		return denyNetwork("openssl s_client")
	case slices.Contains(shells, name):
		return classifyShell(name, args, cmd.stdin, depth)
	case name == "deno" && len(args) > 0 && args[0] == "eval":
		return denyInline("deno eval")
	case name == "find":
		return classifyFind(args, depth)
	}
	if flags, ok := inlineCodeFlags[name]; ok {
		return classifyInterpreter(name, args, flags, cmd.stdin)
	}
	return Decision{Verdict: VerdictNone}
}

// skipFlags returns the index of the first word at or after i that is not a
// flag, skipping the value of each flag in valued.
func skipFlags(words []string, i int, valued []string) int {
	for i < len(words) && strings.HasPrefix(words[i], "-") {
		if words[i] == "--" {
			return i + 1
		}
		if slices.Contains(valued, words[i]) {
			i++
		}
		i++
	}
	return i
}

// classifyShell examines the string given to -c. A shell that reads its
// script from piped or redirected input runs code the guard never sees.
func classifyShell(name string, args []string, stdin bool, depth int) Decision {
	hasC := false
	for j := 0; j < len(args); j++ {
		a := args[j]
		if a == "-" || a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+") {
			if a == "-o" || a == "+o" || a == "-O" || a == "+O" {
				j++
			} else if !strings.HasPrefix(a, "--") && strings.Contains(a[1:], "c") {
				hasC = true
			}
			continue
		}
		if hasC {
			return decideScript(a, depth+1)
		}
		return Decision{Verdict: VerdictNone}
	}
	if stdin && !hasC {
		return denyInline(name)
	}
	return Decision{Verdict: VerdictNone}
}

func classifyInterpreter(name string, args, flags []string, stdin bool) Decision {
	valued := interpreterValueFlags[name]
	for j := 0; j < len(args); j++ {
		a := args[j]
		if a == "-" {
			return denyInline(name)
		}
		if a == "--" || !strings.HasPrefix(a, "-") || (a == "-m" && strings.HasPrefix(name, "python")) {
			return Decision{Verdict: VerdictNone}
		}
		for _, flag := range flags {
			if a == flag || strings.HasPrefix(a, flag+"=") || shortFlag(a, flag) {
				return denyInline(name + " " + a)
			}
		}
		if slices.Contains(valued, a) {
			j++
		}
	}
	if stdin {
		return denyInline(name)
	}
	return Decision{Verdict: VerdictNone}
}

// shortFlag reports whether a carries the one-letter flag with its value
// attached (-cprint(1)) or inside a cluster of letters (-pe, -lne).
func shortFlag(a, flag string) bool {
	if len(flag) != 2 || strings.HasPrefix(a, "--") || len(a) < 2 {
		return false
	}
	if strings.HasPrefix(a, flag) {
		return true
	}
	for _, r := range a[1:] {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return strings.ContainsRune(a[1:], rune(flag[1]))
}

// classifyFind classifies each command find runs through -exec, -execdir,
// -ok, or -okdir.
func classifyFind(args []string, depth int) Decision {
	var cmds []command
	for j := 0; j < len(args); j++ {
		switch args[j] {
		case "-exec", "-execdir", "-ok", "-okdir":
			end := j + 1
			for end < len(args) && args[end] != ";" && args[end] != "+" {
				end++
			}
			cmds = append(cmds, command{words: args[j+1 : end]})
			j = end
		}
	}
	d := combine(cmds, depth)
	if d.Verdict == VerdictAllow {
		return Decision{Verdict: VerdictNone}
	}
	return d
}
