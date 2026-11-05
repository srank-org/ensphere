package guard

import (
	"strings"
)

// The scanner is a small shell reader, not a shell. It honours single and
// double quotes, backslash escapes, comments, line continuations, redirections,
// here-documents, and subshell parentheses; it splits simple commands on |, ||,
// &&, ;, &, and newlines, and parses $(...) and backticks in place, including
// inside double quotes and unquoted here-document bodies. It does not expand
// variables, aliases, functions, globs, or brace lists, does not read scripts
// from disk, and does not follow programs that run other programs
// (make, npm scripts, git hooks). A case pattern's ")" ends a $(...) early,
// and $'...' strings are read as single-quoted. Anything it cannot follow is
// reported as uncheckable so the caller can refuse it.

const maxDepth = 8

type command struct {
	words []string
	stdin bool
}

type uncheckable struct {
	what string
}

func (e *uncheckable) Error() string { return e.what }

type heredoc struct {
	delim     string
	stripTabs bool
	quoted    bool
}

type parser struct {
	src      []rune
	pos      int
	depth    int
	cmds     []command
	words    []string
	word     strings.Builder
	inWord   bool
	stdin    bool
	skipNext bool
	parens   int
	heredocs []heredoc
}

// parse splits src into simple commands, with the commands of every command
// substitution appended alongside the command that contains them.
func parse(src string, depth int) ([]command, error) {
	if depth > maxDepth {
		return nil, &uncheckable{what: "nested shell"}
	}
	p := &parser{src: []rune(src), depth: depth}
	if err := p.run(false); err != nil {
		return nil, err
	}
	return p.cmds, nil
}

func (p *parser) peek(offset int) rune {
	if p.pos+offset < len(p.src) {
		return p.src[p.pos+offset]
	}
	return 0
}

func (p *parser) add(r rune) {
	p.word.WriteRune(r)
	p.inWord = true
}

func (p *parser) addString(s string) {
	p.word.WriteString(s)
	p.inWord = true
}

func (p *parser) endWord() {
	if !p.inWord {
		return
	}
	if p.skipNext {
		p.skipNext = false
	} else {
		p.words = append(p.words, p.word.String())
	}
	p.word.Reset()
	p.inWord = false
}

func (p *parser) endCommand() {
	p.endWord()
	p.skipNext = false
	if len(p.words) > 0 {
		p.cmds = append(p.cmds, command{words: p.words, stdin: p.stdin})
	}
	p.words = nil
	p.stdin = false
}

// run reads until the end of input or, when nested inside $(...), until the
// unmatched closing parenthesis.
func (p *parser) run(nested bool) error {
	for p.pos < len(p.src) {
		r := p.src[p.pos]
		switch {
		case r == '\\':
			if p.peek(1) == '\n' {
				p.pos += 2
				continue
			}
			if p.pos+1 < len(p.src) {
				p.add(p.src[p.pos+1])
			}
			p.pos += 2
		case r == '\'':
			end := indexFrom(p.src, p.pos+1, '\'')
			if end < 0 {
				return unterminated(p.src[p.pos:])
			}
			p.addString(string(p.src[p.pos+1 : end]))
			p.pos = end + 1
		case r == '"':
			start := p.pos
			p.pos++
			p.inWord = true
			if err := p.doubleQuoted(start); err != nil {
				return err
			}
		case r == '`':
			if err := p.backtick(); err != nil {
				return err
			}
		case r == '$' && p.peek(1) == '(':
			if err := p.substitution(); err != nil {
				return err
			}
		case r == '#' && !p.inWord:
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		case r == '\n':
			p.endCommand()
			p.pos++
			if err := p.readHeredocs(); err != nil {
				return err
			}
		case r == ' ' || r == '\t' || r == '\r':
			p.endWord()
			p.pos++
		case r == ';':
			p.endCommand()
			p.pos++
			if next := p.peek(0); next == ';' || next == '&' {
				p.pos++
			}
		case r == '&':
			switch p.peek(1) {
			case '>':
				p.endWord()
				p.pos++
				p.redirect()
			case '&':
				p.endCommand()
				p.pos += 2
			default:
				p.endCommand()
				p.pos++
			}
		case r == '|':
			switch p.peek(1) {
			case '|':
				p.endCommand()
				p.pos += 2
			case '&':
				p.endCommand()
				p.stdin = true
				p.pos += 2
			default:
				p.endCommand()
				p.stdin = true
				p.pos++
			}
		case r == '(':
			p.endCommand()
			p.parens++
			p.pos++
		case r == ')':
			p.endCommand()
			p.pos++
			if p.parens > 0 {
				p.parens--
			} else if nested {
				return nil
			}
		case r == '<' || r == '>':
			if p.peek(1) == '(' {
				return &uncheckable{what: string(r) + "("}
			}
			if p.inWord && isDigits(p.word.String()) {
				p.word.Reset()
				p.inWord = false
			} else {
				p.endWord()
			}
			if r == '<' && p.peek(1) == '<' {
				if err := p.hereInput(); err != nil {
					return err
				}
				continue
			}
			if r == '<' {
				p.stdin = true
			}
			p.redirect()
		default:
			p.add(r)
			p.pos++
		}
	}
	if nested {
		return &uncheckable{what: "$("}
	}
	p.endCommand()
	return p.readHeredocs()
}

// redirect consumes a redirection operator at p.pos and drops the word that
// follows it, which is a file name or descriptor, not a command argument.
func (p *parser) redirect() {
	for p.pos < len(p.src) && strings.ContainsRune("<>&|", p.src[p.pos]) {
		p.pos++
	}
	p.skipNext = true
}

// hereInput handles << and <<- (a here-document whose body starts on the next
// line) and <<< (a here-string whose word follows).
func (p *parser) hereInput() error {
	p.stdin = true
	if p.peek(2) == '<' {
		p.pos += 3
		p.skipNext = true
		return nil
	}
	p.pos += 2
	h := heredoc{}
	if p.peek(0) == '-' {
		h.stripTabs = true
		p.pos++
	}
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t') {
		p.pos++
	}
	var delim strings.Builder
	for p.pos < len(p.src) {
		r := p.src[p.pos]
		if strings.ContainsRune(" \t\r\n;&|<>()", r) {
			break
		}
		switch r {
		case '\'', '"':
			end := indexFrom(p.src, p.pos+1, r)
			if end < 0 {
				return unterminated(p.src[p.pos:])
			}
			delim.WriteString(string(p.src[p.pos+1 : end]))
			h.quoted = true
			p.pos = end + 1
		case '\\':
			h.quoted = true
			if p.pos+1 < len(p.src) {
				delim.WriteRune(p.src[p.pos+1])
			}
			p.pos += 2
		default:
			delim.WriteRune(r)
			p.pos++
		}
	}
	if delim.Len() == 0 {
		return &uncheckable{what: "<<"}
	}
	h.delim = delim.String()
	p.heredocs = append(p.heredocs, h)
	return nil
}

// readHeredocs consumes the bodies of pending here-documents, which start on
// the line after the command that opened them. An unquoted body still runs
// its command substitutions, so those are parsed.
func (p *parser) readHeredocs() error {
	for _, h := range p.heredocs {
		for p.pos < len(p.src) {
			end := indexFrom(p.src, p.pos, '\n')
			if end < 0 {
				end = len(p.src)
			}
			line := p.src[p.pos:end]
			p.pos = min(end+1, len(p.src))
			text := string(line)
			if h.stripTabs {
				text = strings.TrimLeft(text, "\t")
			}
			if strings.TrimRight(text, "\r") == h.delim {
				break
			}
			if !h.quoted {
				if err := p.expansions(line); err != nil {
					return err
				}
			}
		}
	}
	p.heredocs = nil
	return nil
}

// expansions parses the command substitutions in text that is otherwise data.
func (p *parser) expansions(text []rune) error {
	q := &parser{src: text, depth: p.depth}
	for q.pos < len(q.src) {
		switch {
		case q.src[q.pos] == '\\':
			q.pos += 2
		case q.src[q.pos] == '`':
			if err := q.backtick(); err != nil {
				return err
			}
		case q.src[q.pos] == '$' && q.peek(1) == '(':
			if err := q.substitution(); err != nil {
				return err
			}
		default:
			q.pos++
		}
	}
	p.cmds = append(p.cmds, q.cmds...)
	return nil
}

func (p *parser) doubleQuoted(start int) error {
	for p.pos < len(p.src) {
		r := p.src[p.pos]
		switch {
		case r == '"':
			p.pos++
			return nil
		case r == '\\':
			next := p.peek(1)
			switch next {
			case '\n':
			case '"', '\\', '$', '`':
				p.add(next)
			default:
				p.add(r)
				p.pos++
				continue
			}
			p.pos += 2
		case r == '`':
			if err := p.backtick(); err != nil {
				return err
			}
		case r == '$' && p.peek(1) == '(':
			if err := p.substitution(); err != nil {
				return err
			}
		default:
			p.add(r)
			p.pos++
		}
	}
	return unterminated(p.src[start:])
}

// substitution parses $(...) starting at p.pos and leaves "$()" in the
// current word, since its output is unknown.
func (p *parser) substitution() error {
	if p.depth+1 > maxDepth {
		return &uncheckable{what: "nested shell"}
	}
	sub := &parser{src: p.src, pos: p.pos + 2, depth: p.depth + 1}
	if err := sub.run(true); err != nil {
		return err
	}
	p.pos = sub.pos
	p.cmds = append(p.cmds, sub.cmds...)
	p.addString("$()")
	return nil
}

func (p *parser) backtick() error {
	start := p.pos
	p.pos++
	var body strings.Builder
	for p.pos < len(p.src) {
		r := p.src[p.pos]
		if r == '`' {
			p.pos++
			cmds, err := parse(body.String(), p.depth+1)
			if err != nil {
				return err
			}
			p.cmds = append(p.cmds, cmds...)
			p.addString("$()")
			return nil
		}
		if r == '\\' && strings.ContainsRune("`\\$", p.peek(1)) {
			body.WriteRune(p.peek(1))
			p.pos += 2
			continue
		}
		body.WriteRune(r)
		p.pos++
	}
	return unterminated(p.src[start:])
}

func unterminated(rest []rune) error {
	const limit = 40
	if len(rest) > limit {
		rest = append(rest[:limit:limit], '…')
	}
	return &uncheckable{what: string(rest)}
}

func indexFrom(src []rune, from int, target rune) int {
	for i := from; i < len(src); i++ {
		if src[i] == target {
			return i
		}
	}
	return -1
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
