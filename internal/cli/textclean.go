package cli

import (
	"strconv"
	"strings"
	"unicode"
)

// cleanText makes text written by someone else safe to show or hand to an
// AI agent's context: control characters (including ESC), line breaks,
// bidirectional overrides, zero-width and other format characters and line
// or paragraph separators become a plain space or are dropped, so a
// description cannot send terminal escapes, hide itself or imitate another
// name. It does not make the text trustworthy: descriptions are still data
// written by people.
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r' || r == ' ' || r == ' ':
			return ' '
		case unicode.IsControl(r):
			return -1
		case unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			return -1 // zero-width, bidi marks and overrides, BOM, word joiner
		case r == 0xfffd:
			return -1
		}
		return r
	}, s)
}

func cleanTexts(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = cleanText(s)
	}
	return out
}

// displayName makes a name that came from a shared folder (a file or folder
// name, a conflict copy, a quarantine path) safe to put in a message: quoted,
// with control characters (ESC, line breaks), zero-width and bidirectional
// characters and separators escaped (\x1b, \n, \u202e), and cut to a fixed
// length. Whoever can write the folder chooses these names, and the messages
// reach terminals and AI agents.
func displayName(s string) string {
	const maxRunes = 80
	if len(s) <= maxRunes && plainName(s) {
		return s // a validated key name, a hex id, a simple path: nothing to hide
	}
	if r := []rune(s); len(r) > maxRunes {
		s = string(r[:maxRunes]) + "..."
	}
	return strconv.Quote(s)
}

// displayNames is displayName for each, joined with sep.
func displayNames(ss []string, sep string) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = displayName(s)
	}
	return strings.Join(out, sep)
}

// plainName reports whether s is only letters, digits and . _ - / : too plain
// to carry an escape, a line break or a sentence.
func plainName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == '/':
		default:
			return false
		}
	}
	return true
}
