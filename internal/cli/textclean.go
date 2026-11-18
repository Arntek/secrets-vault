package cli

import (
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
