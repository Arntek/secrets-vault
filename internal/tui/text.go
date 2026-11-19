package tui

import (
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/x/ansi"
)

// clean removes everything that could change the terminal's state or
// disguise text: control characters (including ESC, so no escape sequences),
// the C1 range, zero-width and other format characters (Cf), line and
// paragraph separators, and bidirectional overrides. Applied to every string from a
// vault before it is drawn.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case r == '\n' || r == '\r':
			return '⏎'
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			// Control, zero-width, bidi and other format characters, line and
			// paragraph separators: a dot, so they cannot hide or imitate a name.
			return '·'
		case r == 0xfffd:
			return '·'
		}
		return r
	}, s)
}

// fit cuts s to at most w display cells, adding … when it had to cut.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if ansi.StringWidth(s) <= w {
		return s
	}
	return ansi.Truncate(s, w, "…")
}

// pad cuts or pads s to exactly w display cells.
func pad(s string, w int) string {
	s = fit(s, w)
	if n := w - ansi.StringWidth(s); n > 0 {
		s += strings.Repeat(" ", n)
	}
	return s
}

// timeLeft renders a remaining duration as 3h41m, 12m or 40s.
func timeLeft(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	d = d.Round(time.Second)
	switch {
	case d >= time.Hour:
		return fmtInt(int(d/time.Hour)) + "h" + pad2(int(d%time.Hour/time.Minute)) + "m"
	case d >= time.Minute:
		return fmtInt(int(d/time.Minute)) + "m"
	}
	return fmtInt(int(d/time.Second)) + "s"
}

func fmtInt(n int) string { return strconv.Itoa(n) }

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// wrapWords breaks space-separated hints into lines no wider than w.
func wrapWords(items []string, w int) []string {
	var lines []string
	cur := ""
	for _, it := range items {
		switch {
		case cur == "":
			cur = it
		case ansi.StringWidth(cur)+2+ansi.StringWidth(it) <= w:
			cur += "  " + it
		default:
			lines = append(lines, cur)
			cur = it
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func itoa(n int) string { return strconv.Itoa(n) }
