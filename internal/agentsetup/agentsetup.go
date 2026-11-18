// Package agentsetup adds secrets-vault's agent instructions to a person's
// existing AI-agent setup, and removes exactly what it added.
//
// The rule (design decision D8) is additive only. This package touches two
// kinds of thing and nothing else:
//
//   - a file it owns (a skill's SKILL.md), recognised by a checksum marker on
//     its last line;
//   - a block inside a file somebody else owns (CLAUDE.md, AGENTS.md),
//     delimited by <!-- secrets-vault:start --> and <!-- secrets-vault:end -->.
//
// Everything outside the file or the block is never read for meaning, never
// rewritten and never deleted. If the file or block was edited by hand, the
// functions refuse unless Force is set. Writes are atomic (a temporary file in
// the same folder, then rename), keep the original permissions, and refuse
// symlinked targets. DryRun computes the same result and the same diff but
// writes nothing.
//
// The instructions are rules an agent follows. Nothing here enforces them.
package agentsetup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Block delimiters. They are part of the documented format: users can find
// and delete a block by hand.
const (
	StartMarker = "<!-- secrets-vault:start -->"
	EndMarker   = "<!-- secrets-vault:end -->"
	sumPrefix   = "<!-- secrets-vault:sha256 "
	sumSuffix   = " -->"
)

// ErrRefused means nothing was changed because doing so would touch
// something this package did not write. The message says why.
var ErrRefused = errors.New("refused")

func refusef(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// Opts controls a call.
type Opts struct {
	DryRun bool // compute the result and diff, write nothing
	Force  bool // replace or remove content that was edited by hand
}

// Result describes what a call did (or, with DryRun, would do).
type Result struct {
	Path   string `json:"path"`
	Action string `json:"action"` // created, updated, unchanged, removed, absent
	Diff   string `json:"diff,omitempty"`
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// --- files we own (skill) ---

func marked(content string) string {
	content = strings.TrimRight(content, "\n") + "\n"
	return content + sumPrefix + sum(content) + sumSuffix + "\n"
}

// ownedFile reports whether data is a file we wrote and nobody edited: its
// last line is a checksum marker matching everything before it. Any version
// of our content qualifies, so a newer build's file is still recognised.
func ownedFile(data string) (owned, edited bool) {
	trimmed := strings.TrimRight(data, "\n")
	i := strings.LastIndex(trimmed, "\n")
	last := trimmed[i+1:]
	if !strings.HasPrefix(last, sumPrefix) || !strings.HasSuffix(last, sumSuffix) {
		return false, false
	}
	want := strings.TrimSuffix(strings.TrimPrefix(last, sumPrefix), sumSuffix)
	if i < 0 {
		return true, true
	}
	return true, sum(trimmed[:i+1]) != want
}

// SetFile writes content (plus our checksum marker) to path. An existing file
// is replaced only if it is one we wrote and nobody edited; otherwise the call
// refuses unless Force is set.
func SetFile(path, content string, o Opts) (Result, error) {
	res := Result{Path: path}
	old, perm, exists, err := readTarget(path, true)
	if err != nil {
		return res, err
	}
	want := marked(content)
	if exists {
		owned, edited := ownedFile(old)
		if !owned && !o.Force {
			return res, refusef("%s already exists and was not written by secrets-vault, so it was left alone. Move it aside or use --force to replace it", path)
		}
		if owned && edited && !o.Force {
			return res, refusef("%s was edited after secrets-vault wrote it, so it was left alone. Use --force to replace your edits", path)
		}
		if old == want {
			res.Action = "unchanged"
			return res, nil
		}
		res.Action = "updated"
	} else {
		res.Action, perm = "created", 0o644
	}
	res.Diff = diff(path, old, want)
	if o.DryRun {
		return res, nil
	}
	return res, atomicWrite(path, []byte(want), perm, !exists)
}

// RemoveFile deletes path only if it is a file we wrote and nobody edited
// (current or newer version). It removes the folder holding it only if that
// folder is then empty.
func RemoveFile(path string, o Opts) (Result, error) {
	res := Result{Path: path}
	old, _, exists, err := readTarget(path, true)
	if err != nil {
		return res, err
	}
	if !exists {
		res.Action = "absent"
		return res, nil
	}
	owned, edited := ownedFile(old)
	if !owned && !o.Force {
		return res, refusef("%s was not written by secrets-vault, so it was left alone", path)
	}
	if owned && edited && !o.Force {
		return res, refusef("%s was edited after secrets-vault wrote it, so it was left alone. Use --force to delete it anyway", path)
	}
	res.Action = "removed"
	res.Diff = diff(path, old, "")
	if o.DryRun {
		return res, nil
	}
	if err := os.Remove(path); err != nil {
		return res, err
	}
	_ = os.Remove(filepath.Dir(path)) // only succeeds if empty
	return res, nil
}

// --- blocks inside files we do not own ---

func renderBlock(body string) string {
	body = strings.TrimRight(body, "\n") + "\n"
	return StartMarker + "\n" + sumPrefix + sum(body) + sumSuffix + "\n" + body + EndMarker + "\n"
}

type span struct {
	start, end int // byte range of the whole block, markers included, through the newline after the end marker
	body       string
	hasSum     bool
	edited     bool
}

// findBlock locates our block. It refuses an unbalanced or duplicated pair
// rather than guess which text is ours.
func findBlock(path, data string) (*span, error) {
	ns, ne := strings.Count(data, StartMarker), strings.Count(data, EndMarker)
	switch {
	case ns == 0 && ne == 0:
		return nil, nil
	case ns != 1 || ne != 1:
		return nil, refusef("%s has %d start and %d end markers for secrets-vault (expected one of each), so it was left alone. Fix or delete the markers by hand", path, ns, ne)
	}
	s := strings.Index(data, StartMarker)
	e := strings.Index(data, EndMarker)
	if e < s {
		return nil, refusef("%s has the secrets-vault end marker before the start marker, so it was left alone", path)
	}
	end := e + len(EndMarker)
	if end < len(data) && data[end] == '\n' {
		end++
	}
	inner := data[s+len(StartMarker) : e]
	inner = strings.TrimPrefix(inner, "\n")
	sp := &span{start: s, end: end}
	line, rest, _ := strings.Cut(inner, "\n")
	if strings.HasPrefix(line, sumPrefix) && strings.HasSuffix(line, sumSuffix) {
		sp.hasSum = true
		sp.body = rest
		sp.edited = sum(rest) != strings.TrimSuffix(strings.TrimPrefix(line, sumPrefix), sumSuffix)
	} else {
		sp.body, sp.edited = inner, true
	}
	return sp, nil
}

// SetBlock adds our block to the end of path (creating the file if needed),
// or updates it in place if it is already there. Text outside the block is
// never touched. A block edited by hand is replaced only with Force.
func SetBlock(path, body string, o Opts) (Result, error) {
	res := Result{Path: path}
	old, perm, exists, err := readTarget(path, false)
	if err != nil {
		return res, err
	}
	block := renderBlock(body)
	var next string
	switch sp, err := findBlock(path, old); {
	case err != nil:
		return res, err
	case sp != nil:
		if sp.edited && !o.Force {
			return res, refusef("the secrets-vault block in %s was edited by hand, so it was left alone. Use --force to replace your edits", path)
		}
		next = old[:sp.start] + block + old[sp.end:]
		res.Action = "updated"
	default:
		next = old
		if exists && old != "" {
			// One blank line before the block; RemoveBlock undoes exactly
			// this. Without a final newline we add only the newline.
			if strings.HasSuffix(next, "\n") {
				next += "\n"
			} else {
				next += "\n" // no blank line: the file had no final newline
			}
		}
		next += block
		res.Action = "updated"
		if !exists {
			res.Action, perm = "created", 0o644
		}
	}
	if next == old && exists {
		res.Action = "unchanged"
		return res, nil
	}
	res.Diff = diff(path, old, next)
	if o.DryRun {
		return res, nil
	}
	return res, atomicWrite(path, []byte(next), perm, !exists)
}

// RemoveBlock deletes our block, plus the separator SetBlock added in front
// of it, leaving the rest of the file byte-for-byte as it was. A file that
// then holds nothing is deleted, since SetBlock may have created it.
func RemoveBlock(path string, o Opts) (Result, error) {
	res := Result{Path: path}
	old, perm, exists, err := readTarget(path, false)
	if err != nil {
		return res, err
	}
	if !exists {
		res.Action = "absent"
		return res, nil
	}
	sp, err := findBlock(path, old)
	if err != nil {
		return res, err
	}
	if sp == nil {
		res.Action = "absent"
		return res, nil
	}
	if sp.edited && !o.Force {
		return res, refusef("the secrets-vault block in %s was edited by hand, so it was left alone. Use --force to remove it anyway", path)
	}
	before, after := old[:sp.start], old[sp.end:]
	if strings.HasSuffix(before, "\n\n") {
		before = before[:len(before)-1] // the blank line we added
	} else if strings.HasSuffix(before, "\n") && after == "" {
		// The file had no final newline when we appended: we added only one.
		before = before[:len(before)-1]
	}
	next := before + after
	res.Action = "removed"
	res.Diff = diff(path, old, next)
	if o.DryRun {
		return res, nil
	}
	if next == "" {
		return res, os.Remove(path)
	}
	return res, atomicWrite(path, []byte(next), perm, false)
}

// --- file access ---

// readTarget reads path, refusing symlinks and anything that is not a regular
// file. A missing file is not an error.
func readTarget(path string, owned bool) (data string, perm fs.FileMode, exists bool, err error) {
	if owned {
		if err := refuseSymlinkDir(path); err != nil {
			return "", 0, false, err
		}
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", 0o644, false, nil
	}
	if err != nil {
		return "", 0, false, fmt.Errorf("cannot read %s: %w", path, pathErr(err))
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return "", 0, false, refusef("%s is a symlink, so it was left alone (secrets-vault never writes through a link; edit the real file or point the setup at it)", path)
	}
	if !fi.Mode().IsRegular() {
		return "", 0, false, refusef("%s is not a regular file", path)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- the agent-config file the person asked us to edit; symlinks refused above
	if err != nil {
		return "", 0, false, fmt.Errorf("cannot read %s: %w", path, pathErr(err))
	}
	return string(b), fi.Mode().Perm(), true, nil
}

// refuseSymlinkDir refuses when the folder that directly holds a file we own
// (the skill folder) is a symlink, since we would be writing into somewhere
// else. Higher folders may be links: dotfile setups commonly link ~/.claude.
func refuseSymlinkDir(path string) error {
	dir := filepath.Dir(path)
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return refusef("%s is a symlink, so it was left alone", dir)
	}
	return nil
}

func pathErr(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// atomicWrite writes data next to path and renames it into place. perm is the
// original file's permission bits, kept as they were.
func atomicWrite(path string, data []byte, perm fs.FileMode, createDirs bool) error {
	dir := filepath.Dir(path)
	if createDirs {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("cannot create %s: %w", dir, pathErr(err))
		}
	}
	tmp, err := os.CreateTemp(dir, ".secrets-vault-*.tmp")
	if err != nil {
		return fmt.Errorf("cannot write in %s: %w", dir, pathErr(err))
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Re-check just before the rename: a link planted since we looked.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return refusef("%s became a symlink, so it was left alone", path)
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// --- diff ---

// diff returns a small unified-style diff. Our edits are always one
// contiguous region, so common head and tail lines are trimmed and the middle
// is shown with up to three lines of context.
func diff(path, a, b string) string {
	if a == b {
		return ""
	}
	al, bl := splitLines(a), splitLines(b)
	p := 0
	for p < len(al) && p < len(bl) && al[p] == bl[p] {
		p++
	}
	s := 0
	for s < len(al)-p && s < len(bl)-p && al[len(al)-1-s] == bl[len(bl)-1-s] {
		s++
	}
	from := max(p-3, 0)
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "--- %s\n+++ %s\n", path, path)
	for _, l := range al[from:p] {
		buf.WriteString(" " + l + "\n")
	}
	for _, l := range al[p : len(al)-s] {
		buf.WriteString("-" + l + "\n")
	}
	for _, l := range bl[p : len(bl)-s] {
		buf.WriteString("+" + l + "\n")
	}
	tail := al[len(al)-s:]
	for i, l := range tail {
		if i == 3 {
			break
		}
		buf.WriteString(" " + l + "\n")
	}
	return buf.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}
